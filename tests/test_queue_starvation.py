"""Offline regression: 20 HTTP 502 targets must not starve collection."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.agents import collector
from app.db.models import Base, Target, Task
from app.orchestrator import TaskRunner


class QueueStarvationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_async_engine(f"sqlite+aiosqlite:///{Path(self.tmp.name) / 'test.db'}")
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with self.sessions() as session:
            session.add(Task(id="test-task", name="offline", target_source="fofa", status="running"))
            await session.commit()

    async def asyncTearDown(self) -> None:
        await self.engine.dispose()
        self.tmp.cleanup()

    async def add_targets(self, count: int, *, cooling: bool) -> None:
        async with self.sessions() as session:
            for n in range(count):
                session.add(Target(
                    id=f"target-{n}", task_id="test-task", host=f"host{n}.example.invalid",
                    url=f"https://host{n}.example.invalid", source="fofa", status="queued",
                    prefilter_retry_at=datetime.now(timezone.utc) + timedelta(minutes=15) if cooling else None,
                ))
            await session.commit()

    async def test_twenty_cooling_targets_allow_refill(self) -> None:
        await self.add_targets(20, cooling=True)
        async with self.sessions() as session:
            task = await session.get(Task, "test-task")
            with patch.object(collector, "_fofa_collect", new=AsyncMock(return_value=1)) as collect:
                self.assertEqual(await collector.refill(session, task, low_watermark=5), 1)
                collect.assert_awaited_once()

    async def test_twenty_ready_targets_keep_backpressure(self) -> None:
        await self.add_targets(20, cooling=False)
        async with self.sessions() as session:
            task = await session.get(Task, "test-task")
            with patch.object(collector, "_fofa_collect", new=AsyncMock()) as collect:
                self.assertEqual(await collector.refill(session, task, low_watermark=5), 0)
                collect.assert_not_awaited()

    async def test_expired_cooldown_counts_as_ready_again(self) -> None:
        await self.add_targets(5, cooling=True)
        async with self.sessions() as session:
            targets = (await session.execute(select(Target))).scalars().all()
            for target in targets:
                target.prefilter_retry_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            await session.commit()
            task = await session.get(Task, "test-task")
            with patch.object(collector, "_fofa_collect", new=AsyncMock()) as collect:
                await collector.refill(session, task, low_watermark=5)
                collect.assert_not_awaited()

    async def test_cooldown_survives_new_runner(self) -> None:
        await self.add_targets(1, cooling=True)
        runner = TaskRunner("test-task")
        runner._probe_queued_liveness = AsyncMock(side_effect=AssertionError("cooling target must not be probed"))
        async with self.sessions() as session:
            self.assertIsNone(await runner._pop_queued(session))
        runner._probe_queued_liveness.assert_not_awaited()

    async def test_persistent_502_retries_are_bounded_across_runners(self) -> None:
        await self.add_targets(1, cooling=False)
        async with self.sessions() as session:
            target = await session.get(Target, "target-0")
            target.retry_count = 2
            await session.commit()
        for attempt in range(1, 4):
            runner = TaskRunner("test-task")
            runner._log = AsyncMock()
            runner._probe_queued_liveness = AsyncMock(return_value={
                "target-0": {"alive": True, "skip": True, "reason": "服务异常(502)", "status": 502},
            })
            with patch("app.orchestrator.QUEUE_TRANSIENT_PREFILTER_MAX_FAILURES", 3):
                async with self.sessions() as session:
                    self.assertIsNone(await runner._pop_queued(session))
            async with self.sessions() as session:
                target = await session.get(Target, "target-0")
                self.assertEqual(target.prefilter_fail_count, attempt)
                self.assertEqual(target.retry_count, 2)
                if attempt < 3:
                    self.assertEqual(target.status, "queued")
                    self.assertIsNotNone(target.prefilter_retry_at)
                    target.prefilter_retry_at = datetime.now(timezone.utc) - timedelta(seconds=1)
                    await session.commit()
                else:
                    self.assertEqual(target.status, "dead")
                    self.assertEqual(target.verdict, "prefilter_retry_exhausted")
                    self.assertIn("未完成漏洞检测", target.dead_reason)
                    self.assertIsNone(target.prefilter_retry_at)
            if attempt == 3:
                self.assertIn("target_prefilter_exhausted", [c.args[2] for c in runner._log.await_args_list])

    async def test_recovered_service_dispatches_and_resets_failures(self) -> None:
        await self.add_targets(1, cooling=False)
        async with self.sessions() as session:
            target = await session.get(Target, "target-0")
            target.prefilter_fail_count = 2
            target.last_error = "服务异常(502)"
            await session.commit()
        runner = TaskRunner("test-task")
        runner._log = AsyncMock()
        runner._probe_queued_liveness = AsyncMock(return_value={"target-0": {"alive": True, "status": 200}})
        async with self.sessions() as session:
            target = await runner._pop_queued(session)
            self.assertIsNotNone(target)
            self.assertEqual(target.status, "assigned")
            self.assertEqual(target.prefilter_fail_count, 0)
            self.assertEqual(target.last_error, "")
            self.assertIsNone(target.prefilter_retry_at)


class DailyQuotaTests(unittest.IsolatedAsyncioTestCase):
    async def test_today_call_quota_sets_cooldown_and_suppresses_search(self) -> None:
        from types import SimpleNamespace
        task = Task(id="offline-quota", target_source="fofa", fofa_config={
            "current_query": 'domain="example.invalid"', "cursor": 1, "history": [],
        })
        engine = SimpleNamespace(name="fofa", display_name="FOFA", search=AsyncMock(
            side_effect=ValueError("FOFA 错误: [-200] 今日调用次数已用完")),
            get_default_base_url=lambda: "https://fofa.invalid")
        session = SimpleNamespace(commit=AsyncMock())
        config = {"engine": "fofa", "key": "offline-key", "max_pages": 20, "page_size": 100}
        report = AsyncMock()
        with patch.object(collector, "resolve_engine_config", return_value=config), \
             patch.object(collector, "get_engine", return_value=engine), \
             patch.object(collector, "_llm_for_task", return_value=None), \
             patch("app.engines.meter.record_engine_search"):
            await collector._fofa_collect(session, task, set(), {}, report)
            self.assertEqual(task.fofa_config["daily_limit_count"], 1)
            self.assertEqual(task.fofa_config["cursor"], 1)
            self.assertEqual(task.fofa_config["fofa_auth_fail_count"], 0)
            self.assertGreater(task.fofa_config["daily_limit_until"], 0)
            await collector._fofa_collect(session, task, set(), {}, report)
            engine.search.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
