"""Offline regression for retaining in-scope mapping assets after prefilter."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.agents import collector
from app.db.models import Base, Target, Task


class CollectorAssetRetentionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_async_engine(f"sqlite+aiosqlite:///{Path(self.tmp.name) / 'test.db'}")
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)
        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    async def asyncTearDown(self) -> None:
        await self.engine.dispose()
        self.tmp.cleanup()

    async def test_alternate_scheme_recovers_live_site_and_keeps_rejected_reasons(self) -> None:
        candidates = [
            {"host": "live.example.invalid", "url": "http://live.example.invalid"},
            {"host": "down.example.invalid", "url": "http://down.example.invalid"},
            {"host": "cdn.example.invalid", "url": "http://cdn.example.invalid"},
        ]

        def fake_probe(host: str, url: str) -> tuple[bool, str, dict]:
            if host == "cdn.example.invalid":
                return True, "CDN/对象存储/静态托管域名", {}
            if url == "https://live.example.invalid":
                return False, "", {"alive": True, "status": 200}
            return True, "死链/连接超时/无响应", {"alive": False, "status": 0}

        with patch.object(collector.prefilter, "should_skip_ex", side_effect=fake_probe) as probe:
            survivors, rejected = await collector._prefilter(candidates)
        self.assertEqual([item["host"] for item in survivors], ["live.example.invalid"])
        self.assertEqual(survivors[0]["url"], "https://live.example.invalid")
        self.assertEqual([item[0]["host"] for item in rejected], ["down.example.invalid", "cdn.example.invalid"])
        self.assertEqual(probe.call_count, 5)

    async def test_fofa_page_retains_prefilter_reject_without_worker_queueing(self) -> None:
        task = Task(
            id="retention-task", name="offline", src_type="edusrc", target_source="fofa",
            fofa_query='domain="example.invalid"', fofa_config={"intent_mode": "syntax"},
        )
        result = SimpleNamespace(
            fields=["host", "ip", "org", "title"],
            results=[
                ["http://live.example.invalid", "", "", "Live"],
                ["http://down.example.invalid", "", "", "Down"],
            ],
            next_cursor=None,
        )
        provider = SimpleNamespace(
            name="fofa", display_name="FOFA", search=AsyncMock(return_value=result),
            get_default_base_url=lambda: "https://fofa.invalid",
        )
        settings = {"engine": "fofa", "key": "offline-key", "max_pages": 20, "page_size": 100}

        async def fake_prefilter(candidates: list[dict]):
            candidates[0]["_probe"] = {"alive": True, "status": 200}
            return [candidates[0]], [(candidates[1], "死链/连接超时/无响应")]

        async def fake_score(survivors: list[dict], src_type: str):
            survivors[0]["priority_score"] = 10.0
            survivors[0]["priority_reason"] = "offline fixture"

        report = AsyncMock()
        with patch.object(collector, "resolve_engine_config", return_value=settings), \
             patch.object(collector, "get_engine", return_value=provider), \
             patch.object(collector, "_llm_for_task", return_value=None), \
             patch.object(collector, "_prefilter", side_effect=fake_prefilter), \
             patch.object(collector, "_annotate_assets", new=AsyncMock()), \
             patch.object(collector, "_score_targets", side_effect=fake_score), \
             patch.object(collector, "_analyze_target_filters", new=AsyncMock()), \
             patch.object(collector.target_filter, "evaluate_target", return_value=SimpleNamespace(
                 skip=False, score_bonus=0, bonus_reason="")), \
             patch("app.engines.meter.record_engine_search"):
            async with self.sessions() as session:
                session.add(task)
                await session.commit()
                added = await collector._fofa_collect(session, task, set(), {}, report)
                await session.commit()
                targets = (await session.execute(select(Target).order_by(Target.host))).scalars().all()

        self.assertEqual(added, 1)
        self.assertEqual(len(targets), 2)
        self.assertEqual((targets[0].status, targets[0].verdict), ("skipped", "skip_prefilter"))
        self.assertIn("未进入漏洞检测", targets[0].dead_reason)
        self.assertEqual(targets[1].status, "queued")
        self.assertEqual(task.fofa_config["last_prefilter_rejected"], 1)
        scoring = [call.kwargs for call in report.await_args_list if call.args[0] == "scoring"]
        self.assertEqual(scoring[0]["prefilter_rejected"], 1)

    async def test_widespread_transient_failure_pauses_fofa_without_losing_assets(self) -> None:
        task = Task(
            id="outage-task", name="offline outage", src_type="edusrc",
            target_source="fofa", fofa_query='domain="example.invalid"',
            fofa_config={"intent_mode": "syntax"},
        )
        rows = [[f"http://site-{i}.example.invalid", "", "", ""] for i in range(20)]
        result = SimpleNamespace(fields=["host", "ip", "org", "title"], results=rows, next_cursor=None)
        provider = SimpleNamespace(
            name="fofa", display_name="FOFA", search=AsyncMock(return_value=result),
            get_default_base_url=lambda: "https://fofa.invalid",
        )
        settings = {"engine": "fofa", "key": "offline-key", "max_pages": 20, "page_size": 100}

        async def all_unreachable(candidates: list[dict]):
            return [], [(candidate, "死链/连接超时/无响应") for candidate in candidates]

        report = AsyncMock()
        with patch.object(collector, "resolve_engine_config", return_value=settings), \
             patch.object(collector, "get_engine", return_value=provider), \
             patch.object(collector, "_llm_for_task", return_value=None), \
             patch.object(collector, "_prefilter", side_effect=all_unreachable), \
             patch("app.engines.meter.record_engine_search"):
            async with self.sessions() as session:
                session.add(task)
                await session.commit()
                self.assertEqual(await collector._fofa_collect(session, task, set(), {}, report), 0)
                self.assertGreater(task.fofa_config["prefilter_pause_until"], collector.time.time())
                self.assertEqual(await collector._fofa_collect(session, task, set(), {}, report), 0)
                await session.commit()
                targets = (await session.execute(select(Target))).scalars().all()

        self.assertEqual(provider.search.await_count, 1)
        self.assertEqual(len(targets), 20)
        self.assertTrue(all(t.status == "skipped" and t.verdict == "skip_prefilter" for t in targets))
        self.assertIn("prefilter_cooldown", [call.args[0] for call in report.await_args_list])


if __name__ == "__main__":
    unittest.main()
