"""Offline regressions for cooldown admission and independent health gates."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import LLMConfig
from app.db.models import Base, Target, Task
from app.llm import health
from app.orchestrator import TaskRunner


def provider(name: str) -> LLMConfig:
    return LLMConfig(base_url=f"https://{name}.example.invalid/v1", api_key="offline-test-key",
                     model=name, protocol="openai_chat")


class ProviderAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.primary = provider("primary")
        self.ref = health.provider_ref(self.primary.base_url, self.primary.model,
                                       self.primary.api_key, self.primary.protocol)
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.clock = patch.object(health, "_now", return_value=self.now)
        self.clock.start()
        with health._LOCK:
            health._HEALTH.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_async_engine(f"sqlite+aiosqlite:///{Path(self.tmp.name) / 'case.db'}")
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with self.sessions() as session:
            session.add(Task(id="offline", name="offline", status="running", target_source="manual"))
            session.add(Target(id="target", task_id="offline", host="example.invalid",
                               url="https://example.invalid", source="manual", status="queued"))
            await session.commit()
        self.runner = TaskRunner("offline")
        self.runner._log = AsyncMock()
        self.runner._probe_queued_liveness = AsyncMock(return_value={"target": {"alive": True}})

    async def asyncTearDown(self) -> None:
        await self.engine.dispose()
        self.tmp.cleanup()
        self.clock.stop()
        with health._LOCK:
            health._HEALTH.clear()

    def state(self, **fields: object) -> None:
        with health._LOCK:
            health._HEALTH[self.ref] = dict(fields)

    def available(self) -> bool:
        p = self.primary
        return health.provider_slot_available(p.base_url, p.model, p.api_key, p.protocol)

    async def pop(self, providers: list[LLMConfig] | None = None) -> Target | None:
        with patch("app.orchestrator.resolve_llm_providers", return_value=providers or [self.primary], create=True):
            async with self.sessions() as session:
                return await self.runner._pop_queued(session)

    async def test_readiness_does_not_claim_recovery_probe(self) -> None:
        self.state(transport_status="half_open", behavior_status="half_open",
                   half_open_inflight=False, behavior_probe_owner="")
        self.assertTrue(self.available())
        with health._LOCK:
            self.assertFalse(health._HEALTH[self.ref]["half_open_inflight"])
            self.assertEqual(health._HEALTH[self.ref]["behavior_probe_owner"], "")

    async def test_busy_behavior_probe_does_not_start_or_probe_target(self) -> None:
        self.state(transport_status="ok", behavior_status="half_open",
                   behavior_probe_owner="another-client",
                   behavior_probe_until_ts=(self.now + timedelta(minutes=15)).timestamp())
        self.assertIsNone(await self.pop())
        self.assertIsNone(await self.pop())
        self.runner._probe_queued_liveness.assert_not_awaited()
        self.runner._log.assert_awaited_once()
        async with self.sessions() as session:
            target = await session.get(Target, "target")
            self.assertEqual(target.status, "queued")
            self.assertEqual(target.retry_count, 0)

    async def test_busy_transport_probe_blocks_admission(self) -> None:
        self.state(transport_status="half_open", half_open_inflight=True,
                   half_open_until_ts=(self.now + timedelta(seconds=120)).timestamp())
        self.assertFalse(self.available())
        self.assertIsNone(await self.pop())
        self.runner._probe_queued_liveness.assert_not_awaited()

    async def test_recovered_provider_dispatches_without_restarting_runner(self) -> None:
        self.state(transport_status="ok", behavior_status="failed",
                   behavior_retry_at_ts=(self.now + timedelta(seconds=60)).timestamp())
        self.assertIsNone(await self.pop())
        p = self.primary
        health.mark_provider_behavior_ok(p.base_url, p.model, p.api_key, p.protocol)
        self.assertEqual((await self.pop()).status, "assigned")
        self.runner._probe_queued_liveness.assert_awaited_once()

    async def test_healthy_backup_allows_dispatch(self) -> None:
        self.state(transport_status="cooldown",
                   cooldown_until_ts=(self.now + timedelta(seconds=300)).timestamp())
        self.assertEqual((await self.pop([self.primary, provider("backup")])).status, "assigned")

    async def test_expired_failure_allows_unclaimed_probe(self) -> None:
        self.state(transport_status="failed", failed_retry_at_ts=self.now.timestamp() - 1,
                   behavior_status="failed", behavior_retry_at_ts=self.now.timestamp() - 1)
        self.assertTrue(self.available())
        self.assertEqual((await self.pop()).status, "assigned")

    async def test_independent_cooldowns_wait_for_all_gates(self) -> None:
        self.state(transport_status="cooldown", behavior_status="cooldown",
                   cooldown_until_ts=(self.now + timedelta(seconds=300)).timestamp(),
                   behavior_cooldown_until_ts=(self.now + timedelta(seconds=900)).timestamp())
        p = self.primary
        self.assertEqual(health.provider_retry_after_seconds(p.base_url, p.model, p.api_key, p.protocol), 900)

    async def test_busy_probe_poll_does_not_shorten_other_cooldown(self) -> None:
        self.state(transport_status="half_open", half_open_inflight=True,
                   half_open_until_ts=(self.now + timedelta(seconds=120)).timestamp(),
                   behavior_status="cooldown",
                   behavior_cooldown_until_ts=(self.now + timedelta(seconds=300)).timestamp())
        p = self.primary
        self.assertEqual(health.provider_retry_after_seconds(p.base_url, p.model, p.api_key, p.protocol), 300)


if __name__ == "__main__":
    unittest.main()
