"""worker 结束后细粒度轨迹清理。

运行：
  python -m unittest tests.test_trace_cleanup -q
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.db.models import Base, Task, TaskEvent  # noqa: E402
from app.maintenance.cleanup import (  # noqa: E402
    TRACE_FINE_KINDS,
    TRACE_SUMMARY_KINDS,
    count_target_fine_traces,
    prune_target_traces,
    trace_keep_after_finish,
)
from app.orchestrator import TaskRunner  # noqa: E402


class TraceCleanupKindTests(unittest.TestCase):
    def test_summary_and_fine_disjoint(self):
        self.assertFalse(TRACE_SUMMARY_KINDS & TRACE_FINE_KINDS)

    def test_keep_flag(self):
        old = os.environ.get("TRACE_KEEP_AFTER_FINISH")
        try:
            os.environ["TRACE_KEEP_AFTER_FINISH"] = "1"
            self.assertTrue(trace_keep_after_finish())
            os.environ["TRACE_KEEP_AFTER_FINISH"] = "0"
            self.assertFalse(trace_keep_after_finish())
        finally:
            if old is None:
                os.environ.pop("TRACE_KEEP_AFTER_FINISH", None)
            else:
                os.environ["TRACE_KEEP_AFTER_FINISH"] = old


class TraceCleanupDbTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        db = Path(self._tmpdir.name) / "t.db"
        self.engine = create_async_engine(f"sqlite+aiosqlite:///{db}", future=True)
        self.session_local = async_sessionmaker(self.engine, expire_on_commit=False)
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        # 指向测试库
        import app.maintenance.cleanup as cleanup_mod
        self._old_sl = cleanup_mod.SessionLocal
        cleanup_mod.SessionLocal = self.session_local
        async with self.session_local() as s:
            s.add(Task(id="task-clean", name="t", status="running"))
            await s.commit()

    async def asyncTearDown(self):
        import app.maintenance.cleanup as cleanup_mod
        cleanup_mod.SessionLocal = self._old_sl
        await self.engine.dispose()
        self._tmpdir.cleanup()

    async def _seed(self):
        async with self.session_local() as s:
            rows = [
                TaskEvent(task_id="task-clean", agent="worker", kind="worker_start",
                          message="start", payload={"target_id": "t1"}),
                TaskEvent(task_id="task-clean", agent="worker", kind="tool_http",
                          message="GET /a", payload={"target_id": "t1", "url": "/a"}),
                TaskEvent(task_id="task-clean", agent="worker", kind="worker_thought",
                          message="think", payload={"target_id": "t1", "text": "x"}),
                TaskEvent(task_id="task-clean", agent="worker", kind="finding_submitted",
                          message="found", payload={"target_id": "t1", "title": "idor"}),
                TaskEvent(task_id="task-clean", agent="worker", kind="worker_finish",
                          message="done", payload={"target_id": "t1", "verdict": "found"}),
                # 另一目标，不应被清
                TaskEvent(task_id="task-clean", agent="worker", kind="tool_http",
                          message="GET /b", payload={"target_id": "t2", "url": "/b"}),
                # 非 worker agent
                TaskEvent(task_id="task-clean", agent="orchestrator", kind="tool_http",
                          message="noise", payload={"target_id": "t1"}),
            ]
            for r in rows:
                s.add(r)
            await s.commit()

    async def test_prune_keeps_summary_deletes_fine(self):
        await self._seed()
        deleted = await prune_target_traces("task-clean", "t1")
        self.assertEqual(deleted, 2)  # tool_http + worker_thought
        self.assertEqual(await count_target_fine_traces("task-clean", "t1"), 0)

        async with self.session_local() as s:
            kinds = {
                e.kind
                for e in (await s.execute(
                    select(TaskEvent).where(TaskEvent.task_id == "task-clean")
                )).scalars().all()
                if (e.payload or {}).get("target_id") == "t1" and e.agent == "worker"
            }
        self.assertEqual(kinds, {"worker_start", "finding_submitted", "worker_finish"})

        # t2 细粒度仍在
        self.assertEqual(await count_target_fine_traces("task-clean", "t2"), 1)

    async def test_keep_flag_skips_prune(self):
        await self._seed()
        old = os.environ.get("TRACE_KEEP_AFTER_FINISH")
        try:
            os.environ["TRACE_KEEP_AFTER_FINISH"] = "1"
            deleted = await prune_target_traces("task-clean", "t1")
            self.assertEqual(deleted, 0)
            self.assertEqual(await count_target_fine_traces("task-clean", "t1"), 2)
        finally:
            if old is None:
                os.environ.pop("TRACE_KEEP_AFTER_FINISH", None)
            else:
                os.environ["TRACE_KEEP_AFTER_FINISH"] = old


class PersistAfterFinishTests(unittest.IsolatedAsyncioTestCase):
    async def test_fine_persist_skipped_when_not_live(self):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock, Mock, patch

        from tests.test_agent_visibility import _SessionContext

        runner = TaskRunner("task-vis")
        # 不在 _live → 细粒度不应落库
        session = SimpleNamespace(add=Mock(), commit=AsyncMock())
        with patch("app.orchestrator.SessionLocal", return_value=_SessionContext(session)):
            await runner._persist_worker_trace(
                "task-vis", "t1", "tool_http",
                {"method": "GET", "url": "https://example.edu/api"},
            )
        session.add.assert_not_called()

        # 在 _live → 可以落库
        runner._live["t1"] = {"target_id": "t1"}
        with patch("app.orchestrator.SessionLocal", return_value=_SessionContext(session)):
            await runner._persist_worker_trace(
                "task-vis", "t1", "tool_http",
                {"method": "GET", "url": "https://example.edu/api"},
            )
        session.add.assert_called_once()

    async def test_summary_persist_even_when_not_live(self):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock, Mock, patch

        from tests.test_agent_visibility import _SessionContext

        runner = TaskRunner("task-vis")
        session = SimpleNamespace(add=Mock(), commit=AsyncMock())
        with patch("app.orchestrator.SessionLocal", return_value=_SessionContext(session)):
            await runner._persist_worker_trace(
                "task-vis", "t1", "worker_finish",
                {"verdict": "found"},
            )
        session.add.assert_called_once()
        self.assertEqual(session.add.call_args[0][0].kind, "worker_finish")


if __name__ == "__main__":
    unittest.main()
