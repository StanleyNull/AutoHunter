from __future__ import annotations

import threading
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from app.agents.worker import Worker
from app.llm.client import LLMError
from app.orchestrator import TaskRunner
from app.schemas import Verdict, WorkerResult


class WorkerCooldownTests(unittest.TestCase):
    def test_worker_propagates_provider_cooldown(self) -> None:
        worker = Worker.__new__(Worker)
        worker.deepen_context = None
        worker.target = "https://example.invalid"
        worker.src_type = "enterprise"
        worker.prompt_version = "test"
        worker.cancel_event = threading.Event()
        worker.findings = []
        worker._js_tool_enabled = False
        worker._intel_block = Mock(return_value="")
        worker._duplicate_block = Mock(return_value="")
        worker._emit = Mock()
        worker._route_rounds = Mock(return_value=(1, 1))
        worker.executor = SimpleNamespace(session_status_block=Mock(return_value=""))
        worker.llm = SimpleNamespace(
            chat=Mock(side_effect=LLMError("provider_cooldown", "all providers cooling", retry_after=17))
        )

        result = worker.run()

        self.assertEqual(result.verdict, Verdict.error)
        self.assertEqual(result.failure_kind, "provider_cooldown")
        self.assertEqual(result.retry_after_seconds, 17)

    def test_worker_result_cooldown_fields_default_to_no_delay(self) -> None:
        result = WorkerResult(target="x", verdict=Verdict.no_vuln)

        self.assertEqual(result.failure_kind, "")
        self.assertEqual(result.retry_after_seconds, 0)


class _SessionContext:
    def __init__(self, session) -> None:
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


class OrchestratorCooldownTests(unittest.IsolatedAsyncioTestCase):
    async def test_provider_cooldown_requeues_without_consuming_retry(self) -> None:
        target = SimpleNamespace(
            assigned_worker="worker-1",
            url="https://example.invalid",
            host="example.invalid",
            source="manual",
            status="scanning",
            verdict="error",
            heartbeat_at=object(),
            last_error="",
            dead_reason="",
            retry_count=2,
        )
        session = SimpleNamespace(get=AsyncMock(return_value=target), commit=AsyncMock(), add=Mock())
        runner = TaskRunner("task-1")
        runner._harvest_intel = AsyncMock()
        runner._log = AsyncMock()
        result = {
            "verdict": Verdict.error.value,
            "findings": [],
            "error": "LLM 调用失败: all providers cooling",
            "failure_kind": "provider_cooldown",
            "retry_after_seconds": 17,
        }

        with patch("app.orchestrator.SessionLocal", return_value=_SessionContext(session)):
            await runner._persist_worker_result("task-1", "target-1", result)

        self.assertEqual(target.status, "queued")
        self.assertEqual(target.verdict, "")
        self.assertEqual(target.retry_count, 2)
        self.assertEqual(target.assigned_worker, "")
        self.assertIn("target-1", runner._llm_provider_retry_after)
        self.assertGreater(runner._llm_pool_retry_after, 0)
        runner._log.assert_awaited_once()

        blocked_session = SimpleNamespace(execute=AsyncMock(side_effect=AssertionError("must not query")))
        self.assertIsNone(await runner._pop_queued(blocked_session))

    async def test_model_behavior_failure_requeues_instead_of_marking_dead(self) -> None:
        target = SimpleNamespace(
            assigned_worker="worker-1",
            url="https://example.invalid",
            host="example.invalid",
            source="manual",
            status="scanning",
            verdict="error",
            heartbeat_at=object(),
            last_error="",
            dead_reason="",
            retry_count=0,
        )
        session = SimpleNamespace(get=AsyncMock(return_value=target), commit=AsyncMock(), add=Mock())
        runner = TaskRunner("task-1")
        runner._harvest_intel = AsyncMock()
        runner._log = AsyncMock()

        with patch("app.orchestrator.SessionLocal", return_value=_SessionContext(session)):
            await runner._persist_worker_result("task-1", "target-1", {
                "verdict": Verdict.error.value,
                "findings": [],
                "error": "模型连续空转，本轮未得到可靠结论。",
                "failure_kind": "model_behavior",
            })

        self.assertEqual(target.status, "queued")
        self.assertEqual(target.verdict, "")
        self.assertEqual(target.assigned_worker, "")
        self.assertEqual(runner._transient_llm_requeue["target-1"], 1)


if __name__ == "__main__":
    unittest.main()
