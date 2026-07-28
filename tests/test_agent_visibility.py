"""Agent 可见性 / 可控性：API 过滤规则 + orchestrator 指令/扩大危害 + worker 注入。

不启 Docker 浏览器、不调真实 LLM，几秒内回归。
运行：
  python -m unittest tests.test_agent_visibility -q
"""
from __future__ import annotations

import asyncio
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.agents.worker import Worker  # noqa: E402
from app.api import tasks as tasks_api  # noqa: E402
from app.api.dto import DirectiveRequest  # noqa: E402
from app.llm.client import LLMError  # noqa: E402
from app.orchestrator import TaskRunner, manager  # noqa: E402
from app.schemas import Verdict  # noqa: E402
from pydantic import ValidationError  # noqa: E402


class StreamFilterTests(unittest.TestCase):
    def test_noise_always_hidden(self):
        self.assertFalse(tasks_api._stream_event_visible("ping", "info"))
        self.assertFalse(tasks_api._stream_event_visible("refill", "info", verbose=True))

    def test_important_always_visible(self):
        self.assertTrue(tasks_api._stream_event_visible("target_done", "info"))
        self.assertTrue(tasks_api._stream_event_visible("escalate_done", "info"))
        self.assertTrue(tasks_api._stream_event_visible("worker_directive_queued", "info"))

    def test_trace_kinds_only_in_verbose(self):
        self.assertFalse(tasks_api._stream_event_visible("tool_http", "info"))
        self.assertFalse(tasks_api._stream_event_visible("worker_thought", "info"))
        self.assertTrue(tasks_api._stream_event_visible("tool_http", "info", verbose=True))
        self.assertTrue(tasks_api._stream_event_visible("worker_thought", "info", verbose=True))
        self.assertTrue(tasks_api._stream_event_visible("escalate_http", "info", verbose=True))

    def test_warn_error_always_visible(self):
        self.assertTrue(tasks_api._stream_event_visible("whatever", "warn"))
        self.assertTrue(tasks_api._stream_event_visible("tool_http", "error"))


class DirectiveRequestTests(unittest.TestCase):
    def test_accepts_nonempty(self):
        body = DirectiveRequest(directive="  优先打 IDOR  ")
        self.assertEqual(body.directive, "  优先打 IDOR  ")

    def test_rejects_empty(self):
        with self.assertRaises(ValidationError):
            DirectiveRequest(directive="")


class TaskRunnerDirectiveTests(unittest.TestCase):
    def test_inject_requires_active_worker(self):
        runner = TaskRunner("task-vis")
        res = runner.inject_directive("t1", " dig deeper ")
        self.assertFalse(res["ok"])
        self.assertIn("没有运行中", res["error"])

    def test_inject_rejects_blank(self):
        runner = TaskRunner("task-vis")
        runner._active_workers["t1"] = object()  # type: ignore[assignment]
        res = runner.inject_directive("t1", "   ")
        self.assertFalse(res["ok"])
        self.assertIn("不能为空", res["error"])

    def test_inject_and_pop_fifo(self):
        runner = TaskRunner("task-vis")
        runner._active_workers["t1"] = object()  # type: ignore[assignment]
        runner._live["t1"] = {"host": "example.edu"}

        a = runner.inject_directive("t1", "先做登录")
        b = runner.inject_directive("t1", "再打越权")
        self.assertTrue(a["ok"] and b["ok"])
        self.assertEqual(a["host"], "example.edu")
        self.assertEqual(runner._pop_directive("t1"), "先做登录")
        self.assertEqual(runner._pop_directive("t1"), "再打越权")
        self.assertIsNone(runner._pop_directive("t1"))
        self.assertNotIn("t1", runner._worker_directives)

    def test_inject_truncates_to_2000(self):
        runner = TaskRunner("task-vis")
        runner._active_workers["t1"] = object()  # type: ignore[assignment]
        long = "x" * 5000
        res = runner.inject_directive("t1", long)
        self.assertTrue(res["ok"])
        self.assertEqual(len(runner._pop_directive("t1") or ""), 2000)


class TaskRunnerEscalationTests(unittest.TestCase):
    def test_cancel_missing(self):
        runner = TaskRunner("task-vis")
        res = runner.cancel_escalation("f1")
        self.assertFalse(res["ok"])

    def test_cancel_sets_event_and_clears_live(self):
        runner = TaskRunner("task-vis")
        ev = threading.Event()
        runner._escalation_inflight.add("f1")
        runner._escalation_cancel_events["f1"] = ev
        runner._live_escalations["f1"] = {"title": "越权读订单", "finding_id": "f1"}

        res = runner.cancel_escalation("f1", reason="测试取消")
        self.assertTrue(res["ok"])
        self.assertTrue(ev.is_set())
        self.assertEqual(res["title"], "越权读订单")
        self.assertNotIn("f1", runner._live_escalations)

    def test_live_escalations_list(self):
        runner = TaskRunner("task-vis")
        runner._live_escalations["f1"] = {"finding_id": "f1", "action": "扩大危害进行中…"}
        items = runner.live_escalations()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["finding_id"], "f1")


class TracePayloadTests(unittest.TestCase):
    def test_truncate_drops_finding_and_long_text(self):
        payload = {
            "finding": {"huge": True},
            "text": "t" * 800,
            "command": "c" * 600,
            "url": "https://example.edu/" + "a" * 400,
            "round": 3,
            "kinds": ["cookie", "pass"],
        }
        out = TaskRunner._truncate_trace_payload(payload)
        self.assertNotIn("finding", out)
        self.assertEqual(len(out["text"]), 500)
        self.assertEqual(len(out["command"]), 500)
        self.assertEqual(out["round"], 3)
        self.assertEqual(out["kinds"], ["cookie", "pass"])


class ManagerWrapperTests(unittest.TestCase):
    def test_inject_without_runner(self):
        # 确保不误伤真实 runner：用一个绝不可能冲突的 id
        tid = "__visibility_test_missing__"
        manager._runners.pop(tid, None)
        res = manager.inject_directive(tid, "t1", "hello")
        self.assertFalse(res["ok"])
        self.assertIn("未在运行", res["error"])

    def test_cancel_escalation_without_runner(self):
        tid = "__visibility_test_missing__"
        manager._runners.pop(tid, None)
        res = manager.cancel_escalation(tid, "f1")
        self.assertFalse(res["ok"])


class _SessionContext:
    def __init__(self, session) -> None:
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


class PersistTraceTests(unittest.IsolatedAsyncioTestCase):
    async def test_persist_skips_non_trace_kinds(self):
        runner = TaskRunner("task-vis")
        session = SimpleNamespace(add=Mock(), commit=AsyncMock())
        with patch("app.orchestrator.SessionLocal", return_value=_SessionContext(session)):
            await runner._persist_worker_trace("task-vis", "t1", "ping", {"x": 1})
        session.add.assert_not_called()

    async def test_persist_writes_task_event(self):
        runner = TaskRunner("task-vis")
        runner._live["t1"] = {"target_id": "t1"}  # 细粒度仅在活态中落库
        session = SimpleNamespace(add=Mock(), commit=AsyncMock())
        with patch("app.orchestrator.SessionLocal", return_value=_SessionContext(session)):
            await runner._persist_worker_trace(
                "task-vis", "t1", "tool_http",
                {"method": "GET", "url": "https://example.edu/api", "round": 2},
            )
        session.add.assert_called_once()
        event = session.add.call_args[0][0]
        self.assertEqual(event.agent, "worker")
        self.assertEqual(event.kind, "tool_http")
        self.assertEqual(event.payload.get("target_id"), "t1")
        self.assertIn("GET", event.message)
        session.commit.assert_awaited_once()


class WorkerDirectiveInjectionTests(unittest.TestCase):
    def test_directive_injected_before_llm_round(self):
        """pop_directive 返回内容后，应 emit worker_directive，并把指令塞进 messages。"""
        captured: list = []

        class FakeLLM:
            def chat(self, messages, tools=None, tool_choice=None):
                captured.append(list(messages))
                # 立刻报错结束，避免继续挖；软重试路径外的 interrupt
                raise LLMError("fatal", "stop-after-directive")

        worker = Worker.__new__(Worker)
        worker.deepen_context = None
        worker.target = "https://example.invalid"
        worker.src_type = "enterprise"
        worker.prompt_version = "test"
        worker.cancel_event = threading.Event()
        worker.findings = []
        worker._finished = None
        worker._js_tool_enabled = False
        worker._reported_intel = []
        worker._reported_coverage = []
        worker._intel_block = Mock(return_value="")
        worker._duplicate_block = Mock(return_value="")
        worker._emit = Mock()
        worker._route_rounds = Mock(return_value=(2, 1))
        worker._should_soft_retry_llm = Mock(return_value=False)
        worker._llm_interrupt_result = Mock(side_effect=lambda **kw: SimpleNamespace(
            target=worker.target, verdict=Verdict.error, findings=[],
            rounds=kw.get("rounds", 0), error=kw.get("error", ""),
            deepen_lead="", failure_kind=kw.get("failure_kind", ""),
            retry_after_seconds=0, model_dump=lambda mode="json": {},
        ))
        worker._cancelled_result = Mock()
        worker.executor = SimpleNamespace(
            session_status_block=Mock(return_value="session"),
            kill_processes=Mock(),
        )
        worker.llm = FakeLLM()
        worker.pop_directive = Mock(return_value="只测 /api/admin 越权")
        worker.target_meta = {}
        worker.duplicate_history = []

        # run() 开头会 bootstrap auth / restore；一并短路
        worker._bootstrap_user_auth = Mock()
        worker._restore_interrupt_progress = Mock()

        worker.run()

        # 发出了指令事件
        kinds = [c.args[0] for c in worker._emit.call_args_list]
        self.assertIn("worker_directive", kinds)
        # 发给 LLM 的消息里包含人工指令
        self.assertTrue(captured, "应至少发起一轮 LLM")
        blob = "\n".join(
            (m.get("content") or "") if isinstance(m, dict) else ""
            for m in captured[0]
        )
        self.assertIn("人工实时指令", blob)
        self.assertIn("只测 /api/admin 越权", blob)


class EventBusDropOldestTests(unittest.IsolatedAsyncioTestCase):
    async def test_queue_full_drops_oldest_keeps_newest(self):
        from app.events import EventBus

        bus = EventBus()
        q = asyncio.Queue(maxsize=2)
        bus._subscribers["t"] = {q}
        await bus.publish("t", {"n": 1})
        await bus.publish("t", {"n": 2})
        await bus.publish("t", {"n": 3})  # 应挤掉 1
        self.assertEqual(q.qsize(), 2)
        a = q.get_nowait()
        b = q.get_nowait()
        self.assertEqual([a["n"], b["n"]], [2, 3])


if __name__ == "__main__":
    unittest.main()
