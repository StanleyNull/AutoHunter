import threading
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.agents import worker as worker_mod  # noqa: E402
from app.llm.client import LLMError  # noqa: E402
from app.schemas import Verdict  # noqa: E402


class WorkerLlmSoftRetryTest(unittest.TestCase):
    def test_should_soft_retry_kinds(self):
        self.assertTrue(worker_mod.Worker._should_soft_retry_llm(
            LLMError("rate_limit", "限流")
        ))
        self.assertTrue(worker_mod.Worker._should_soft_retry_llm(
            LLMError("timeout", "超时")
        ))
        self.assertTrue(worker_mod.Worker._should_soft_retry_llm(
            LLMError("provider_cooldown", "冷却", retry_after=5)
        ))
        self.assertFalse(worker_mod.Worker._should_soft_retry_llm(
            LLMError("auth", "API Key 无效")
        ))
        self.assertFalse(worker_mod.Worker._should_soft_retry_llm(
            LLMError("invalid_request", "参数错误")
        ))

    def test_interrupt_keeps_resume_context(self):
        w = worker_mod.Worker("https://example.com", cancel_event=threading.Event())

        class FakeExecutor:
            def export_resume_state(self):
                return {
                    "worker_notes": "登录成功，下一步打 /admin",
                    "session_cookies": {"sid": "1"},
                    "session_headers": {"Authorization": "Bearer x"},
                }

        w.executor = FakeExecutor()  # type: ignore
        result = w._llm_interrupt_result(
            rounds=7,
            error="LLM 调用失败：限流",
            failure_kind="rate_limit",
            retry_after=3,
        )
        self.assertEqual(result.verdict, Verdict.error)
        self.assertEqual(result.failure_kind, "rate_limit")
        self.assertIn("登录成功", result.resume_context.get("worker_notes", ""))
        self.assertEqual(result.resume_context.get("session_cookies", {}).get("sid"), "1")
        self.assertEqual(result.resume_context.get("source"), "llm_interrupt")

    def test_apply_resume_context_on_target(self):
        from app.orchestrator import TaskRunner

        tgt = type("T", (), {"deepen_context": None})()
        TaskRunner._apply_resume_context(tgt, {
            "resume_context": {
                "directive": "继续打 /admin",
                "worker_notes": "已登录",
                "session_cookies": {"a": "b"},
                "session_headers": {},
                "rounds_done": 4,
                "source": "llm_interrupt",
            }
        })
        self.assertEqual(tgt.deepen_context["source"], "llm_interrupt")
        self.assertEqual(tgt.deepen_context["session_cookies"]["a"], "b")
        self.assertIn("已登录", tgt.deepen_context["worker_notes"])


if __name__ == "__main__":
    unittest.main()
