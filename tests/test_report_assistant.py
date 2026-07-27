import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.api import findings  # noqa: E402


class ReportAssistantTest(unittest.TestCase):
    def test_cleans_markdown_url_and_flattened_shell_continuation(self):
        command = (
            "curl -k -s '[https://example.com/a](https://example.com/a)' "
            "\\ -H 'Content-Type: application/json'"
        )

        cleaned = findings._clean_shell_command(command)

        self.assertIn("https://example.com/a", cleaned)
        self.assertNotIn("[https://example.com/a]", cleaned)
        self.assertNotIn("\\ -H", cleaned)

    def test_timeout_parser_treats_false_string_as_default(self):
        self.assertEqual(findings._safe_timeout("false", default=30, upper=90), 30)
        self.assertEqual(findings._safe_timeout(False, default=30, upper=90), 30)
        self.assertEqual(findings._safe_timeout("120", default=30, upper=90), 90)

    def test_loop_does_not_accept_pseudo_tool_text_as_final_work(self):
        old_rounds = findings._ASSISTANT_MAX_ROUNDS
        findings._ASSISTANT_MAX_ROUNDS = 3
        try:
            class FakeLLM:
                def __init__(self):
                    self.calls = 0

                def chat(self, *_args, **_kwargs):
                    self.calls += 1
                    if self.calls == 1:
                        return SimpleNamespace(
                            content="<｜｜DSML｜｜tool_calls><｜｜DSML｜｜invoke name=\"run_shell\">curl -I https://example.com",
                            tool_calls=None,
                        )
                    return SimpleNamespace(content="结论：基于现有结果，证据不足。", tool_calls=None)

            llm = FakeLLM()
            result = findings._run_report_assistant_loop(
                llm,
                executor=SimpleNamespace(),
                messages=[{"role": "user", "content": "test"}],
                tool_logs=[],
                cancel_event=threading.Event(),
                emit=lambda _ev: None,
            )

            self.assertEqual(llm.calls, 2)
            self.assertIn("证据不足", result["answer"])
        finally:
            findings._ASSISTANT_MAX_ROUNDS = old_rounds

    def test_unavailable_message_keeps_llm_error_short(self):
        from app.llm.client import LLMError

        msg = findings._assistant_unavailable_message(
            LLMError("blocked", "此模型不让你搞网络安全。")
        )
        self.assertEqual(msg, "报告助手暂不可用：此模型不让你搞网络安全。")

    def test_run_assistant_returns_pool_failure_as_answer(self):
        """端点池耗尽时不应抛到 SSE 外层被吞成『已完成』。"""
        from app.llm.client import LLMError

        class BoomLLM:
            def chat(self, *_args, **_kwargs):
                raise LLMError("rate_limit", "LLM 请求被限流，请稍后重试或降低并发。")

        old_llm = findings._llm_for_task
        findings._llm_for_task = lambda _task: BoomLLM()
        try:
            finding = SimpleNamespace(
                id="f1",
                target_url="https://example.com",
                title="t",
                vuln_type="xss",
                owner="demo",
                severity_claimed="高危",
                description="",
                affected_scope="",
                steps=[],
                poc="",
                raw_request="",
                raw_response="",
                evidence={},
                kill_chain=[],
                self_check={},
                assistant_messages=[],
            )
            result = findings._run_report_assistant(
                f=finding,
                r=None,
                task=SimpleNamespace(id="t1", model_config_json={}),
                req=findings.ReportAssistantRequest(message="帮我看下证据"),
                cancel_event=threading.Event(),
            )
            self.assertIn("限流", result["answer"])
            self.assertTrue(result["answer"].startswith("报告助手暂不可用："))
        finally:
            findings._llm_for_task = old_llm


if __name__ == "__main__":
    unittest.main()
