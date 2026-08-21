"""LLM 响应 coerce / 错误归类单测。"""
from __future__ import annotations

import unittest
from types import SimpleNamespace

from app.llm.client import LLMError, _classify_error, _coerce_chat_message, llm_error_event_fields


class CoerceChatMessageTests(unittest.TestCase):
    def test_openai_object(self):
        msg = SimpleNamespace(content="hi", tool_calls=None)
        resp = SimpleNamespace(choices=[SimpleNamespace(message=msg)])
        self.assertIs(_coerce_chat_message(resp), msg)

    def test_json_string(self):
        raw = '{"choices":[{"message":{"role":"assistant","content":"ok"}}]}'
        out = _coerce_chat_message(raw)
        self.assertEqual(out.content, "ok")

    def test_plain_string(self):
        out = _coerce_chat_message("just text")
        self.assertEqual(out.content, "just text")

    def test_dict_message(self):
        out = _coerce_chat_message({"choices": [{"message": {"content": "x", "tool_calls": None}}]})
        self.assertEqual(out.content, "x")

    def test_sse_string(self):
        raw = 'data: {"choices":[{"message":{"content":"sse"}}]}\n\ndata: [DONE]\n'
        out = _coerce_chat_message(raw)
        self.assertEqual(out.content, "sse")

    def test_choices_attrerror_classified_upstream(self):
        err = _classify_error(AttributeError("'str' object has no attribute 'choices'"))
        self.assertEqual(err.kind, "upstream")

    def test_copy_text_includes_kind_status_detail(self):
        err = LLMError("quota", "LLM 额度不足或账户余额不足，请更换/充值模型 API Key 后重试。",
                       status=429, code="insufficient_quota",
                       detail="Error code: 429 - allocated quota exceeded")
        text = err.copy_text()
        self.assertIn("kind=quota", text)
        self.assertIn("status=429", text)
        self.assertIn("code=insufficient_quota", text)
        self.assertIn("allocated quota exceeded", text)
        fields = llm_error_event_fields(err)
        self.assertEqual(fields["error_kind"], "quota")
        self.assertEqual(fields["error_copy"], text)
        self.assertIn("quota", fields["diagnostic"])


if __name__ == "__main__":
    unittest.main()
