"""LLM 响应 coerce / 错误归类单测。"""
from __future__ import annotations

import unittest
from types import SimpleNamespace

from app.llm.client import LLMError, _classify_error, _coerce_chat_message


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


if __name__ == "__main__":
    unittest.main()
