"""LLM 响应 coerce / 错误归类单测。"""
from __future__ import annotations

import json
import re
import unittest
from types import SimpleNamespace

from app.llm.client import (
    LLMClient,
    LLMError,
    _apply_emulated_tool_calls,
    _classify_error,
    _coerce_chat_message,
    _strip_thinking_tags,
    llm_error_event_fields,
)


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

    def test_sdk_wrapper_data_payload(self):
        # Some DeepSeek-compatible gateways leave ChatCompletion.choices empty
        # and put the actual OpenAI payload in the SDK object's ``data`` field.
        resp = SimpleNamespace(
            choices=None,
            data={"choices": [{"message": {"content": "wrapped"}}]},
        )
        out = _coerce_chat_message(resp)
        self.assertEqual(out.content, "wrapped")

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


class StripThinkingTagsTests(unittest.TestCase):
    """MiniMax-M3 把思考嵌在 content 的 <think> 里；PR #55 正则是坏的。"""

    SAMPLE = "<think>\nI should check auth\n</think>\n{\"verdict\":\"accepted\"}"

    def test_closed_block_leaves_json(self):
        self.assertEqual(_strip_thinking_tags(self.SAMPLE), '{"verdict":"accepted"}')
        json.loads(_strip_thinking_tags(self.SAMPLE))

    def test_pr55_regex_leaves_pollution(self):
        broken = re.compile(r"<think>.*?\s*", re.DOTALL)
        leftover = broken.sub("", self.SAMPLE).strip()
        self.assertIn("</think>", leftover)
        self.assertIn("I should check auth", leftover)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(leftover)

    def test_multiple_blocks_and_case(self):
        text = "<THINK>a</THINK>\nkeep\n<think extra>b</think>\n{\"ok\":1}"
        out = _strip_thinking_tags(text)
        self.assertEqual(out, 'keep\n\n{"ok":1}')
        self.assertNotIn("think", out.lower())

    def test_no_tags_unchanged(self):
        self.assertEqual(_strip_thinking_tags('{"verdict":"accepted"}'), '{"verdict":"accepted"}')
        self.assertEqual(_strip_thinking_tags(""), "")

    def test_coerce_plain_string(self):
        out = _coerce_chat_message(self.SAMPLE)
        self.assertEqual(out.content, '{"verdict":"accepted"}')

    def test_coerce_dict_and_openai_object_keep_tool_calls(self):
        out = _coerce_chat_message({
            "choices": [{"message": {"content": self.SAMPLE, "tool_calls": None}}],
        })
        self.assertEqual(out.content, '{"verdict":"accepted"}')

        args = '{"verdict":"accepted"}'
        calls = [SimpleNamespace(
            id="c1",
            function=SimpleNamespace(name="submit_review", arguments=args),
        )]
        msg = SimpleNamespace(content=self.SAMPLE, tool_calls=calls)
        resp = SimpleNamespace(choices=[SimpleNamespace(message=msg)])
        out = _coerce_chat_message(resp)
        self.assertIs(out, msg)
        self.assertEqual(out.content, '{"verdict":"accepted"}')
        self.assertIs(out.tool_calls, calls)
        self.assertEqual(out.tool_calls[0].function.arguments, args)

    def test_text_tool_call_accepts_argument_alias(self):
        out = _apply_emulated_tool_calls(SimpleNamespace(
            content='```json\n{"tool_calls":[{"name":"http_request",'
                    '"argument":{"url":"https://example.com"}}]}\n```',
            tool_calls=None,
        ))
        self.assertEqual(out.tool_calls[0].function.name, "http_request")
        self.assertEqual(json.loads(out.tool_calls[0].function.arguments)["url"], "https://example.com")

    def test_dsml_text_tool_call_is_coerced(self):
        text = (
            '准备侦察。<｜｜DSML｜｜ calls>\n'
            '<｜｜DSML｜｜ invoke name="http_request">\n'
            '<｜｜DSML｜｜ parameter name="method" string="true">GET'
            '</｜｜DSML｜｜ parameter>\n'
            '<｜｜DSML｜｜ parameter name="url" string="true">https://example.com'
            '</｜｜DSML｜｜ parameter>\n'
            '<｜｜DSML｜｜ /invoke>\n<｜｜DSML｜｜ /calls>'
        )
        out = _apply_emulated_tool_calls(SimpleNamespace(content=text, tool_calls=None))
        self.assertEqual(out.content, "准备侦察。")
        self.assertEqual(out.tool_calls[0].function.name, "http_request")
        args = json.loads(out.tool_calls[0].function.arguments)
        self.assertEqual(args, {"method": "GET", "url": "https://example.com"})

    def test_dsml_json_argument_fallback(self):
        text = (
            '<｜｜DSML｜｜ invoke name="http_request">\n'
            '<｜｜DSML｜｜ parameter name="arguments">'
            '{"url":"https://example.com","method":"GET"}'
            '</｜｜DSML｜｜ parameter>'
        )
        out = _apply_emulated_tool_calls(SimpleNamespace(content=text, tool_calls=None))
        self.assertEqual(out.tool_calls[0].function.name, "http_request")
        self.assertEqual(json.loads(out.tool_calls[0].function.arguments)["method"], "GET")

    def test_messages_response_strips_text_keeps_tool_use(self):
        out = LLMClient._parse_messages_response({
            "content": [
                {"type": "text", "text": "<think>plan</think>\nYES 复现成功"},
                {"type": "tool_use", "id": "t1", "name": "submit_review",
                 "input": {"verdict": "accepted"}},
            ],
        })
        self.assertEqual(out.content, "YES 复现成功")
        self.assertEqual(out.tool_calls[0].function.name, "submit_review")
        self.assertEqual(json.loads(out.tool_calls[0].function.arguments)["verdict"], "accepted")


if __name__ == "__main__":
    unittest.main()
