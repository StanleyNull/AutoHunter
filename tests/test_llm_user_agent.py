"""LLM 动态 User-Agent / stainless 头抹除单测。

覆盖：
- 按模型族推断 UA（deepseek/claude/gpt/glm/...）
- 未知模型兜底浏览器 UA
- LLM_USER_AGENT 环境变量：browser / auto / 自定义串 三种覆盖
- default_headers 用 Omit 删掉 X-Stainless-* 指纹头，且 UA 被真正下发到请求
"""
from __future__ import annotations

import os
import unittest

from app.llm.client import (
    _BROWSER_UA,
    _default_ua_for_model,
    _llm_default_headers,
    _per_request_omit_headers,
    _resolve_user_agent,
)


class UserAgentResolveTests(unittest.TestCase):
    def test_model_family_mapping(self):
        self.assertIn("DeepSeek", _default_ua_for_model("deepseek-chat", ""))
        self.assertIn("Anthropic", _default_ua_for_model("claude-3-5-sonnet", ""))
        self.assertIn("OpenAI", _default_ua_for_model("gpt-4o", ""))
        self.assertIn("zhipuai", _default_ua_for_model("glm-4-plus", ""))
        self.assertIn("dashscope", _default_ua_for_model("qwen-max", ""))
        self.assertIn("moonshot", _default_ua_for_model("kimi-k2", ""))
        self.assertIn("xai", _default_ua_for_model("grok-4", ""))

    def test_unknown_model_falls_back_to_browser(self):
        self.assertEqual(_default_ua_for_model("mystery-model", ""), _BROWSER_UA)

    def test_env_override_browser(self):
        os.environ["LLM_USER_AGENT"] = "browser"
        try:
            self.assertEqual(_resolve_user_agent("gpt-4o", ""), _BROWSER_UA)
        finally:
            os.environ.pop("LLM_USER_AGENT", None)

    def test_env_override_auto(self):
        os.environ["LLM_USER_AGENT"] = "auto"
        try:
            self.assertIn("OpenAI", _resolve_user_agent("gpt-4o", ""))
        finally:
            os.environ.pop("LLM_USER_AGENT", None)

    def test_env_override_custom_string(self):
        os.environ["LLM_USER_AGENT"] = "curl/8.7.1"
        try:
            self.assertEqual(_resolve_user_agent("gpt-4o", ""), "curl/8.7.1")
        finally:
            os.environ.pop("LLM_USER_AGENT", None)


class DefaultHeadersTests(unittest.TestCase):
    def test_headers_override_ua_and_strip_stainless(self):
        """default_headers + per-request omit 后，最终请求应无任何 x-stainless-*，UA 为我们指定值。"""
        from openai import OpenAI
        from openai._base_client import FinalRequestOptions

        dh = _llm_default_headers("deepseek-chat", "")
        client = OpenAI(
            base_url="https://relay.example.com/v1",
            api_key="sk-test",
            max_retries=0,
            default_headers=dh,
        )
        opts = FinalRequestOptions.construct(
            method="post",
            url="/chat/completions",
            json_data={"model": "x", "messages": []},
            headers=_per_request_omit_headers(),
        )
        req = client._build_request(opts)
        hdrs = {k.lower(): v for k, v in req.headers.items()}
        self.assertEqual(hdrs.get("user-agent"), "DeepSeek/1.0 (compatible)")
        leftover = [k for k in hdrs if k.startswith("x-stainless")]
        self.assertEqual(leftover, [], f"still leaking SDK fingerprint headers: {leftover}")


if __name__ == "__main__":
    unittest.main()
