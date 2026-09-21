"""自定义 LLM 请求头（LLM_EXTRA_HEADERS）回归测试。

覆盖：JSON / key:value 两种写法、异常输入不炸、环境变量热读，
以及 OpenAI Chat 默认头与 Anthropic Messages 两条链路是否真的带上自定义头
（opencode Go 缺 x-opencode-session 会回 HTTP 400 MissingSessionID）。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import LLMConfig  # noqa: E402
from app.llm.client import (  # noqa: E402
    LLMClient,
    _llm_default_headers,
    _parse_extra_headers,
    extra_llm_headers,
)


def _client(base_url="https://opencode.ai/zen/go", model="deepseek-v4-flash",
            protocol="openai_chat"):
    return LLMClient(
        providers=[LLMConfig(base_url=base_url, api_key="sk-test", model=model,
                             temperature=0.3, protocol=protocol)],
        pool_mode=False,
    )


def test_parse_json_form():
    assert _parse_extra_headers('{"x-opencode-session": "sess-1"}') == \
        {"x-opencode-session": "sess-1"}


def test_parse_kv_form():
    assert _parse_extra_headers("x-opencode-session:sess-1,X-Trace: t-2") == \
        {"x-opencode-session": "sess-1", "X-Trace": "t-2"}


def test_parse_tolerates_empty_and_junk():
    assert _parse_extra_headers("") == {}
    assert _parse_extra_headers("   ") == {}
    assert _parse_extra_headers("no-colon-here") == {}
    assert _parse_extra_headers("[1,2,3]") == {}
    # key 为空时丢弃，value 为空保留
    assert _parse_extra_headers(":,X-Empty:") == {"X-Empty": ""}


def test_extra_llm_headers_reads_env_each_call(monkeypatch):
    monkeypatch.setenv("LLM_EXTRA_HEADERS", "x-opencode-session:sess-1")
    assert extra_llm_headers() == {"x-opencode-session": "sess-1"}
    # 环境变量是每次调用重读的，改完无需重启进程
    monkeypatch.setenv("LLM_EXTRA_HEADERS", '{"x-opencode-session":"sess-2"}')
    assert extra_llm_headers() == {"x-opencode-session": "sess-2"}
    monkeypatch.delenv("LLM_EXTRA_HEADERS", raising=False)
    assert extra_llm_headers() == {}


def test_openai_default_headers_include_extra(monkeypatch):
    monkeypatch.setenv("LLM_EXTRA_HEADERS", "x-opencode-session:sess-1")
    headers = _llm_default_headers("deepseek-v4-flash", "https://opencode.ai/zen/go")
    assert headers["x-opencode-session"] == "sess-1"
    # 没配额外头时 UA 仍按模型族推断，行为不变
    monkeypatch.delenv("LLM_EXTRA_HEADERS", raising=False)
    plain = _llm_default_headers("deepseek-v4-flash", "https://opencode.ai/zen/go")
    assert "x-opencode-session" not in plain
    assert plain["User-Agent"] == headers["User-Agent"]


def test_extra_headers_can_override_default_ua(monkeypatch):
    monkeypatch.setenv("LLM_EXTRA_HEADERS", '{"User-Agent":"autohunter/1.0"}')
    headers = _llm_default_headers("deepseek-v4-flash", "https://opencode.ai/zen/go")
    assert headers["User-Agent"] == "autohunter/1.0"


def test_anthropic_messages_headers_include_extra(monkeypatch):
    monkeypatch.setenv("LLM_EXTRA_HEADERS", "x-opencode-session:sess-3")
    payload, headers = _client()._build_messages_payload(
        messages=[{"role": "user", "content": "hi"}],
        tools=None,
        tool_choice=None,
        temperature=0.3,
        max_tokens=16,
    )
    assert headers["x-opencode-session"] == "sess-3"
    assert payload["model"] == "deepseek-v4-flash"
