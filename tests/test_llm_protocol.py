"""Anthropic Messages 协议修复回归测试：协议识别优先级 / 运行时切换守卫 /
tool_choice 映射 / temperature 上限夹取。"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import LLMConfig  # noqa: E402
from app.llm.client import LLMClient  # noqa: E402


def _client(base_url="https://api.deepseek.com/v1", model="deepseek-chat",
            temperature=0.3, protocol="auto"):
    return LLMClient(
        providers=[LLMConfig(base_url=base_url, api_key="sk-test", model=model,
                             temperature=temperature, protocol=protocol)],
        pool_mode=False,
    )


def test_tool_choice_mapping():
    tc = LLMClient._to_messages_tool_choice
    assert tc("required") == {"type": "any"}      # 强制调用任意工具，勿静默降级为 auto
    assert tc("none") == {"type": "none"}
    assert tc("auto") == {"type": "auto"}
    assert tc(None) == {"type": "auto"}
    assert tc({"type": "function", "function": {"name": "submit_finding"}}) == \
        {"type": "tool", "name": "submit_finding"}


def test_detect_protocol_chat_completions_beats_anthropic_substring():
    # 名字带 anthropic 但走 OpenAI Chat 的中转，不能因子串误锁成 messages
    c = _client(base_url="https://x.anthropic-proxy.com/v1/chat/completions", model="claude-3")
    assert c._detect_messages_protocol() == (False, True)
    # 真 messages 端点仍判 messages
    c2 = _client(base_url="https://api.anthropic.com/v1", model="claude-3")
    assert c2._detect_messages_protocol()[0] is True


def test_temperature_clamped_to_anthropic_max():
    c = _client(temperature=1.5)
    payload, _ = c._build_messages_payload([{"role": "user", "content": "hi"}], None, "auto", 1.5, 100)
    assert payload["temperature"] == 1.0   # Anthropic 上限 1.0（OpenAI 是 2.0）
    payload2, _ = c._build_messages_payload([{"role": "user", "content": "hi"}], None, "auto", 0.3, 100)
    assert payload2["temperature"] == 0.3  # 合法值不动


def test_protocol_switch_ignores_model_and_param_errors():
    # OpenAI "model does not exist" / invalid_request_error 不是协议不匹配，绝不切协议
    c = _client()
    before = c._messages_protocol
    assert c._maybe_switch_protocol(Exception("The model 'gpt-x' does not exist")) is False
    assert c._messages_protocol == before
    c2 = _client()
    assert c2._maybe_switch_protocol(
        Exception('{"type":"invalid_request_error","message":"bad param"}')) is False
    # 真·端点级 404（不含 model/param 字样）该触发切换
    c3 = _client()
    assert c3._maybe_switch_protocol(
        Exception("404 not found: unknown path /chat/completions")) is True


def test_coding_plan_v4_does_not_insert_extra_v1():
    from app.llm.client import llm_models_url, llm_request_url, _ensure_versioned_api_root

    glm = "https://open.bigmodel.cn/api/coding/paas/v4"
    assert llm_request_url(glm, "openai_chat") == f"{glm}/chat/completions"
    assert llm_request_url(glm + "/", "openai_chat") == f"{glm}/chat/completions"
    assert llm_request_url(glm + "/chat/completions", "openai_chat") == f"{glm}/chat/completions"
    assert llm_models_url(glm) == f"{glm}/models"
    assert _ensure_versioned_api_root(glm) == glm
    assert _client(base_url=glm)._messages_url() == f"{glm}/messages"


def test_ark_and_kimi_coding_roots():
    from app.llm.client import llm_request_url

    ark = "https://ark.cn-beijing.volces.com/api/coding/v3"
    assert llm_request_url(ark, "openai_chat") == f"{ark}/chat/completions"
    kimi = "https://api.kimi.com/coding/v1"
    assert llm_request_url(kimi, "openai_chat") == f"{kimi}/chat/completions"


def test_unversioned_root_still_gets_v1():
    from app.llm.client import llm_models_url, llm_request_url, _ensure_versioned_api_root

    assert llm_request_url("https://api.deepseek.com", "openai_chat") == (
        "https://api.deepseek.com/v1/chat/completions"
    )
    assert _ensure_versioned_api_root("https://api.deepseek.com") == "https://api.deepseek.com/v1"
    assert llm_models_url("https://api.deepseek.com") == "https://api.deepseek.com/v1/models"
    assert llm_request_url("https://api.anthropic.com", "anthropic_messages") == (
        "https://api.anthropic.com/v1/messages"
    )
    assert llm_request_url("https://open.bigmodel.cn/api/anthropic", "anthropic_messages") == (
        "https://open.bigmodel.cn/api/anthropic/v1/messages"
    )
    assert llm_request_url("https://api.openai.com/v1", "openai_chat") == (
        "https://api.openai.com/v1/chat/completions"
    )

