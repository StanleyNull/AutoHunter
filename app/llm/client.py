"""LLM 客户端，封装 function calling 调用。

同时支持 OpenAI Chat Completions 与 Anthropic Messages 两种协议，按 base_url/model/显式
protocol 自动协商与运行时切换。支持 DeepSeek / Qwen / Kimi / GPT / Claude 等接口。

24x7 健壮性：请求级超时 + 轻量重试。LLM 挂起会几分钟内失败重试或放弃，
而不是把 worker 线程拖到 30min 墙钟超时才回收（白占一个并发位）。
"""
from __future__ import annotations

import os
import json
import logging
import re
import threading
import time
import uuid
from typing import Any, Callable, Optional
from types import SimpleNamespace

import httpx
from openai import OpenAI

from app.config import LLMConfig, llm_config
from app.llm.health import (
    acquire_provider_slot,
    mark_provider_failed,
    mark_provider_behavior_failed,
    mark_provider_behavior_ok,
    mark_provider_ok,
    provider_ref,
    provider_retry_after_seconds,
    snapshot as health_snapshot,
)
from app.llm.usage import record_usage

logger = logging.getLogger("autohunter.llm")

_SECRET_RE = re.compile(
    r"(?:\bsk-[A-Za-z0-9_-]{8,}\b"
    r"|\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}"
    r"|(?:api[_-]?key|token|secret|password|passwd|pwd)"
    r"\b[\"']?\s*[:=]\s*[\"']?[^\s'\"&]{6,})",
    re.IGNORECASE,
)

# 单次 LLM 请求超时（秒）；DeepSeek 带工具调用通常 10-60s，120s 足够且能兜住挂起。
_REQUEST_TIMEOUT = float(os.environ.get("LLM_REQUEST_TIMEOUT", "120"))
# 失败重试次数（网络抖动/限流/5xx）；默认 4 次（含网络抖动场景多给几次机会）。
_MAX_RETRIES = int(os.environ.get("LLM_MAX_RETRIES", "4"))
# 端点池：同端点先轻量重试几次再切下一个（避免一次网络毛刺就换模型丢上下文）。
_POOL_SAME_PROVIDER_RETRIES = int(os.environ.get("LLM_POOL_SAME_PROVIDER_RETRIES", "1"))
_RR_LOCK = threading.Lock()
# Smooth weighted round-robin current weights, keyed by pool/rank/provider.
# The state is intentionally process-local; the production process runs one Uvicorn worker.
_RR_STATE: dict[str, int] = {}


def _api_root(base_url: str) -> str:
    base = str(base_url or "").strip().rstrip("/")
    lowered = base.lower()
    for suffix in ("/chat/completions", "/messages"):
        if lowered.endswith(suffix):
            return base[: -len(suffix)].rstrip("/")
    return base


def _is_kimi_coding_endpoint(base_url: str) -> bool:
    """Kimi Code 专用端点（https://api.kimi.com/coding/v1，k3 等思考模型）。

    该端点只接受 temperature=1，传其它值会 HTTP 400
    "invalid temperature: only 1 is allowed for this model"。
    """
    return "api.kimi.com/coding" in str(base_url or "").lower()

# 浏览器 UA（伪装成 Chrome，绕过 Cloudflare/WAF 对 SDK UA 的封禁）
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)


def _default_ua_for_model(model: str, base_url: str) -> str:
    """按模型/中转特征给一个贴近官方客户端的 User-Agent。

    反指纹主要靠删除 `x-stainless-*` SDK 指纹头（见 _llm_default_headers）；UA 则钉一个
    可信的官方客户端版本号（对 GPT/Claude 即其官方 SDK 的 UA 形态），避免中转站/2api 网关
    （尤其套 Cloudflare 的）因缺失/异常 UA 而回 403，最大化通过率。
    """
    m = (model or "").lower()
    if any(k in m for k in ("deepseek",)):
        return "DeepSeek/1.0 (compatible)"
    if any(k in m for k in ("claude", "anthropic")):
        return "Anthropic/Python 0.39.0"
    if any(k in m for k in ("gpt", "o1", "o3", "o4", "openai")):
        return "OpenAI/Python 1.51.0"
    if any(k in m for k in ("glm", "zhipu", "chatglm")):
        return "zhipuai/2.1.0"
    if any(k in m for k in ("qwen", "qianwen", "dashscope", "tongyi")):
        return "dashscope/1.20.0 python"
    if any(k in m for k in ("kimi", "moonshot")):
        return "moonshot/1.0 python"
    if any(k in m for k in ("gemini", "google")):
        return "google-genai/0.8.0"
    if any(k in m for k in ("grok", "xai")):
        return "xai-sdk/0.1.0"
    # 兜底：直接伪装浏览器，最不容易被 WAF 拦
    return _BROWSER_UA


def _resolve_user_agent(model: str, base_url: str) -> str:
    """决定实际使用的 UA：显式配置优先，其次按模型推断。

    - LLM_USER_AGENT="browser" → 用浏览器 UA
    - LLM_USER_AGENT=<自定义串> → 原样使用
    - 未配置 → 按模型族自动选（_default_ua_for_model）
    """
    explicit = (os.environ.get("LLM_USER_AGENT", "") or "").strip()
    if explicit:
        low = explicit.lower()
        if low in ("browser", "chrome"):
            return _BROWSER_UA
        if low in ("auto", "model"):
            return _default_ua_for_model(model, base_url)
        return explicit
    return _default_ua_for_model(model, base_url)


def _stainless_omit_value():
    """返回让 openai SDK 彻底删除 header 的哨兵值。

    新版 SDK 用 `Omit()` 表示「从最终请求里删掉这个头」；置 None 会让 httpx 崩，
    置空串又会被 SDK 拼成 `python, `（仍泄露指纹）。老版本没有 Omit 时退回空串。
    """
    try:
        from openai import Omit  # type: ignore
        return Omit()
    except Exception:  # pragma: no cover - 老 SDK 兜底
        return ""


def _llm_default_headers(model: str, base_url: str) -> dict[str, Any]:
    """OpenAI SDK 的 default_headers：覆盖 UA + 抹掉暴露 SDK 的 x-stainless-* 头。

    很多中转/2api 网关只按 `User-Agent` 与 `x-stainless-*` 指纹拦 SDK 流量，
    转发到上游时回 403。这里把 UA 换成贴近官方客户端/浏览器的值，并用 Omit()
    删除 stainless 指纹头，让请求看起来不像 Python SDK。
    """
    omit = _stainless_omit_value()
    headers: dict[str, Any] = {"User-Agent": _resolve_user_agent(model, base_url)}
    # 大小写必须与 SDK platform_headers() 完全一致，否则会被当成不同 key、删不掉。
    for h in (
        "X-Stainless-Lang", "X-Stainless-Package-Version", "X-Stainless-OS",
        "X-Stainless-Arch", "X-Stainless-Runtime", "X-Stainless-Runtime-Version",
        "X-Stainless-Async", "X-Stainless-Retry-Count", "X-Stainless-Read-Timeout",
    ):
        headers[h] = omit
    return headers


def _per_request_omit_headers() -> dict[str, Any]:
    """逐请求删除 SDK 动态补写的 x-stainless-retry-count / read-timeout。

    这两个头在 `_build_headers` 里按 `custom_headers`（即 create() 的 extra_headers）
    是否存在来决定要不要补；用 Omit() 占位即可让最终请求里不出现它们。
    老 SDK 无 Omit 时返回空 dict（放弃删这两个无关紧要的头）。
    """
    omit = _stainless_omit_value()
    if omit == "":
        return {}
    return {
        "X-Stainless-Retry-Count": omit,
        "X-Stainless-Read-Timeout": omit,
    }


class LLMError(RuntimeError):
    """归一化 LLM 错误，避免前端/日志只看到 SDK 原始异常。"""

    def __init__(
        self,
        kind: str,
        message: str,
        original: Exception | None = None,
        *,
        status: int | None = None,
        code: str = "",
        detail: str = "",
        retry_after: int = 0,
    ):
        super().__init__(message)
        self.kind = kind
        self.original = original
        self.status = status
        self.code = code
        self.detail = detail
        self.retry_after = max(0, int(retry_after or 0))

    def diagnostic(self) -> str:
        parts = [f"kind={self.kind}"]
        if self.status:
            parts.append(f"status={self.status}")
        if self.code:
            parts.append(f"code={self.code}")
        parts.append(f"message={super().__str__()}")
        if self.detail:
            parts.append(f"detail={self.detail}")
        if self.retry_after:
            parts.append(f"retry_after={self.retry_after}")
        return "；".join(parts)

    def __str__(self) -> str:
        # 前端/事件流只展示短文案；完整 diagnostic 留给后端日志
        return super().__str__()


def _sanitize_error_detail(text: str, limit: int = 1200) -> str:
    text = _SECRET_RE.sub("<masked>", text or "")
    text = " ".join(text.split())
    return text[:limit]


def _is_forced_tool_choice(tool_choice: Any) -> bool:
    if tool_choice in (None, "auto", "none"):
        return False
    if isinstance(tool_choice, dict):
        fn = (tool_choice.get("function") or {}).get("name")
        return bool(fn)
    return True


def _is_forced_tool_choice_unsupported(err: LLMError) -> bool:
    """强制指定函数的 tool_choice 不被上游模型/网关接受时的各种表现。

    并非所有模型都支持 OpenAI 的 `tool_choice={"type":"function",...}`（强制调用指定函数）：
    - DeepSeek thinking：明确报 "thinking mode does not support this tool_choice"；
    - 部分代理网关(vveai/gpt.ge/goaiaog 等)的 Grok/GLM/Qwen/Gemini：直接返回 HTTP 400/422
      （如 Upstream error: 422、code=1210 "API 调用参数有误"），或提示 tool_choice/parameter invalid。
    命中这些时中心降级为 auto 重试，避免 reviewer/collector 这类强制调用方在非 DeepSeek 模型上
    直接失败（表现为审核异常 kind=unknown）。
    """
    text = (err.detail or str(err)).lower()
    if "thinking mode does not support this tool_choice" in text:
        return True
    status = getattr(err, "status", None)
    # 400/422：网关常把不支持的 forced tool_choice 包装成参数错误或 Upstream error。
    if str(status) in ("400", "422") or " 400 " in f" {text} " or " 422 " in f" {text} ":
        markers = (
            "tool_choice", "tool choice", "function call",
            "参数有误", "参数错误", "invalid parameter", "invalid_request",
            "unsupported", "not support", "unrecognized", "unexpected",
            "upstream error", "unprocessable",
        )
        # 422 Upstream error 几乎总是网关对请求形态的拒绝；对 forced tool_choice 场景直接降级。
        if str(status) == "422" or "upstream error" in text or "unprocessable" in text:
            return True
        return any(m in text for m in markers)
    return False


def _is_max_tokens_unsupported(err: LLMError) -> bool:
    text = (err.detail or str(err)).lower()
    return (
        "max_tokens" in text
        and any(marker in text for marker in (
            "unsupported", "unrecognized", "unknown", "unexpected", "extra",
            "not support", "invalid parameter", "invalid_request_error",
        ))
    )


# ─── 提示词模拟工具调用（tool-calling 兼容层）─────────────────────────────
# 部分模型/网关不支持原生 function calling。为了让这类模型也能跑 AutoHunter 的
# agent 循环，这里提供一个「文本模拟」兜底：把 tools 描述注入提示词、要求模型用
# 固定 JSON 格式表达工具调用，再把返回文本解析回 tool_calls。对话历史里的
# assistant.tool_calls / role:"tool" 在发送前改写成纯文本，agent 层完全无感。
#
# 只对不支持工具的模型启用（tool_compat=prompt 或 auto 命中硬报错自动切换），
# 原生可用的模型走原路径、零影响。

def _resolve_tool_compat(config: Any) -> str:
    """工具调用兼容模式：native / prompt / auto（默认）。

    auto：先走原生；若端点对 tools 参数硬报错(不支持)，自动切到提示词模拟。
    prompt：始终用提示词模拟（给「接受 tools 参数但从不真正调用」的哑模型用）。
    native：只用原生，永不模拟（等价旧行为）。
    """
    v = (
        (getattr(config, "tool_compat", None) or "")
        or os.environ.get("AUTOHUNTER_TOOL_COMPAT")
        or os.environ.get("LLM_TOOL_COMPAT")
        or "auto"
    )
    v = str(v).strip().lower()
    return v if v in ("auto", "prompt", "native") else "auto"


def _is_tools_unsupported(err: LLMError) -> bool:
    """端点/模型明确不支持 tools 参数（区别于「只是不支持强制 tool_choice」）。

    只在信号明确时判 True，避免把原生可用的模型误切成模拟模式。"""
    text = (getattr(err, "detail", "") or str(err) or "").lower()
    if not text:
        return False
    markers = (
        "does not support tools", "do not support tools", "not support tool use",
        "tool use is not supported", "tools is not supported", "tools are not supported",
        "function calling is not supported", "does not support function calling",
        "no endpoints found that support tool use", "no endpoints found that support tools",
        "unsupported parameter: 'tools'", "unsupported parameter: \"tools\"",
        "unknown parameter: 'tools'", "unrecognized request argument supplied: tools",
        "unexpected keyword argument 'tools'", "'tools' is not a valid",
        "tool_calls is not supported", "tools not supported", "不支持工具", "不支持函数调用",
    )
    return any(m in text for m in markers)


def _tool_schema_fields(t: dict[str, Any]) -> tuple[str, str, dict]:
    """从 OpenAI 或 Anthropic 风格的 tool schema 里取 name/description/parameters。"""
    if isinstance(t, dict) and isinstance(t.get("function"), dict):
        fn = t["function"]
        return str(fn.get("name") or ""), str(fn.get("description") or ""), (fn.get("parameters") or {})
    if isinstance(t, dict):
        return (
            str(t.get("name") or ""),
            str(t.get("description") or ""),
            (t.get("input_schema") or t.get("parameters") or {}),
        )
    return "", "", {}


def _emulation_preamble(tools: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for t in tools or []:
        name, desc, params = _tool_schema_fields(t)
        if not name:
            continue
        try:
            pj = json.dumps(params, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            pj = "{}"
        lines.append(f"- {name}: {desc} 参数: {pj}")
    tool_block = "\n".join(lines)
    return (
        "【工具调用协议】本模型无原生 function calling，改用文本模拟：\n"
        "需要行动或给结论时，只输出一个 ```json 代码块，块外不写任何字符：\n"
        '{"tool_calls":[{"name":"工具名","arguments":{...}}]}（可多个）。\n'
        "禁止用自然语言下结论——收尾必须调用 finish / submit_* 工具。\n"
        "工具结果以「[工具返回] 名称: ...」用户消息回传，据此继续。\n"
        "可用工具：\n" + tool_block
    )


def _build_prompt_tools_messages(
    messages: list[dict[str, Any]], tools: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """把「带 tools 的原生对话」改写成「纯文本对话」：注入协议说明，
    并把 assistant.tool_calls / role:"tool" 转成模型能读的纯文本。"""
    preamble = _emulation_preamble(tools)
    out: list[dict[str, Any]] = []
    injected = False
    for m in messages:
        role = m.get("role")
        if role == "system" and not injected:
            base = m.get("content") or ""
            out.append({"role": "system", "content": f"{base}\n\n{preamble}" if base else preamble})
            injected = True
            continue
        if role == "assistant":
            tcs = m.get("tool_calls")
            if tcs:
                calls = []
                for tc in tcs:
                    fn = tc.get("function") if isinstance(tc, dict) else {}
                    fn = fn or {}
                    args = fn.get("arguments")
                    if isinstance(args, str):
                        try:
                            args = json.loads(args or "{}")
                        except Exception:
                            args = args
                    calls.append({"name": fn.get("name", ""), "arguments": args if args is not None else {}})
                body = json.dumps({"tool_calls": calls}, ensure_ascii=False)
                prose = (m.get("content") or "").strip()
                text = (f"{prose}\n" if prose else "") + f"```json\n{body}\n```"
                out.append({"role": "assistant", "content": text})
            else:
                out.append({"role": "assistant", "content": m.get("content") or ""})
            continue
        if role == "tool":
            name = m.get("_tool") or "tool"
            out.append({"role": "user", "content": f"[工具返回] {name}:\n{m.get('content') or ''}"})
            continue
        out.append({"role": role or "user", "content": m.get("content") or ""})
    if not injected:
        out.insert(0, {"role": "system", "content": preamble})
    return out


def _first_balanced_json(s: str) -> str | None:
    """返回 s 中第一个大括号平衡的 JSON 对象子串（考虑字符串转义）。"""
    start = s.find("{")
    while start != -1:
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(s)):
            c = s[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        return s[start:i + 1]
        start = s.find("{", start + 1)
    return None


_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)


def _extract_emulated_calls(obj: Any) -> list[Any] | None:
    if not isinstance(obj, dict):
        return None
    items: Any = None
    if isinstance(obj.get("tool_calls"), list):
        items = obj["tool_calls"]
    elif obj.get("name"):
        items = [obj]
    elif obj.get("tool"):
        items = [{"name": obj.get("tool"), "arguments": obj.get("arguments", {})}]
    if not items:
        return None
    calls: list[Any] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        fn = it.get("function") if isinstance(it.get("function"), dict) else it
        name = fn.get("name") or it.get("name")
        if not name:
            continue
        args = fn.get("arguments", it.get("arguments", {}))
        args_str = args if isinstance(args, str) else json.dumps(args or {}, ensure_ascii=False)
        calls.append(SimpleNamespace(
            id="call_" + uuid.uuid4().hex[:24],
            type="function",
            function=SimpleNamespace(name=str(name), arguments=args_str),
        ))
    return calls or None


def _parse_emulated_tool_calls(text: str) -> tuple[str, list[Any] | None]:
    """从模型文本里解析模拟工具调用，返回 (去掉调用块后的文本, tool_calls 或 None)。"""
    if not text:
        return text, None
    candidates: list[str] = []
    for inner in _FENCE_RE.findall(text):
        obj_str = _first_balanced_json(inner)
        if obj_str:
            candidates.append(obj_str)
    if not candidates:
        obj_str = _first_balanced_json(text)
        if obj_str:
            candidates.append(obj_str)
    for raw in reversed(candidates):  # 最后一个动作块优先
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        calls = _extract_emulated_calls(obj)
        if calls:
            content = text.replace(raw, "")
            content = _FENCE_RE.sub("", content).replace("```json", "").replace("```", "").strip()
            return content, calls
    return text, None


def _apply_emulated_tool_calls(msg: Any) -> Any:
    """把模拟模式下的纯文本响应解析成带 tool_calls 的 message。"""
    text = getattr(msg, "content", None) or ""
    content, calls = _parse_emulated_tool_calls(text)
    if calls:
        return SimpleNamespace(content=content, tool_calls=calls, role="assistant")
    return msg


def _dict_to_message(msg: dict[str, Any]) -> SimpleNamespace:
    """把网关 dict message 转成与 OpenAI SDK 相近的 SimpleNamespace。"""
    content = msg.get("content")
    if isinstance(content, list):
        parts: list[str] = []
        for p in content:
            if isinstance(p, dict) and p.get("type") == "text":
                parts.append(str(p.get("text") or ""))
            elif isinstance(p, str):
                parts.append(p)
        content = "".join(parts)
    tool_calls = msg.get("tool_calls")
    ns_calls = None
    if isinstance(tool_calls, list) and tool_calls:
        ns_calls = []
        for c in tool_calls:
            if not isinstance(c, dict):
                continue
            fn = c.get("function") if isinstance(c.get("function"), dict) else {}
            args = fn.get("arguments")
            if args is not None and not isinstance(args, str):
                args = json.dumps(args, ensure_ascii=False)
            ns_calls.append(SimpleNamespace(
                id=c.get("id", ""),
                type=c.get("type", "function"),
                function=SimpleNamespace(name=fn.get("name", ""), arguments=args or ""),
            ))
    return SimpleNamespace(
        content="" if content is None else content,
        tool_calls=ns_calls or None,
        role=msg.get("role") or "assistant",
    )


def _coerce_chat_message(resp: Any) -> Any:
    """兼容各类网关返回：ChatCompletion / dict / JSON 字符串 / 纯文本 / SSE 残留。

    部分中转会把整段 JSON 当字符串返回，或 200 直接回纯文本，官方 SDK 解出来是 str，
    随后访问 ``resp.choices`` 就会报 ``'str' object has no attribute 'choices'``。
    """
    if resp is None:
        raise LLMError("upstream", "LLM 返回空响应。", detail="resp is None")

    if isinstance(resp, (bytes, bytearray)):
        resp = resp.decode("utf-8", errors="replace")

    if isinstance(resp, str):
        text = resp.strip()
        if not text:
            raise LLMError("upstream", "LLM 返回空字符串。", detail="empty string")
        # SSE：取最后一条有效 data:
        if text.startswith("data:") or "\ndata:" in text:
            lines = [ln[5:].strip() for ln in text.splitlines() if ln.startswith("data:")]
            lines = [ln for ln in lines if ln and ln != "[DONE]"]
            if lines:
                text = lines[-1]
        try:
            resp = json.loads(text)
        except json.JSONDecodeError:
            return SimpleNamespace(content=text, tool_calls=None, role="assistant")

    if isinstance(resp, dict):
        if resp.get("error"):
            err = resp["error"]
            detail = err if isinstance(err, str) else json.dumps(err, ensure_ascii=False)
            raise LLMError(
                "upstream", "LLM 网关返回错误。",
                detail=_sanitize_error_detail(str(detail)),
            )
        choices = resp.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, str):
                return SimpleNamespace(content=first, tool_calls=None, role="assistant")
            if isinstance(first, dict):
                msg = first.get("message", first)
                if isinstance(msg, str):
                    return SimpleNamespace(content=msg, tool_calls=None, role="assistant")
                if isinstance(msg, dict):
                    return _dict_to_message(msg)
        if "content" in resp or "tool_calls" in resp:
            return _dict_to_message(resp)
        raise LLMError(
            "upstream", "LLM 响应无法解析为 message。",
            detail=_sanitize_error_detail(str(resp)[:400]),
        )

    # 标准 ChatCompletion 对象
    choices = getattr(resp, "choices", None)
    if choices:
        first = choices[0]
        msg = getattr(first, "message", None)
        if msg is not None:
            return msg
        if isinstance(first, str):
            return SimpleNamespace(content=first, tool_calls=None, role="assistant")
        return first

    # 已是 message 形态（如 Anthropic 解析结果）
    if hasattr(resp, "content") or hasattr(resp, "tool_calls"):
        return resp

    raise LLMError(
        "upstream",
        "LLM 响应格式异常。",
        detail=_sanitize_error_detail(f"{type(resp).__name__}: {resp!r}"[:400]),
    )


def _classify_error(e: Exception) -> LLMError:
    response = getattr(e, "response", None)
    status = getattr(e, "status_code", None) or getattr(response, "status_code", None)
    code = getattr(e, "code", "") or ""
    raw = str(e)
    if response is not None:
        try:
            raw = f"{raw} {response.text[:500]}"
        except Exception:
            pass
    detail = _sanitize_error_detail(raw)
    text = f"{status or ''} {code} {raw}".lower()

    # 网关返回了字符串/非标准对象，访问 .choices 失败 → 归为 upstream（可临时回队）
    if isinstance(e, AttributeError) and "choices" in text:
        return LLMError(
            "upstream",
            "LLM 响应格式异常（非标准 ChatCompletion，常见于中转网关）。",
            e, status=status, code=str(code), detail=detail,
        )
    if isinstance(e, LLMError):
        return e
    if any(k in text for k in ("insufficient_quota", "quota", "billing", "余额", "额度", "balance")):
        return LLMError(
            "quota", "LLM 额度不足或账户余额不足，请更换/充值模型 API Key 后重试。",
            e, status=status, code=str(code), detail=detail,
        )
    if status == 401 or any(k in text for k in (
        "unauthorized", "invalid api key", "incorrect api key",
        "api key 无效", "apikey 无效", "密钥无效", "令牌无效",
    )):
        return LLMError(
            "auth", "LLM API Key 无效或无权限，请检查任务配置或服务端 .env。",
            e, status=status, code=str(code), detail=detail,
        )
    if status == 403 or any(k in text for k in (
        "forbidden", "request blocked", "access denied", "content policy", "被拦截", "禁止访问",
        "cybersecurity risk", "trusted access for cyber", "chatgpt.com/cyber",
        "flagged for possible cybersecurity",
    )):
        if any(k in text for k in (
            "cybersecurity risk", "trusted access for cyber", "chatgpt.com/cyber",
            "flagged for possible cybersecurity",
        )):
            return LLMError(
                "blocked",
                "此模型不让你搞网络安全。",
                e, status=status, code=str(code), detail=detail,
            )
        return LLMError(
            "blocked", "LLM 请求被上游网关或安全策略拒绝，请检查访问策略或稍后重试。",
            e, status=status, code=str(code), detail=detail,
        )
    if status == 429 or any(k in text for k in ("rate limit", "too many requests", "限流")):
        return LLMError(
            "rate_limit", "LLM 请求被限流，请稍后重试或降低并发。",
            e, status=status, code=str(code), detail=detail,
        )
    if status in {400, 422} or any(k in text for k in (
        "invalid_request", "bad request", "unprocessable entity", "参数有误", "参数错误",
    )):
        # OpenAI 常把安全策略拦截包装成 400 invalid_request
        if any(k in text for k in (
            "cybersecurity risk", "trusted access for cyber", "chatgpt.com/cyber",
            "flagged for possible cybersecurity",
        )):
            return LLMError(
                "blocked",
                "此模型不让你搞网络安全。",
                e, status=status, code=str(code), detail=detail,
            )
        return LLMError(
            "invalid_request", "LLM 请求参数不被接受，请检查模型名、协议或请求配置。",
            e, status=status, code=str(code), detail=detail,
        )
    if any(k in text for k in ("timeout", "timed out", "readtimeout", "connecttimeout", "超时")):
        return LLMError(
            "timeout", "LLM 请求超时，可能是模型服务或网络临时不可用。",
            e, status=status, code=str(code), detail=detail,
        )
    if any(k in text for k in ("connection", "network", "name resolution", "连接")):
        return LLMError(
            "network", "LLM 网络连接失败，请检查服务器出网或代理。",
            e, status=status, code=str(code), detail=detail,
        )
    if status and int(status) >= 500:
        return LLMError(
            "upstream", "LLM 上游服务临时异常，请稍后重试。",
            e, status=status, code=str(code), detail=detail,
        )
    # unknown：对前端脱敏，但在后端日志留下真实底层异常，便于定位（这是排查“未知错误”的关键）。
    logger.warning(
        "LLM unknown error: type=%s status=%s code=%s detail=%s",
        type(e).__name__, status, code, raw[:600],
    )
    return LLMError(
        "unknown", "LLM 调用失败：模型服务返回未知错误。",
        e, status=status, code=str(code), detail=detail,
    )


def _should_try_next_provider(error: Exception) -> bool:
    if not isinstance(error, LLMError):
        return False
    if error.kind in {
        "quota", "auth", "blocked", "invalid_request",
        "rate_limit", "timeout", "network", "upstream",
    }:
        return True
    if error.kind != "unknown":
        return False
    try:
        status = int(error.status or 0)
    except (TypeError, ValueError):
        status = 0
    return status == 0 or status >= 400


def _should_retry_current_provider(error: Exception) -> bool:
    return isinstance(error, LLMError) and error.kind in {
        "rate_limit", "timeout", "network", "upstream",
    }


def _provider_weight(provider: LLMConfig) -> int:
    try:
        weight = int(getattr(provider, "weight", 1) or 1)
    except (TypeError, ValueError):
        weight = 1
    return max(1, min(weight, 100))


def _provider_health_rank(provider: LLMConfig, health: dict[str, dict[str, Any]]) -> int:
    state = health.get(provider_ref(
        provider.base_url, provider.model, provider.api_key, provider.protocol
    )) or {}
    status = str(state.get("status") or "")
    if status == "half_open":
        return 0
    if status == "failed":
        return 1
    if status == "cooldown":
        return 2
    return 0


class LLMClient:
    def __init__(
        self,
        config: Optional[LLMConfig] = None,
        usage_key: str | None = None,
        providers: Optional[list[LLMConfig]] = None,
        pool_mode: bool | None = None,
        on_provider_failure: Callable[[dict[str, Any]], None] | None = None,
        on_provider_selected: Callable[[dict[str, Any]], None] | None = None,
    ):
        raw_providers = list(providers) if providers is not None else [config or llm_config]
        self.providers = [
            provider for provider in raw_providers
            if provider and provider.api_key and getattr(provider, "enabled", True)
        ]
        self.usage_key = usage_key
        # A one-entry pool has no failover candidate and must retain single-provider
        # transport retries even when the configuration mode is named "pool".
        self.pool_mode = len(self.providers) > 1 and (
            pool_mode is None or bool(pool_mode)
        )
        self.on_provider_failure = on_provider_failure
        self.on_provider_selected = on_provider_selected
        self.selected_provider: LLMConfig | None = None
        if not self.providers:
            raise RuntimeError("缺少 LLM_API_KEY/LLM_PROVIDERS_JSON，请在 .env 或系统设置中配置")
        self._auto_protocol_cache: dict[str, bool] = {}
        self._insecure_provider_refs: set[str] = set()
        self._global_insecure_tls = os.environ.get("LLM_INSECURE_TLS", "").strip() in ("1", "true", "True")
        self._client_cache: dict[tuple[str, bool], OpenAI] = {}
        self._sticky_provider_ref = ""
        self._provider_slot_owner = uuid.uuid4().hex
        self._activate_provider(self.providers[0])
        # 工具调用兼容：不支持原生 function calling 的模型走「提示词模拟」兜底。
        # 自动切换的记录按「端点」而非整个 client 维度——池化时某个哑端点触发模拟，
        # 不会连累池里其它支持原生工具调用的端点。
        self._tool_compat = _resolve_tool_compat(self.config)
        self._prompt_tools_providers: set[str] = set()

    def _current_provider_ref(self) -> str:
        return provider_ref(
            self.config.base_url, self.config.model, self.config.api_key, self.config.protocol
        )

    def _prompt_tools_enabled(self) -> bool:
        return self._tool_compat == "prompt" or self._current_provider_ref() in self._prompt_tools_providers

    def force_prompt_tools_current(self) -> bool:
        """把当前活动端点标记为「提示词模拟工具调用」并对后续调用生效。

        供上层(如 worker)在检测到「模型接受 tools 参数但全程一个工具都不调」的哑模型
        时主动自愈：不必等用户手动设 AUTOHUNTER_TOOL_COMPAT=prompt。
        仅 auto 模式生效（native=用户明确只要原生，不擅自切；prompt=本就全程模拟）。
        返回是否真的发生了切换（已在模拟或非 auto 则 False，便于调用方判断要不要重试）。
        """
        if self._tool_compat != "auto":
            return False
        ref = self._current_provider_ref()
        if ref in self._prompt_tools_providers:
            return False
        self._prompt_tools_providers.add(ref)
        logger.warning(
            "LLM 端点疑似不支持工具调用(全程零工具)，自愈切换为提示词模拟 (model=%s)",
            self.config.model,
        )
        return True

    def _provider_order(self) -> list[LLMConfig]:
        if len(self.providers) <= 1:
            return list(self.providers)
        health = health_snapshot()
        if self._sticky_provider_ref:
            sticky_index = next((
                index
                for index, provider in enumerate(self.providers)
                if provider_ref(
                    provider.base_url, provider.model, provider.api_key, provider.protocol
                )
                == self._sticky_provider_ref
                and _provider_health_rank(provider, health) == 0
            ), None)
            if sticky_index is not None:
                remaining = sorted(
                    (index for index in range(len(self.providers)) if index != sticky_index),
                    key=lambda index: _provider_health_rank(self.providers[index], health),
                )
                return [self.providers[sticky_index], *(self.providers[index] for index in remaining)]
        groups: dict[int, list[int]] = {0: [], 1: [], 2: []}
        for index, provider in enumerate(self.providers):
            groups[_provider_health_rank(provider, health)].append(index)

        ordered: list[int] = []
        for rank in (0, 1, 2):
            for index in self._weighted_group_order(groups[rank], rank):
                if index not in ordered:
                    ordered.append(index)
        return [self.providers[index] for index in ordered]

    def _weighted_group_order(self, indices: list[int], rank: int) -> list[int]:
        if not indices:
            return []
        positions = {index: position for position, index in enumerate(indices)}
        refs = {
            index: provider_ref(
                self.providers[index].base_url,
                self.providers[index].model,
                self.providers[index].api_key,
                self.providers[index].protocol,
            )
            for index in indices
        }
        weights = {index: _provider_weight(self.providers[index]) for index in indices}
        pool_key = "|".join(
            f"{refs[index]}:{weights[index]}"
            for index in indices
        )
        total_weight = sum(weights.values())
        state_prefix = f"{rank}:{pool_key}:"
        with _RR_LOCK:
            scores: dict[int, int] = {}
            for index in indices:
                key = f"{state_prefix}{positions[index]}:{refs[index]}"
                score = _RR_STATE.get(key, 0) + weights[index]
                _RR_STATE[key] = score
                scores[index] = score

            # Choose the highest accumulated score, then subtract the pool total.
            # This is the standard Smooth WRR recurrence and avoids bursts such as
            # A,A,A,B for a 3:1 pool while preserving the exact long-run ratio.
            selected = max(indices, key=lambda index: (scores[index], -positions[index]))
            selected_key = f"{state_prefix}{positions[selected]}:{refs[selected]}"
            _RR_STATE[selected_key] -= total_weight
            scores[selected] -= total_weight

            remaining = sorted(
                (index for index in indices if index != selected),
                key=lambda index: (-scores[index], positions[index]),
            )
        return [selected, *remaining]

    def _activate_provider(self, config: LLMConfig) -> None:
        self.config = config
        # 协议自适应：先按显式配置/强特征确定；不确定时给个默认猜测(未锁定)，
        # 运行时若首个请求报“协议不匹配”特征错误，自动切另一种协议重试并沿用。
        self._messages_protocol, self._protocol_locked = self._detect_messages_protocol()
        self._protocol_autoswitched = False
        self._is_https = self.config.base_url.lower().startswith("https")
        # TLS 自适应：默认走正规证书校验；只有当 base_url 是 https 且首次遇到
        # “证书校验失败”（多为自建中转/网关的自签证书）时，才自动降级为不校验并沿用。
        # 也支持显式 LLM_INSECURE_TLS=1 一开始就不校验（兜底）。降级状态按端点隔离。
        ref = provider_ref(
            self.config.base_url, self.config.model, self.config.api_key, self.config.protocol
        )
        self._insecure_tls = self._global_insecure_tls or ref in self._insecure_provider_refs
        cache_key = (ref, self._insecure_tls)
        if cache_key not in self._client_cache:
            self._client_cache[cache_key] = self._build_client(insecure=self._insecure_tls)
        self.client = self._client_cache[cache_key]

    def _detect_messages_protocol(self) -> tuple[bool, bool]:
        """判定协议，返回 (是否 Anthropic Messages, 是否已锁定)。

        - 当前 provider 显式指定 → 锁定（anthropic_messages / openai_chat）。
        - base_url 强特征（openmodel.ai / 路径含 messages / anthropic）→ 锁定 messages。
        - base_url 强特征（路径含 chat/completions）→ 锁定 openai。
        - 都没命中 → 默认按 openai 猜测，但**不锁定**，交给运行时自适应纠正。
        """
        explicit = str(getattr(self.config, "protocol", "auto") or "auto").strip().lower()
        if explicit in ("messages", "anthropic", "anthropic_messages"):
            return True, True
        if explicit in ("openai", "chat", "completions", "openai_chat"):
            return False, True
        ref = provider_ref(
            self.config.base_url, self.config.model, self.config.api_key, self.config.protocol
        )
        if ref in self._auto_protocol_cache:
            return self._auto_protocol_cache[ref], False
        url = self.config.base_url.lower()
        # 先判 OpenAI 兼容端点特征：像 xxx.anthropic-proxy.com/v1/chat/completions 这类
        # 名字带 anthropic 但实际走 OpenAI Chat 的中转，不能因 "anthropic" 子串误锁成 messages。
        if "/chat/completions" in url or "chat/completions" in url:
            return False, True
        if "openmodel.ai" in url or "/messages" in url or "anthropic" in url:
            return True, True
        return False, False  # 默认 openai，未锁定，运行时可自适应切换

    def _remember_auto_protocol(self) -> None:
        if self._protocol_locked:
            return
        ref = provider_ref(
            self.config.base_url, self.config.model, self.config.api_key, self.config.protocol
        )
        self._auto_protocol_cache[ref] = self._messages_protocol

    def _maybe_switch_protocol(self, exc: Exception) -> bool:
        """协议自适应：首个请求报“协议不匹配”特征错误时，自动切另一种协议重试。

        仅在未锁定且未切换过时生效，只切一次（切完置位，不会来回横跳/死循环）。
        典型触发：走错端点导致 404 / not found / no such / method not allowed /
        提示 messages 或 chat/completions 路径不对等。
        """
        if self._protocol_locked or self._protocol_autoswitched:
            return False
        text = f"{exc} {getattr(exc, '__cause__', '')} {getattr(exc, 'detail', '')}".lower()
        # 排除“模型/参数”类错误（OpenAI 常见 "model 'x' does not exist" / invalid_request_error）：
        # 这类不是协议/端点不匹配，切协议只会把清晰的参数错误变成另一协议上的二次失败。
        if "invalid_request_error" in text or (
            "model" in text and any(w in text for w in ("does not exist", "not found", "not a valid", "no such"))
        ):
            return False
        proto_markers = (
            "404", "not found", "method not allowed", "405",
            "unknown path", "invalid path", "/messages", "chat/completions",
            "unsupported endpoint",
        )
        if any(m in text for m in proto_markers):
            self._messages_protocol = not self._messages_protocol
            self._protocol_autoswitched = True
            logger.warning(
                "LLM 端点疑似协议不匹配，已自动切换为 %s 协议重试(model=%s)",
                "Anthropic Messages" if self._messages_protocol else "OpenAI Chat",
                self.config.model,
            )
            return True
        return False

    def _build_client(self, insecure: bool) -> OpenAI:
        """构造 OpenAI 客户端。insecure=True 时用不校验证书的 httpx client。"""
        http_client = httpx.Client(verify=False, timeout=_REQUEST_TIMEOUT) if insecure else None
        # 关闭 SDK 内置重试，自己控制重试节奏与日志；设请求超时兜住挂起。
        # default_headers 换 UA + 抹 x-stainless-*，绕过中转/WAF 对 SDK UA 的 403 封禁。
        return OpenAI(
            base_url=_api_root(self.config.base_url), api_key=self.config.api_key,
            timeout=_REQUEST_TIMEOUT, max_retries=0,
            default_headers=_llm_default_headers(self.config.model, self.config.base_url),
            **({"http_client": http_client} if http_client else {}),
        )

    def _maybe_downgrade_tls(self, exc: Exception) -> bool:
        """遇到 TLS 证书校验失败时自动降级为不校验并重建 client。

        仅对 https + 证书类错误生效，且只降级一次；返回 True 表示已降级、可立即重试。
        普通 HTTPS 的安全性不受影响（只有握手因自签证书失败才会触发）。
        """
        if self._insecure_tls or not self._is_https:
            return False
        text = f"{exc} {getattr(exc, '__cause__', '')} {getattr(exc, '__context__', '')}".lower()
        tls_markers = (
            "certificate verify failed", "certificate_verify_failed",
            "self signed certificate", "self-signed certificate",
            "sslcertverificationerror", "ssl: certificate", "unable to get local issuer",
        )
        if any(m in text for m in tls_markers):
            self._insecure_tls = True
            ref = provider_ref(
                self.config.base_url, self.config.model, self.config.api_key, self.config.protocol
            )
            self._insecure_provider_refs.add(ref)
            cache_key = (ref, True)
            if cache_key not in self._client_cache:
                self._client_cache[cache_key] = self._build_client(insecure=True)
            self.client = self._client_cache[cache_key]
            logger.warning("检测到 LLM 中转 TLS 证书校验失败，已自动降级为不校验证书重试（多为自建自签中转）")
            return True
        return False

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        tool_choice: str = "auto",
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ):
        """调用一个健康端点，失败时按健康状态和权重切换备用端点。"""
        last_exc: Exception | None = None
        cooldown_delays: list[int] = []
        order = self._provider_order()
        for index, provider in enumerate(order):
            self._activate_provider(provider)
            can_try, slot_state = acquire_provider_slot(
                provider.base_url,
                provider.model,
                provider.api_key,
                provider.protocol,
                owner=self._provider_slot_owner,
            )
            if not can_try:
                cooldown_delays.append(
                    provider_retry_after_seconds(
                        provider.base_url, provider.model, provider.api_key, provider.protocol
                    )
                )
                continue
            self.selected_provider = provider
            self._notify_provider_selected(provider, slot_state)
            try:
                message = self._chat_current_provider(
                    messages, tools, tool_choice, temperature, max_tokens
                )
                self._remember_auto_protocol()
                mark_provider_ok(
                    provider.base_url, provider.model, provider.api_key, provider.protocol
                )
                self._sticky_provider_ref = provider_ref(
                    provider.base_url, provider.model, provider.api_key, provider.protocol
                )
                return message
            except Exception as exc:
                error = exc if isinstance(exc, LLMError) else _classify_error(exc)
                state = mark_provider_failed(
                    provider.base_url,
                    provider.model,
                    str(error),
                    provider.api_key,
                    provider.protocol,
                    kind=getattr(error, "kind", ""),
                )
                self._notify_provider_failure(error, state)
                last_exc = error
                if (
                    not self.pool_mode
                    and state.get("status") == "cooldown"
                    and _should_retry_current_provider(error)
                ):
                    retry_after = provider_retry_after_seconds(
                        provider.base_url,
                        provider.model,
                        provider.api_key,
                        provider.protocol,
                    )
                    raise LLMError(
                        "provider_cooldown",
                        f"LLM 端点正在冷却，预计 {retry_after} 秒后重试。",
                        retry_after=retry_after,
                    )
                if index + 1 < len(order) and _should_try_next_provider(error):
                    logger.warning(
                        "LLM provider failed; trying next provider %d/%d "
                        "(kind=%s, slot=%s, model=%s, base=%s)",
                        index + 2, len(order), getattr(error, "kind", "?"), slot_state,
                        provider.model, provider.base_url,
                    )
                    continue
                if self.pool_mode and _should_try_next_provider(error):
                    break
                raise error

        # A cooldown result means that no endpoint was actually called. If at
        # least one endpoint was called, preserve its real error so quota/auth/
        # request failures are not misreported as a generic pool cooldown.
        if last_exc:
            raise last_exc
        if cooldown_delays:
            retry_after = min(cooldown_delays)
            msg = (
                f"LLM 端点池正在冷却，预计 {retry_after} 秒后重试。"
                if self.pool_mode
                else f"LLM 暂时不可用，预计 {retry_after} 秒后重试。"
            )
            raise LLMError(
                "provider_cooldown",
                msg,
                retry_after=retry_after,
            )
        raise RuntimeError("没有可用的 LLM 端点")

    def clear_sticky_provider(self) -> None:
        """清掉粘性端点，下次 chat 重新按健康度/权重选端点（worker 软重试用）。"""
        self._sticky_provider_ref = ""

    def _notify_provider_selected(self, provider: LLMConfig, slot_state: str) -> None:
        if not self.on_provider_selected:
            return
        try:
            self.on_provider_selected({
                "base_url": provider.base_url,
                "model": provider.model,
                "protocol": provider.protocol,
                "slot_state": slot_state,
            })
        except Exception:
            logger.exception("LLM provider selection callback failed")

    def _notify_provider_failure(self, error: Exception, state: dict[str, Any]) -> None:
        if not self.on_provider_failure:
            return
        try:
            self.on_provider_failure({
                "base_url": self.config.base_url,
                "model": self.config.model,
                "kind": getattr(error, "kind", ""),
                "status": getattr(error, "status", None),
                "error": _sanitize_error_detail(str(error), 500),
                "provider_status": state.get("status"),
                "transition": state.get("transition"),
                "consecutive_failures": state.get("consecutive_failures", 0),
                "cooldown_seconds": state.get("cooldown_seconds", 0),
                "cooldown_until": state.get("cooldown_until", ""),
                "pool_mode": bool(self.pool_mode),
            })
        except Exception:
            logger.exception("LLM provider failure callback failed")

    def report_current_provider_failure(self, reason: str, *, kind: str = "model_behavior") -> dict[str, Any]:
        error = LLMError(kind, _sanitize_error_detail(reason, 500))
        state = mark_provider_behavior_failed(
            self.config.base_url,
            self.config.model,
            str(error),
            self.config.api_key,
            self.config.protocol,
            kind=kind,
        )
        self._notify_provider_failure(error, state)
        return state

    def report_current_provider_success(self) -> None:
        mark_provider_behavior_ok(
            self.config.base_url,
            self.config.model,
            self.config.api_key,
            self.config.protocol,
        )

    def _chat_current_provider(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        tool_choice: str = "auto",
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ):
        """单次对话调用，返回完整 message 对象（可能含 tool_calls）。"""
        # 工具调用兼容层：不支持原生 function calling 的模型改用「提示词模拟」——
        # 把 tools 注入提示词、请求不带 tools 参数，返回文本再解析回 tool_calls。
        messages_orig, tools_orig = messages, tools
        prompt_tools = bool(tools) and self._prompt_tools_enabled()
        if prompt_tools:
            messages = _build_prompt_tools_messages(messages_orig, tools_orig)
            tools = None
            tool_choice = "auto"

        def _finish(msg: Any) -> Any:
            return _apply_emulated_tool_calls(msg) if prompt_tools else msg

        kwargs: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature if temperature is None else temperature,
            "max_tokens": int(max_tokens or os.environ.get("LLM_MAX_TOKENS", "4096")),
        }
        if _is_kimi_coding_endpoint(self.config.base_url):
            kwargs["temperature"] = 1  # 该端点只接受 temperature=1
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = tool_choice
        # 逐请求再抹掉 SDK 在 _build_headers 里补写的 retry-count/read-timeout 两个
        # x-stainless-* 头（它们不在 default_headers 里，只能靠 per-request 覆盖）。
        extra = _per_request_omit_headers()
        if extra:
            kwargs["extra_headers"] = extra

        last_exc: Optional[Exception] = None
        active_tool_choice: Any = tool_choice
        tool_choice_fallback_used = False
        max_tokens_fallback_used = False
        max_retries = _POOL_SAME_PROVIDER_RETRIES if self.pool_mode else _MAX_RETRIES
        retry_count = 0
        # TLS/协议/参数兼容降级各自最多触发一次，不占传输重试次数。
        for _attempt in range(max_retries + 5):
            try:
                if self._messages_protocol:
                    return _finish(self._messages_chat(
                        messages, tools, active_tool_choice,
                        kwargs.get("temperature", 0.3), kwargs.get("max_tokens", 4096),
                    ))
                resp = self.client.chat.completions.create(**kwargs)
                self._record_openai_usage(resp)
                return _finish(_coerce_chat_message(resp))
            except Exception as e:  # 网络/超时/限流/5xx 统一重试
                # TLS 自适应：https 中转自签证书导致校验失败时，自动降级不校验并立即重试。
                # 只会降级一次（之后 _insecure_tls=True，再进来直接返回 False），不会死循环。
                if self._maybe_downgrade_tls(e):
                    continue
                last_exc = _classify_error(e)
                kind = getattr(last_exc, "kind", "?")
                # 协议自适应：端点用错协议（走错路径 404 等）时自动切 messages/openai 重试。
                if self._maybe_switch_protocol(last_exc):
                    continue
                if (
                    tools
                    and not tool_choice_fallback_used
                    and _is_forced_tool_choice(active_tool_choice)
                    and isinstance(last_exc, LLMError)
                    and _is_forced_tool_choice_unsupported(last_exc)
                ):
                    # 不是所有模型/网关都支持强制指定函数的 tool_choice：DeepSeek thinking 明确拒绝，
                    # 部分代理网关的 GLM/Qwen/Gemini 直接 400(如 code=1210 "API 调用参数有误")。
                    # 这些模型仍支持 tools + auto，故中心降级为 auto 重试，让 reviewer/collector 等
                    # 强制调用方在非 DeepSeek 模型上也能正常出结果，而不是 kind=unknown 直接失败。
                    logger.warning(
                        "LLM forced tool_choice rejected (thinking/400/422); falling back to auto "
                        "(model=%s, detail=%s)",
                        self.config.model, last_exc.detail[:300],
                    )
                    active_tool_choice = "auto"
                    kwargs["tool_choice"] = "auto"
                    tool_choice_fallback_used = True
                    continue
                # 工具调用兼容：端点对 tools 参数硬报错「不支持」时，自动切提示词模拟重试。
                # 仅 auto 模式、仅命中明确「不支持工具」的信号才切，原生可用模型不受影响。
                # 放在 forced tool_choice 降级之后：强制指定函数被拒时优先降级为 auto 保持原生，
                # 只有确认端点连 tools 参数本身都不认时，才退到提示词模拟。
                if (
                    tools_orig
                    and not prompt_tools
                    and self._tool_compat == "auto"
                    and isinstance(last_exc, LLMError)
                    and _is_tools_unsupported(last_exc)
                ):
                    logger.warning(
                        "LLM tools 参数不被支持，切换为提示词模拟工具调用 (model=%s, detail=%s)",
                        self.config.model, (getattr(last_exc, "detail", "") or "")[:200],
                    )
                    self._prompt_tools_providers.add(self._current_provider_ref())
                    prompt_tools = True
                    messages = _build_prompt_tools_messages(messages_orig, tools_orig)
                    tools = None
                    active_tool_choice = "auto"
                    kwargs["messages"] = messages
                    kwargs.pop("tools", None)
                    kwargs.pop("tool_choice", None)
                    continue
                if (
                    not max_tokens_fallback_used
                    and not self._messages_protocol
                    and "max_tokens" in kwargs
                    and isinstance(last_exc, LLMError)
                    and _is_max_tokens_unsupported(last_exc)
                ):
                    logger.warning(
                        "LLM max_tokens rejected; retrying once without max_tokens "
                        "(model=%s, detail=%s)",
                        self.config.model, last_exc.detail[:300],
                    )
                    kwargs.pop("max_tokens", None)
                    max_tokens_fallback_used = True
                    continue
                if not _should_retry_current_provider(last_exc):
                    diag = last_exc.diagnostic() if isinstance(last_exc, LLMError) else str(last_exc)
                    logger.warning(
                        "LLM chat failed without same-provider retry (kind=%s, model=%s, detail=%s)",
                        kind, self.config.model, diag[:400],
                    )
                    break
                if retry_count < max_retries:
                    logger.info("LLM chat retry %d/%d (kind=%s, model=%s)",
                                retry_count + 1, max_retries, kind, self.config.model)
                    time.sleep(min(2 ** retry_count, 8))  # 1s, 2s, 4s... 封顶 8s
                    retry_count += 1
                else:
                    diag = last_exc.diagnostic() if isinstance(last_exc, LLMError) else str(last_exc)
                    logger.warning(
                        "LLM chat giving up after %d retries (kind=%s, model=%s, detail=%s)",
                        max_retries, kind, self.config.model, diag[:400],
                    )
                    break
        raise last_exc  # type: ignore[misc]

    def _messages_url(self) -> str:
        base = _api_root(self.config.base_url)
        if base.endswith("/v1"):
            return f"{base}/messages"
        return f"{base}/v1/messages"

    @staticmethod
    def _to_messages_tools(tools: Optional[list[dict[str, Any]]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for item in tools or []:
            fn = item.get("function") or {}
            name = fn.get("name")
            if not name:
                continue
            out.append({
                "name": name,
                "description": fn.get("description", ""),
                "input_schema": fn.get("parameters") or {"type": "object", "properties": {}},
            })
        return out

    @staticmethod
    def _to_messages_tool_choice(tool_choice: Any) -> dict[str, Any] | None:
        if tool_choice in (None, "auto"):
            return {"type": "auto"}
        if tool_choice == "none":
            return {"type": "none"}
        if tool_choice == "required":
            return {"type": "any"}   # OpenAI 强制调用任意工具 → Anthropic any（勿静默降级为 auto）
        if isinstance(tool_choice, dict):
            fn = (tool_choice.get("function") or {}).get("name")
            if fn:
                return {"type": "tool", "name": fn}
        return {"type": "auto"}

    @staticmethod
    def _convert_messages(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
        """OpenAI 风格历史 → Anthropic messages 格式。

        Anthropic 要求 user/assistant 角色【严格交替】、不允许连续同角色消息，且同一轮的多个
        tool_result 必须落在同一条 user 消息里。而 OpenAI 历史里连续同角色很常见（开局
        system + 两条 user 前缀、一轮多个 tool 响应、工具响应后又追加 user 提示），因此这里把
        相邻同角色消息统一合并进一条、content 归一为 block 列表，避免拼出连续 user/assistant
        触发 400。
        """
        system_parts: list[str] = []
        out: list[dict[str, Any]] = []

        def _push(role: str, blocks: list[dict[str, Any]]) -> None:
            # 丢掉空 text block（Anthropic 拒绝空文本）；tool_use / tool_result 一律保留。
            blocks = [b for b in blocks if not (b.get("type") == "text" and not b.get("text"))]
            if not blocks:
                return
            if out and out[-1]["role"] == role:
                prev = out[-1]["content"]
                if isinstance(prev, str):  # 防御：正常情况下 out 里的 content 恒为 list
                    prev = [{"type": "text", "text": prev}] if prev else []
                    out[-1]["content"] = prev
                prev.extend(blocks)
            else:
                out.append({"role": role, "content": blocks})

        for msg in messages:
            role = msg.get("role")
            content = msg.get("content") or ""
            if role == "system":
                if content:
                    system_parts.append(str(content))
                continue
            if role == "tool":
                _push("user", [{
                    "type": "tool_result",
                    "tool_use_id": msg.get("tool_call_id", ""),
                    "content": str(content),
                }])
                continue
            if role == "assistant":
                blocks: list[dict[str, Any]] = []
                if content:
                    blocks.append({"type": "text", "text": str(content)})
                for call in msg.get("tool_calls") or []:
                    fn = call.get("function") or {}
                    try:
                        tool_input = json.loads(fn.get("arguments") or "{}")
                    except Exception:
                        tool_input = {}
                    blocks.append({
                        "type": "tool_use",
                        "id": call.get("id", ""),
                        "name": fn.get("name", ""),
                        "input": tool_input,
                    })
                _push("assistant", blocks)
                continue
            _push("user", [{"type": "text", "text": str(content)}])
        return "\n\n".join(system_parts), out

    def _messages_chat(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]],
        tool_choice: Any,
        temperature: float,
        max_tokens: int,
    ):
        payload, headers = self._build_messages_payload(messages, tools, tool_choice, temperature, max_tokens)
        with httpx.Client(timeout=_REQUEST_TIMEOUT, verify=not self._insecure_tls) as client:
            resp = client.post(self._messages_url(), headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
        self._record_messages_usage(data)
        return self._parse_messages_response(data)

    def _build_messages_payload(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]],
        tool_choice: Any,
        temperature: float,
        max_tokens: int,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        system, converted = self._convert_messages(messages)
        payload: dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": max_tokens,
            "messages": converted,
            "temperature": min(temperature, 1.0),  # Anthropic temperature 上限 1.0（OpenAI 是 2.0），>1.0 会 400
        }
        if system:
            payload["system"] = system
        converted_tools = self._to_messages_tools(tools)
        if converted_tools:
            payload["tools"] = converted_tools
            choice = self._to_messages_tool_choice(tool_choice)
            if choice:
                payload["tool_choice"] = choice
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "x-api-key": self.config.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "anthropic-version": "2023-06-01",
            # 换 UA，绕过中转/2api WAF 对 SDK UA 的 403 封禁。
            "User-Agent": _resolve_user_agent(self.config.model, self.config.base_url),
        }
        return payload, headers

    @staticmethod
    def _parse_messages_response(data: dict[str, Any]):
        text_parts: list[str] = []
        calls = []
        for block in data.get("content") or []:
            btype = block.get("type")
            if btype == "text":
                text_parts.append(block.get("text") or "")
            elif btype == "tool_use":
                calls.append(SimpleNamespace(
                    id=block.get("id", ""),
                    function=SimpleNamespace(
                        name=block.get("name", ""),
                        arguments=json.dumps(block.get("input") or {}, ensure_ascii=False),
                    ),
                ))
        return SimpleNamespace(content="".join(text_parts), tool_calls=calls or None)

    def _record_openai_usage(self, resp: Any) -> None:
        usage = getattr(resp, "usage", None)
        if not usage:
            return
        # DeepSeek 在 usage 顶层给 prompt_cache_hit_tokens/prompt_cache_miss_tokens；
        # 部分 OpenAI 兼容网关走 prompt_tokens_details.cached_tokens。两种都抓。
        cache_hit = getattr(usage, "prompt_cache_hit_tokens", 0) or 0
        cache_miss = getattr(usage, "prompt_cache_miss_tokens", 0) or 0
        if not cache_hit:
            details = getattr(usage, "prompt_tokens_details", None)
            if details is not None:
                cache_hit = getattr(details, "cached_tokens", 0) or 0
        record_usage(
            self.usage_key,
            self.config.model,
            prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
            total_tokens=getattr(usage, "total_tokens", 0) or 0,
            cache_hit_tokens=cache_hit,
            cache_miss_tokens=cache_miss,
        )

    def _record_messages_usage(self, data: dict[str, Any]) -> None:
        usage = data.get("usage") or {}
        # anthropic messages 协议：cache_read_input_tokens / cache_creation_input_tokens。
        cache_hit = usage.get("cache_read_input_tokens") or usage.get("prompt_cache_hit_tokens") or 0
        cache_miss = usage.get("cache_creation_input_tokens") or usage.get("prompt_cache_miss_tokens") or 0
        record_usage(
            self.usage_key,
            self.config.model,
            prompt_tokens=usage.get("input_tokens") or usage.get("prompt_tokens") or 0,
            completion_tokens=usage.get("output_tokens") or usage.get("completion_tokens") or 0,
            total_tokens=usage.get("total_tokens") or 0,
            cache_hit_tokens=cache_hit,
            cache_miss_tokens=cache_miss,
        )
