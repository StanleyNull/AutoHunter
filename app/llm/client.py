"""OpenAI 兼容 LLM 客户端，封装 function calling 调用。

支持 DeepSeek / Qwen / Kimi / GPT 等所有 OpenAI 兼容接口。

24x7 健壮性：请求级超时 + 轻量重试。LLM 挂起会几分钟内失败重试或放弃，
而不是把 worker 线程拖到 30min 墙钟超时才回收（白占一个并发位）。
"""
from __future__ import annotations

import os
import json
import logging
import re
import time
from typing import Any, Optional
from types import SimpleNamespace

import httpx
from openai import OpenAI

from app.config import LLMConfig, llm_config
from app.llm.usage import record_usage

logger = logging.getLogger("autohunter.llm")

_SECRET_RE = re.compile(r"\b(sk-[A-Za-z0-9_-]{8,})\b")

# 单次 LLM 请求超时（秒）；DeepSeek 带工具调用通常 10-60s，120s 足够且能兜住挂起。
_REQUEST_TIMEOUT = float(os.environ.get("LLM_REQUEST_TIMEOUT", "120"))
# 失败重试次数（网络抖动/限流/5xx）；默认 4 次（含网络抖动场景多给几次机会）。
_MAX_RETRIES = int(os.environ.get("LLM_MAX_RETRIES", "4"))


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
    ):
        super().__init__(message)
        self.kind = kind
        self.original = original
        self.status = status
        self.code = code
        self.detail = detail

    def diagnostic(self) -> str:
        parts = [f"kind={self.kind}"]
        if self.status:
            parts.append(f"status={self.status}")
        if self.code:
            parts.append(f"code={self.code}")
        parts.append(f"message={super().__str__()}")
        if self.detail:
            parts.append(f"detail={self.detail}")
        return "；".join(parts)

    def __str__(self) -> str:
        return self.diagnostic()


def _sanitize_error_detail(text: str, limit: int = 1200) -> str:
    text = _SECRET_RE.sub("sk-<masked>", text or "")
    text = " ".join(text.split())
    return text[:limit]


def _is_forced_tool_choice(tool_choice: Any) -> bool:
    if tool_choice in (None, "auto", "none"):
        return False
    if isinstance(tool_choice, dict):
        fn = (tool_choice.get("function") or {}).get("name")
        return bool(fn)
    return True


def _is_thinking_tool_choice_error(err: LLMError) -> bool:
    return "thinking mode does not support this tool_choice" in (err.detail or str(err)).lower()


def _is_max_tokens_unsupported(err: LLMError) -> bool:
    text = (err.detail or str(err)).lower()
    return (
        "max_tokens" in text
        and any(marker in text for marker in (
            "unsupported", "unrecognized", "unknown", "unexpected", "extra",
            "not support", "invalid parameter", "invalid_request_error",
        ))
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

    if any(k in text for k in ("insufficient_quota", "quota", "billing", "余额", "额度", "balance")):
        return LLMError(
            "quota", "LLM 额度不足或账户余额不足，请更换/充值模型 API Key 后重试。",
            e, status=status, code=str(code), detail=detail,
        )
    if status == 401 or any(k in text for k in ("unauthorized", "invalid api key", "incorrect api key", "无效")):
        return LLMError(
            "auth", "LLM API Key 无效或无权限，请检查任务配置或服务端 .env。",
            e, status=status, code=str(code), detail=detail,
        )
    if status == 429 or any(k in text for k in ("rate limit", "too many requests", "限流")):
        return LLMError(
            "rate_limit", "LLM 请求被限流，请稍后重试或降低并发。",
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


class LLMClient:
    def __init__(self, config: Optional[LLMConfig] = None, usage_key: str | None = None):
        self.config = config or llm_config
        self.usage_key = usage_key
        if not self.config.api_key:
            raise RuntimeError("缺少 LLM_API_KEY，请在 .env 中配置")
        self._messages_protocol = "openmodel.ai" in self.config.base_url.lower()
        # 关闭 SDK 内置重试，自己控制重试节奏与日志；设请求超时兜住挂起。
        self.client = OpenAI(
            base_url=self.config.base_url, api_key=self.config.api_key,
            timeout=_REQUEST_TIMEOUT, max_retries=0,
        )

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        tool_choice: str = "auto",
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ):
        """单次对话调用，返回完整 message 对象（可能含 tool_calls）。

        带超时 + 指数退避重试；耗尽重试后抛出最后一次异常（调用方已有兜底）。
        """
        kwargs: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature if temperature is None else temperature,
            "max_tokens": int(max_tokens or os.environ.get("LLM_MAX_TOKENS", "4096")),
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = tool_choice

        last_exc: Optional[Exception] = None
        active_tool_choice: Any = tool_choice
        tool_choice_fallback_used = False
        max_tokens_fallback_used = False
        for attempt in range(_MAX_RETRIES + 1):
            try:
                if self._messages_protocol:
                    return self._messages_chat(
                        messages, tools, active_tool_choice, kwargs["temperature"], kwargs["max_tokens"]
                    )
                resp = self.client.chat.completions.create(**kwargs)
                self._record_openai_usage(resp)
                return resp.choices[0].message
            except Exception as e:  # 网络/超时/限流/5xx 统一重试
                last_exc = _classify_error(e)
                kind = getattr(last_exc, "kind", "?")
                if (
                    tools
                    and not tool_choice_fallback_used
                    and _is_forced_tool_choice(active_tool_choice)
                    and isinstance(last_exc, LLMError)
                    and _is_thinking_tool_choice_error(last_exc)
                ):
                    # DeepSeek v4 thinking mode rejects forced function tool_choice, but
                    # still supports tools with auto tool choice. Fall back centrally so
                    # reviewer/collector/other forced-tool callers do not get stuck.
                    logger.warning(
                        "LLM forced tool_choice rejected by thinking mode; falling back to auto "
                        "(model=%s, detail=%s)",
                        self.config.model, last_exc.detail[:300],
                    )
                    active_tool_choice = "auto"
                    kwargs["tool_choice"] = "auto"
                    tool_choice_fallback_used = True
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
                if attempt < _MAX_RETRIES:
                    logger.info("LLM chat retry %d/%d (kind=%s, model=%s)",
                                attempt + 1, _MAX_RETRIES, kind, self.config.model)
                    time.sleep(min(2 ** attempt, 8))  # 1s, 2s, 4s... 封顶 8s
                else:
                    logger.warning("LLM chat giving up after %d retries (kind=%s, model=%s)",
                                   _MAX_RETRIES, kind, self.config.model)
        raise last_exc  # type: ignore[misc]

    def _messages_url(self) -> str:
        base = self.config.base_url.rstrip("/")
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
        if isinstance(tool_choice, dict):
            fn = (tool_choice.get("function") or {}).get("name")
            if fn:
                return {"type": "tool", "name": fn}
        return {"type": "auto"}

    @staticmethod
    def _convert_messages(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
        system_parts: list[str] = []
        out: list[dict[str, Any]] = []
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content") or ""
            if role == "system":
                if content:
                    system_parts.append(str(content))
                continue
            if role == "tool":
                out.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": msg.get("tool_call_id", ""),
                        "content": str(content),
                    }],
                })
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
                out.append({"role": "assistant", "content": blocks or str(content)})
                continue
            out.append({"role": "user", "content": str(content)})
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
        with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
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
            "temperature": temperature,
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
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
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
