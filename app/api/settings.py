"""全局系统配置 API。"""
from __future__ import annotations

import re
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dto import SettingsUpdateRequest
from app.config import LLMConfig
from app.db.session import get_session
from app.llm.client import _resolve_user_agent
from app.llm.health import mark_provider_failed, mark_provider_ok
from app.tools.netguard import SsrfBlocked, assert_safe_outbound_url
from app.settings_service import (
    _clean_llm_providers,
    _preserve_provider_keys,
    effective_settings,
    is_masked_secret,
    list_available_models,
    normalize_llm_mode,
    normalize_llm_protocol,
    public_settings_view,
    refresh_cache,
    resolve_llm_key_for_identity,
    resolve_llm_key_ref,
    resolve_llm_providers,
    update_settings,
)

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
async def get_settings(session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    return public_settings_view()


class ModelsProbeRequest(BaseModel):
    base_url: str | None = None
    api_key: str | None = None
    protocol: str | None = None
    key_ref: str | None = None
    model: str | None = None


@router.post("/models")
async def probe_models(
    body: ModelsProbeRequest,
    session: AsyncSession = Depends(get_session),
):
    """拉取模型商可用模型列表，供前端下拉选择。base_url/api_key 留空用有效配置。
    注意：api_key 为脱敏占位（如 ****）时视为未传，回退到服务端已存的真实 key。"""
    await refresh_cache(session)
    key = (body.api_key or "").strip()
    if key and is_masked_secret(key):
        key = ""  # 前端回显的脱敏占位，丢弃
    return await list_available_models(
        base_url=body.base_url,
        api_key=key or None,
        protocol=body.protocol,
        key_ref=body.key_ref,
        model=body.model,
    )


@router.get("/provider-health")
async def get_provider_health(session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    llm = public_settings_view()["llm"]
    return {
        "mode": llm.get("mode", "single"),
        "single": {
            "health_ref": llm.get("health_ref", ""),
            "health": llm.get("health", {}),
        },
        "providers": [
            {
                "name": item.get("name", ""),
                "base_url": item.get("base_url", ""),
                "model": item.get("model", ""),
                "protocol": item.get("protocol", "auto"),
                "health_ref": item.get("health_ref", ""),
                "health": item.get("health", {}),
            }
            for item in llm.get("providers", [])
        ],
    }


class LLMTestRequest(BaseModel):
    base_url: str | None = None
    api_key: str | None = None
    key_ref: str | None = None
    model: str | None = None
    protocol: str | None = None
    temperature: float | None = None
    providers: list[dict] | None = None


_TEST_SECRET_RE = re.compile(
    r"(?:\bsk-[A-Za-z0-9_-]{8,}\b|\bBearer\s+[A-Za-z0-9._~+/=-]{8,})",
    re.IGNORECASE,
)


_NAMED_SECRET_RE = re.compile(
    r"((?:api[_-]?key|x-api-key|token|secret|password|passwd|pwd)"
    r"\s*[\"']?\s*[:=]\s*[\"']?)[^\s,;\"']+",
    re.IGNORECASE,
)


def _safe_error(value: object, *secrets: str) -> str:
    text = " ".join(str(value or "").split())
    for secret in secrets:
        if secret:
            text = text.replace(str(secret), "<masked>")
    text = _NAMED_SECRET_RE.sub(r"\1<masked>", text)
    return _TEST_SECRET_RE.sub("<masked>", text)[:500]


def _api_root(base_url: str) -> str:
    base = str(base_url or "").strip().rstrip("/")
    lowered = base.lower()
    for suffix in ("/chat/completions", "/messages"):
        if lowered.endswith(suffix):
            return base[: -len(suffix)].rstrip("/")
    return base


def _chat_url(base_url: str, protocol: str) -> str:
    base = _api_root(base_url)
    path = "messages" if protocol == "anthropic_messages" else "chat/completions"
    return f"{base}/{path}" if base.lower().endswith("/v1") else f"{base}/v1/{path}"


def _test_configs(body: LLMTestRequest) -> list[tuple[str, LLMConfig]]:
    eff = effective_settings()["llm"]
    old_providers = _clean_llm_providers(eff.get("providers") or [])
    if body.providers is not None:
        items = _clean_llm_providers(_preserve_provider_keys(body.providers, old_providers))
        return [
            (
                str(item.get("name") or f"llm-{index + 1}"),
                LLMConfig(
                    base_url=item["base_url"],
                    api_key=item["api_key"],
                    model=item["model"],
                    protocol=item["protocol"],
                    temperature=float(item["temperature"]),
                    weight=int(item["weight"]),
                    enabled=bool(item["enabled"]),
                ),
            )
            for index, item in enumerate(items)
            if item.get("enabled", True)
        ]

    explicit_single = any((body.base_url, body.api_key, body.key_ref, body.model, body.protocol))
    if explicit_single:
        base_url = body.base_url or eff.get("base_url") or ""
        model = body.model or eff.get("model") or ""
        protocol = normalize_llm_protocol(body.protocol or eff.get("protocol"))
        api_key = str(body.api_key or "").strip()
        if not api_key or is_masked_secret(api_key):
            api_key = resolve_llm_key_ref(
                body.key_ref, base_url, model, protocol
            ) or resolve_llm_key_for_identity(base_url, model, protocol)
        return [("single", LLMConfig(
            base_url=base_url,
            api_key=api_key,
            model=model,
            protocol=protocol,
            temperature=float(body.temperature if body.temperature is not None else eff.get("temperature") or 0.3),
        ))]

    return [
        (f"llm-{index + 1}", config)
        for index, config in enumerate(resolve_llm_providers())
    ]


async def _test_llm_one(name: str, provider: LLMConfig) -> dict:
    import httpx

    protocol = normalize_llm_protocol(provider.protocol)
    if protocol == "auto":
        lowered = provider.base_url.lower()
        protocol = "anthropic_messages" if "anthropic" in lowered or "/messages" in lowered else "openai_chat"
    url = _chat_url(provider.base_url, protocol)
    result = {
        "name": name,
        "ok": False,
        "base_url": provider.base_url,
        "model": provider.model,
        "protocol": protocol,
        "status_code": 0,
        "latency_ms": 0,
        "error": "",
    }
    if not provider.api_key:
        result["error"] = "未配置 API Key"
        return result
    try:
        assert_safe_outbound_url(url)
    except SsrfBlocked as exc:
        result["error"] = f"base_url 不被允许：{exc}"
        return result

    headers = {
        "Authorization": f"Bearer {provider.api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": _resolve_user_agent(provider.model, provider.base_url),
    }
    payload = {
        "model": provider.model,
        "messages": [{"role": "user", "content": "Reply with exactly: ok"}],
        "temperature": 0,
        "max_tokens": 8,
    }
    if protocol == "anthropic_messages":
        headers.update({
            "x-api-key": provider.api_key,
            "anthropic-version": "2023-06-01",
        })

    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(url, headers=headers, json=payload)
            if response.status_code == 400 and "max_tokens" in response.text.lower():
                payload.pop("max_tokens", None)
                response = await client.post(url, headers=headers, json=payload)
        result["latency_ms"] = int((time.perf_counter() - started) * 1000)
        result["status_code"] = response.status_code
        if response.status_code >= 400:
            result["error"] = _safe_error(
                f"HTTP {response.status_code}: {response.text[:300]}", provider.api_key
            )
            mark_provider_failed(
                provider.base_url, provider.model, result["error"], provider.api_key,
                provider.protocol, kind="probe"
            )
            return result
        data = response.json()
        if protocol == "anthropic_messages":
            reply = "".join(
                str(block.get("text") or "")
                for block in data.get("content") or []
                if isinstance(block, dict) and block.get("type") == "text"
            )
        else:
            choice = (data.get("choices") or [{}])[0]
            reply = str((choice.get("message") or {}).get("content") or choice.get("text") or "")
        result.update(ok=True, reply=reply[:80])
        mark_provider_ok(
            provider.base_url, provider.model, provider.api_key, provider.protocol
        )
        return result
    except Exception as exc:
        result["latency_ms"] = int((time.perf_counter() - started) * 1000)
        result["error"] = _safe_error(exc, provider.api_key)
        mark_provider_failed(
            provider.base_url, provider.model, result["error"], provider.api_key,
            provider.protocol, kind="probe"
        )
        return result


@router.post("/test-llm")
async def test_llm(body: LLMTestRequest, session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    providers = _test_configs(body)
    if not providers:
        return {"ok": False, "results": [], "error": "未配置可用 LLM 端点"}
    results = [await _test_llm_one(name, provider) for name, provider in providers]
    return {"ok": all(item["ok"] for item in results), "results": results}


@router.put("")
async def put_settings(
    body: SettingsUpdateRequest,
    session: AsyncSession = Depends(get_session),
):
    payload = body.model_dump(exclude_unset=True)
    llm_update = payload.get("llm") or {}
    if llm_update:
        current_llm = effective_settings()["llm"]
        mode = normalize_llm_mode(llm_update.get("mode", current_llm.get("mode")))
        if mode == "pool":
            old_providers = _clean_llm_providers(current_llm.get("providers") or [])
            incoming = llm_update.get("providers", current_llm.get("providers") or [])
            providers = _clean_llm_providers(
                _preserve_provider_keys(incoming, old_providers)
            )
            if not any(item.get("enabled", True) for item in providers):
                raise HTTPException(
                    status_code=400,
                    detail="端点池模式至少需要一个配置完整且已启用的 LLM 端点",
                )
    return await update_settings(session, payload)
