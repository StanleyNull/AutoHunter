"""全局系统配置：DB 持久化 + 内存缓存 + 与 env / 任务级合并解析。"""
from __future__ import annotations

import os
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import LLMConfig, llm_config
from app.agents.prompts import normalize_worker_prompt_version
from app.db.models import SystemSettings, Task
from app.db.session import SessionLocal

SETTINGS_ID = "global"

_cache: dict[str, Any] = {"llm": {}, "fofa": {}, "defaults": {}}


def mask_secret(value: str) -> str:
    v = str(value or "").strip()
    if not v:
        return ""
    if len(v) <= 8:
        return "••••••••"
    return f"{v[:4]}…{v[-4:]}"


def _env_llm() -> dict[str, Any]:
    return {
        "base_url": os.environ.get("LLM_BASE_URL", "https://api.deepseek.com/v1"),
        "api_key": os.environ.get("LLM_API_KEY", ""),
        "model": os.environ.get("LLM_MODEL", "deepseek-chat"),
        "temperature": float(os.environ.get("LLM_TEMPERATURE", "0.3")),
    }


def _env_fofa() -> dict[str, Any]:
    return {
        "key": os.environ.get("FOFA_KEY", ""),
        "base_url": os.environ.get("FOFA_BASE_URL") or "https://fofa.info",
        "max_pages": 20,
        "page_size": 100,
        "default_intent_mode": "",
    }


def _env_defaults() -> dict[str, Any]:
    return {
        "concurrency": 3,
        "skip_score_threshold": float(os.environ.get("SKIP_SCORE_THRESHOLD", "-10")),
        "worker_prompt_version": normalize_worker_prompt_version(os.environ.get("WORKER_PROMPT_VERSION", "legacy")),
    }


def _merge_section(stored: dict, env: dict) -> dict[str, Any]:
    out = dict(env)
    for k, v in (stored or {}).items():
        if v is not None and v != "":
            out[k] = v
    return out


def effective_settings() -> dict[str, Any]:
    """合并 env + DB 缓存的有效配置（含明文密钥，仅服务端内部使用）。"""
    return {
        "llm": _merge_section(_cache.get("llm"), _env_llm()),
        "fofa": _merge_section(_cache.get("fofa"), _env_fofa()),
        "defaults": _merge_section(_cache.get("defaults"), _env_defaults()),
    }


def resolve_llm_config(task: Task | None = None) -> LLMConfig:
    eff = effective_settings()["llm"]
    mc = (task.model_config_json or {}) if task else {}
    return LLMConfig(
        base_url=mc.get("base_url") or eff["base_url"],
        api_key=mc.get("api_key") or eff["api_key"],
        model=mc.get("model") or eff["model"],
        temperature=float(mc.get("temperature") or eff["temperature"]),
    )


def resolve_fofa_key(task: Task | None = None) -> str:
    eff = effective_settings()["fofa"]
    cfg = (task.fofa_config or {}) if task else {}
    return str(cfg.get("key") or eff.get("key") or "")


def resolve_fofa_base_url(task: Task | None = None) -> str:
    eff = effective_settings()["fofa"]
    cfg = (task.fofa_config or {}) if task else {}
    return str(cfg.get("base_url") or eff.get("base_url") or "https://fofa.info").rstrip("/")


def resolve_fofa_defaults(task: Task | None = None) -> dict[str, Any]:
    eff = effective_settings()["fofa"]
    cfg = (task.fofa_config or {}) if task else {}
    return {
        "key": resolve_fofa_key(task),
        "base_url": resolve_fofa_base_url(task),
        "max_pages": int(cfg.get("max_pages") or eff.get("max_pages") or 20),
        "page_size": int(cfg.get("page_size") or eff.get("page_size") or 100),
        "intent_mode": str(cfg.get("intent_mode") or eff.get("default_intent_mode") or ""),
    }


def resolve_skip_score_threshold() -> float:
    return float(effective_settings()["defaults"].get("skip_score_threshold", -10))


def resolve_worker_prompt_version(task: Task | None = None) -> str:
    mc = (task.model_config_json or {}) if task else {}
    if mc.get("prompt_version"):
        return normalize_worker_prompt_version(mc.get("prompt_version"))
    return normalize_worker_prompt_version(effective_settings()["defaults"].get("worker_prompt_version"))


def public_settings_view() -> dict[str, Any]:
    """API 返回：密钥脱敏。"""
    eff = effective_settings()
    llm = eff["llm"]
    fofa = eff["fofa"]
    return {
        "llm": {
            "base_url": llm["base_url"],
            "model": llm["model"],
            "temperature": llm["temperature"],
            "api_key": mask_secret(llm["api_key"]),
            "api_key_set": bool(llm["api_key"]),
        },
        "fofa": {
            "base_url": fofa.get("base_url") or "https://fofa.info",
            "max_pages": int(fofa.get("max_pages") or 20),
            "page_size": int(fofa.get("page_size") or 100),
            "default_intent_mode": fofa.get("default_intent_mode") or "",
            "key": mask_secret(fofa.get("key") or ""),
            "key_set": bool(fofa.get("key")),
        },
        "defaults": {
            "concurrency": int(eff["defaults"].get("concurrency") or 3),
            "skip_score_threshold": float(eff["defaults"].get("skip_score_threshold", -10)),
            "worker_prompt_version": normalize_worker_prompt_version(eff["defaults"].get("worker_prompt_version")),
        },
        "updated_at": _cache.get("updated_at"),
    }


async def refresh_cache(session: AsyncSession) -> SystemSettings:
    global _cache
    row = await session.get(SystemSettings, SETTINGS_ID)
    if row is None:
        row = SystemSettings(id=SETTINGS_ID)
        session.add(row)
        await session.commit()
        await session.refresh(row)
    _cache = {
        "llm": dict(row.llm or {}),
        "fofa": dict(row.fofa or {}),
        "defaults": dict(row.defaults or {}),
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }
    return row


async def init_settings_cache() -> None:
    async with SessionLocal() as session:
        await refresh_cache(session)


async def update_settings(session: AsyncSession, payload: dict[str, Any]) -> dict[str, Any]:
    row = await session.get(SystemSettings, SETTINGS_ID)
    if row is None:
        row = SystemSettings(id=SETTINGS_ID)
        session.add(row)

    if "llm" in payload and payload["llm"]:
        llm = dict(row.llm or {})
        for k, v in payload["llm"].items():
            if k == "api_key" and not str(v or "").strip():
                continue
            if v is not None:
                llm[k] = v
        row.llm = llm

    if "fofa" in payload and payload["fofa"]:
        fofa = dict(row.fofa or {})
        for k, v in payload["fofa"].items():
            if k == "key" and not str(v or "").strip():
                continue
            if v is not None:
                fofa[k] = v
        row.fofa = fofa

    if "defaults" in payload and payload["defaults"]:
        defaults = dict(row.defaults or {})
        for k, v in payload["defaults"].items():
            if v is not None:
                defaults[k] = v
        row.defaults = defaults

    await session.commit()
    await session.refresh(row)
    await refresh_cache(session)
    return public_settings_view()


def llm_client_for_task(task: Task | None = None):
    """返回 LLMClient；无 key 时抛 RuntimeError（与旧行为一致）。"""
    from app.llm.client import LLMClient

    return LLMClient(resolve_llm_config(task), usage_key=task.id if task else None)


def llm_client_for_task_optional(task: Task | None = None):
    """有 key 则返回 LLMClient，否则 None（collector 降级）。"""
    from app.llm.client import LLMClient

    cfg = resolve_llm_config(task)
    if not cfg.api_key:
        return None
    try:
        return LLMClient(cfg, usage_key=task.id if task else None)
    except Exception:
        return None


async def list_available_models(base_url: str | None = None, api_key: str | None = None) -> dict[str, Any]:
    """拉取模型商可用模型列表（OpenAI 兼容 GET /models）。

    base_url/api_key 留空时用有效配置（DB+env）。失败时返回 {ok:False, error, models:[]}，
    前端可据此降级为手动输入。"""
    import httpx

    eff = effective_settings()["llm"]
    base = (base_url or eff["base_url"] or "").strip().rstrip("/")
    key = (api_key or eff["api_key"] or "").strip()
    if not base:
        return {"ok": False, "error": "未配置模型 base_url", "models": []}
    if not key:
        return {"ok": False, "error": "未配置 API Key，无法拉取模型列表", "models": []}
    url = base if base.endswith("/models") else f"{base}/models"
    headers = {"Authorization": f"Bearer {key}"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            return {"ok": False, "error": f"模型商返回 {resp.status_code}", "models": []}
        data = resp.json()
    except Exception as e:
        return {"ok": False, "error": f"拉取模型列表失败：{type(e).__name__}", "models": []}
    # OpenAI 兼容：{"data":[{"id":"..."},...]}；也兜底 {"models":[...]} 等格式
    items = data.get("data") or data.get("models") or []
    models: list[str] = []
    for it in items:
        mid = it.get("id") if isinstance(it, dict) else str(it)
        if mid and mid not in models:
            models.append(mid)
    models.sort()
    return {"ok": True, "error": "", "models": models}
