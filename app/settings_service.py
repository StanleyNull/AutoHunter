"""全局系统配置：DB 持久化 + 内存缓存 + 与 env / 任务级合并解析。"""
from __future__ import annotations

import os
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import LLMConfig, ProxyConfig, llm_config
from app.agents.prompts import normalize_worker_prompt_version
from app.db.models import SystemSettings, Task, to_cst_iso
from app.db.session import SessionLocal
from app.engines import get_engine, list_engines, get_default_engine

SETTINGS_ID = "global"

_cache: dict[str, Any] = {"llm": {}, "fofa": {}, "engines": {}, "defaults": {}, "proxy": {}}


# 统一脱敏占位：不再泄露密钥首尾字符，避免降低离线爆破成本。
_MASK_PLACEHOLDER = "••••••••"


def mask_secret(value: str) -> str:
    v = str(value or "").strip()
    if not v:
        return ""
    return _MASK_PLACEHOLDER


def is_masked_secret(value: str) -> bool:
    """判断传入值是否为前端回显的脱敏占位（应视为"未修改"，不可回写覆盖真实密钥）。"""
    v = str(value or "").strip()
    if not v:
        return False
    return set(v) <= {"*", "•", "·", "●", "…", ".", "○", "◦"}


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


def _env_engines() -> dict[str, Any]:
    """从环境变量读取所有已注册引擎的 API Key 和 base_url。
    约定环境变量名为 {ENGINE_ENV_KEY}_KEY 和 {ENGINE_ENV_KEY}_BASE_URL。
    """
    result: dict[str, dict[str, str]] = {}
    for eng in list_engines():
        name = eng["name"]
        env_key = name.upper()
        key = os.environ.get(f"{env_key}_KEY", "")
        base_url = os.environ.get(f"{env_key}_BASE_URL", "")
        if key:
            result.setdefault(name, {})["key"] = key
        if base_url:
            result.setdefault(name, {})["base_url"] = base_url
    # 兼容旧 FOFA_KEY / FOFA_BASE_URL
    if "fofa" not in result:
        fofa_key = os.environ.get("FOFA_KEY", "")
        fofa_base = os.environ.get("FOFA_BASE_URL", "")
        if fofa_key:
            result["fofa"] = {"key": fofa_key}
            if fofa_base:
                result["fofa"]["base_url"] = fofa_base
    return result


def _env_defaults() -> dict[str, Any]:
    return {
        "concurrency": 3,
        "skip_score_threshold": float(os.environ.get("SKIP_SCORE_THRESHOLD", "-10")),
        "worker_prompt_version": normalize_worker_prompt_version(os.environ.get("WORKER_PROMPT_VERSION", "legacy")),
        "engine": os.environ.get("SEARCH_ENGINE", get_default_engine()),
    }


def _env_proxy() -> dict[str, Any]:
    return {
        "ssh_servers": os.environ.get("PROXY_SSH_SERVERS", ""),
        "ssh_key_path": os.environ.get("PROXY_SSH_KEY_PATH", "/root/.ssh/id_ed25519"),
        "probe_servers": os.environ.get("PROXY_PROBE_SERVERS", ""),
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
        "engines": _merge_section(_cache.get("engines"), _env_engines()),
        "defaults": _merge_section(_cache.get("defaults"), _env_defaults()),
        "proxy": _merge_section(_cache.get("proxy"), _env_proxy()),
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


# ── 引擎相关解析函数 ──────────────────────────────────────────

def resolve_engine_name(task: Task | None = None) -> str:
    """获取任务使用的搜索引擎名称。"""
    if task and task.engine:
        return task.engine
    eff = effective_settings()["defaults"]
    return str(eff.get("engine") or get_default_engine())


def resolve_engine_key(engine_name: str, task: Task | None = None) -> str:
    """获取指定引擎的 API Key（任务级 > DB缓存 > 环境变量）。"""
    eff = effective_settings()["engines"]
    # 任务级 fofa_config 兼容旧版
    if engine_name == "fofa" and task:
        cfg = task.fofa_config or {}
        if cfg.get("key"):
            return str(cfg["key"])
    eng_cfg = eff.get(engine_name, {})
    return str(eng_cfg.get("key") or "")


def resolve_engine_base_url(engine_name: str, task: Task | None = None) -> str:
    """获取指定引擎的 base_url。"""
    engine = get_engine(engine_name)
    default = engine.get_default_base_url() if engine else ""
    eff = effective_settings()["engines"]
    # 任务级 fofa_config 兼容旧版
    if engine_name == "fofa" and task:
        cfg = task.fofa_config or {}
        if cfg.get("base_url"):
            return str(cfg["base_url"])
    eng_cfg = eff.get(engine_name, {})
    return str(eng_cfg.get("base_url") or default)


def resolve_engine_config(task: Task | None = None) -> dict[str, Any]:
    """解析任务使用的引擎完整配置。"""
    engine_name = resolve_engine_name(task)
    # 兼容旧版 fofa_config 分页设置
    cfg = (task.fofa_config or {}) if task else {}
    eff = effective_settings()["engines"]
    eng_cfg = eff.get(engine_name, {})
    return {
        "engine": engine_name,
        "key": resolve_engine_key(engine_name, task),
        "base_url": resolve_engine_base_url(engine_name, task),
        "max_pages": int(cfg.get("max_pages") or eng_cfg.get("max_pages") or 20),
        "page_size": int(cfg.get("page_size") or eng_cfg.get("page_size") or 100),
        "intent_mode": str(cfg.get("intent_mode") or ""),
    }


# ── 旧版兼容 ──────────────────────────────────────────────────

def resolve_fofa_key(task: Task | None = None) -> str:
    """兼容旧版：等价于 resolve_engine_key('fofa', task)。"""
    return resolve_engine_key("fofa", task)


def resolve_fofa_base_url(task: Task | None = None) -> str:
    """兼容旧版：等价于 resolve_engine_base_url('fofa', task)。"""
    return resolve_engine_base_url("fofa", task)


def resolve_fofa_defaults(task: Task | None = None) -> dict[str, Any]:
    """兼容旧版。"""
    return resolve_engine_config(task)


# ── 其他 ──────────────────────────────────────────────────────

def resolve_skip_score_threshold() -> float:
    return float(effective_settings()["defaults"].get("skip_score_threshold", -10))


def resolve_worker_prompt_version(task: Task | None = None) -> str:
    mc = (task.model_config_json or {}) if task else {}
    if mc.get("prompt_version"):
        return normalize_worker_prompt_version(mc.get("prompt_version"))
    return normalize_worker_prompt_version(effective_settings()["defaults"].get("worker_prompt_version"))


def resolve_proxy_config() -> ProxyConfig:
    """返回合并 env + DB 缓存后的 SSH 代理配置（供 worker/orchestrator 读取）。

    接口与 config.ProxyConfig 一致（.available / .server_list / .ssh_key_path），
    调用方无需改动读取方式；数据源从纯 env 升级为「DB 热配置优先，env 兜底」。
    """
    eff = effective_settings()["proxy"]
    return ProxyConfig(
        ssh_servers=str(eff.get("ssh_servers") or ""),
        ssh_key_path=str(eff.get("ssh_key_path") or "/root/.ssh/id_ed25519"),
        probe_servers=str(eff.get("probe_servers") or ""),
    )


def public_settings_view() -> dict[str, Any]:
    """API 返回：密钥脱敏。"""
    eff = effective_settings()
    llm = eff["llm"]
    fofa = eff["fofa"]
    engines = eff.get("engines", {})
    defaults = eff["defaults"]

    # 构建引擎列表视图
    engines_view = {}
    for eng in list_engines():
        name = eng["name"]
        ecfg = engines.get(name, {})
        engines_view[name] = {
            "display_name": eng["display_name"],
            "key": mask_secret(ecfg.get("key", "")),
            "key_set": bool(ecfg.get("key")),
            "base_url": ecfg.get("base_url", ""),
        }

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
        "engines": engines_view,
        "defaults": {
            "concurrency": int(defaults.get("concurrency") or 3),
            "skip_score_threshold": float(defaults.get("skip_score_threshold", -10)),
            "worker_prompt_version": normalize_worker_prompt_version(defaults.get("worker_prompt_version")),
            "engine": defaults.get("engine", get_default_engine()),
        },
        "proxy": {
            "ssh_servers": eff.get("proxy", {}).get("ssh_servers") or "",
            "ssh_key_path": eff.get("proxy", {}).get("ssh_key_path") or "/root/.ssh/id_ed25519",
            "probe_servers": eff.get("proxy", {}).get("probe_servers") or "",
        },
        "available_engines": list_engines(),
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
        "engines": dict(row.engines or {}),
        "defaults": dict(row.defaults or {}),
        "proxy": dict(row.proxy or {}),
        "updated_at": to_cst_iso(row.updated_at),
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
            if k == "api_key":
                if not str(v or "").strip() or is_masked_secret(v):
                    continue
            if v is not None:
                llm[k] = v
        row.llm = llm

    if "fofa" in payload and payload["fofa"]:
        fofa = dict(row.fofa or {})
        for k, v in payload["fofa"].items():
            if k == "key":
                if not str(v or "").strip() or is_masked_secret(v):
                    continue
            if v is not None:
                fofa[k] = v
        row.fofa = fofa

    # 多引擎配置
    if "engines" in payload and payload["engines"]:
        engines = dict(row.engines or {})
        for eng_name, eng_cfg in payload["engines"].items():
            if not isinstance(eng_cfg, dict):
                continue
            current = dict(engines.get(eng_name, {}))
            for k, v in eng_cfg.items():
                if k == "key":
                    if not str(v or "").strip() or is_masked_secret(v):
                        continue
                if v is not None:
                    current[k] = v
            if current:
                engines[eng_name] = current
        row.engines = engines

    if "defaults" in payload and payload["defaults"]:
        defaults = dict(row.defaults or {})
        for k, v in payload["defaults"].items():
            if v is not None:
                defaults[k] = v
        row.defaults = defaults

    if "proxy" in payload and payload["proxy"]:
        proxy = dict(row.proxy or {})
        for k, v in payload["proxy"].items():
            if v is not None:
                proxy[k] = v
        row.proxy = proxy

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
    """拉取模型商可用模型列表（OpenAI 兼容 GET /models）。"""
    import httpx

    eff = effective_settings()["llm"]
    base = (base_url or eff["base_url"] or "").strip().rstrip("/")
    key = (api_key or eff["api_key"] or "").strip()
    if not base:
        return {"ok": False, "error": "未配置模型 base_url", "models": []}
    if not key:
        return {"ok": False, "error": "未配置 API Key，无法拉取模型列表", "models": []}
    url = base if base.endswith("/models") else f"{base}/models"
    from app.tools.netguard import SsrfBlocked, assert_safe_outbound_url

    try:
        assert_safe_outbound_url(url)
    except SsrfBlocked as e:
        return {"ok": False, "error": f"base_url 不被允许：{e}", "models": []}
    headers = {"Authorization": f"Bearer {key}"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            return {"ok": False, "error": f"模型商返回 {resp.status_code}", "models": []}
        data = resp.json()
    except Exception as e:
        return {"ok": False, "error": f"拉取模型列表失败：{type(e).__name__}", "models": []}
    items = data.get("data") or data.get("models") or []
    models: list[str] = []
    for it in items:
        mid = it.get("id") if isinstance(it, dict) else str(it)
        if mid and mid not in models:
            models.append(mid)
    models.sort()
    return {"ok": True, "error": "", "models": models}
