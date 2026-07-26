"""全局系统配置：DB 持久化 + 内存缓存 + 与 env / 任务级合并解析。"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import LLMConfig, llm_config
from app.agents.prompts import normalize_worker_prompt_version
from app.db.models import SystemSettings, Task, to_cst_iso
from app.db.session import SessionLocal
from app.engines import get_engine, list_engines, get_default_engine
from app.llm.health import provider_ref, snapshot as llm_health_snapshot

SETTINGS_ID = "global"
LLM_MODES = {"single", "pool"}
LLM_PROTOCOLS = {"auto", "openai_chat", "anthropic_messages"}

_cache: dict[str, Any] = {"llm": {}, "fofa": {}, "engines": {}, "defaults": {}}


# 统一脱敏占位：不再泄露密钥首尾字符，避免降低离线爆破成本。
_MASK_PLACEHOLDER = "••••••••"


def normalize_llm_mode(value: Any) -> str:
    mode = str(value or "single").strip().lower()
    return mode if mode in LLM_MODES else "single"


def normalize_llm_protocol(value: Any) -> str:
    protocol = str(value or "auto").strip().lower()
    aliases = {
        "detect": "auto",
        "openai": "openai_chat",
        "chat": "openai_chat",
        "completions": "openai_chat",
        "messages": "anthropic_messages",
        "anthropic": "anthropic_messages",
    }
    protocol = aliases.get(protocol, protocol)
    return protocol if protocol in LLM_PROTOCOLS else "auto"


def _normalize_llm_base_url(value: Any) -> str:
    raw = str(value or "").strip().rstrip("/")
    if not raw:
        return ""
    parts = urlsplit(raw)
    if not parts.scheme or not parts.netloc:
        return raw
    return urlunsplit((
        parts.scheme.lower(),
        parts.netloc.lower(),
        parts.path.rstrip("/"),
        parts.query,
        parts.fragment,
    ))


def _llm_identity(base_url: Any, protocol: Any) -> tuple[str, str]:
    return _normalize_llm_base_url(base_url), normalize_llm_protocol(protocol)


def _json_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, dict)]
    raw = str(value or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return [dict(item) for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def secret_ref(value: str) -> str:
    secret = str(value or "").strip()
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16] if secret else ""


def _provider_enabled(value: Any) -> bool:
    return not (
        value is False
        or str(value).strip().lower() in {"0", "false", "no", "off", "disabled"}
    )


def _clean_llm_providers(items: Any) -> list[dict[str, Any]]:
    providers: list[dict[str, Any]] = []
    for index, item in enumerate(_json_list(items)):
        base_url = str(item.get("base_url") or item.get("base") or "").strip()
        api_key = str(item.get("api_key") or item.get("key") or "").strip()
        model = str(item.get("model") or "").strip()
        if not (base_url and api_key and model):
            continue
        try:
            temperature = float(item.get("temperature", 0.3))
        except (TypeError, ValueError):
            temperature = 0.3
        try:
            weight = int(item.get("weight", 1))
        except (TypeError, ValueError):
            weight = 1
        providers.append({
            "name": str(item.get("name") or f"llm-{index + 1}").strip(),
            "base_url": base_url,
            "api_key": api_key,
            "model": model,
            "protocol": normalize_llm_protocol(item.get("protocol")),
            "temperature": max(0.0, min(temperature, 2.0)),
            "weight": max(1, min(weight, 100)),
            "enabled": _provider_enabled(item.get("enabled", True)),
        })
    return providers


def _preserve_provider_keys(
    items: Any,
    old_providers: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in _json_list(items):
        row = dict(item)
        supplied = str(row.get("api_key") or row.get("key") or "").strip()
        if not supplied or is_masked_secret(supplied):
            ref = str(row.get("key_ref") or row.get("api_key_ref") or "").strip()
            identity = _llm_identity(row.get("base_url"), row.get("protocol"))
            name = str(row.get("name") or "").strip()
            old_key = ""
            for old in old_providers:
                candidate = str(old.get("api_key") or "").strip()
                if not candidate or _llm_identity(old.get("base_url"), old.get("protocol")) != identity:
                    continue
                if ref and secret_ref(candidate) != ref:
                    continue
                if not ref and str(old.get("name") or "").strip() != name:
                    continue
                old_key = candidate
                break
            if old_key:
                row["api_key"] = old_key
        out.append(row)
    return out


def _public_llm_provider(item: dict[str, Any]) -> dict[str, Any]:
    api_key = str(item.get("api_key") or "").strip()
    health_ref = provider_ref(
        item.get("base_url", ""), item.get("model", ""), api_key, item.get("protocol", "auto")
    )
    return {
        **{key: value for key, value in item.items() if key != "api_key"},
        "api_key": "",
        "api_key_set": bool(api_key),
        "api_key_masked": mask_secret(api_key),
        "key_ref": secret_ref(api_key),
        "health_ref": health_ref,
        "health": llm_health_snapshot().get(health_ref, {}),
    }


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
    providers = _clean_llm_providers(os.environ.get("LLM_PROVIDERS_JSON", ""))
    configured_mode = os.environ.get("LLM_PROVIDER_MODE", "").strip()
    return {
        "mode": normalize_llm_mode(configured_mode or ("pool" if providers else "single")),
        "base_url": os.environ.get("LLM_BASE_URL", "https://api.deepseek.com/v1"),
        "api_key": os.environ.get("LLM_API_KEY", ""),
        "model": os.environ.get("LLM_MODEL", "deepseek-chat"),
        "temperature": float(os.environ.get("LLM_TEMPERATURE", "0.3")),
        "protocol": normalize_llm_protocol(os.environ.get("LLM_PROTOCOL", "auto")),
        "providers": providers,
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


def _merge_section(stored: dict, env: dict) -> dict[str, Any]:
    out = dict(env)
    for k, v in (stored or {}).items():
        if v is not None and v != "":
            out[k] = v
    return out


def effective_settings() -> dict[str, Any]:
    """合并 env + DB 缓存的有效配置（含明文密钥，仅服务端内部使用）。"""
    stored_llm = _cache.get("llm") or {}
    env_llm = _env_llm()
    llm = _merge_section(stored_llm, env_llm)
    if (
        not str(stored_llm.get("api_key") or "").strip()
        and any(str(stored_llm.get(key) or "").strip() for key in ("base_url", "protocol"))
        and _llm_identity(llm.get("base_url"), llm.get("protocol"))
        != _llm_identity(env_llm.get("base_url"), env_llm.get("protocol"))
    ):
        llm["api_key"] = ""
    if not str(stored_llm.get("mode") or os.environ.get("LLM_PROVIDER_MODE") or "").strip():
        llm["mode"] = "pool" if _clean_llm_providers(llm.get("providers")) else "single"
    else:
        llm["mode"] = normalize_llm_mode(llm.get("mode"))
    llm["protocol"] = normalize_llm_protocol(llm.get("protocol"))
    return {
        "llm": llm,
        "fofa": _merge_section(_cache.get("fofa"), _env_fofa()),
        "engines": _merge_section(_cache.get("engines"), _env_engines()),
        "defaults": _merge_section(_cache.get("defaults"), _env_defaults()),
    }


def _llm_config_from_provider(item: dict[str, Any], default_temperature: float) -> LLMConfig:
    return LLMConfig(
        base_url=str(item.get("base_url") or "").strip(),
        api_key=str(item.get("api_key") or "").strip(),
        model=str(item.get("model") or "").strip(),
        temperature=float(item.get("temperature", default_temperature)),
        protocol=normalize_llm_protocol(item.get("protocol")),
        weight=max(1, min(int(item.get("weight") or 1), 100)),
        enabled=_provider_enabled(item.get("enabled", True)),
    )


def resolve_llm_providers(task: Task | None = None) -> list[LLMConfig]:
    eff = effective_settings()["llm"]
    mc = (task.model_config_json or {}) if task else {}
    inherit_setting = mc.get("inherit_global")
    inherit_global = inherit_setting is True
    if inherit_global:
        mc = {"inherit_global": True, "prompt_version": mc.get("prompt_version")}
    task_providers = _clean_llm_providers(
        mc.get("providers") or mc.get("providers_json") or []
    )
    if task_providers:
        return [
            _llm_config_from_provider(item, float(eff["temperature"]))
            for item in task_providers
            if item.get("enabled", True)
        ]

    task_has_single_override = any(
        str(mc.get(key) or "").strip()
        for key in ("base_url", "api_key", "model", "protocol")
    )
    implicit_global = inherit_setting is None and not task_has_single_override
    if (inherit_global or implicit_global) and normalize_llm_mode(eff.get("mode")) == "pool":
        providers = _clean_llm_providers(eff.get("providers") or [])
        return [
            _llm_config_from_provider(item, float(eff["temperature"]))
            for item in providers
            if item.get("enabled", True)
        ]

    base_url = mc.get("base_url") or eff["base_url"]
    model = mc.get("model") or eff["model"]
    protocol = normalize_llm_protocol(mc.get("protocol") or eff.get("protocol"))
    api_key = str(mc.get("api_key") or "").strip()
    if not api_key:
        api_key = resolve_llm_key_for_identity(base_url, model, protocol)
    config = LLMConfig(
        base_url=base_url,
        api_key=api_key,
        model=model,
        temperature=float(mc.get("temperature") or eff["temperature"]),
        protocol=protocol,
        weight=1,
        enabled=True,
    )
    return [config] if config.api_key else []


def resolve_llm_runtime_mode(task: Task | None = None) -> str:
    if task is None:
        return normalize_llm_mode(effective_settings()["llm"].get("mode"))
    mc = dict(task.model_config_json or {})
    if mc.get("inherit_global") is False or mc.get("providers") or mc.get("providers_json"):
        return "pool" if mc.get("providers") or mc.get("providers_json") else "single"
    if mc.get("inherit_global") is True or not any(
        str(mc.get(key) or "").strip()
        for key in ("base_url", "api_key", "model", "protocol")
    ):
        return normalize_llm_mode(effective_settings()["llm"].get("mode"))
    return "single"


def resolve_llm_config(task: Task | None = None) -> LLMConfig:
    providers = resolve_llm_providers(task)
    if providers:
        return providers[0]
    eff = effective_settings()["llm"]
    return LLMConfig(
        base_url=eff["base_url"],
        api_key="",
        model=eff["model"],
        temperature=float(eff["temperature"]),
        protocol=normalize_llm_protocol(eff.get("protocol")),
    )


# ── 引擎相关解析函数 ──────────────────────────────────────────

def resolve_engine_name(task: Task | None = None) -> str:
    """获取任务使用的搜索引擎名称。"""
    if task and task.engine:
        return task.engine
    eff = effective_settings()["defaults"]
    return str(eff.get("engine") or get_default_engine())


def resolve_engine_key(engine_name: str, task: Task | None = None) -> str:
    """获取指定引擎的 API Key（任务级 > DB缓存 > 环境变量）。

    FOFA 引擎额外兼容旧版 fofa section（key 保存在 row.fofa 而非 row.engines）。
    """
    eff = effective_settings()
    # 任务级 fofa_config 兼容旧版
    if engine_name == "fofa" and task:
        cfg = task.fofa_config or {}
        if cfg.get("key"):
            return str(cfg["key"])
    eng_cfg = eff.get("engines", {}).get(engine_name, {})
    key = str(eng_cfg.get("key") or "")
    # FOFA 兼容旧版 fofa section
    if not key and engine_name == "fofa":
        key = str(eff.get("fofa", {}).get("key") or "")
    return key


def resolve_engine_base_url(engine_name: str, task: Task | None = None) -> str:
    """获取指定引擎的 base_url。

    FOFA 引擎额外兼容旧版 fofa section。
    """
    engine = get_engine(engine_name)
    default = engine.get_default_base_url() if engine else ""
    eff = effective_settings()
    # 任务级 fofa_config 兼容旧版
    if engine_name == "fofa" and task:
        cfg = task.fofa_config or {}
        if cfg.get("base_url"):
            return str(cfg["base_url"])
    eng_cfg = eff.get("engines", {}).get(engine_name, {})
    base = str(eng_cfg.get("base_url") or "")
    # FOFA 兼容旧版 fofa section
    if not base and engine_name == "fofa":
        base = str(eff.get("fofa", {}).get("base_url") or "")
    return base or default


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


def public_settings_view() -> dict[str, Any]:
    """API 返回：密钥脱敏。"""
    eff = effective_settings()
    llm = eff["llm"]
    fofa = eff["fofa"]
    engines = eff.get("engines", {})
    defaults = eff["defaults"]
    llm_providers = _clean_llm_providers(llm.get("providers") or [])
    llm_mode = normalize_llm_mode(llm.get("mode"))
    single_key = resolve_llm_key_for_identity(
        llm.get("base_url", ""), llm.get("model", ""), llm.get("protocol", "auto")
    )
    single_health_ref = provider_ref(
        llm.get("base_url", ""), llm.get("model", ""), single_key, llm.get("protocol", "auto")
    )
    llm_health = llm_health_snapshot()

    # 构建引擎列表视图
    # FOFA 引擎需额外合并 fofa section 的 key/base_url（旧版兼容）
    engines_view = {}
    for eng in list_engines():
        name = eng["name"]
        ecfg = engines.get(name, {})
        key = ecfg.get("key", "")
        base_url = ecfg.get("base_url", "")
        if name == "fofa":
            if not key:
                key = fofa.get("key", "")
            if not base_url:
                base_url = fofa.get("base_url", "")
        engines_view[name] = {
            "display_name": eng["display_name"],
            "key": mask_secret(key),
            "key_set": bool(key),
            "base_url": base_url or "",
        }

    return {
        "llm": {
            "mode": llm_mode,
            "base_url": llm["base_url"],
            "model": llm["model"],
            "temperature": llm["temperature"],
            "protocol": normalize_llm_protocol(llm.get("protocol")),
            "api_key": mask_secret(single_key),
            "api_key_set": bool(single_key),
            "key_ref": secret_ref(single_key),
            "health_ref": single_health_ref,
            "health": llm_health.get(single_health_ref, {}),
            "provider_count": len(llm_providers),
            "providers": [_public_llm_provider(item) for item in llm_providers],
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
        current_llm = effective_settings()["llm"]
        llm_update = dict(payload["llm"])
        old_llm_providers = _clean_llm_providers(current_llm.get("providers") or [])
        supplied_key = str(llm_update.get("api_key") or "").strip()
        has_new_key = bool(supplied_key and not is_masked_secret(supplied_key))
        next_identity = _llm_identity(
            llm_update.get("base_url") or current_llm.get("base_url"),
            llm_update.get("protocol") or current_llm.get("protocol"),
        )
        current_identity = _llm_identity(
            current_llm.get("base_url"), current_llm.get("protocol")
        )
        if next_identity != current_identity and not has_new_key:
            llm.pop("api_key", None)
        if has_new_key:
            llm.setdefault("base_url", current_llm.get("base_url", ""))
            llm.setdefault("protocol", normalize_llm_protocol(current_llm.get("protocol")))
        for k, v in llm_update.items():
            if k == "api_key":
                if not str(v or "").strip() or is_masked_secret(v):
                    continue
            if k == "providers":
                preserved = _preserve_provider_keys(v or [], old_llm_providers)
                llm["providers"] = _clean_llm_providers(preserved)
                continue
            if k == "mode":
                llm["mode"] = normalize_llm_mode(v)
                continue
            if k == "protocol":
                llm["protocol"] = normalize_llm_protocol(v)
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
        # 同步 FOFA key/base_url 到 engines.fofa（多引擎统一路径）
        if fofa.get("key") or fofa.get("base_url"):
            engines = dict(row.engines or {})
            eng_fofa = dict(engines.get("fofa", {}))
            if fofa.get("key"):
                eng_fofa["key"] = fofa["key"]
            if fofa.get("base_url"):
                eng_fofa["base_url"] = fofa["base_url"]
            engines["fofa"] = eng_fofa
            row.engines = engines

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

    await session.commit()
    await session.refresh(row)
    await refresh_cache(session)
    return public_settings_view()


def llm_client_for_task(
    task: Task | None = None,
    on_provider_failure=None,
    on_provider_selected=None,
):
    """返回 LLMClient；无 key 时抛 RuntimeError（与旧行为一致）。"""
    from app.llm.client import LLMClient

    return LLMClient(
        providers=resolve_llm_providers(task),
        pool_mode=resolve_llm_runtime_mode(task) == "pool",
        usage_key=task.id if task else None,
        on_provider_failure=on_provider_failure,
        on_provider_selected=on_provider_selected,
    )


def llm_client_for_task_optional(
    task: Task | None = None,
    on_provider_failure=None,
    on_provider_selected=None,
):
    """有 key 则返回 LLMClient，否则 None（collector 降级）。"""
    from app.llm.client import LLMClient

    providers = resolve_llm_providers(task)
    if not providers:
        return None
    try:
        return LLMClient(
            providers=providers,
            pool_mode=resolve_llm_runtime_mode(task) == "pool",
            usage_key=task.id if task else None,
            on_provider_failure=on_provider_failure,
            on_provider_selected=on_provider_selected,
        )
    except Exception:
        return None


def _llm_key_candidates() -> list[tuple[str, str, str, str]]:
    llm = effective_settings()["llm"]
    env_llm = _env_llm()
    rows = [{
        "base_url": llm.get("base_url", ""),
        "api_key": llm.get("api_key", ""),
        "model": llm.get("model", ""),
        "protocol": llm.get("protocol", "auto"),
    }, *_clean_llm_providers(llm.get("providers") or []), {
        "base_url": env_llm.get("base_url", ""),
        "api_key": env_llm.get("api_key", ""),
        "model": env_llm.get("model", ""),
        "protocol": env_llm.get("protocol", "auto"),
    }, *_clean_llm_providers(env_llm.get("providers") or [])]
    return [
        (
            str(row.get("base_url") or ""),
            str(row.get("model") or ""),
            normalize_llm_protocol(row.get("protocol")),
            str(row.get("api_key") or "").strip(),
        )
        for row in rows
        if str(row.get("api_key") or "").strip()
    ]


def resolve_llm_key_for_identity(
    base_url: str | None,
    model: str | None = None,
    protocol: str | None = None,
) -> str:
    identity = _llm_identity(base_url, protocol)
    if not all(identity):
        return ""
    for candidate_base, _candidate_model, candidate_protocol, key in _llm_key_candidates():
        if _llm_identity(candidate_base, candidate_protocol) == identity:
            return key
    return ""


def resolve_llm_key_ref(
    key_ref: str | None,
    base_url: str | None = None,
    model: str | None = None,
    protocol: str | None = None,
) -> str:
    ref = str(key_ref or "").strip()
    identity = _llm_identity(base_url, protocol)
    if not ref or not all(identity):
        return ""
    for candidate_base, _candidate_model, candidate_protocol, key in _llm_key_candidates():
        if (
            _llm_identity(candidate_base, candidate_protocol) == identity
            and secret_ref(key) == ref
        ):
            return key
    return ""


async def list_available_models(
    base_url: str | None = None,
    api_key: str | None = None,
    protocol: str | None = None,
    key_ref: str | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    """拉取模型商可用模型列表（OpenAI 兼容 GET /models）。"""
    import httpx

    eff = effective_settings()["llm"]
    resolved = resolve_llm_providers()
    fallback = resolved[0] if resolved else resolve_llm_config()
    base = (base_url or fallback.base_url or eff["base_url"] or "").strip().rstrip("/")
    resolved_protocol = normalize_llm_protocol(protocol or fallback.protocol or eff.get("protocol"))
    resolved_model = str(model or fallback.model or eff.get("model") or "").strip()
    key = str(api_key or "").strip()
    if not key or is_masked_secret(key):
        key = resolve_llm_key_ref(
            key_ref, base, resolved_model, resolved_protocol
        ) or resolve_llm_key_for_identity(base, resolved_model, resolved_protocol)
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
    if resolved_protocol == "anthropic_messages":
        headers.update({
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        })
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
