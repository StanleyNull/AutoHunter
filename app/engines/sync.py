"""同步引擎查询桥接：给线程池里的同步 agent（worker.fofa_lookup / killsweep）使用。

engine.search 是 async；worker/killsweep 跑在 AGENT_EXECUTOR 线程里（无事件循环），
用 asyncio.run 开一个临时 loop 执行即可。查询按当前引擎官网语法原样请求，不再从 FOFA 翻译。
"""
from __future__ import annotations

import asyncio
from typing import Any

from app.engines.base import EngineResult, get_engine


def engine_display_name(engine_name: str) -> str:
    """引擎展示名，找不到时回退到原始标识。"""
    engine = get_engine(engine_name)
    return engine.display_name if engine else (engine_name or "测绘引擎")


def engine_search_sync(
    engine_name: str,
    api_key: str,
    query: str,
    *,
    page: int = 1,
    page_size: int = 20,
    base_url: str | None = None,
    translate_from_fofa: bool = False,
) -> EngineResult:
    """同步执行一次引擎查询，返回统一 EngineResult。异常向上抛给调用方降级处理。"""
    engine = get_engine(engine_name)
    if engine is None:
        raise ValueError(f"未知测绘引擎: {engine_name}")
    q = query
    base = base_url or engine.get_default_base_url()
    return asyncio.run(
        engine.search(api_key, q, page=page, page_size=page_size, base_url=base)
    )


def result_rows_to_dicts(result: EngineResult, limit: int | None = None) -> list[dict[str, Any]]:
    """把 EngineResult 的行按 fields 映射成 dict（键=字段名），值统一转安全字符串，
    杜绝各引擎字段缺失 / None 导致下游 None[:n] 崩溃。缺失字段返回空串。"""
    fields = result.fields or []
    rows = result.results or []
    if limit is not None:
        rows = rows[:limit]
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, (list, tuple)):
            continue
        item: dict[str, Any] = {}
        for i, name in enumerate(fields):
            item[name] = str(row[i]) if i < len(row) and row[i] is not None else ""
        out.append(item)
    return out
