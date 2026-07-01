"""任务级 LLM token 用量计数。

运行态计数足够支撑看板实时观察；进程重启后清零，不参与审计结算。
"""
from __future__ import annotations

from threading import Lock
from time import time
from typing import Any

_LOCK = Lock()
_USAGE: dict[str, dict[str, Any]] = {}


def record_usage(task_id: str | None, model: str, prompt_tokens: int = 0,
                 completion_tokens: int = 0, total_tokens: int = 0,
                 cache_hit_tokens: int = 0, cache_miss_tokens: int = 0) -> None:
    if not task_id:
        return
    prompt = max(0, int(prompt_tokens or 0))
    completion = max(0, int(completion_tokens or 0))
    total = max(0, int(total_tokens or 0)) or (prompt + completion)
    cache_hit = max(0, int(cache_hit_tokens or 0))
    cache_miss = max(0, int(cache_miss_tokens or 0))
    with _LOCK:
        row = _USAGE.setdefault(task_id, {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "cache_hit_tokens": 0,
            "cache_miss_tokens": 0,
            "requests": 0,
            "model": model,
            "updated_at": None,
        })
        row["prompt_tokens"] += prompt
        row["completion_tokens"] += completion
        row["total_tokens"] += total
        row["cache_hit_tokens"] = row.get("cache_hit_tokens", 0) + cache_hit
        row["cache_miss_tokens"] = row.get("cache_miss_tokens", 0) + cache_miss
        row["requests"] += 1
        row["model"] = model
        row["updated_at"] = time()


def usage_snapshot(task_id: str | None, model: str = "") -> dict[str, Any]:
    if not task_id:
        return _empty(model)
    with _LOCK:
        row = dict(_USAGE.get(task_id) or {})
    if not row:
        return _empty(model)
    if model and not row.get("model"):
        row["model"] = model
    return row


def _empty(model: str = "") -> dict[str, Any]:
    return {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "cache_hit_tokens": 0,
        "cache_miss_tokens": 0,
        "requests": 0,
        "model": model,
        "updated_at": None,
    }
