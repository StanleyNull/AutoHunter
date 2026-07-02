"""Shared runtime for blocking agent work.

所有 agent 风格的阻塞工作（worker/reviewer/killsweep/report-assistant）都跑在
同一个线程池里，避免各自开池把 FastAPI 事件循环拖垮。

关键：线程池容量必须 ≥ 所有并发提交者的并发上限之和，否则后提交的任务会在
池子队列里永久排队、对应的 `await run_in_executor` 永远等不到线程，全体 futex_wait
死锁（历史事故根因）。这里用「大池 + 每类 asyncio 信号量」双保险：
- 线程池开到足够大，容纳 worker + reviewer + killsweep + assistant 的并发上限之和；
- 每类再用独立信号量封顶，保证任何一类都不会独占整池、把别人饿死。

collector 的轻量探活/评分不走这个池（见 collector.py 的独立 IO 池），避免一轮
几十个探测请求瞬间榨干 agent 池。
"""
from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return default


# 各类 agent 的并发上限（asyncio 信号量层封顶，互不饿死）
WORKER_MAX_CONCURRENCY = _int_env("AUTOHUNTER_WORKER_MAX_CONCURRENCY", 8)
REVIEW_MAX_CONCURRENCY = _int_env("AUTOHUNTER_REVIEW_MAX_CONCURRENCY", 4)
KILLSWEEP_MAX_CONCURRENCY = _int_env("AUTOHUNTER_KILLSWEEP_MAX_CONCURRENCY", 3)
ESCALATION_MAX_CONCURRENCY = _int_env("AUTOHUNTER_ESCALATION_MAX_CONCURRENCY", 2)
ASSISTANT_MAX_CONCURRENCY = _int_env("AUTOHUNTER_ASSISTANT_MAX_CONCURRENCY", 3)

# 线程池容量：默认 = 各类上限之和 + 余量，保证不会因容量不足而排队死锁。
# 允许用 AUTOHUNTER_AGENT_THREAD_POOL_SIZE 覆盖，但不得小于各类上限之和。
_SUM_LIMITS = (
    WORKER_MAX_CONCURRENCY
    + REVIEW_MAX_CONCURRENCY
    + KILLSWEEP_MAX_CONCURRENCY
    + ESCALATION_MAX_CONCURRENCY
    + ASSISTANT_MAX_CONCURRENCY
)
AGENT_THREAD_POOL_SIZE = max(
    _SUM_LIMITS,
    _int_env("AUTOHUNTER_AGENT_THREAD_POOL_SIZE", _SUM_LIMITS),
)

AGENT_EXECUTOR = ThreadPoolExecutor(
    max_workers=AGENT_THREAD_POOL_SIZE,
    thread_name_prefix="ah-agent",
)

# collector 轻量 IO（探活/评分）独立小池，与重型 agent 工作彻底隔离，
# 避免 collector 一轮几十个探测把 agent 池占满。
_COLLECTOR_IO_SIZE = _int_env("AUTOHUNTER_COLLECTOR_IO_POOL_SIZE", 12)
COLLECTOR_IO_EXECUTOR = ThreadPoolExecutor(
    max_workers=_COLLECTOR_IO_SIZE,
    thread_name_prefix="ah-collector-io",
)


# 每类 agent 的并发信号量（在事件循环里 acquire，再提交线程池）。
# 注意：必须在有事件循环时惰性创建，避免模块导入期无 loop 报错。
_SEMAPHORES: dict[str, asyncio.Semaphore] = {}
_SEM_LIMITS = {
    "worker": WORKER_MAX_CONCURRENCY,
    "review": REVIEW_MAX_CONCURRENCY,
    "killsweep": KILLSWEEP_MAX_CONCURRENCY,
    "escalation": ESCALATION_MAX_CONCURRENCY,
    "assistant": ASSISTANT_MAX_CONCURRENCY,
}


def agent_semaphore(kind: str) -> asyncio.Semaphore:
    """返回某类 agent 的并发信号量（惰性创建，绑定当前事件循环）。"""
    sem = _SEMAPHORES.get(kind)
    if sem is None:
        sem = asyncio.Semaphore(_SEM_LIMITS.get(kind, 1))
        _SEMAPHORES[kind] = sem
    return sem


def shutdown_agent_executor() -> None:
    AGENT_EXECUTOR.shutdown(wait=False, cancel_futures=True)
    COLLECTOR_IO_EXECUTOR.shutdown(wait=False, cancel_futures=True)
