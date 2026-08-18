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


def _detect_cpus() -> int:
    """探测可用 CPU 数：优先 sched_getaffinity（尊重 cgroup/容器绑核），退回 cpu_count。"""
    try:
        return max(1, len(os.sched_getaffinity(0)))  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return max(1, os.cpu_count() or 1)


def _detect_mem_gib() -> float:
    """探测物理内存(GiB)。取不到时返回 0（表示未知，不参与限制）。"""
    try:
        pages = os.sysconf("SC_PHYS_PAGES")  # type: ignore[attr-defined]
        page_size = os.sysconf("SC_PAGE_SIZE")  # type: ignore[attr-defined]
        return (pages * page_size) / (1024 ** 3)
    except (AttributeError, ValueError, OSError):
        return 0.0


def _auto_worker_base() -> int:
    """按机器规格自动挑 worker 并发基准（其余 agent 按固定比例从它推导）。

    agent 工作是 IO 密集（大部分时间阻塞等 LLM 响应），不是 CPU 密集，所以：
    - 不按 CPU 线性缩放（28 核不代表要开 28 worker）；
    - 真正的天花板是 LLM 上游限流 + 本机句柄，故 worker 封顶 32；
    - 小机器则按 CPU / 内存里更紧的那个降档，避免内存和上下文切换吃紧。

    可用 AUTOHUNTER_WORKER_MAX_CONCURRENCY 显式覆盖（覆盖优先，跳过自动档）。
    """
    cpus = _detect_cpus()
    mem = _detect_mem_gib()
    # CPU 档：worker 是 IO 密集（大部分时间阻塞等 LLM），可按核数约 2～3 倍叠 in-flight。
    if cpus <= 2:
        by_cpu = 8
    elif cpus <= 4:
        by_cpu = 12
    elif cpus <= 8:
        by_cpu = 20
    elif cpus <= 16:
        by_cpu = 24
    else:
        by_cpu = 32
    # 内存档（每个 worker 峰值主要是 LLM 上下文，粗估 ~0.5GiB 预算；0=未知则不限）。
    if mem <= 0:
        by_mem = by_cpu
    else:
        by_mem = max(6, int(mem // 0.5))
    # 绝对下限 6：再小的机器也别把并发压到个位数，否则小云服务器几乎跑不动。
    return max(6, min(by_cpu, by_mem, 32))


# worker 基准：env 显式给了就用 env，否则按机器规格自动定档。
_WORKER_ENV = os.environ.get("AUTOHUNTER_WORKER_MAX_CONCURRENCY")
_WORKER_BASE = _int_env("AUTOHUNTER_WORKER_MAX_CONCURRENCY", _auto_worker_base()) \
    if _WORKER_ENV else _auto_worker_base()

# 各类 agent 并发上限：worker 为主，其余按固定比例从 worker 基准推导，
# 保持 worker:review:killsweep:escalation:assistant ≈ 6:2:1.5:1:1.5 的成熟配比。
# 每一项仍可用对应 env 单独覆盖（覆盖优先）。
WORKER_MAX_CONCURRENCY = _WORKER_BASE
REVIEW_MAX_CONCURRENCY = _int_env("AUTOHUNTER_REVIEW_MAX_CONCURRENCY", max(2, _WORKER_BASE // 3))
KILLSWEEP_MAX_CONCURRENCY = _int_env("AUTOHUNTER_KILLSWEEP_MAX_CONCURRENCY", max(2, _WORKER_BASE // 4))
ESCALATION_MAX_CONCURRENCY = _int_env("AUTOHUNTER_ESCALATION_MAX_CONCURRENCY", max(1, _WORKER_BASE // 6))
ASSISTANT_MAX_CONCURRENCY = _int_env("AUTOHUNTER_ASSISTANT_MAX_CONCURRENCY", max(2, _WORKER_BASE // 4))

# 线程池容量：默认 = 各类上限之和 + 余量，保证不会因容量不足而排队死锁。
# 允许用 AUTOHUNTER_AGENT_THREAD_POOL_SIZE 覆盖，但不得小于各类上限之和。
_SUM_LIMITS = (
    WORKER_MAX_CONCURRENCY
    + REVIEW_MAX_CONCURRENCY
    + KILLSWEEP_MAX_CONCURRENCY
    + ESCALATION_MAX_CONCURRENCY
    + ASSISTANT_MAX_CONCURRENCY
)
# 余量：为偶发的临时提交（如少量并发的 report assistant）留 4 个缓冲，仍可 env 覆盖，
# 但无论如何不会小于 _SUM_LIMITS（否则触发历史 futex_wait 死锁）。
AGENT_THREAD_POOL_SIZE = max(
    _SUM_LIMITS,
    _int_env("AUTOHUNTER_AGENT_THREAD_POOL_SIZE", _SUM_LIMITS + 4),
)

AGENT_EXECUTOR = ThreadPoolExecutor(
    max_workers=AGENT_THREAD_POOL_SIZE,
    thread_name_prefix="ah-agent",
)

# collector 轻量 IO（探活/评分）独立小池，与重型 agent 工作彻底隔离，
# 避免 collector 一轮几十个探测把 agent 池占满。
COLLECTOR_IO_POOL_SIZE = _int_env("AUTOHUNTER_COLLECTOR_IO_POOL_SIZE", max(24, _WORKER_BASE))
COLLECTOR_IO_EXECUTOR = ThreadPoolExecutor(
    max_workers=COLLECTOR_IO_POOL_SIZE,
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
