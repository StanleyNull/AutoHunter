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

并发默认按机器规格自动档（尊重 Docker cgroup 的 CPU/内存限额）：
大约 1C1G→3，2C4G→8，4C8G→12，8C16G→20，大机器顶 32。
可用 AUTOHUNTER_WORKER_MAX_CONCURRENCY 显式覆盖（覆盖优先，跳过自动档）。
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


def _clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(int(n), hi))


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _cgroup_cpu_count() -> float:
    """容器 CPU 配额。无配额或读失败返回 0。"""
    raw = _read_text("/sys/fs/cgroup/cpu.max")
    if raw:
        parts = raw.split()
        if parts and parts[0] != "max":
            try:
                quota = int(parts[0])
                period = int(parts[1]) if len(parts) > 1 else 100_000
                if quota > 0 and period > 0:
                    return max(0.5, quota / period)
            except ValueError:
                pass
    quota_s = _read_text("/sys/fs/cgroup/cpu/cpu.cfs_quota_us") or _read_text(
        "/sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota_us"
    )
    period_s = _read_text("/sys/fs/cgroup/cpu/cpu.cfs_period_us") or _read_text(
        "/sys/fs/cgroup/cpu,cpuacct/cpu.cfs_period_us"
    )
    try:
        quota = int(quota_s)
        period = int(period_s)
        if quota > 0 and period > 0:
            return max(0.5, quota / period)
    except (TypeError, ValueError):
        pass
    return 0.0


def _cgroup_mem_gib() -> float:
    """容器内存上限（GiB）。无上限或读失败返回 0。"""
    raw = _read_text("/sys/fs/cgroup/memory.max") or _read_text(
        "/sys/fs/cgroup/memory/memory.limit_in_bytes"
    )
    if not raw or raw == "max":
        return 0.0
    try:
        n = int(raw)
    except ValueError:
        return 0.0
    # cgroup v1 未设限额时常是 ~2^63，视为无上限。
    if n <= 0 or n >= (1 << 60):
        return 0.0
    return n / (1024 ** 3)


def _detect_cpus() -> float:
    """可用 CPU：affinity 与 cgroup 配额取更紧的那个。"""
    try:
        affinity = float(max(1, len(os.sched_getaffinity(0))))  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        affinity = float(max(1, os.cpu_count() or 1))
    cgroup = _cgroup_cpu_count()
    if cgroup > 0:
        return max(0.5, min(affinity, cgroup))
    return affinity


def _detect_mem_gib() -> float:
    """可用内存(GiB)：物理内存与 cgroup 限额取更紧的那个。都读不到返回 0（不按内存限）。"""
    host = 0.0
    try:
        pages = os.sysconf("SC_PHYS_PAGES")  # type: ignore[attr-defined]
        page_size = os.sysconf("SC_PAGE_SIZE")  # type: ignore[attr-defined]
        host = (pages * page_size) / (1024 ** 3)
    except (AttributeError, ValueError, OSError):
        host = 0.0
    cgroup = _cgroup_mem_gib()
    vals = [v for v in (host, cgroup) if v > 0]
    return min(vals) if vals else 0.0


def _auto_worker_base_from(cpus: float, mem_gib: float) -> int:
    """把机器规格映射成 worker 并发。纯函数，方便单测。

    agent 工作是 IO 密集（大部分时间阻塞等 LLM），不是 CPU 密集：
    - 不按核数 1:1（28 核不代表 28 worker）；
    - 硬顶 32，避免把 LLM 上游和本机句柄打满；
    - 小机器按 CPU / 内存里更紧的那个降档，1C1G 也能起步。
    """
    if cpus <= 1:
        by_cpu = 4
    elif cpus <= 2:
        by_cpu = 8
    elif cpus <= 4:
        by_cpu = 12
    elif cpus <= 8:
        by_cpu = 20
    elif cpus <= 16:
        by_cpu = 24
    else:
        by_cpu = 32
    if mem_gib <= 0:
        by_mem = by_cpu
    elif mem_gib < 1.5:
        by_mem = 3
    elif mem_gib < 3:
        by_mem = max(4, int(mem_gib / 0.6))
    else:
        by_mem = max(4, int(mem_gib / 0.5))
    return max(3, min(by_cpu, by_mem, 32))


def _auto_worker_base() -> int:
    """按本机（含 cgroup）规格自动挑 worker 并发基准。"""
    return _auto_worker_base_from(DETECTED_CPUS, DETECTED_MEM_GIB)


DETECTED_CPUS = _detect_cpus()
DETECTED_MEM_GIB = _detect_mem_gib()

# worker 基准：env 显式给了就用 env，否则按机器规格自动定档。
_WORKER_ENV = os.environ.get("AUTOHUNTER_WORKER_MAX_CONCURRENCY")
_WORKER_BASE = _int_env("AUTOHUNTER_WORKER_MAX_CONCURRENCY", _auto_worker_base()) \
    if _WORKER_ENV else _auto_worker_base()

# 各类 agent 并发上限：worker 为主，其余按固定比例从 worker 基准推导，
# 保持 worker:review:killsweep:escalation:assistant ≈ 6:2:1.5:1:1.5。
# 小机器允许降到 1，避免 1G 盒子被「每类至少 2」抬爆。
# 每一项仍可用对应 env 单独覆盖（覆盖优先）。
WORKER_MAX_CONCURRENCY = _WORKER_BASE
REVIEW_MAX_CONCURRENCY = _int_env("AUTOHUNTER_REVIEW_MAX_CONCURRENCY", max(1, _WORKER_BASE // 3))
KILLSWEEP_MAX_CONCURRENCY = _int_env("AUTOHUNTER_KILLSWEEP_MAX_CONCURRENCY", max(1, _WORKER_BASE // 4))
ESCALATION_MAX_CONCURRENCY = _int_env("AUTOHUNTER_ESCALATION_MAX_CONCURRENCY", max(1, _WORKER_BASE // 6))
ASSISTANT_MAX_CONCURRENCY = _int_env("AUTOHUNTER_ASSISTANT_MAX_CONCURRENCY", max(1, _WORKER_BASE // 4))

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

# collector 轻量 IO（探活/评分）独立小池，与重型 agent 工作彻底隔离。
# 随 worker 基准缩放：1G 盒子约 8，大机器顶 32。不要写死 24。
COLLECTOR_IO_POOL_SIZE = _int_env(
    "AUTOHUNTER_COLLECTOR_IO_POOL_SIZE", _clamp(_WORKER_BASE, 8, 32)
)
COLLECTOR_IO_EXECUTOR = ThreadPoolExecutor(
    max_workers=COLLECTOR_IO_POOL_SIZE,
    thread_name_prefix="ah-collector-io",
)

# 其余 IO 并发同样跟 worker 基准走，env 仍可单项覆盖。
PREFILTER_CONCURRENCY = _int_env("COLLECTOR_PREFILTER_CONCURRENCY", _clamp(_WORKER_BASE, 6, 24))
SCORE_CONCURRENCY = _int_env("COLLECTOR_SCORE_CONCURRENCY", _clamp(_WORKER_BASE // 2, 4, 16))
TARGET_FILTER_CONCURRENCY = _int_env("TARGET_FILTER_CONCURRENCY", _clamp(_WORKER_BASE // 2, 3, 12))
QUEUE_LIVENESS_CONCURRENCY = _int_env("QUEUE_LIVENESS_CONCURRENCY", _clamp(_WORKER_BASE, 4, 16))
QUEUE_LIVENESS_BATCH_SIZE = _int_env("QUEUE_LIVENESS_BATCH_SIZE", _clamp(_WORKER_BASE * 2, 12, 48))
DEFAULT_THREAD_POOL_SIZE = _int_env(
    "AUTOHUNTER_DEFAULT_THREAD_POOL_SIZE", _clamp(_WORKER_BASE // 2 + 4, 4, 16)
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
