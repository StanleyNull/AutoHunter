"""进程内内存回收：工作目录页缓存 + glibc 堆。

Docker mem_limit 把 Linux page cache 算进 cgroup。Worker 写 /work 日志、读 JS
之后，这些页会留在 active_file 里，监控曲线持续上涨，看起来像泄漏，直到 OOM。
这里主动 posix_fadvise(DONTNEED) + malloc_trim，把可回收页还给内核。
SQLite 数据文件不碰，避免把热库页踢出缓存。
"""
from __future__ import annotations

import asyncio
import ctypes
import gc
import logging
import os
from pathlib import Path

from app.config import worker_config

logger = logging.getLogger("autohunter.memory")

_SKIP_SUFFIXES = {".db", ".db-wal", ".db-shm", ".sqlite", ".sqlite3"}
_RECLAIM_SECONDS = max(60, int(os.environ.get("AUTOHUNTER_MEMORY_RECLAIM_SECONDS", "300")))
_WALK_CAP = 800


def drop_file_cache(path: Path | str) -> None:
    advise = getattr(os, "posix_fadvise", None)
    flag = getattr(os, "POSIX_FADV_DONTNEED", None)
    if advise is None or flag is None:
        return
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        advise(fd, 0, 0, flag)
    except OSError:
        pass
    finally:
        os.close(fd)


def drop_tree_cache(root: Path | str | None, cap: int = _WALK_CAP) -> int:
    if root is None:
        return 0
    base = Path(root)
    if not base.is_dir():
        return 0
    n = 0
    try:
        for entry in base.rglob("*"):
            if n >= cap:
                break
            if not entry.is_file() or entry.is_symlink():
                continue
            if entry.suffix.lower() in _SKIP_SUFFIXES:
                continue
            drop_file_cache(entry)
            n += 1
    except OSError:
        return n
    return n


def trim_process_memory() -> None:
    gc.collect()
    try:
        libc = ctypes.CDLL("libc.so.6")
        libc.malloc_trim(0)
    except Exception:
        pass


def reclaim_runtime_memory() -> dict[str, int]:
    work_root = worker_config.work_root
    dropped = drop_tree_cache(work_root)
    trim_process_memory()
    return {"files": dropped}


async def run_periodic_memory_reclaim() -> None:
    logger.info("内存回收已启动: 间隔 %ds, work_root=%s", _RECLAIM_SECONDS, worker_config.work_root)
    while True:
        try:
            await asyncio.sleep(_RECLAIM_SECONDS)
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, reclaim_runtime_memory)
            logger.info("内存回收完成: 释放页缓存文件 %s 个", result.get("files", 0))
        except asyncio.CancelledError:
            logger.info("内存回收已停止")
            break
        except Exception:
            logger.exception("内存回收异常")
