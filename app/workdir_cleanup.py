"""工作目录自动清理。

Worker / Escalate / Killsweep / Reviewer 在 work_root 下为每个目标建子目录。
长期运行后会占满磁盘。按「目录内文件活动时间」判断过期，避免 Linux 上
只往已有日志追加时父目录 mtime 不变、把正在跑的 worker 目录误删。
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from app.config import worker_config
from app.memory import drop_tree_cache, trim_process_memory

logger = logging.getLogger("autohunter.workdir_cleanup")

PROTECTED_DIR_NAMES = frozenset({
    "node_modules",
    "browser_profile",
    "app-deobfuscated",
    "chunk-deobfuscated",
})
# 再新也不删：正在写日志的目录即使父目录 mtime 很旧也要保住。
_MIN_IDLE_SECONDS = 30 * 60
_WALK_CAP = 400
_STATS_SIZE_DIRS = 80


def _work_root() -> Path | None:
    raw = Path(worker_config.work_root or "")
    if not str(raw):
        return None
    try:
        root = raw.resolve()
    except OSError:
        return None
    if root == Path("/") or len(root.parts) < 2:
        logger.error("拒绝使用不安全的工作目录根: %s", root)
        return None
    return root


def _is_protected(name: str) -> bool:
    return name in PROTECTED_DIR_NAMES


def _is_safe_child(root: Path, entry: Path) -> Path | None:
    if entry.is_symlink():
        return None
    try:
        resolved = entry.resolve()
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    if not resolved.is_dir() or resolved == root:
        return None
    return resolved


def _walk_limited(path: Path, cap: int = _WALK_CAP):
    n = 0
    try:
        for entry in path.rglob("*"):
            n += 1
            if n > cap:
                return
            yield entry
    except OSError:
        return


def _activity_mtime(path: Path) -> float:
    """目录自身 + 内部文件的最新 mtime（不用 ctime：utime/chmod 会把 ctime 刷成现在）。"""
    latest = 0.0
    try:
        st = path.stat()
        latest = st.st_mtime
    except OSError:
        pass
    for entry in _walk_limited(path):
        try:
            latest = max(latest, entry.stat().st_mtime)
        except OSError:
            continue
    return latest


def _dir_size(path: Path) -> int:
    total = 0
    for entry in _walk_limited(path):
        if entry.is_file() and not entry.is_symlink():
            try:
                total += entry.stat().st_size
            except OSError:
                pass
    return total


def _human_size(n: int | float) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def _empty_stats(root: Path | None) -> dict:
    return {
        "work_root": str(root or worker_config.work_root),
        "total_size_bytes": 0,
        "total_size_human": "0 B",
        "total_dirs": 0,
        "protected_dirs": list(PROTECTED_DIR_NAMES),
        "oldest_dir": None,
        "newest_dir": None,
        "retention_days": worker_config.work_retention_days,
        "auto_cleanup_enabled": worker_config.work_retention_days > 0,
        "size_is_sample": False,
    }


def get_workdir_stats() -> dict:
    root = _work_root()
    if root is None or not root.exists():
        return _empty_stats(root)

    total_size = 0
    total_dirs = 0
    sized = 0
    oldest_mtime = float("inf")
    oldest_name = ""
    newest_mtime = 0.0
    newest_name = ""
    now = time.time()

    for entry in root.iterdir():
        if not entry.is_dir() or entry.is_symlink() or _is_protected(entry.name):
            continue
        total_dirs += 1
        if sized < _STATS_SIZE_DIRS:
            total_size += _dir_size(entry)
            sized += 1
        mtime = _activity_mtime(entry)
        if mtime < oldest_mtime:
            oldest_mtime = mtime
            oldest_name = entry.name
        if mtime > newest_mtime:
            newest_mtime = mtime
            newest_name = entry.name

    def _fmt_dir(name: str, mtime: float) -> dict | None:
        if not name or mtime == 0.0:
            return None
        return {
            "name": name,
            "mtime": datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat(),
            "age_days": round((now - mtime) / 86400.0, 1),
        }

    return {
        "work_root": str(root),
        "total_size_bytes": total_size,
        "total_size_human": _human_size(total_size),
        "total_dirs": total_dirs,
        "protected_dirs": list(PROTECTED_DIR_NAMES),
        "oldest_dir": _fmt_dir(oldest_name, oldest_mtime) if oldest_name else None,
        "newest_dir": _fmt_dir(newest_name, newest_mtime) if newest_name else None,
        "retention_days": worker_config.work_retention_days,
        "auto_cleanup_enabled": worker_config.work_retention_days > 0,
        "size_is_sample": total_dirs > _STATS_SIZE_DIRS,
    }


def cleanup_workdir(
    retention_days: int | None = None,
    dry_run: bool = False,
) -> dict:
    if retention_days is None:
        retention_days = worker_config.work_retention_days

    root = _work_root()
    result: dict = {
        "dry_run": dry_run,
        "retention_days": retention_days,
        "scanned_dirs": 0,
        "deleted_dirs": 0,
        "failed_dirs": 0,
        "skipped_recent": 0,
        "freed_bytes": 0,
        "freed_human": "0 B",
        "deleted": [],
        "failed": [],
    }
    if retention_days <= 0 or root is None or not root.exists():
        return result

    now = time.time()
    cutoff = now - retention_days * 86400
    idle_cutoff = now - _MIN_IDLE_SECONDS

    for entry in root.iterdir():
        if not entry.is_dir() or entry.is_symlink() or _is_protected(entry.name):
            continue
        target = _is_safe_child(root, entry)
        if target is None:
            continue

        result["scanned_dirs"] += 1
        mtime = _activity_mtime(target)
        if mtime > cutoff or mtime > idle_cutoff:
            if mtime > idle_cutoff and mtime <= cutoff:
                result["skipped_recent"] += 1
            continue

        size = _dir_size(target)
        age_days = (now - mtime) / 86400.0 if mtime else 0.0
        item = {
            "name": entry.name,
            "age_days": round(age_days, 1),
            "size_human": _human_size(size),
        }
        if dry_run:
            result["deleted_dirs"] += 1
            result["freed_bytes"] += size
            result["deleted"].append(item)
            continue
        try:
            shutil.rmtree(target)
            result["deleted_dirs"] += 1
            result["freed_bytes"] += size
            result["deleted"].append(item)
        except Exception as exc:
            result["failed_dirs"] += 1
            result["failed"].append({"name": entry.name, "error": str(exc)})
            logger.warning("清理工作目录失败 %s: %s", entry.name, exc)

    result["freed_human"] = _human_size(result["freed_bytes"])
    if not dry_run and root is not None:
        drop_tree_cache(root)
        trim_process_memory()
    logger.info(
        "工作目录清理完成: 扫描 %d, 删除 %d, 跳过活跃 %d, 失败 %d, 释放 %s%s",
        result["scanned_dirs"],
        result["deleted_dirs"],
        result["skipped_recent"],
        result["failed_dirs"],
        result["freed_human"],
        "（dry-run）" if dry_run else "",
    )
    return result


async def run_periodic_cleanup() -> None:
    interval = max(1, worker_config.work_cleanup_interval_hours) * 3600
    logger.info(
        "工作目录定时清理已启动: 间隔 %dh, 保留 %dd",
        worker_config.work_cleanup_interval_hours,
        worker_config.work_retention_days,
    )
    while True:
        try:
            await asyncio.sleep(interval)
            if worker_config.work_retention_days > 0:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, cleanup_workdir)
        except asyncio.CancelledError:
            logger.info("工作目录定时清理已停止")
            break
        except Exception:
            logger.exception("工作目录定时清理异常")
