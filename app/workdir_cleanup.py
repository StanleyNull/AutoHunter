"""工作目录自动清理模块。

Worker / Escalate / Killsweep / Reviewer 等 agent 在 work_root 下为每个目标创建
独立子目录，存放 shell 日志、curl 输出等临时文件。长期运行后数千个目录会占用大量磁盘。

本模块提供：
- get_workdir_stats(): 统计磁盘占用与目录数量
- cleanup_workdir(): 按目录最后修改时间清理过期工作目录
- run_periodic_cleanup(): 供 main.py lifespan 调用的定时清理协程
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from app.config import worker_config

logger = logging.getLogger("autohunter.workdir_cleanup")

# 永不删除的特殊目录（非目标工作目录）
PROTECTED_DIR_NAMES = frozenset({
    "node_modules",
    "browser_profile",
    "app-deobfuscated",
    "chunk-deobfuscated",
})


def _work_root() -> Path:
    return Path(worker_config.work_root)


def _is_protected(name: str) -> bool:
    """判断目录名是否为受保护的非目标目录。"""
    return name in PROTECTED_DIR_NAMES


def _dir_mtime(path: Path) -> float:
    """获取目录的最后修改时间（取 mtime 和 cstat 中较大者，兼顾文件写入场景）。"""
    try:
        st = path.stat()
        return max(st.st_mtime, st.st_ctime)
    except OSError:
        return 0.0


def _dir_size(path: Path) -> int:
    """递归计算目录总大小（字节）。"""
    total = 0
    try:
        for entry in path.rglob("*"):
            if entry.is_file():
                try:
                    total += entry.stat().st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


def _human_size(n: int) -> str:
    """字节数转人类可读字符串。"""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} PB"


def get_workdir_stats() -> dict:
    """统计工作目录的磁盘占用情况。

    Returns:
        {
            "work_root": str,
            "total_size_bytes": int,
            "total_size_human": str,
            "total_dirs": int,
            "protected_dirs": list[str],
            "oldest_dir": {"name": str, "mtime": str, "age_days": float} | None,
            "newest_dir": {"name": str, "mtime": str, "age_days": float} | None,
            "retention_days": int,
            "auto_cleanup_enabled": bool,
        }
    """
    root = _work_root()
    if not root.exists():
        return {
            "work_root": str(root),
            "total_size_bytes": 0,
            "total_size_human": "0 B",
            "total_dirs": 0,
            "protected_dirs": list(PROTECTED_DIR_NAMES),
            "oldest_dir": None,
            "newest_dir": None,
            "retention_days": worker_config.work_retention_days,
            "auto_cleanup_enabled": worker_config.work_retention_days > 0,
        }

    total_size = 0
    total_dirs = 0
    oldest_mtime = float("inf")
    oldest_name = ""
    newest_mtime = 0.0
    newest_name = ""
    now = time.time()

    for entry in root.iterdir():
        if not entry.is_dir():
            continue
        if _is_protected(entry.name):
            continue
        total_dirs += 1
        total_size += _dir_size(entry)
        mtime = _dir_mtime(entry)
        if mtime < oldest_mtime:
            oldest_mtime = mtime
            oldest_name = entry.name
        if mtime > newest_mtime:
            newest_mtime = mtime
            newest_name = entry.name

    def _fmt_dir(name: str, mtime: float) -> dict | None:
        if not name or mtime == 0.0:
            return None
        dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
        age_days = (now - mtime) / 86400.0
        return {
            "name": name,
            "mtime": dt.isoformat(),
            "age_days": round(age_days, 1),
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
    }


def cleanup_workdir(
    retention_days: int | None = None,
    dry_run: bool = False,
) -> dict:
    """清理过期的工作目录。

    按目录最后修改时间判断：超过 retention_days 天未修改的目录将被删除。
    受保护目录（node_modules 等）不会被删除。

    Args:
        retention_days: 保留天数，None 则使用配置默认值。0 表示不清理。
        dry_run: 仅模拟运行，不实际删除。

    Returns:
        {
            "dry_run": bool,
            "retention_days": int,
            "scanned_dirs": int,
            "deleted_dirs": int,
            "failed_dirs": int,
            "freed_bytes": int,
            "freed_human": str,
            "deleted": list[{"name": str, "age_days": float, "size_human": str}],
            "failed": list[{"name": str, "error": str}],
        }
    """
    if retention_days is None:
        retention_days = worker_config.work_retention_days

    root = _work_root()
    result: dict = {
        "dry_run": dry_run,
        "retention_days": retention_days,
        "scanned_dirs": 0,
        "deleted_dirs": 0,
        "failed_dirs": 0,
        "freed_bytes": 0,
        "freed_human": "0 B",
        "deleted": [],
        "failed": [],
    }

    if retention_days <= 0:
        return result

    if not root.exists():
        return result

    now = time.time()
    cutoff = now - retention_days * 86400

    for entry in root.iterdir():
        if not entry.is_dir():
            continue
        if _is_protected(entry.name):
            continue

        result["scanned_dirs"] += 1
        mtime = _dir_mtime(entry)

        if mtime > cutoff:
            continue  # 尚未过期

        size = _dir_size(entry)
        age_days = (now - mtime) / 86400.0

        if dry_run:
            result["deleted_dirs"] += 1
            result["freed_bytes"] += size
            result["deleted"].append({
                "name": entry.name,
                "age_days": round(age_days, 1),
                "size_human": _human_size(size),
            })
            continue

        try:
            shutil.rmtree(entry)
            result["deleted_dirs"] += 1
            result["freed_bytes"] += size
            result["deleted"].append({
                "name": entry.name,
                "age_days": round(age_days, 1),
                "size_human": _human_size(size),
            })
        except Exception as exc:
            result["failed_dirs"] += 1
            result["failed"].append({
                "name": entry.name,
                "error": str(exc),
            })
            logger.warning("清理工作目录失败 %s: %s", entry.name, exc)

    result["freed_human"] = _human_size(result["freed_bytes"])
    logger.info(
        "工作目录清理完成: 扫描 %d, 删除 %d, 失败 %d, 释放 %s%s",
        result["scanned_dirs"],
        result["deleted_dirs"],
        result["failed_dirs"],
        result["freed_human"],
        "（dry-run）" if dry_run else "",
    )
    return result


async def run_periodic_cleanup() -> None:
    """定时清理协程，由 main.py lifespan 创建为后台任务。

    按 work_cleanup_interval_hours 间隔执行清理，retention_days<=0 时不清理。
    """
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
                # 清理是 IO 密集操作，放到线程池执行避免阻塞事件循环
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, cleanup_workdir)
        except asyncio.CancelledError:
            logger.info("工作目录定时清理已停止")
            break
        except Exception:
            logger.exception("工作目录定时清理异常")
            # 异常后继续循环，不退出
