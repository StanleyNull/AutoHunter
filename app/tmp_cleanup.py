"""容器内临时目录（/tmp）自动清理。

Worker 挖洞过程中把下载物直接落在 `/tmp`：apk、exe、heapdump、JS dump、chromium
profile 等。这些不属于 `work_root`，`workdir_cleanup` 管不到，而容器可写层会一直
涨——实测单台 4C/3.6G 机器 20 天累积到 **14 GB /tmp**（容器可写层 24 GB），
磁盘打到 94% 才开始人工清理。

本模块按「文件活动时间」回收，并支持总量上限：
- 天数优先：超过 `WORKER_TMP_RETENTION_DAYS` 未活动的条目删除；
- 上限兜底：`/tmp` 总量超过 `WORKER_TMP_MAX_GB` 时，按最旧优先删到阈值以下，
  避免突发下载（一次拉几十个 apk）在保留期内就把盘写满。

安全性：只删超过最小空闲期（30 分钟）的条目，跳过符号链接，保护 work_root
与系统临时目录，绝不递归出 `tmp_root` 之外。
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import time
from pathlib import Path

from app.config import worker_config

logger = logging.getLogger("autohunter.tmp_cleanup")

# 再新也不删：正在下载/解压的条目，父目录 mtime 可能已经很旧。
_MIN_IDLE_SECONDS = 30 * 60

# 永不清理的名字（系统/框架自己用的临时目录）。
_PROTECTED_NAMES = frozenset({
    "systemd-private",
    "snap-private-tmp",
    ".X11-unix",
    ".ICE-unix",
    ".font-unix",
    ".Test-unix",
    "tmp",  # 防御性：避免 root 误配成 "/" 时把 /tmp 自身当子项删掉
})

# 单次扫描/统计的条目上限，避免 /tmp 里堆上万文件时拖慢事件循环。
_SCAN_CAP = 5000


def _tmp_root() -> Path | None:
    """解析并校验 tmp_root，拒绝明显危险的配置（"/"、过短路径）。"""
    raw = str(worker_config.tmp_root or "").strip()
    if not raw:
        return None
    try:
        root = Path(raw).resolve()
    except OSError:
        return None
    if root == Path("/") or len(root.parts) < 2:
        logger.error("拒绝使用不安全的临时目录根: %s", root)
        return None
    return root


def _work_root() -> Path | None:
    raw = str(worker_config.work_root or "").strip()
    if not raw:
        return None
    try:
        return Path(raw).resolve()
    except OSError:
        return None


def _is_protected(entry: Path, work_root: Path | None) -> bool:
    name = entry.name
    if name in _PROTECTED_NAMES or name.startswith("systemd-private"):
        return True
    # work_root 可能就落在 /tmp 下（默认 /tmp/autohunter/work），必须整体跳过。
    if work_root is not None:
        try:
            resolved = entry.resolve()
        except OSError:
            return True
        if resolved == work_root or work_root.is_relative_to(resolved):
            return True
    return False


def _entry_size(path: Path) -> int:
    """文件或目录的字节数（目录递归，带上限）。"""
    try:
        if path.is_symlink():
            return 0
        if path.is_file():
            return path.stat().st_size
    except OSError:
        return 0
    total = 0
    n = 0
    try:
        for sub in path.rglob("*"):
            n += 1
            if n > _SCAN_CAP:
                break
            try:
                if sub.is_file() and not sub.is_symlink():
                    total += sub.stat().st_size
            except OSError:
                continue
    except OSError:
        pass
    return total


def _activity_mtime(path: Path) -> float:
    """条目自身 + 内部文件的最新 mtime（不用 ctime：chmod/utime 会刷 ctime）。"""
    latest = 0.0
    try:
        latest = path.stat().st_mtime
    except OSError:
        return 0.0
    if path.is_dir():
        n = 0
        try:
            for sub in path.rglob("*"):
                n += 1
                if n > _SCAN_CAP:
                    break
                try:
                    latest = max(latest, sub.stat().st_mtime)
                except OSError:
                    continue
        except OSError:
            pass
    return latest


def _human_size(n: float) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def _collect(root: Path) -> list[dict]:
    """列出 tmp_root 下的候选条目（已排除保护项/符号链接）。"""
    work_root = _work_root()
    out: list[dict] = []
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        logger.warning("无法读取临时目录 %s: %s", root, exc)
        return out

    for entry in entries[:_SCAN_CAP]:
        if entry.is_symlink():
            continue
        if _is_protected(entry, work_root):
            continue
        try:
            size = _entry_size(entry)
        except OSError:
            size = 0
        out.append({
            "path": entry,
            "name": entry.name,
            "size": size,
            "mtime": _activity_mtime(entry),
        })
    return out


def get_tmp_stats(root: Path | str | None = None) -> dict:
    base = Path(root).resolve() if root else _tmp_root()
    if base is None or not base.exists():
        return {
            "tmp_root": str(base or worker_config.tmp_root),
            "exists": False,
            "total_size_bytes": 0,
            "total_size_human": "0.0 B",
            "entries": 0,
            "deletable_entries": 0,
            "deletable_size_bytes": 0,
            "deletable_size_human": "0.0 B",
            "retention_days": worker_config.tmp_retention_days,
            "max_bytes": int(worker_config.tmp_max_gb * 1024 ** 3),
            "max_human": _human_size(worker_config.tmp_max_gb * 1024 ** 3),
            "auto_cleanup_enabled": worker_config.tmp_retention_days > 0,
        }

    items = _collect(base)
    now = time.time()
    cutoff = now - worker_config.tmp_retention_days * 86400
    idle_cutoff = now - _MIN_IDLE_SECONDS
    total = sum(i["size"] for i in items)
    deletable = [i for i in items if 0 < i["mtime"] < cutoff and i["mtime"] < idle_cutoff]
    return {
        "tmp_root": str(base),
        "exists": True,
        "total_size_bytes": total,
        "total_size_human": _human_size(total),
        "entries": len(items),
        "deletable_entries": len(deletable),
        "deletable_size_bytes": sum(i["size"] for i in deletable),
        "deletable_size_human": _human_size(sum(i["size"] for i in deletable)),
        "retention_days": worker_config.tmp_retention_days,
        "max_bytes": int(worker_config.tmp_max_gb * 1024 ** 3),
        "max_human": _human_size(worker_config.tmp_max_gb * 1024 ** 3),
        "auto_cleanup_enabled": worker_config.tmp_retention_days > 0,
    }


def cleanup_tmp(
    retention_days: int | None = None,
    max_bytes: int | None = None,
    dry_run: bool = False,
    root: Path | str | None = None,
) -> dict:
    """清理临时目录。retention_days<=0 且 max_bytes<=0 时不做任何事。"""
    if retention_days is None:
        retention_days = worker_config.tmp_retention_days
    if max_bytes is None:
        max_bytes = int(worker_config.tmp_max_gb * 1024 ** 3)

    result: dict = {
        "dry_run": dry_run,
        "retention_days": retention_days,
        "max_bytes": max_bytes,
        "scanned_entries": 0,
        "deleted_entries": 0,
        "failed_entries": 0,
        "skipped_recent": 0,
        "freed_bytes": 0,
        "freed_human": "0.0 B",
        "size_before_bytes": 0,
        "size_after_bytes": 0,
        "reason": "",
        "deleted": [],
        "failed": [],
    }

    base = Path(root).resolve() if root else _tmp_root()
    enabled = retention_days > 0 or max_bytes > 0
    if not enabled or base is None or not base.exists():
        result["reason"] = "disabled" if not enabled else "no_tmp_root"
        return result

    items = _collect(base)
    result["scanned_entries"] = len(items)
    total = sum(i["size"] for i in items)
    result["size_before_bytes"] = total
    if not items:
        result["reason"] = "empty"
        return result

    now = time.time()
    idle_cutoff = now - _MIN_IDLE_SECONDS
    age_cutoff = now - retention_days * 86400 if retention_days > 0 else 0.0

    # 候选：既超过最小空闲期，又（超过保留天数 或 需要为总量上限腾地方）
    candidates = [i for i in items if i["mtime"] and i["mtime"] < idle_cutoff]
    result["skipped_recent"] = len(items) - len(candidates)

    victims: list[dict] = []
    if age_cutoff > 0:
        for i in candidates:
            if i["mtime"] < age_cutoff:
                victims.append(i)
    if max_bytes > 0 and total > max_bytes:
        # 上限兜底：按最旧优先继续追加，直到剩余量降到阈值以下。
        remaining = total - sum(v["size"] for v in victims)
        rest = sorted((i for i in candidates if i not in victims), key=lambda x: x["mtime"])
        for i in rest:
            if remaining <= max_bytes:
                break
            victims.append(i)
            remaining -= i["size"]

    if not victims:
        result["reason"] = "nothing_to_delete"
        result["size_after_bytes"] = total
        return result

    result["reason"] = "collected"
    freed = 0
    for item in victims:
        target: Path = item["path"]
        # 二次校验：绝不能删到 tmp_root 之外，也绝不能是保护项
        try:
            target.resolve().relative_to(base)
        except (OSError, ValueError):
            continue
        if _is_protected(target, _work_root()):
            continue
        if dry_run:
            result["deleted_entries"] += 1
            freed += item["size"]
            result["deleted"].append({"name": item["name"],
                                      "size_human": _human_size(item["size"])})
            continue
        try:
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
            result["deleted_entries"] += 1
            freed += item["size"]
            result["deleted"].append({"name": item["name"],
                                      "size_human": _human_size(item["size"])})
        except Exception as exc:  # noqa: BLE001 - 单个条目失败不能中断整轮
            result["failed_entries"] += 1
            result["failed"].append({"name": item["name"], "error": str(exc)})
            logger.warning("清理临时文件失败 %s: %s", item["name"], exc)

    result["freed_bytes"] = freed
    result["freed_human"] = _human_size(freed)
    result["size_after_bytes"] = max(0, total - freed)
    logger.info(
        "临时目录清理完成: 扫描 %d, 删除 %d, 跳过最近 %d, 失败 %d, 释放 %s (%s -> %s)%s",
        result["scanned_entries"],
        result["deleted_entries"],
        result["skipped_recent"],
        result["failed_entries"],
        result["freed_human"],
        _human_size(total),
        _human_size(result["size_after_bytes"]),
        "（dry-run）" if dry_run else "",
    )
    return result


async def run_periodic_tmp_cleanup() -> None:
    interval = max(1, worker_config.tmp_cleanup_interval_hours) * 3600
    logger.info(
        "临时目录定时清理已启动: 间隔 %dh, 保留 %dd, 上限 %.1fGB, 目录 %s",
        worker_config.tmp_cleanup_interval_hours,
        worker_config.tmp_retention_days,
        worker_config.tmp_max_gb,
        worker_config.tmp_root,
    )
    while True:
        try:
            await asyncio.sleep(interval)
            if worker_config.tmp_retention_days <= 0 and worker_config.tmp_max_gb <= 0:
                continue
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, cleanup_tmp)
        except asyncio.CancelledError:
            logger.info("临时目录定时清理已停止")
            break
        except Exception:
            logger.exception("临时目录定时清理异常")
