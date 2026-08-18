"""SQLite 在线备份 + 可选工作目录打包。

备份用 SQLite Online Backup API（conn.backup），不直接拷正在写的 WAL 文件，
避免虚机断电那种「文件在、库已坏」的半截拷贝。

归档格式（迁移用 tar.gz）：
  manifest.json
  db/autohunter.db
  work/...                 # 仅 include_work=True

服务器本地快照只存 db：{db_dir}/backups/autohunter-YYYYmmdd-HHMMSS.db
"""
from __future__ import annotations

import io
import json
import logging
import os
import shutil
import sqlite3
import tarfile
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from app.workdir_cleanup import PROTECTED_DIR_NAMES, _work_root

logger = logging.getLogger("autohunter.backup")

MAGIC = "autohunter-backup"
FORMAT_VERSION = 1
SNAPSHOT_PREFIX = "autohunter-"
SNAPSHOT_SUFFIX = ".db"

_op_lock = threading.Lock()


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def backup_interval_seconds() -> float:
    hours = max(0.0, float(_env_int("AUTOHUNTER_BACKUP_INTERVAL_HOURS", 6)))
    return hours * 3600


def backup_keep() -> int:
    return max(0, _env_int("AUTOHUNTER_BACKUP_KEEP", 7))


def work_backup_max_bytes() -> int:
    return max(0, _env_int("AUTOHUNTER_BACKUP_WORK_MAX_MB", 2048)) * 1024 * 1024


def db_path() -> Path:
    raw = os.environ.get("DB_PATH", "").strip()
    if raw:
        return Path(raw).expanduser()
    return Path(__file__).resolve().parent.parent / "data" / "autohunter.db"


def backups_dir() -> Path:
    return db_path().resolve().parent / "backups"


def _human_size(n: int | float) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{int(n)} B"


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def integrity_check(path: str | Path) -> tuple[bool, str]:
    """对一份独立 sqlite 文件做 PRAGMA integrity_check。"""
    db = Path(path)
    if not db.is_file():
        return False, "文件不存在"
    if db.stat().st_size < 100:
        return False, "文件过小，不像有效数据库"
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=30)
    except sqlite3.Error as exc:
        return False, f"无法打开: {exc}"
    try:
        row = conn.execute("PRAGMA integrity_check").fetchone()
        msg = str(row[0]) if row else "empty"
        return msg.lower() == "ok", msg
    except sqlite3.Error as exc:
        return False, str(exc)
    finally:
        conn.close()


def snapshot_sqlite(src: str | Path, dest: str | Path) -> Path:
    """把 src 在线备份成 dest（原子替换）。失败不覆盖旧 dest。"""
    src_path = Path(src)
    dest_path = Path(dest)
    if not src_path.is_file():
        raise FileNotFoundError(f"数据库不存在: {src_path}")
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest_path.with_name(dest_path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    src_conn = sqlite3.connect(str(src_path), timeout=60)
    try:
        dst_conn = sqlite3.connect(str(tmp), timeout=60)
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
    finally:
        src_conn.close()
    ok, msg = integrity_check(tmp)
    if not ok:
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"备份完整性检查失败: {msg}")
    os.replace(tmp, dest_path)
    return dest_path


def rotate_snapshots(keep: int | None = None) -> list[str]:
    """按 mtime 保留最新 keep 份，返回被删文件名。"""
    n = backup_keep() if keep is None else max(0, keep)
    d = backups_dir()
    if not d.is_dir() or n <= 0:
        return []
    files = sorted(
            [p for p in d.glob(f"{SNAPSHOT_PREFIX}*{SNAPSHOT_SUFFIX}")
             if p.is_file() and "pre-restore" not in p.name],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    deleted: list[str] = []
    for extra in files[n:]:
        try:
            extra.unlink()
            deleted.append(extra.name)
        except OSError as exc:
            logger.warning("删除过期快照失败 %s: %s", extra, exc)
    return deleted


def snapshot_now() -> dict[str, Any]:
    """在 backups/ 打一份本地 db 快照并轮转。"""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    dest = backups_dir() / f"{SNAPSHOT_PREFIX}{ts}{SNAPSHOT_SUFFIX}"
    with _op_lock:
        snapshot_sqlite(db_path(), dest)
        deleted = rotate_snapshots()
    logger.info("本地快照 %s (%s)", dest.name, _human_size(_file_size(dest)))
    return {
        "ok": True,
        "name": dest.name,
        "path": str(dest),
        "bytes": _file_size(dest),
        "human": _human_size(_file_size(dest)),
        "rotated": deleted,
    }


def list_snapshots() -> list[dict[str, Any]]:
    d = backups_dir()
    if not d.is_dir():
        return []
    items = []
    for p in sorted(d.glob(f"{SNAPSHOT_PREFIX}*{SNAPSHOT_SUFFIX}"), key=lambda x: x.stat().st_mtime, reverse=True):
        if not p.is_file():
            continue
        st = p.stat()
        items.append({
            "name": p.name,
            "bytes": st.st_size,
            "human": _human_size(st.st_size),
            "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
        })
    return items


def snapshot_file(name: str) -> Path:
    """只允许 backups/ 下 autohunter-*.db，拒绝路径穿越。"""
    if "/" in name or "\\" in name or name in {".", ".."} or not name.endswith(SNAPSHOT_SUFFIX):
        raise ValueError("非法快照名")
    if not name.startswith(SNAPSHOT_PREFIX) or ".." in name:
        raise ValueError("非法快照名")
    path = (backups_dir() / name).resolve()
    if path.parent != backups_dir().resolve() or not path.is_file():
        raise FileNotFoundError("快照不存在")
    return path


def _safe_work_root() -> Path | None:
    return _work_root()


def _iter_work_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            n for n in dirnames
            if n not in PROTECTED_DIR_NAMES and not (Path(dirpath) / n).is_symlink()
        ]
        for name in filenames:
            p = Path(dirpath) / name
            if p.is_symlink() or not p.is_file():
                continue
            yield p


def _work_bytes(root: Path, cap: int) -> int:
    total = 0
    for p in _iter_work_files(root):
        try:
            total += p.stat().st_size
        except OSError:
            continue
        if cap and total > cap:
            return total
    return total


def create_archive(dest: str | Path, include_work: bool = False) -> dict[str, Any]:
    """生成可下载/迁移的 tar.gz。dest 为最终路径。"""
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    work_root = _safe_work_root() if include_work else None
    work_bytes = 0
    if include_work:
        if work_root is None or not work_root.is_dir():
            raise RuntimeError("工作目录不可用，无法打包 work")
        cap = work_backup_max_bytes()
        work_bytes = _work_bytes(work_root, cap)
        if cap and work_bytes > cap:
            raise RuntimeError(
                f"工作目录约 {_human_size(work_bytes)}，超过上限 {_human_size(cap)}。"
                "请先清理工作目录，或提高 AUTOHUNTER_BACKUP_WORK_MAX_MB。"
            )

    with tempfile.TemporaryDirectory(prefix="ah-bak-") as td:
        tmp_db = Path(td) / "autohunter.db"
        with _op_lock:
            snapshot_sqlite(db_path(), tmp_db)
        db_bytes = _file_size(tmp_db)
        manifest = {
            "magic": MAGIC,
            "version": FORMAT_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "include_work": bool(include_work),
            "db_bytes": db_bytes,
            "work_bytes": work_bytes if include_work else 0,
            "integrity": "ok",
        }
        tmp_tar = Path(td) / "archive.tar.gz"
        with tarfile.open(tmp_tar, "w:gz") as tar:
            info = tarfile.TarInfo("manifest.json")
            payload = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
            info.size = len(payload)
            tar.addfile(info, fileobj=io.BytesIO(payload))
            tar.add(tmp_db, arcname="db/autohunter.db")
            if include_work and work_root is not None:
                for p in _iter_work_files(work_root):
                    rel = p.relative_to(work_root).as_posix()
                    tar.add(p, arcname=f"work/{rel}", recursive=False)
        os.replace(tmp_tar, dest_path)

    return {
        **manifest,
        "archive_bytes": _file_size(dest_path),
        "archive_human": _human_size(_file_size(dest_path)),
        "path": str(dest_path),
    }


def _read_manifest(tar: tarfile.TarFile) -> dict[str, Any]:
    try:
        member = tar.getmember("manifest.json")
    except KeyError as exc:
        raise ValueError("不是 AutoHunter 备份：缺少 manifest.json") from exc
    if not member.isfile() or member.size > 64 * 1024:
        raise ValueError("manifest.json 异常")
    raw = tar.extractfile(member)
    if raw is None:
        raise ValueError("无法读取 manifest.json")
    try:
        data = json.loads(raw.read().decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("manifest.json 不是合法 JSON") from exc
    if data.get("magic") != MAGIC:
        raise ValueError("不是 AutoHunter 备份包")
    if int(data.get("version") or 0) != FORMAT_VERSION:
        raise ValueError(f"不支持的备份版本: {data.get('version')}")
    return data


def _safe_member_name(name: str) -> str:
    n = name.replace("\\", "/").lstrip("/")
    if not n or n.endswith("/"):
        return n
    parts = [p for p in n.split("/") if p and p != "."]
    if not parts or any(p == ".." for p in parts):
        raise ValueError(f"备份包含非法路径: {name}")
    return "/".join(parts)


def inspect_archive(archive: str | Path) -> dict[str, Any]:
    with tarfile.open(archive, "r:gz") as tar:
        return _read_manifest(tar)


def _install_db(snapshot: Path, live: Path) -> None:
    live.parent.mkdir(parents=True, exist_ok=True)
    tmp = live.with_name(live.name + ".incoming")
    tmp.unlink(missing_ok=True)
    shutil.copy2(snapshot, tmp)
    os.replace(tmp, live)
    for suffix in ("-wal", "-shm"):
        Path(str(live) + suffix).unlink(missing_ok=True)


def restore_archive(
    archive: str | Path,
    include_work: bool = False,
    live_db: str | Path | None = None,
    work_root: str | Path | None = None,
) -> dict[str, Any]:
    """校验归档并覆盖当前 db（可选 work）。调用方负责随后重启进程。"""
    live = Path(live_db) if live_db else db_path()
    archive_path = Path(archive)
    with tarfile.open(archive_path, "r:gz") as tar:
        manifest = _read_manifest(tar)
        try:
            db_member = tar.getmember("db/autohunter.db")
        except KeyError as exc:
            raise ValueError("备份缺少 db/autohunter.db") from exc
        if not db_member.isfile() or db_member.size < 100:
            raise ValueError("备份中的数据库无效")

        with tempfile.TemporaryDirectory(prefix="ah-restore-") as td:
            td_path = Path(td)
            extracted_db = td_path / "autohunter.db"
            src = tar.extractfile(db_member)
            if src is None:
                raise ValueError("无法读取备份数据库")
            extracted_db.write_bytes(src.read())
            ok, msg = integrity_check(extracted_db)
            if not ok:
                raise ValueError(f"备份数据库损坏: {msg}")

            work_files = 0
            if include_work:
                dest_work = Path(work_root) if work_root else _safe_work_root()
                if dest_work is None:
                    raise RuntimeError("工作目录不可用，无法恢复 work")
                dest_work.mkdir(parents=True, exist_ok=True)
                dest_resolved = dest_work.resolve()
                for member in tar.getmembers():
                    name = _safe_member_name(member.name)
                    if not name.startswith("work/"):
                        continue
                    rel = name[len("work/"):]
                    if not rel or member.isdir():
                        continue
                    if not member.isfile():
                        continue
                    target = (dest_work / rel).resolve()
                    try:
                        target.relative_to(dest_resolved)
                    except ValueError as exc:
                        raise ValueError(f"备份包含越界路径: {member.name}") from exc
                    target.parent.mkdir(parents=True, exist_ok=True)
                    blob = tar.extractfile(member)
                    if blob is None:
                        continue
                    target.write_bytes(blob.read())
                    work_files += 1

            pre = None
            if live.is_file():
                pre_dir = backups_dir()
                pre_dir.mkdir(parents=True, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d-%H%M%S")
                pre = pre_dir / f"{SNAPSHOT_PREFIX}pre-restore-{ts}{SNAPSHOT_SUFFIX}"
                try:
                    snapshot_sqlite(live, pre)
                except Exception as exc:  # noqa: BLE001 - 旧库已坏时仍允许覆盖
                    logger.warning("恢复前快照失败（将继续覆盖）: %s", exc)
                    pre = None

            with _op_lock:
                _install_db(extracted_db, live)
                rotate_snapshots()

    return {
        "ok": True,
        "manifest": manifest,
        "include_work": bool(include_work),
        "work_files": work_files if include_work else 0,
        "pre_restore": pre.name if pre else None,
        "db_path": str(live),
    }


def backup_status() -> dict[str, Any]:
    live = db_path()
    wal = Path(str(live) + "-wal")
    shm = Path(str(live) + "-shm")
    work = _safe_work_root()
    work_bytes = _work_bytes(work, 0) if work and work.is_dir() else 0
    interval = backup_interval_seconds()
    snaps = list_snapshots()
    return {
        "db_path": str(live),
        "db_exists": live.is_file(),
        "db_bytes": _file_size(live),
        "db_human": _human_size(_file_size(live)),
        "wal_bytes": _file_size(wal),
        "shm_bytes": _file_size(shm),
        "snapshots": snaps,
        "last_snapshot": snaps[0] if snaps else None,
        "auto_backup": {
            "enabled": interval > 0 and backup_keep() > 0,
            "interval_hours": interval / 3600 if interval else 0,
            "keep": backup_keep(),
        },
        "work": {
            "root": str(work) if work else "",
            "bytes": work_bytes,
            "human": _human_size(work_bytes),
            "max_human": _human_size(work_backup_max_bytes()),
        },
    }


async def run_periodic_backup() -> None:
    """启动时若过期则补一份，之后按间隔轮转。interval=0 关闭自动快照。"""
    import asyncio

    interval = backup_interval_seconds()
    if interval <= 0 or backup_keep() <= 0:
        logger.info("自动备份已关闭（AUTOHUNTER_BACKUP_INTERVAL_HOURS=0 或 KEEP=0）")
        return

    async def _once(reason: str) -> None:
        loop = asyncio.get_running_loop()
        try:
            result = await loop.run_in_executor(None, snapshot_now)
            logger.info("自动备份完成 (%s): %s", reason, result.get("name"))
        except Exception:
            logger.exception("自动备份失败 (%s)", reason)

    snaps = list_snapshots()
    due = True
    if snaps:
        try:
            last = datetime.fromisoformat(snaps[0]["mtime"])
            due = (datetime.now(timezone.utc) - last).total_seconds() >= interval
        except Exception:
            due = True
    if due:
        await _once("startup")

    while True:
        await asyncio.sleep(interval)
        await _once("interval")
