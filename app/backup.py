"""SQLite 在线备份 + 可选工作目录打包。

备份用 SQLite Online Backup API（conn.backup），不直接拷正在写的 WAL 文件，
避免虚机断电那种「文件在、库已坏」的半截拷贝。

归档格式（迁移用 tar.gz）：
  manifest.json
  db/autohunter.db
  work/...                 # 仅 include_work=True

服务器本地快照只留一份压缩文件：{db_dir}/backups/autohunter-latest.db.gz
再备份会覆盖，避免把磁盘堆满。日常迁移请用导出/导入把文件带走。
"""
from __future__ import annotations

import gzip
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
LATEST_NAME = "autohunter-latest.db.gz"
PRE_RESTORE_NAME = "autohunter-pre-restore.db.gz"

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
    hours = max(0.0, float(_env_int("AUTOHUNTER_BACKUP_INTERVAL_HOURS", 0)))
    return hours * 3600


def backup_keep() -> int:
    """本地只覆盖 1 份。KEEP=0 表示连这一份也不写（仍可用导出/导入）。"""
    return 1 if _env_int("AUTOHUNTER_BACKUP_KEEP", 1) > 0 else 0


def work_backup_max_bytes() -> int:
    return max(0, _env_int("AUTOHUNTER_BACKUP_WORK_MAX_MB", 512)) * 1024 * 1024


def reserve_bytes() -> int:
    return max(0, _env_int("AUTOHUNTER_BACKUP_RESERVE_MB", 512)) * 1024 * 1024


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


def disk_info(path: Path | None = None) -> dict[str, Any]:
    target = path or db_path().parent
    try:
        target.mkdir(parents=True, exist_ok=True)
        usage = shutil.disk_usage(target)
    except OSError:
        return {"free": 0, "total": 0, "free_human": "未知", "total_human": "未知"}
    return {
        "free": usage.free,
        "total": usage.total,
        "free_human": _human_size(usage.free),
        "total_human": _human_size(usage.total),
    }


def assert_free_space(needed: int, path: Path | None = None, what: str = "备份") -> None:
    """需要 needed 字节峰值，外加预留，否则拒绝，避免把库盘写满。"""
    info = disk_info(path)
    need = max(0, int(needed)) + reserve_bytes()
    if info["free"] < need:
        raise RuntimeError(
            f"磁盘剩余 {info['free_human']}，{what}大约还要 {_human_size(need)} "
            f"（含 {_human_size(reserve_bytes())} 预留）。请先导出带走或清理工作目录。"
        )


def _gzip_file(src: Path, dest: Path) -> None:
    tmp = dest.with_name(dest.name + ".tmp")
    tmp.unlink(missing_ok=True)
    with open(src, "rb") as fin, gzip.open(tmp, "wb", compresslevel=6) as fout:
        shutil.copyfileobj(fin, fout, 1024 * 1024)
    os.replace(tmp, dest)


def _iter_snapshot_files(d: Path) -> list[Path]:
    if not d.is_dir():
        return []
    out = []
    for p in d.iterdir():
        if not p.is_file() or p.name.startswith("."):
            continue
        if p.name.startswith(SNAPSHOT_PREFIX) and (
            p.name.endswith(".db") or p.name.endswith(".db.gz")
        ):
            out.append(p)
    return out


def staging_dir() -> Path:
    d = backups_dir() / ".staging"
    d.mkdir(parents=True, exist_ok=True)
    return d


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
    for suffix in ("-wal", "-shm"):
        Path(str(tmp) + suffix).unlink(missing_ok=True)
    return dest_path


def rotate_snapshots(keep: int | None = None) -> list[str]:
    """本地只留 latest + 一份恢复前快照，清掉旧的时间戳文件。"""
    n = backup_keep() if keep is None else max(0, int(keep))
    d = backups_dir()
    if not d.is_dir():
        return []
    keep_names = {PRE_RESTORE_NAME}
    if n > 0:
        keep_names.add(LATEST_NAME)
    deleted: list[str] = []
    for extra in _iter_snapshot_files(d):
        if extra.name in keep_names:
            continue
        try:
            extra.unlink()
            deleted.append(extra.name)
        except OSError as exc:
            logger.warning("删除过期快照失败 %s: %s", extra, exc)
    for extra in list(d.iterdir()):
        if not extra.is_file():
            continue
        if ".tmp" in extra.name or extra.name.endswith(".tmp"):
            try:
                extra.unlink()
                deleted.append(extra.name)
            except OSError as exc:
                logger.warning("删除备份临时文件失败 %s: %s", extra, exc)
    return deleted


def snapshot_now() -> dict[str, Any]:
    """覆盖写入 backups/autohunter-latest.db.gz。KEEP=0 时拒绝。"""
    if backup_keep() <= 0:
        raise RuntimeError("本地快照已关闭（AUTOHUNTER_BACKUP_KEEP=0），请用导出把备份下载带走。")
    live = db_path()
    dest_dir = backups_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / LATEST_NAME
    # 峰值：未压缩临时库 + gzip 临时文件 + 旧 latest，约 3 倍库体积
    assert_free_space(_file_size(live) * 3, dest_dir, "本地快照")
    with tempfile.TemporaryDirectory(prefix="ah-snap-", dir=str(dest_dir)) as td:
        tmp_db = Path(td) / "snap.db"
        with _op_lock:
            snapshot_sqlite(live, tmp_db)
            _gzip_file(tmp_db, dest)
            deleted = rotate_snapshots()
    logger.info("本地快照 %s (%s)", dest.name, _human_size(_file_size(dest)))
    return {
        "ok": True,
        "name": dest.name,
        "path": str(dest),
        "bytes": _file_size(dest),
        "human": _human_size(_file_size(dest)),
        "rotated": deleted,
        "overwritten": True,
    }


def list_snapshots() -> list[dict[str, Any]]:
    d = backups_dir()
    items = []
    for p in sorted(_iter_snapshot_files(d), key=lambda x: x.stat().st_mtime, reverse=True):
        st = p.stat()
        items.append({
            "name": p.name,
            "bytes": st.st_size,
            "human": _human_size(st.st_size),
            "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
            "slot": "latest" if p.name == LATEST_NAME else (
                "pre-restore" if p.name == PRE_RESTORE_NAME else "leftover"
            ),
        })
    return items


def snapshot_file(name: str) -> Path:
    """只允许 backups/ 下 autohunter-*.db / .db.gz，拒绝路径穿越。"""
    if "/" in name or "\\" in name or name in {".", ".."}:
        raise ValueError("非法快照名")
    if not name.startswith(SNAPSHOT_PREFIX) or ".." in name:
        raise ValueError("非法快照名")
    if not (name.endswith(".db") or name.endswith(".db.gz")):
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
    """生成可下载/迁移的 tar.gz。dest 为最终路径。临时文件落在库同盘 backups/.staging。"""
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

    live = db_path()
    stage = staging_dir()
    # 峰值：临时 sqlite + tar.gz ≈ 2×库 + work
    assert_free_space(_file_size(live) * 2 + work_bytes, stage, "导出备份")

    with tempfile.TemporaryDirectory(prefix="ah-bak-", dir=str(stage)) as td:
        tmp_db = Path(td) / "autohunter.db"
        with _op_lock:
            snapshot_sqlite(live, tmp_db)
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
                pre = pre_dir / PRE_RESTORE_NAME
                try:
                    assert_free_space(_file_size(live) * 3, pre_dir, "恢复前快照")
                    with tempfile.TemporaryDirectory(prefix="ah-pre-", dir=str(pre_dir)) as pre_td:
                        tmp_pre = Path(pre_td) / "pre.db"
                        snapshot_sqlite(live, tmp_pre)
                        _gzip_file(tmp_pre, pre)
                except Exception as exc:  # noqa: BLE001 - 旧库已坏或盘满时仍允许覆盖
                    logger.warning("恢复前快照失败（将继续覆盖）: %s", exc)
                    pre = None

            with _op_lock:
                assert_free_space(_file_size(extracted_db) * 2, live.parent, "恢复数据库")
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
    snap_bytes = sum(int(s.get("bytes") or 0) for s in snaps)
    disk = disk_info(live.parent)
    return {
        "db_path": str(live),
        "db_exists": live.is_file(),
        "db_bytes": _file_size(live),
        "db_human": _human_size(_file_size(live)),
        "wal_bytes": _file_size(wal),
        "shm_bytes": _file_size(shm),
        "snapshots": snaps,
        "last_snapshot": snaps[0] if snaps else None,
        "snapshots_bytes": snap_bytes,
        "snapshots_human": _human_size(snap_bytes),
        "disk": disk,
        "reserve_human": _human_size(reserve_bytes()),
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
    """启动时清掉多出来的旧快照；interval=0 则不再自动打新的。"""
    import asyncio

    try:
        deleted = rotate_snapshots()
        if deleted:
            logger.info("已清理过期本地快照: %s", ", ".join(deleted))
    except Exception:
        logger.exception("清理过期快照失败")

    interval = backup_interval_seconds()
    if interval <= 0 or backup_keep() <= 0:
        logger.info("自动备份已关闭（AUTOHUNTER_BACKUP_INTERVAL_HOURS=0 或 KEEP=0），请用设置页导出带走")
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
