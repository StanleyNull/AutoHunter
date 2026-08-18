"""数据备份 / 恢复 API。

- POST /export 下载 tar.gz（db 必含，work 可选）
- POST /snapshot 在服务器 backups/ 打一份本地快照
- GET /status 体积、快照列表
- GET /snapshots/{name} 下载某份本地快照
- POST /restore 上传归档覆盖当前库，默认随后 SIGTERM 让容器干净拉起

全权令牌才能访问（库内含密钥与登录凭据）。只读/观摩令牌 403。
"""
from __future__ import annotations

import logging
import os
import signal
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from app import backup as bak
from app.security import auth_enabled, resolve_role, token_from_headers

logger = logging.getLogger("autohunter.backup")

router = APIRouter(prefix="/api/backup", tags=["backup"])


def _require_full(request: Request) -> None:
    """库里有 LLM/测绘 Key 和登录凭据，只读/观摩不能拉备份。"""
    if not auth_enabled():
        return
    role = resolve_role(token_from_headers(request.headers))
    if role != "full":
        raise HTTPException(403, "备份/恢复需要全权限令牌")


def _unlink(path: str) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except OSError:
        pass


def _schedule_restart() -> None:
    def delayed_restart():
        time.sleep(2)
        logger.info("备份恢复完成，触发重启（SIGTERM）")
        os.kill(os.getpid(), signal.SIGTERM)

    threading.Thread(target=delayed_restart, daemon=True, name="ah-backup-restart").start()


@router.get("/status")
def backup_status(request: Request):
    _require_full(request)
    return bak.backup_status()


@router.post("/snapshot")
def make_snapshot(request: Request):
    _require_full(request)
    try:
        return bak.snapshot_now()
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("本地快照失败")
        raise HTTPException(500, f"快照失败: {exc}") from exc


@router.post("/export")
def export_backup(
    request: Request,
    include_work: bool = Query(False, description="同时打包工作目录"),
):
    _require_full(request)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    kind = "full" if include_work else "db"
    tmp = tempfile.NamedTemporaryFile(
        prefix=f"ah-export-{kind}-", suffix=".tar.gz", delete=False,
    )
    tmp_path = tmp.name
    tmp.close()
    try:
        bak.create_archive(tmp_path, include_work=include_work)
    except Exception as exc:  # noqa: BLE001
        _unlink(tmp_path)
        logger.exception("导出备份失败")
        raise HTTPException(500, f"导出失败: {exc}") from exc
    filename = f"autohunter-backup-{kind}-{ts}.tar.gz"
    return FileResponse(
        tmp_path,
        media_type="application/gzip",
        filename=filename,
        background=BackgroundTask(_unlink, tmp_path),
    )


@router.get("/snapshots/{name}")
def download_snapshot(request: Request, name: str):
    _require_full(request)
    try:
        path = bak.snapshot_file(name)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    return FileResponse(path, media_type="application/x-sqlite3", filename=name)


@router.post("/restore")
def restore_backup(
    request: Request,
    file: UploadFile = File(..., description="create_archive 生成的 tar.gz"),
    include_work: bool = Query(False, description="同时恢复归档里的 work/"),
    restart: bool = Query(True, description="恢复后重启进程以加载新库"),
):
    _require_full(request)
    suffix = Path(file.filename or "backup.tar.gz").suffix.lower()
    if suffix not in {".gz", ".tgz"} and not (file.filename or "").endswith(".tar.gz"):
        # 仍允许无后缀；后面 tar 打开会再校验
        pass
    tmp = tempfile.NamedTemporaryFile(prefix="ah-restore-up-", suffix=".tar.gz", delete=False)
    tmp_path = tmp.name
    try:
        while True:
            chunk = file.file.read(1024 * 1024)
            if not chunk:
                break
            tmp.write(chunk)
        tmp.close()
        result = bak.restore_archive(tmp_path, include_work=include_work)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("恢复备份失败")
        raise HTTPException(500, f"恢复失败: {exc}") from exc
    finally:
        _unlink(tmp_path)

    result["restarted"] = bool(restart)
    if restart:
        _schedule_restart()
        result["message"] = "数据库已替换，服务即将重启以加载新数据。"
    else:
        result["message"] = "数据库已替换。未重启，请尽快重启进程后再访问。"
    return result
