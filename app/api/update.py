"""一键更新 API：检测 + git pull + 自动重启。

适用于 git 部署（docker compose up -d --build）的场景。
容器内 .git 存在（Dockerfile COPY . .），git 已安装，可直接 git pull。
重启靠 SIGTERM → watchdog 退出 → Docker restart: unless-stopped 自动拉起。
"""
import os
import signal
import subprocess
import threading
import time
from pathlib import Path

from fastapi import APIRouter

router = APIRouter(prefix="/api/update", tags=["update"])

REPO_ROOT = Path(__file__).resolve().parents[2]
# 这些路径的变更需要完整重建（容器内无法热更新）
REBUILD_PATTERNS = ("frontend/", "Dockerfile", "docker-compose", ".github/")


def _git(*args: str, timeout: int = 30) -> tuple[int, str, str]:
    """运行 git 命令，返回 (returncode, stdout, stderr)。"""
    try:
        r = subprocess.run(
            ["git", *args], cwd=str(REPO_ROOT),
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


@router.get("/check")
async def check_update():
    """检测是否有新版本。对比当前 HEAD vs origin/main。"""
    if not (REPO_ROOT / ".git").exists():
        return {"update_available": False, "error": "非 git 部署，无法自动更新。请手动下载新版本。"}

    rc, _, err = _git("fetch", "origin", "main", timeout=60)
    if rc != 0:
        return {"update_available": False, "error": f"git fetch 失败: {err or '网络不通'}"}

    _, current, _ = _git("rev-parse", "HEAD")
    _, latest, _ = _git("rev-parse", "origin/main")
    if not current or not latest:
        return {"update_available": False, "error": "无法读取 git 版本信息"}

    if current == latest:
        return {"update_available": False, "current_commit": current[:8]}

    _, diff_out, _ = _git("diff", "--name-only", "HEAD", "origin/main")
    changed = [f for f in diff_out.split("\n") if f.strip()]
    needs_rebuild = any(any(f.startswith(p) for p in REBUILD_PATTERNS) for f in changed)
    _, msg, _ = _git("log", "-1", "--format=%s", "origin/main")
    _, log_count, _ = _git("rev-list", "--count", "HEAD", "origin/main")

    return {
        "update_available": True,
        "current_commit": current[:8],
        "latest_commit": latest[:8],
        "latest_message": msg,
        "commits_behind": int(log_count) if log_count.isdigit() else 0,
        "changed_files": changed[:30],
        "hot_updateable": not needs_rebuild,
        "needs_rebuild": needs_rebuild,
    }


@router.post("/run")
async def run_update():
    """执行热更新：git pull + pip install（如有需要）+ 重启。"""
    if not (REPO_ROOT / ".git").exists():
        return {"ok": False, "error": "非 git 部署，无法自动更新"}

    rc, _, err = _git("fetch", "origin", "main", timeout=60)
    if rc != 0:
        return {"ok": False, "error": f"git fetch 失败: {err}"}

    _, current, _ = _git("rev-parse", "HEAD")
    _, latest, _ = _git("rev-parse", "origin/main")
    if current == latest:
        return {"ok": False, "error": "已是最新版本"}

    _, diff_out, _ = _git("diff", "--name-only", "HEAD", "origin/main")
    changed = [f for f in diff_out.split("\n") if f.strip()]
    needs_rebuild = any(any(f.startswith(p) for p in REBUILD_PATTERNS) for f in changed)
    if needs_rebuild:
        return {
            "ok": False,
            "error": "本次更新包含前端/Dockerfile 变更，需在服务器执行完整重建",
            "command": "cd \"$(dirname $(docker inspect -f '{{.Config.Labels}}' autohunter 2>/dev/null || echo /opt/autohunter))\" 2>/dev/null; git pull && docker compose up -d --build",
            "changed_files": changed[:10],
        }

    rc, _, err = _git("pull", "origin", "main", timeout=120)
    if rc != 0:
        return {"ok": False, "error": f"git pull 失败: {err}"}

    if "requirements.txt" in changed:
        try:
            subprocess.run(
                ["pip", "install", "--quiet", "-r", "requirements.txt"],
                capture_output=True, text=True, timeout=300,
            )
        except Exception:
            pass

    def delayed_restart():
        time.sleep(2)
        os.kill(os.getpid(), signal.SIGTERM)

    threading.Thread(target=delayed_restart, daemon=True).start()
    return {"ok": True, "message": "更新完成，服务正在重启…"}
