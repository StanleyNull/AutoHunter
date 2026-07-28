"""一键更新 API：检测 + git pull + 自动重启。

适用于 git 部署（docker compose up -d --build）的场景。
容器内 .git 存在（Dockerfile COPY . .），git 已安装，可直接 git pull。
重启靠 SIGTERM → watchdog 退出 → Docker restart: unless-stopped 自动拉起。

鉴权：`/api/update/*` 由全局安全中间件（app/security.py）保护——
check 需任意有效读令牌，run（POST 写操作）需全权令牌，未认证/只读/观摩均拒绝。

实现要点（加固）：
- 处理器用同步 `def` 而非 `async def`：git/pip 是阻塞子进程，FastAPI 会把同步
  处理器放到线程池执行，避免阻塞事件循环（否则一次 git fetch 能冻结整个服务几十秒）。
- `/run` 用非阻塞锁串行化，杜绝并发 git pull / 双重重启。
- `git pull --ff-only` + 脏工作树预检：只快进、绝不产生合并提交/冲突，本地分叉则干净失败。
- 依赖安装失败则不重启：新代码已落盘但不重启，避免重启进新代码却缺依赖导致崩溃循环。
"""
import logging
import os
import signal
import subprocess
import threading
import time
from pathlib import Path

from fastapi import APIRouter

logger = logging.getLogger("autohunter.update")

router = APIRouter(prefix="/api/update", tags=["update"])

REPO_ROOT = Path(__file__).resolve().parents[2]
# 这些路径的变更需要完整重建（容器内无法热更新）
REBUILD_PATTERNS = ("frontend/", "Dockerfile", "docker-compose", ".github/")

# 串行化 /run：同一时刻只允许一个更新在跑，避免并发 git pull 与双重重启线程。
_update_lock = threading.Lock()


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
    except Exception as e:  # noqa: BLE001 - git 环境异常统一降级为错误返回
        return 1, "", str(e)


def _is_git_deploy() -> bool:
    return (REPO_ROOT / ".git").exists()


def _changed_files(base: str, head: str) -> list[str]:
    _, diff_out, _ = _git("diff", "--name-only", base, head)
    return [f for f in diff_out.split("\n") if f.strip()]


def _needs_rebuild(changed: list[str]) -> bool:
    return any(any(f.startswith(p) for p in REBUILD_PATTERNS) for f in changed)


# 同步 def：见模块 docstring（阻塞子进程放线程池，别阻塞事件循环）。
@router.get("/check")
def check_update():
    """检测是否有新版本。对比当前 HEAD vs origin/main。"""
    releases_url = "https://github.com/StanleyNull/AutoHunter"
    if not _is_git_deploy():
        # Docker 镜像默认不带 .git（.dockerignore 排除），不能一键热更；
        # 仍返回结构化说明，前端保留「检查更新」入口，避免整块消失。
        return {
            "update_available": False,
            "error": "当前是镜像/非 git 部署，容器内无法一键热更新。",
            "hint": "请到 GitHub 拉取最新代码后，在服务器执行 docker compose up -d --build 重建。若希望支持一键更新，请用 git clone 部署并保留 .git。",
            "releases_url": releases_url,
            "manual_only": True,
        }

    rc, _, err = _git("fetch", "origin", "main", timeout=60)
    if rc != 0:
        return {
            "update_available": False,
            "error": f"git fetch 失败: {err or '网络不通'}",
            "hint": "检查容器出网或 GitHub 访问；也可手动到仓库查看最新提交后重建。",
            "releases_url": releases_url,
        }

    _, current, _ = _git("rev-parse", "HEAD")
    _, latest, _ = _git("rev-parse", "origin/main")
    if not current or not latest:
        return {
            "update_available": False,
            "error": "无法读取 git 版本信息",
            "hint": "请确认仓库完整，或手动到 GitHub 对照版本。",
            "releases_url": releases_url,
        }

    if current == latest:
        return {"update_available": False, "current_commit": current[:8]}

    changed = _changed_files("HEAD", "origin/main")
    needs_rebuild = _needs_rebuild(changed)
    _, msg, _ = _git("log", "-1", "--format=%s", "origin/main")
    # 落后提交数 = 仅 origin/main 有、本地 HEAD 没有的提交（HEAD..origin/main）。
    # 旧写法 `rev-list --count HEAD origin/main` 数的是并集，会高估落后数。
    _, behind, _ = _git("rev-list", "--count", "HEAD..origin/main")

    return {
        "update_available": True,
        "current_commit": current[:8],
        "latest_commit": latest[:8],
        "latest_message": msg,
        "commits_behind": int(behind) if behind.isdigit() else 0,
        "changed_files": changed[:30],
        "hot_updateable": not needs_rebuild,
        "needs_rebuild": needs_rebuild,
        "releases_url": releases_url,
    }


@router.post("/run")
def run_update():
    """执行热更新：git pull(--ff-only) + pip install（如有需要）+ 重启。"""
    if not _is_git_deploy():
        return {"ok": False, "error": "非 git 部署，无法自动更新"}

    # 非阻塞抢锁：拿不到说明已有更新在跑，直接拒绝，避免并发拉取/重复重启。
    if not _update_lock.acquire(blocking=False):
        return {"ok": False, "error": "更新已在进行中，请稍候再试"}

    restart_scheduled = False
    try:
        rc, _, err = _git("fetch", "origin", "main", timeout=60)
        if rc != 0:
            return {"ok": False, "error": f"git fetch 失败: {err}"}

        _, current, _ = _git("rev-parse", "HEAD")
        _, latest, _ = _git("rev-parse", "origin/main")
        if current == latest:
            return {"ok": False, "error": "已是最新版本"}

        changed = _changed_files("HEAD", "origin/main")
        if _needs_rebuild(changed):
            return {
                "ok": False,
                "error": "本次更新包含前端/Dockerfile/compose 变更，容器内无法热更新，需在服务器执行完整重建",
                "command": "cd <项目目录> && git pull && docker compose up -d --build",
                "changed_files": changed[:10],
            }

        # 工作树有【已跟踪文件】的未提交改动时 pull --ff-only 会失败；提前预检给清晰提示。
        # 用 --untracked-files=no：未跟踪文件不阻塞 --ff-only（只有它会被覆盖时才失败），
        # 避免仓库里一个无害的未跟踪文件把自动更新永久锁死。
        _, dirty, _ = _git("status", "--porcelain", "--untracked-files=no")
        if dirty:
            return {
                "ok": False,
                "error": "工作目录有本地改动，自动更新已中止（避免覆盖）。请在服务器手动 git stash/commit 后重试。",
            }

        # --ff-only：只做快进合并，绝不产生合并提交或冲突；本地已分叉则干净失败。
        rc, _, err = _git("pull", "--ff-only", "origin", "main", timeout=120)
        if rc != 0:
            logger.warning("auto-update git pull 失败: %s", err)
            return {"ok": False, "error": f"git pull 失败（可能本地已分叉）: {err}"}

        _, new_head, _ = _git("rev-parse", "HEAD")
        logger.info("auto-update 已拉取 %s → %s", current[:8], new_head[:8])

        # 依赖变更：装依赖失败则【不重启】，保留当前进程继续服务（新代码已落盘，
        # 待人工处理依赖后再手动重启），避免重启进新代码却缺依赖导致崩溃循环。
        if "requirements.txt" in changed:
            try:
                pr = subprocess.run(
                    ["pip", "install", "--quiet", "-r", "requirements.txt"],
                    cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=300,
                )
                pip_err = (pr.stderr or pr.stdout or "").strip()
                pip_ok = pr.returncode == 0
            except Exception as e:  # noqa: BLE001
                pip_ok, pip_err = False, str(e)
            if not pip_ok:
                logger.error("auto-update 依赖安装失败，已拉代码但不重启: %s", pip_err[:500])
                return {
                    "ok": False,
                    "restarted": False,
                    "error": "代码已更新但依赖安装失败，未自动重启。请在服务器手动安装依赖后重启容器。",
                    "pip_error": pip_err[:500],
                }

        def delayed_restart():
            time.sleep(2)
            logger.info("auto-update 触发重启（SIGTERM）")
            os.kill(os.getpid(), signal.SIGTERM)

        threading.Thread(target=delayed_restart, daemon=True).start()
        restart_scheduled = True
        return {"ok": True, "restarted": True, "commit": new_head[:8], "message": "更新完成，服务正在重启…"}
    finally:
        # 成功排定重启时不释放锁：进程即将退出，保持串行避免 2s 窗口内再次触发更新。
        if not restart_scheduled:
            _update_lock.release()
