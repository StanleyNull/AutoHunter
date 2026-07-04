"""FastAPI 入口。lifespan 启动时初始化 DB + 恢复 24x7 任务。

AutoHunter — AI 自主漏洞挖掘平台
Powered By StanleyNull
License: CC BY-NC 4.0（署名-非商业性使用）
"""
from __future__ import annotations

import asyncio
import faulthandler
import json
import logging
import os
import signal
import sys
import time
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from app.api import findings, intel, runtime_logs, settings, stream, tasks, vulns
from app.db.session import init_db
from app.ds2api_proxy import ENABLED as DS2API_ENABLED, router as ds2api_router
from app.orchestrator import manager
from app.settings_service import init_settings_cache
from app.security import SECURITY_HEADERS, auth_enabled, protected_path, request_allowed, resolve_role, token_from_headers
from app.waf import WAF_BLOCK_MODE, inspect_request, waf_headers

# Vite 构建产物目录（多阶段构建拷贝到此）
WEB_DIR = Path(__file__).resolve().parent.parent / "web" / "dist"
INDEX_FILE = WEB_DIR / "index.html"
DIAG_LOG = logging.getLogger("autohunter.diag")
LOOP_LAG_INTERVAL = float(os.environ.get("AUTOHUNTER_LOOP_LAG_INTERVAL", "5"))
LOOP_LAG_WARN_SECONDS = float(os.environ.get("AUTOHUNTER_LOOP_LAG_WARN_SECONDS", "10"))


def _json_dump(data: object) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


def _task_summary(loop) -> list[dict]:
    items: list[dict] = []
    for task in asyncio.all_tasks(loop):
        coro = task.get_coro()
        items.append({
            "done": task.done(),
            "cancelled": task.cancelled(),
            "coro": getattr(coro, "__qualname__", repr(coro)),
        })
    return items


def _install_diagnostics(loop) -> None:
    try:
        faulthandler.enable(file=sys.stderr, all_threads=True)
        if hasattr(signal, "SIGUSR1"):
            faulthandler.register(signal.SIGUSR1, file=sys.stderr, all_threads=True)
    except Exception as exc:
        DIAG_LOG.warning("failed to enable faulthandler diagnostics: %s", exc)

    def _dump_runtime(signum, _frame) -> None:
        DIAG_LOG.error("received diagnostic signal: %s", signum)
        try:
            DIAG_LOG.error("orchestrator snapshot: %s", _json_dump(manager.diagnostic_snapshot()))
        except Exception as exc:
            DIAG_LOG.exception("failed to dump orchestrator snapshot: %s", exc)
        try:
            DIAG_LOG.error("asyncio task snapshot: %s", _json_dump(_task_summary(loop)[:100]))
        except Exception as exc:
            DIAG_LOG.exception("failed to dump asyncio tasks: %s", exc)
        try:
            faulthandler.dump_traceback(file=sys.stderr, all_threads=True)
        except Exception as exc:
            DIAG_LOG.exception("failed to dump thread traceback: %s", exc)

    if hasattr(signal, "SIGUSR1"):
        signal.signal(signal.SIGUSR1, _dump_runtime)


async def _loop_lag_monitor() -> None:
    loop = asyncio.get_running_loop()
    expected = loop.time() + LOOP_LAG_INTERVAL
    while True:
        await asyncio.sleep(LOOP_LAG_INTERVAL)
        now = loop.time()
        lag = max(0.0, now - expected)
        expected = now + LOOP_LAG_INTERVAL
        if lag >= LOOP_LAG_WARN_SECONDS:
            DIAG_LOG.warning(
                "event loop lag detected: %.2fs; snapshot=%s",
                lag,
                _json_dump(manager.diagnostic_snapshot()),
            )


@asynccontextmanager
async def lifespan(app: FastAPI):
    _install_diagnostics(asyncio.get_running_loop())
    default_executor = ThreadPoolExecutor(
        max_workers=int(os.environ.get("AUTOHUNTER_DEFAULT_THREAD_POOL_SIZE", "8")),
        thread_name_prefix="ah-default",
    )
    asyncio.get_running_loop().set_default_executor(default_executor)
    lag_monitor = asyncio.create_task(_loop_lag_monitor())
    await init_db()
    await init_settings_cache()
    if not auth_enabled():
        DIAG_LOG.warning(
            "安全告警：未配置任何访问令牌（AUTOHUNTER_API_TOKEN / _READ_TOKEN / _OBSERVER_TOKEN），"
            "所有 /api 接口（含报告助手命令执行、设置修改、任务删除）对可达网络完全开放。"
            "生产/公网部署务必设置 AUTOHUNTER_API_TOKEN，或仅监听 127.0.0.1。"
        )
    if os.environ.get("AUTOHUNTER_RESTORE_ON_STARTUP", "1").lower() not in {"0", "false", "no", "off"}:
        await manager.restore_on_startup()  # 重启恢复 running/idle 任务
    else:
        await manager.pause_on_startup()
    try:
        yield
    finally:
        lag_monitor.cancel()
        try:
            await lag_monitor
        except asyncio.CancelledError:
            pass
        await manager.shutdown()
        default_executor.shutdown(wait=False, cancel_futures=True)


app = FastAPI(title="AutoHunter", version="0.1", lifespan=lifespan)
# 可选的 LLM 反代（默认关闭；仅当 DS2API_PROXY_ENABLED=1 才挂载）。
if DS2API_ENABLED:
    app.include_router(ds2api_router)
app.include_router(settings.router)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    waf_decision = inspect_request(request)
    if not waf_decision.allowed and WAF_BLOCK_MODE:
        response = JSONResponse(
            {"detail": "请求被 AutoHunter WAF 拦截", "reason": waf_decision.reason},
            status_code=waf_decision.status_code,
        )
    elif auth_enabled() and protected_path(request.url.path):
        allowed, role = request_allowed(request)
        if not allowed:
            if role in {"readonly", "observer"}:
                detail = "观摩令牌不允许访问敏感信息或执行写操作" if role == "observer" else "只读令牌不允许此操作"
                response = JSONResponse(
                    {"detail": detail},
                    status_code=403,
                )
            else:
                response = JSONResponse(
                    {"detail": "需要 AutoHunter 访问令牌"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
        else:
            response = await call_next(request)
    else:
        response = await call_next(request)
    for key, value in SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
    for key, value in waf_headers(waf_decision).items():
        response.headers.setdefault(key, value)
    return response

app.include_router(tasks.router)
app.include_router(findings.router)
app.include_router(stream.router)
app.include_router(intel.router)
app.include_router(runtime_logs.router)
app.include_router(vulns.router)


@app.get("/health")
async def health():
    return {"ok": True}


CREDIT = "Powered By StanleyNull"


@app.get("/api/about")
async def about():
    return {
        "name": "AutoHunter",
        "description": "AI 自主漏洞挖掘平台",
        "author": "StanleyNull",
        "license": "CC BY-NC 4.0",
        "credit": CREDIT,
    }


@app.get("/api/auth/status")
async def auth_status(request: Request):
    role = resolve_role(token_from_headers(request.headers))
    return {"auth_required": auth_enabled(), "role": role}


# 极简品牌图标：瞄准镜 reticle（作战终端 / 漏洞猎手意象），单色矢量，明暗标签页都清晰
FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none" '
    'stroke="#3b9eff" stroke-width="2.2" stroke-linecap="round">'
    '<circle cx="16" cy="16" r="9"/>'
    '<path d="M16 2.5v6M16 23.5v6M2.5 16h6M23.5 16h6"/>'
    '<circle cx="16" cy="16" r="2" fill="#3b9eff" stroke="none"/>'
    '</svg>'
)


@app.get("/favicon.svg")
async def favicon_svg():
    return Response(content=FAVICON_SVG, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})


@app.get("/favicon.ico")
async def favicon_ico():
    # 浏览器默认请求 .ico，统一返回同一 SVG，避免 404 噪音
    return Response(content=FAVICON_SVG, media_type="image/svg+xml")


# Vite 资源目录（/assets/*.js|css）
if (WEB_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(WEB_DIR / "assets")), name="assets")


@app.get("/")
async def index():
    if INDEX_FILE.exists():
        return FileResponse(str(INDEX_FILE))
    return {"msg": "前端未构建，请运行 vite build 或使用 Docker 镜像"}
