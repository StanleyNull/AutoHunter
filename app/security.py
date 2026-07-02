"""HTTP/WS 访问保护与安全响应头。

多令牌模式：
- AUTOHUNTER_API_TOKEN：全权限（读写、启停任务、复审、助手等）
- AUTOHUNTER_READ_TOKEN：只读（GET + WebSocket 看板，禁止一切写操作）
- AUTOHUNTER_OBSERVER_TOKEN：观摩（仅安全概览，禁止敏感信息与写操作）
"""
from __future__ import annotations

import hmac
import os
from collections.abc import Mapping
from http.cookies import SimpleCookie

from fastapi import Request

_TOKEN_ENV = "AUTOHUNTER_API_TOKEN"
_READ_TOKEN_ENV = "AUTOHUNTER_READ_TOKEN"
_OBSERVER_TOKEN_ENV = "AUTOHUNTER_OBSERVER_TOKEN"
_AUTH_EXEMPT_PATHS = {"/api/auth/status", "/health", "/favicon.svg", "/favicon.ico"}
# /dpskapi 是本机 ds2api（LLM 代理/管理台）的反代。默认纳入鉴权，避免未授权者
# 白嫖 LLM 算力或直连内网 ds2api 管理面。如需把它当公开 LLM 网关，
# 显式设置 DS2API_PROXY_PUBLIC=1 放行。
_DS2API_PUBLIC = os.environ.get("DS2API_PROXY_PUBLIC", "").strip().lower() in {"1", "true", "yes", "on"}
_AUTH_EXEMPT_PREFIXES: tuple[str, ...] = ("/dpskapi",) if _DS2API_PUBLIC else ()
_AUTH_PROTECTED_PREFIXES = ("/api/",)
_AUTH_PROTECTED_PATHS = {"/docs", "/redoc", "/openapi.json"}
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'"
    ),
}


def configured_full_token() -> str:
    return os.environ.get(_TOKEN_ENV, "").strip()


def configured_read_token() -> str:
    return os.environ.get(_READ_TOKEN_ENV, "").strip()


def configured_observer_token() -> str:
    return os.environ.get(_OBSERVER_TOKEN_ENV, "").strip()


def auth_enabled() -> bool:
    return bool(configured_full_token() or configured_read_token() or configured_observer_token())


def protected_path(path: str) -> bool:
    if path in _AUTH_EXEMPT_PATHS:
        return False
    for prefix in _AUTH_EXEMPT_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return False
    # 未显式放行 DS2API_PROXY_PUBLIC 时，ds2api 反代（/dpskapi 及 /admin 别名）需要鉴权。
    if not _DS2API_PUBLIC and (
        path == "/dpskapi"
        or path.startswith("/dpskapi/")
        or path == "/admin"
        or path.startswith("/admin/")
    ):
        return True
    return path in _AUTH_PROTECTED_PATHS or path.startswith(_AUTH_PROTECTED_PREFIXES)


def _bearer_token(value: str | None) -> str:
    if not value:
        return ""
    prefix = "Bearer "
    return value[len(prefix):].strip() if value.startswith(prefix) else ""


def token_from_headers(headers: Mapping[str, str]) -> str:
    cookie = SimpleCookie()
    try:
        cookie.load(headers.get("cookie", ""))
    except Exception:
        cookie = SimpleCookie()
    return (
        headers.get("x-autohunter-token")
        or _bearer_token(headers.get("authorization"))
        or (cookie.get("ah_api_token").value if cookie.get("ah_api_token") else "")
        or ""
    ).strip()


def resolve_role(token: str | None) -> str | None:
    """返回 full / readonly / observer / None（未认证）。"""
    if not auth_enabled():
        return "full"
    t = str(token or "")
    full = configured_full_token()
    read = configured_read_token()
    observer = configured_observer_token()
    if full and t and hmac.compare_digest(t, full):
        return "full"
    if read and t and hmac.compare_digest(t, read):
        return "readonly"
    if observer and t and hmac.compare_digest(t, observer):
        return "observer"
    return None


def valid_token(token: str | None) -> bool:
    """任意有效令牌（含只读/观摩）。"""
    return resolve_role(token) is not None


def observer_path_allowed(path: str) -> bool:
    """观摩令牌可访问的只读路径白名单。

    观摩只看任务运行概况，不给漏洞证据、报告、设置、情报库、凭证等敏感接口。
    """
    if path in {"/api/auth/status", "/api/tasks"}:
        return True
    if path == "/api/tasks/hard-targets":
        return True
    if not path.startswith("/api/tasks/"):
        return False
    parts = [p for p in path.split("/") if p]
    # /api/tasks/{task_id}
    if len(parts) == 3:
        return True
    # /api/tasks/{task_id}/board 或 /targets
    if len(parts) == 4 and parts[3] in {"board", "targets"}:
        return True
    return False


def request_allowed(request: Request) -> tuple[bool, str | None]:
    """检查请求是否被当前令牌授权。返回 (allowed, role)。"""
    role = resolve_role(token_from_headers(request.headers))
    if role is None:
        return False, None
    if role in {"readonly", "observer"} and request.method not in _READ_METHODS:
        return False, role
    if role == "observer" and not observer_path_allowed(request.url.path):
        return False, role
    return True, role
