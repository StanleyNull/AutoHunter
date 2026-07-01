"""可选：将 /dpskapi 反代到一个 OpenAI 兼容上游（默认关闭）。

默认不启用此代理，推荐直接在设置里填官方/自建 LLM 的 base_url。
仅当你确实需要把某个上游挂在 /dpskapi 下时，设 DS2API_PROXY_ENABLED=1
并配置 DS2API_UPSTREAM 即可启用。
"""
from __future__ import annotations

import os

import httpx
from fastapi import APIRouter, Request, Response
from starlette.responses import StreamingResponse

PREFIX = "/dpskapi"
UPSTREAM = os.environ.get("DS2API_UPSTREAM", "http://127.0.0.1:5001").rstrip("/")
# 默认关闭：不依赖任何外部代理服务，直连官方/自建 LLM API。
ENABLED = os.environ.get("DS2API_PROXY_ENABLED", "0").lower() not in {"0", "false", "no", "off"}
REQUEST_TIMEOUT = httpx.Timeout(
    float(os.environ.get("DS2API_PROXY_TIMEOUT", "60")),
    connect=float(os.environ.get("DS2API_PROXY_CONNECT_TIMEOUT", "10")),
    read=float(os.environ.get("DS2API_PROXY_READ_TIMEOUT", "60")),
    write=float(os.environ.get("DS2API_PROXY_WRITE_TIMEOUT", "30")),
    pool=float(os.environ.get("DS2API_PROXY_POOL_TIMEOUT", "10")),
)
MAX_REWRITE_BODY_BYTES = int(os.environ.get("DS2API_PROXY_MAX_REWRITE_BODY_BYTES", str(5 * 1024 * 1024)))

_HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
})

router = APIRouter(include_in_schema=False)


def is_ds2api_path(path: str) -> bool:
    return path == PREFIX or path.startswith(PREFIX + "/")


def _upstream_url(path: str, query: str) -> str:
    sub = path.lstrip("/")
    url = f"{UPSTREAM}/{sub}" if sub else f"{UPSTREAM}/"
    if query:
        return f"{url}?{query}"
    return url


def _forward_headers(request: Request) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in request.headers.items():
        lk = key.lower()
        if lk in _HOP_HEADERS or lk == "host":
            continue
        out[key] = value
    return out


def _rewrite_admin_assets(content: bytes, content_type: str, mount_prefix: str) -> bytes | None:
    """让 ds2api /admin 管理台可以挂在 /dpskapi/admin 下。

    ds2api WebUI 是用 Vite base=/admin/ 构建的，HTML 和动态 import
    会引用绝对路径 /admin/...。AutoHunter 对外只暴露 /dpskapi，所以需要
    把这些路径改写成 /dpskapi/admin/...。
    """
    if not (
        "text/html" in content_type
        or "javascript" in content_type
        or "application/ecmascript" in content_type
    ):
        return None
    text = content.decode("utf-8", errors="ignore")
    admin_prefix = f"{mount_prefix}/admin"
    changed = False
    if "/admin/" in text:
        text = text.replace("/admin/", f"{admin_prefix}/")
        changed = True
    # React Router basename is emitted as basename:`/admin` (without trailing slash).
    # If left untouched, /dpskapi/admin renders a black empty root.
    for quote in ("`", '"', "'"):
        old = f"{quote}/admin{quote}"
        if old in text:
            text = text.replace(old, f"{quote}{admin_prefix}{quote}")
            changed = True
    if not changed:
        return None
    return text.encode("utf-8")


@router.api_route(
    PREFIX,
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
@router.api_route(
    f"{PREFIX}/{{path:path}}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def proxy_ds2api(request: Request, path: str = "", mount_prefix: str = PREFIX) -> Response:
    if not ENABLED:
        return Response(status_code=503, content="ds2api proxy disabled")

    upstream_url = _upstream_url(path, request.url.query)
    body = await request.body()
    headers = _forward_headers(request)

    client = httpx.AsyncClient(timeout=REQUEST_TIMEOUT)
    try:
        req = client.build_request(request.method, upstream_url, headers=headers, content=body)
        upstream = await client.send(req, stream=True)
    except httpx.RequestError as exc:
        await client.aclose()
        return Response(
            status_code=502,
            content=f"ds2api upstream unreachable ({UPSTREAM}): {exc}",
            media_type="text/plain; charset=utf-8",
        )

    out_headers = {
        k: v for k, v in upstream.headers.items()
        if k.lower() not in _HOP_HEADERS
    }
    content_type = upstream.headers.get("content-type", "")

    # ds2api 管理台需要路径重写，不能按流式原样返回。
    if path == "admin" or path.startswith("admin/"):
        try:
            content = await _read_limited(upstream)
        except httpx.HTTPError as exc:
            await upstream.aclose()
            await client.aclose()
            return Response(
                status_code=502,
                content=f"ds2api upstream read failed ({UPSTREAM}): {exc}",
                media_type="text/plain; charset=utf-8",
            )
        rewritten = _rewrite_admin_assets(content, content_type, mount_prefix)
        await upstream.aclose()
        await client.aclose()
        if rewritten is not None:
            content = rewritten
            out_headers.pop("content-length", None)
            out_headers.pop("Content-Length", None)
        return Response(
            content=content,
            status_code=upstream.status_code,
            headers=out_headers,
            media_type=content_type or None,
        )

    async def body_iter():
        try:
            async for chunk in upstream.aiter_bytes():
                yield chunk
        finally:
            await upstream.aclose()
            await client.aclose()

    return StreamingResponse(
        body_iter(),
        status_code=upstream.status_code,
        headers=out_headers,
        media_type=content_type,
    )


async def _read_limited(resp: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in resp.aiter_bytes():
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_REWRITE_BODY_BYTES:
            raise httpx.ReadError(
                f"ds2api rewrite body exceeds {MAX_REWRITE_BODY_BYTES} bytes",
                request=resp.request,
            )
        chunks.append(chunk)
    return b"".join(chunks)


@router.api_route(
    "/admin",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
@router.api_route(
    "/admin/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def proxy_ds2api_admin_alias(request: Request, path: str = "") -> Response:
    """兼容 ds2api 管理台硬编码的 /admin/* 资源路径。

    对外推荐 /dpskapi/admin；这里保留 /admin alias，避免浏览器缓存、
    Vite 动态 import 或第三方资源仍请求 /admin/* 时出现黑屏。
    """
    upstream_path = "admin" if not path else f"admin/{path}"
    return await proxy_ds2api(request, upstream_path, mount_prefix="")
