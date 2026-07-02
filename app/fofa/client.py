"""FOFA 官方 API 客户端（移植自项目已有 fofa-team 逻辑）。"""
from __future__ import annotations

import base64
import os
from typing import Any

import httpx

BASE = "https://fofa.info"

# 允许指向内网/私有的 FOFA base_url 白名单（私有部署/镜像场景，逗号分隔的 host）。
# 默认空——即默认阻断把携带 FOFA key 的请求发往内网/云元数据。
_FOFA_ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("FOFA_ALLOWED_HOSTS", "").split(",")
    if h.strip()
}


class FofaError(Exception):
    pass


def _qbase64(query: str) -> str:
    return base64.b64encode(query.encode("utf-8")).decode("ascii")


async def search(key: str, query: str, page: int = 1, size: int = 100,
                 fields: str = "host,ip,port,title,domain,org",
                 base_url: str | None = None) -> dict[str, Any]:
    """调用 FOFA search/all，返回 {results: [...], size, page}。

    base_url 留空则用官方 https://fofa.info；可传入私有部署/镜像/代理网关地址。
    """
    if not key:
        raise FofaError("缺少 FOFA key")
    base = (base_url or BASE).rstrip("/")
    # 请求会把真实 FOFA key 放进 query，必须防 SSRF（篡改 base_url 外泄 key）。
    # 私有 FOFA 部署可通过 FOFA_ALLOWED_HOSTS 显式放行。
    from app.tools.netguard import SsrfBlocked, assert_safe_outbound_url

    try:
        assert_safe_outbound_url(
            f"{base}/api/v1/search/all", allow_extra_hosts=_FOFA_ALLOWED_HOSTS
        )
    except SsrfBlocked as e:
        raise FofaError(f"FOFA base_url 不被允许：{e}") from e
    params = {
        "key": key, "qbase64": _qbase64(query),
        "fields": fields, "page": str(page), "size": str(size), "full": "false",
    }
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"{base}/api/v1/search/all", params=params)
            try:
                data = resp.json()
            except Exception:
                raise FofaError(f"FOFA 返回非 JSON (HTTP {resp.status_code}): {resp.text[:200]}")
    except FofaError:
        raise
    except httpx.HTTPError as e:
        # 网络抖动/超时/连接失败等统一包装成 FofaError，避免裸 httpx 异常
        # 一路冒到 orchestrator 主循环（外部 API 不可用是常态，应降级而非告警）。
        raise FofaError(f"FOFA 请求失败: {type(e).__name__}: {e}") from e
    if data.get("error"):
        raise FofaError(f"FOFA 错误: {data.get('errmsg')}")
    return {
        "fields": fields.split(","),
        "results": data.get("results", []),
        "size": data.get("size", 0),
        "page": page,
    }
