"""FOFA 官方 API 客户端（移植自项目已有 fofa-team 逻辑）。"""
from __future__ import annotations

import base64
from typing import Any

import httpx

BASE = "https://fofa.info"


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
