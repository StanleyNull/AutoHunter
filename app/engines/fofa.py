"""FOFA 搜索引擎适配。"""
from __future__ import annotations

import base64
import os
from typing import Any

import httpx

from app.engines.base import EngineResult, SearchEngine, register_engine

BASE = "https://fofa.info"

# 允许指向内网/私有的 FOFA base_url 白名单
_FOFA_ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("FOFA_ALLOWED_HOSTS", "").split(",")
    if h.strip()
}


class FofaError(Exception):
    def __init__(self, message: str, account_error: bool = False):
        super().__init__(message)
        self.account_error = account_error


_FOFA_ACCOUNT_ERROR_MARKERS = (
    "820000", "820001", "-700", "账号无效", "账号已过期", "账号过期",
    "无效的fofa", "无效的 fofa", "f点不足", "f币不足", "余额不足", "配额",
    "权限不足", "没有权限", "会员", "account invalid", "invalid key",
    "expired", "insufficient", "quota", "permission", "unauthorized", "forbidden",
)


def _is_account_error(errmsg: str) -> bool:
    text = str(errmsg or "").lower()
    return any(m in text for m in _FOFA_ACCOUNT_ERROR_MARKERS)


def _qbase64(query: str) -> str:
    return base64.b64encode(query.encode("utf-8")).decode("ascii")


@register_engine
class FofaEngine(SearchEngine):
    @property
    def name(self) -> str:
        return "fofa"

    @property
    def display_name(self) -> str:
        return "FOFA"

    @property
    def env_key_name(self) -> str:
        return "FOFA"

    def get_default_base_url(self) -> str:
        return BASE

    async def search(
        self,
        api_key: str,
        query: str,
        page: int = 1,
        page_size: int = 100,
        base_url: str | None = None,
    ) -> EngineResult:
        if not api_key:
            raise FofaError("缺少 FOFA key")
        base = (base_url or BASE).rstrip("/")
        # SSRF 防护
        from app.tools.netguard import SsrfBlocked, assert_safe_outbound_url
        try:
            assert_safe_outbound_url(
                f"{base}/api/v1/search/all", allow_extra_hosts=_FOFA_ALLOWED_HOSTS
            )
        except SsrfBlocked as e:
            raise FofaError(f"FOFA base_url 不被允许：{e}") from e

        fields = "host,ip,port,title,domain,org"
        params = {
            "key": api_key, "qbase64": _qbase64(query),
            "fields": fields, "page": str(page), "size": str(page_size), "full": "false",
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
            raise FofaError(f"FOFA 请求失败: {type(e).__name__}: {e}") from e

        if data.get("error"):
            errmsg = data.get("errmsg")
            raise FofaError(f"FOFA 错误: {errmsg}", account_error=_is_account_error(errmsg))

        return EngineResult(
            fields=fields.split(","),
            results=data.get("results", []),
            size=data.get("size", 0),
            page=page,
            engine="fofa",
        )