"""Censys 搜索引擎适配。

默认走 Platform API v3（Personal Access Token + CenQL）。
若 Key 仍是旧版 `API_ID:SECRET`，自动回退 Legacy Search v2 hosts。
"""
from __future__ import annotations

import base64
from typing import Any

import httpx

from app.engines.base import EngineResult, SearchEngine, register_engine

_PLATFORM_BASE = "https://api.platform.censys.io"
_LEGACY_BASE = "https://search.censys.io"

_PLATFORM_FIELDS = [
    "host.ip",
    "host.dns.names",
    "host.services.port",
    "host.services.protocol",
    "host.services.transport_protocol",
    "host.autonomous_system.organization",
    "host.services.http.response.html_title",
    "web.hostname",
    "web.resource.hostname",
]


def _is_legacy_key(api_key: str) -> bool:
    """Legacy Search 凭证是 API_ID:SECRET；Platform PAT 通常不含单个冒号分段。"""
    key = (api_key or "").strip()
    if key.count(":") != 1:
        return False
    left, right = key.split(":", 1)
    return bool(left.strip() and right.strip() and len(right.strip()) >= 8)


def _hit_row(hit: dict) -> list[str] | None:
    if not isinstance(hit, dict):
        return None
    host_v1 = hit.get("host_v1") if isinstance(hit.get("host_v1"), dict) else {}
    web_v1 = hit.get("webproperty_v1") if isinstance(hit.get("webproperty_v1"), dict) else {}

    ip, port, title, hostname, org = "", "", "", "", ""

    if host_v1:
        resource = host_v1.get("resource") if isinstance(host_v1.get("resource"), dict) else {}
        ip = str(resource.get("ip") or "")
        dns = resource.get("dns") if isinstance(resource.get("dns"), dict) else {}
        names = dns.get("names") or []
        if isinstance(names, list) and names:
            hostname = str(names[0])
        as_info = resource.get("autonomous_system") if isinstance(resource.get("autonomous_system"), dict) else {}
        org = str(as_info.get("organization") or as_info.get("name") or "")
        matched = host_v1.get("matched_services") or resource.get("services") or []
        if isinstance(matched, list):
            for svc in matched:
                if not isinstance(svc, dict):
                    continue
                if not port:
                    port = str(svc.get("port") or "")
                http = svc.get("http") if isinstance(svc.get("http"), dict) else {}
                resp_obj = http.get("response") if isinstance(http.get("response"), dict) else {}
                html_title = http.get("title") or resp_obj.get("html_title") or ""
                if html_title and not title:
                    title = str(html_title)

    if web_v1:
        resource = web_v1.get("resource") if isinstance(web_v1.get("resource"), dict) else web_v1
        if isinstance(resource, dict):
            hostname = hostname or str(resource.get("hostname") or resource.get("name") or "")
            ip = ip or str(resource.get("ip") or "")
            if not title:
                title = str(resource.get("html_title") or resource.get("title") or "")

    host = hostname or ip
    if not host:
        return None
    return [host, ip, port, title, hostname, org]


def _legacy_row(item: dict) -> list[str]:
    ip = item.get("ip", "")
    services = item.get("services") or []
    title = ""
    hostname = ""
    port = ""
    for svc in services:
        if not isinstance(svc, dict):
            if not port:
                port = str(svc)
            continue
        if not port:
            port = str(svc.get("port", ""))
        http = svc.get("http") if isinstance(svc.get("http"), dict) else {}
        resp_obj = http.get("response") if isinstance(http.get("response"), dict) else {}
        html_title = (
            http.get("title")
            or resp_obj.get("html_title")
            or ""
        )
        if html_title and not title:
            title = str(html_title)
        if svc.get("service_name") in ("HTTP", "HTTPS") and not hostname:
            hostname = str(http.get("host") or "")
    name_keys = item.get("name") or item.get("dns") or {}
    if not hostname and isinstance(name_keys, dict):
        names = name_keys.get("names") or []
        if names:
            hostname = str(names[0])
    as_info = item.get("autonomous_system") or {}
    org = ""
    if isinstance(as_info, dict):
        org = as_info.get("organization") or as_info.get("name") or ""
    return [
        hostname or ip,
        ip,
        port,
        title,
        hostname,
        org,
    ]


@register_engine
class CensysEngine(SearchEngine):
    @property
    def name(self) -> str:
        return "censys"

    @property
    def display_name(self) -> str:
        return "Censys"

    @property
    def env_key_name(self) -> str:
        return "CENSYS"

    def get_default_base_url(self) -> str:
        return _PLATFORM_BASE

    async def search(
        self,
        api_key: str,
        query: str,
        page: int = 1,
        page_size: int = 100,
        base_url: str | None = None,
        cursor: str | None = None,
    ) -> EngineResult:
        if not api_key:
            raise ValueError("缺少 Censys API Key")
        base = (base_url or self.get_default_base_url()).rstrip("/")
        if _is_legacy_key(api_key) or "search.censys.io" in base:
            return await self._search_legacy(api_key, query, page, page_size, base, cursor)
        return await self._search_platform(api_key, query, page_size, base, cursor)

    async def _search_platform(
        self,
        api_key: str,
        query: str,
        page_size: int,
        base: str,
        cursor: str | None,
    ) -> EngineResult:
        if "search.censys.io" in base:
            base = _PLATFORM_BASE
        headers = {
            "Authorization": f"Bearer {api_key.strip()}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "query": query,
            "page_size": min(max(int(page_size or 50), 1), 100),
            "fields": _PLATFORM_FIELDS,
        }
        if cursor:
            payload["page_token"] = cursor
        try:
            async with httpx.AsyncClient(timeout=45, follow_redirects=True) as client:
                resp = await client.post(f"{base}/v3/global/search/query", json=payload, headers=headers)
        except Exception as e:
            raise ValueError(f"Censys 请求失败: {e}") from e
        try:
            data = resp.json()
        except Exception:
            raise ValueError(f"Censys 返回非 JSON (HTTP {resp.status_code}): {(resp.text or '')[:200]}")
        if resp.status_code >= 400:
            err = data.get("error") if isinstance(data, dict) else None
            msg = ""
            if isinstance(err, dict):
                msg = str(err.get("message") or err)
            elif err:
                msg = str(err)
            else:
                msg = str(data.get("message") or data.get("title") or data)[:240]
            raise ValueError(f"Censys 错误 (HTTP {resp.status_code}): {msg}")

        result = (data or {}).get("result") or data or {}
        hits = result.get("hits") or []
        rows = []
        for hit in hits:
            row = _hit_row(hit) if isinstance(hit, dict) else None
            if row:
                rows.append(row)
        next_cursor = result.get("next_page_token") or None
        total = int(result.get("total_hits") or 0)
        return EngineResult(
            fields=["host", "ip", "port", "title", "domain", "org"],
            results=rows,
            size=total,
            page=1,
            engine="censys",
            next_cursor=next_cursor or None,
        )

    async def _search_legacy(
        self,
        api_key: str,
        query: str,
        page: int,
        page_size: int,
        base: str,
        cursor: str | None,
    ) -> EngineResult:
        if ":" not in api_key:
            raise ValueError("Censys 旧版 API Key 格式应为 API_ID:SECRET；新账号请填 Platform Personal Access Token")
        if "api.platform.censys.io" in base or not base:
            base = _LEGACY_BASE
        basic_auth = base64.b64encode(api_key.encode()).decode()
        headers = {"Authorization": f"Basic {basic_auth}"}
        params: dict[str, str] = {
            "q": query,
            "per_page": str(min(int(page_size or 100), 100)),
        }
        if cursor:
            params["cursor"] = cursor
        try:
            async with httpx.AsyncClient(timeout=45, follow_redirects=True) as client:
                resp = await client.get(f"{base}/api/v2/hosts/search", params=params, headers=headers)
                data = resp.json()
        except Exception as e:
            raise ValueError(f"Censys Legacy 请求失败: {e}") from e

        if isinstance(data, dict) and data.get("error"):
            err = data.get("error")
            msg = err.get("message") if isinstance(err, dict) else err
            raise ValueError(f"Censys 错误: {msg}")

        result = (data or {}).get("result") or {}
        hits = result.get("hits") or []
        results = [_legacy_row(item) for item in hits if isinstance(item, dict)]
        links = result.get("links") or {}
        next_cursor = links.get("next") if isinstance(links, dict) else None
        return EngineResult(
            fields=["host", "ip", "port", "title", "domain", "org"],
            results=results,
            size=int(result.get("total") or 0),
            page=page,
            engine="censys",
            next_cursor=next_cursor,
        )
