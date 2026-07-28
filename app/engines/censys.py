"""Censys 搜索引擎适配（Legacy Search API v2 hosts）。"""
from __future__ import annotations

import base64

import httpx

from app.engines.base import EngineResult, SearchEngine, register_engine


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
        return "https://search.censys.io"

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
        # Censys 的 api_key 格式为 "API_ID:SECRET"
        if ":" not in api_key:
            raise ValueError("Censys API Key 格式应为 API_ID:SECRET")
        base = (base_url or self.get_default_base_url()).rstrip("/")
        basic_auth = base64.b64encode(api_key.encode()).decode()
        headers = {"Authorization": f"Basic {basic_auth}"}
        # v2 用 cursor 翻页，没有 page 参数
        params: dict[str, str] = {
            "q": query,
            "per_page": str(min(int(page_size or 100), 100)),
        }
        if cursor:
            params["cursor"] = cursor
        try:
            async with httpx.AsyncClient(timeout=45) as client:
                resp = await client.get(f"{base}/api/v2/hosts/search", params=params, headers=headers)
                data = resp.json()
        except Exception as e:
            raise ValueError(f"Censys 请求失败: {e}") from e

        if isinstance(data, dict) and data.get("error"):
            err = data.get("error")
            msg = err.get("message") if isinstance(err, dict) else err
            raise ValueError(f"Censys 错误: {msg}")

        result = (data or {}).get("result") or {}
        hits = result.get("hits") or []
        results = []
        for item in hits:
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
                # legacy / v2 字段差异兼容
                resp_obj = http.get("response") if isinstance(http.get("response"), dict) else {}
                html_title = (
                    http.get("title")
                    or resp_obj.get("html_title")
                    or (resp_obj.get("body") or "")[:80]
                )
                if html_title and not title:
                    title = str(html_title)
                if svc.get("service_name") in ("HTTP", "HTTPS") and not hostname:
                    hostname = str(http.get("host") or "")
            name_keys = item.get("name") or item.get("dns", {}) or {}
            if not hostname and isinstance(name_keys, dict):
                names = name_keys.get("names") or []
                if names:
                    hostname = str(names[0])
            as_info = item.get("autonomous_system") or {}
            org = ""
            if isinstance(as_info, dict):
                org = as_info.get("organization") or as_info.get("name") or ""
            if not org:
                loc = item.get("location") or {}
                if isinstance(loc, dict):
                    org = loc.get("country") or ""
            results.append([
                hostname or ip,
                ip,
                port,
                title,
                hostname,
                org,
            ])

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
