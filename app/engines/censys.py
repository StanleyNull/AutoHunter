"""Censys 搜索引擎适配。"""
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
    ) -> EngineResult:
        if not api_key:
            raise ValueError("缺少 Censys API Key")
        # Censys 的 api_key 格式为 "API_ID:SECRET"
        if ":" not in api_key:
            raise ValueError("Censys API Key 格式应为 API_ID:SECRET")
        base = (base_url or self.get_default_base_url()).rstrip("/")
        basic_auth = base64.b64encode(api_key.encode()).decode()
        headers = {"Authorization": f"Basic {basic_auth}"}
        params = {"q": query, "per_page": str(page_size), "page": str(page)}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"{base}/api/v2/hosts/search", params=params, headers=headers)
                data = resp.json()
        except Exception as e:
            raise ValueError(f"Censys 请求失败: {e}") from e

        hits = data.get("result", {}).get("hits", [])
        results = []
        for item in hits:
            ip = item.get("ip", "")
            services = item.get("services", [])
            # 取第一个 HTTP 服务的 title
            title = ""
            hostname = ""
            org = ""
            port = ""
            for svc in services:
                if isinstance(svc, dict):
                    if not port:
                        port = str(svc.get("port", ""))
                    http = svc.get("http", {}) if isinstance(svc.get("http"), dict) else {}
                    if http and http.get("title"):
                        title = http.get("title", "")
                    if svc.get("service_name") == "HTTP" and http:
                        hostname = http.get("host", hostname)
                else:
                    if not port:
                        port = str(svc)
            location = item.get("location", {}) or {}
            org = location.get("country", "") if isinstance(location, dict) else ""
            results.append([
                hostname or ip,
                ip,
                port,
                title,
                hostname,
                org,
            ])

        return EngineResult(
            fields=["host", "ip", "port", "title", "domain", "org"],
            results=results,
            size=data.get("result", {}).get("total", 0),
            page=page,
            engine="censys",
        )