"""Shodan 搜索引擎适配。"""
from __future__ import annotations

import httpx

from app.engines.base import EngineResult, SearchEngine, register_engine


@register_engine
class ShodanEngine(SearchEngine):
    @property
    def name(self) -> str:
        return "shodan"

    @property
    def display_name(self) -> str:
        return "Shodan"

    @property
    def env_key_name(self) -> str:
        return "SHODAN"

    def get_default_base_url(self) -> str:
        return "https://api.shodan.io"

    async def search(
        self,
        api_key: str,
        query: str,
        page: int = 1,
        page_size: int = 100,
        base_url: str | None = None,
    ) -> EngineResult:
        if not api_key:
            raise ValueError("缺少 Shodan API Key")
        base = (base_url or self.get_default_base_url()).rstrip("/")
        params = {"key": api_key, "query": query, "page": str(page), "limit": str(min(page_size, 100))}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"{base}/shodan/host/search", params=params)
                data = resp.json()
        except Exception as e:
            raise ValueError(f"Shodan 请求失败: {e}") from e

        if "error" in data:
            raise ValueError(f"Shodan 错误: {data['error']}")

        matches = data.get("matches", [])
        results = []
        for item in matches:
            http_data = item.get("http", {}) if isinstance(item.get("http"), dict) else {}
            title = ""
            if http_data:
                title = http_data.get("title", "")
            hostnames = item.get("hostnames", [])
            host = hostnames[0] if hostnames else item.get("ip_str", "")
            results.append([
                host,
                item.get("ip_str", ""),
                str(item.get("port", "")),
                title,
                host,
                item.get("org", ""),
            ])

        return EngineResult(
            fields=["host", "ip", "port", "title", "domain", "org"],
            results=results,
            size=data.get("total", 0),
            page=page,
            engine="shodan",
        )