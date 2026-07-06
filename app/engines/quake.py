"""360 Quake 搜索引擎适配。"""
from __future__ import annotations

import httpx

from app.engines.base import EngineResult, SearchEngine, register_engine


@register_engine
class QuakeEngine(SearchEngine):
    @property
    def name(self) -> str:
        return "quake"

    @property
    def display_name(self) -> str:
        return "360 Quake"

    @property
    def env_key_name(self) -> str:
        return "QUAKE"

    def get_default_base_url(self) -> str:
        return "https://quake.360.net"

    async def search(
        self,
        api_key: str,
        query: str,
        page: int = 1,
        page_size: int = 100,
        base_url: str | None = None,
    ) -> EngineResult:
        if not api_key:
            raise ValueError("缺少 Quake API Key")
        base = (base_url or self.get_default_base_url()).rstrip("/")
        url = f"{base}/api/v3/search/quake_service"
        headers = {"X-QuakeToken": api_key, "Content-Type": "application/json"}
        payload = {"query": query, "start": (page - 1) * page_size, "size": page_size}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(url, json=payload, headers=headers)
                data = resp.json()
        except Exception as e:
            raise ValueError(f"Quake 请求失败: {e}") from e

        if data.get("code") != 0:
            msg = data.get("message", str(data.get("data", "")))
            raise ValueError(f"Quake 错误: {msg}")

        items = data.get("data", {}).get("items", [])
        results = []
        for item in items:
            host = item.get("hostname") or item.get("ip", "")
            port = str(item.get("port", ""))
            results.append([
                host,
                item.get("ip", ""),
                port,
                item.get("service", {}).get("title", "") if isinstance(item.get("service"), dict) else "",
                host,
                item.get("org", ""),
            ])

        return EngineResult(
            fields=["host", "ip", "port", "title", "domain", "org"],
            results=results,
            size=data.get("data", {}).get("total", 0),
            page=page,
            engine="quake",
        )