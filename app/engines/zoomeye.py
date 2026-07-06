"""ZoomEye 搜索引擎适配。"""
from __future__ import annotations

import httpx

from app.engines.base import EngineResult, SearchEngine, register_engine


@register_engine
class ZoomEyeEngine(SearchEngine):
    @property
    def name(self) -> str:
        return "zoomeye"

    @property
    def display_name(self) -> str:
        return "ZoomEye"

    @property
    def env_key_name(self) -> str:
        return "ZOOMEYE"

    def get_default_base_url(self) -> str:
        return "https://api.zoomeye.org"

    async def search(
        self,
        api_key: str,
        query: str,
        page: int = 1,
        page_size: int = 100,
        base_url: str | None = None,
    ) -> EngineResult:
        if not api_key:
            raise ValueError("缺少 ZoomEye API Key")
        base = (base_url or self.get_default_base_url()).rstrip("/")

        # ZoomEye 同时支持 web / host 搜索，优先 web（侧重 Web 应用）
        params = {"query": query, "page": str(page), "size": str(page_size)}
        headers = {"API-KEY": api_key}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"{base}/web/search", params=params, headers=headers)
                data = resp.json()
        except Exception as e:
            raise ValueError(f"ZoomEye 请求失败: {e}") from e

        matches = data.get("matches", [])
        results = []
        for item in matches:
            site_info = item.get("site", {}) if isinstance(item.get("site"), dict) else {}
            results.append([
                site_info.get("host", item.get("ip", "")),
                item.get("ip", ""),
                str(item.get("port", "")),
                item.get("title", ""),
                site_info.get("domain", item.get("domain", "")),
                item.get("geoinfo", {}).get("org", "") if isinstance(item.get("geoinfo"), dict) else "",
            ])

        return EngineResult(
            fields=["host", "ip", "port", "title", "domain", "org"],
            results=results,
            size=data.get("total", 0),
            page=page,
            engine="zoomeye",
        )