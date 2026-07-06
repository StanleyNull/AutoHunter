"""Hunter (鹰图) 搜索引擎适配。"""
from __future__ import annotations

import httpx

from app.engines.base import EngineResult, SearchEngine, register_engine


@register_engine
class HunterEngine(SearchEngine):
    @property
    def name(self) -> str:
        return "hunter"

    @property
    def display_name(self) -> str:
        return "Hunter (鹰图)"

    @property
    def env_key_name(self) -> str:
        return "HUNTER"

    def get_default_base_url(self) -> str:
        return "https://hunter.qianxin.com"

    async def search(
        self,
        api_key: str,
        query: str,
        page: int = 1,
        page_size: int = 100,
        base_url: str | None = None,
    ) -> EngineResult:
        if not api_key:
            raise ValueError("缺少 Hunter API Key")
        base = (base_url or self.get_default_base_url()).rstrip("/")
        params = {
            "api-key": api_key,
            "search": query,
            "page": str(page),
            "page_size": str(page_size),
            "is_web": "1",
            "status_code": "200",
        }
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"{base}/api/v1/search", params=params)
                data = resp.json()
        except Exception as e:
            raise ValueError(f"Hunter 请求失败: {e}") from e

        # 猎鹰返回 code=200 表示成功
        if data.get("code") != 200:
            msg = data.get("message", str(data.get("data", "")))
            raise ValueError(f"Hunter 错误: {msg}")

        items = data.get("data", {}).get("arr", [])
        results = []
        for item in items:
            url = item.get("url", "")
            host = item.get("domain") or item.get("ip", "")
            results.append([
                host,
                item.get("ip", ""),
                str(item.get("port", "")),
                item.get("title", ""),
                item.get("domain", ""),
                item.get("company_name", ""),
            ])

        return EngineResult(
            fields=["host", "ip", "port", "title", "domain", "org"],
            results=results,
            size=data.get("data", {}).get("total", 0),
            page=page,
            engine="hunter",
        )