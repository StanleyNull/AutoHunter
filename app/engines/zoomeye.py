"""ZoomEye 搜索引擎适配（API v2）。"""
from __future__ import annotations

import base64

import httpx

from app.engines.base import EngineResult, SearchEngine, register_engine


def _qbase64(query: str) -> str:
    return base64.b64encode(query.encode("utf-8")).decode("ascii")


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
        # 新官方 API；旧 api.zoomeye.org/web/search 已不适用 v2 语法
        return "https://api.zoomeye.ai"

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
            raise ValueError("缺少 ZoomEye API Key")
        base = (base_url or self.get_default_base_url()).rstrip("/")
        headers = {"API-KEY": api_key, "Content-Type": "application/json"}
        payload = {
            "qbase64": _qbase64(query),
            "page": int(page or 1),
            "pagesize": int(min(page_size or 20, 1000)),
            # web 侧重站点；与 edu/SRC 场景更匹配。用户可用原生语法再收窄。
            "sub_type": "web",
            "fields": "ip,port,domain,hostname,title,url,organization.name",
        }
        try:
            async with httpx.AsyncClient(timeout=45) as client:
                resp = await client.post(f"{base}/v2/search", json=payload, headers=headers)
                data = resp.json()
        except Exception as e:
            raise ValueError(f"ZoomEye 请求失败: {e}") from e

        code = data.get("code")
        # 60000 = success（官方）；兼容少数网关返回 0/200
        if code not in (None, 0, 200, 60000) and not data.get("data"):
            msg = data.get("message") or data.get("error") or str(data)[:200]
            raise ValueError(f"ZoomEye 错误: {msg}")

        items = data.get("data") or data.get("matches") or []
        results = []
        for item in items:
            if not isinstance(item, dict):
                continue
            title = item.get("title") or ""
            if isinstance(title, list):
                title = " | ".join(str(x) for x in title if x)[:200]
            org = ""
            for key in ("organization.name", "org", "organization"):
                val = item.get(key)
                if isinstance(val, dict):
                    org = val.get("name") or ""
                elif val:
                    org = str(val)
                if org:
                    break
            host = (
                item.get("hostname")
                or item.get("domain")
                or item.get("url")
                or item.get("ip")
                or ""
            )
            results.append([
                str(host),
                str(item.get("ip") or ""),
                str(item.get("port") or ""),
                str(title),
                str(item.get("domain") or ""),
                str(org),
            ])

        return EngineResult(
            fields=["host", "ip", "port", "title", "domain", "org"],
            results=results,
            size=int(data.get("total") or 0),
            page=page,
            engine="zoomeye",
        )
