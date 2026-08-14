"""360 Quake 搜索引擎适配。"""
from __future__ import annotations

import json
import re
from typing import Any

import httpx

from app.engines.base import EngineResult, SearchEngine, register_engine


class QuakeRateLimitError(ValueError):
    """Quake API 频率限制错误，调用方应延迟重试。"""
    def __init__(self, message: str, retry_after: float = 5.0):
        super().__init__(message)
        self.retry_after = retry_after


_RATE_LIMIT_PATTERNS = re.compile(
    r"调用API过于频繁|请求太频繁|rate limit|too many|q3005",
    re.I,
)

# 注册用户可返回的字段；不主动要 service.response（会员字段），标题走 service.http.title
_INCLUDE_FIELDS = [
    "ip", "port", "hostname", "org", "domain", "asn",
    "service.name", "service.http.host", "service.http.title", "service.http.server",
]


def _ok_code(code: Any) -> bool:
    return code in (0, "0", None)


def extract_quake_row(item: dict) -> list[str]:
    """把一条 Quake service 记录抽成统一 [host, ip, port, title, domain, org]。"""
    service = item.get("service") or {}
    if not isinstance(service, dict):
        service = {}
    http = service.get("http") if isinstance(service.get("http"), dict) else {}
    title = str(http.get("title") or "").strip()
    if not title:
        # 兼容旧数据：偶尔仍带 response 文本
        resp_text = service.get("response") or ""
        if isinstance(resp_text, str):
            for line in resp_text.split("\n"):
                if line.lower().startswith("<title>"):
                    title = line[7:].rsplit("</", 1)[0].strip()
                    break
    if not title:
        title = str(service.get("name") or "")
    host = (
        str(http.get("host") or "").strip()
        or str(item.get("hostname") or "").strip()
        or str(item.get("domain") or "").strip()
        or str(item.get("ip") or "")
    )
    domain = str(item.get("domain") or host)
    return [
        host,
        str(item.get("ip") or ""),
        str(item.get("port") or ""),
        title,
        domain,
        str(item.get("org") or ""),
    ]


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
        # 官网已迁 .net；.cn 会 308 到这里
        return "https://quake.360.net"

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
            raise ValueError("缺少 Quake API Key")
        base = (base_url or self.get_default_base_url()).rstrip("/")
        url = f"{base}/api/v3/search/quake_service"
        headers = {"X-QuakeToken": api_key, "Content-Type": "application/json; charset=utf-8"}
        payload = {
            "query": query,
            "start": max(0, (page - 1) * page_size),
            "size": min(max(int(page_size or 10), 1), 100),
            "include": _INCLUDE_FIELDS,
        }
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            async with httpx.AsyncClient(timeout=45, follow_redirects=True) as client:
                resp = await client.post(url, content=body, headers=headers)
        except Exception as e:
            raise ValueError(f"Quake 请求失败: {e}") from e

        try:
            data = resp.json()
        except Exception:
            snippet = (resp.text or "")[:240].replace("\n", " ")
            raise ValueError(
                f"Quake 返回非 JSON (HTTP {resp.status_code}): {snippet or '(空响应)'}"
            )

        if not isinstance(data, dict):
            raise ValueError(f"Quake 响应格式异常: {type(data).__name__}")

        code = data.get("code")
        if not _ok_code(code):
            msg = str(data.get("message") or data.get("data") or data)[:300]
            if _RATE_LIMIT_PATTERNS.search(msg) or str(code).lower() in ("q3005", "q3015"):
                raise QuakeRateLimitError(f"Quake 频率限制: {msg}")
            raise ValueError(f"Quake 错误[{code}]: {msg}")

        if resp.status_code >= 400:
            raise ValueError(f"Quake HTTP {resp.status_code}: {data.get('message') or resp.text[:200]}")

        items = data.get("data") or []
        if not isinstance(items, list):
            items = []
        meta = data.get("meta") or {}
        pagination = meta.get("pagination") if isinstance(meta, dict) else {}
        total = 0
        if isinstance(pagination, dict):
            total = int(pagination.get("total") or 0)

        results = []
        for item in items:
            if isinstance(item, dict):
                results.append(extract_quake_row(item))

        return EngineResult(
            fields=["host", "ip", "port", "title", "domain", "org"],
            results=results,
            size=total or len(results),
            page=page,
            engine="quake",
        )
