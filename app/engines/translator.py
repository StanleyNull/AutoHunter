"""FOFA 语法解析器：将 FOFA 查询语法解析为结构化中间表示，再翻译成各引擎语法。"""
from __future__ import annotations

import re
from typing import Any


# ── FOFA 词法分析 ─────────────────────────────────────────────

class FofaToken:
    """单个 FOFA 查询条件。"""
    def __init__(self, field: str, op: str, value: str):
        self.field = field.lower().strip()   # title, body, domain, host, ip, port, org, ...
        self.op = op                          # = , !=, =~, !=~
        self.value = value.strip().strip('"').strip("'")

    def __repr__(self) -> str:
        return f"{self.field}{self.op}\"{self.value}\""


class FofaGroup:
    """一组用 && 或 || 连接的 FOFA 条件。"""
    def __init__(self):
        self.tokens: list[FofaToken | FofaGroup] = []
        self.op: str = "&&"  # 连接符


def _tokenize_fofa(query: str) -> list[dict[str, Any]]:
    """将 FOFA 查询拆分成条件列表。
    
    返回 [{field, op, value}, ...]。
    不处理嵌套括号（简单展平），适用于常见 FOFA 语法。
    """
    q = query.strip()
    if not q:
        return []

    results = []
    # 提取所有 field="value" / field!="value" / field=~"value" 模式
    pattern = r'([a-zA-Z_][\w.]*)\s*([!]?=~?|!=)\s*((?:"[^"]*"|\'[^\']*\'))'
    for m in re.finditer(pattern, q):
        field = m.group(1)
        op = m.group(2)
        value = m.group(3).strip('"').strip("'")
        results.append({"field": field, "op": op, "value": value})

    return results


# ── 各引擎翻译 ────────────────────────────────────────────────

# FOFA 字段 → Quake 字段映射
_FOFA_TO_QUAKE = {
    "title": "title",
    "body": "body",
    "domain": "hostname",
    "host": "hostname",
    "ip": "ip",
    "port": "port",
    "org": "org",
    "protocol": "transport",
    "server": "service.name",
    "country": "location.country_code",
    "city": "location.city",
    "header": "service.response_header",
    "app": "service.product_name",
    "os": "service.os",
    "cert.subject.org": "certificate.subject_org",
    # 以下字段 Quake 不直接支持，用近似字段
    "icon_hash": "",
    "after": "",
    "before": "",
}


def fofa_to_quake(query: str) -> str:
    """将 FOFA 语法翻译为 360 Quake 语法。"""
    tokens = _tokenize_fofa(query)
    if not tokens:
        return query

    parts = []
    for t in tokens:
        f = _FOFA_TO_QUAKE.get(t["field"], t["field"])
        if not f:
            continue
        op = t["op"]
        v = t["value"]
        if t["field"] == "port":
            v = v.lstrip("0") or "0"
            parts.append(f"{f}:{v}")
        elif t["field"] in ("domain",):
            # FOFA domain 是后缀匹配；Quake hostname 不支持 *. 通配符，直接裸值
            parts.append(f"{f}:{v}")
        elif op in ("=", "=~"):
            parts.append(f'{f}:"{v}"')
        elif op == "!=":
            parts.append(f'NOT {f}:"{v}"')

    q = " AND ".join(parts) if parts else query
    q = re.sub(r'\s*&&\s*', ' AND ', q)
    q = re.sub(r'\s*\|\|\s*', ' OR ', q)
    return q


# FOFA 字段 → Hunter 字段映射
_FOFA_TO_HUNTER = {
    "title": "web.title",
    "body": "web.body",
    "domain": "domain",
    "host": "host",
    "ip": "ip",
    "port": "port",
    "org": "org",
    "protocol": "protocol",
    "server": "web.server",
    "country": "ip.country",
    "city": "ip.city",
    "app": "web.app",
    "header": "web.header",
    "cert.subject.org": "cert.subject",
}


def fofa_to_hunter(query: str) -> str:
    """将 FOFA 语法翻译为 Hunter (鹰图) 语法。"""
    tokens = _tokenize_fofa(query)
    if not tokens:
        return query

    parts = []
    for t in tokens:
        f = _FOFA_TO_HUNTER.get(t["field"], t["field"])
        op = t["op"]
        v = t["value"]
        if t["field"] == "port":
            parts.append(f'{f}={v}')
        elif op in ("=", "=~"):
            parts.append(f'{f}="{v}"')
        elif op == "!=":
            parts.append(f'{f}!="{v}"')

    q = " && ".join(parts) if parts else query
    return q


# FOFA 字段 → ZoomEye 字段映射
_FOFA_TO_ZOOMEYE = {
    "title": "title",
    "body": "content",
    "domain": "site",
    "host": "hostname",
    "ip": "ip",
    "port": "port",
    "org": "org",
    "protocol": "service",
    "server": "server",
    "country": "country",
    "city": "city",
    "app": "app",
    "header": "headers",
    "os": "os",
}


def fofa_to_zoomeye(query: str) -> str:
    """将 FOFA 语法翻译为 ZoomEye 语法。"""
    tokens = _tokenize_fofa(query)
    if not tokens:
        return query

    parts = []
    for t in tokens:
        f = _FOFA_TO_ZOOMEYE.get(t["field"], t["field"])
        op = t["op"]
        v = t["value"]
        if t["field"] == "port":
            parts.append(f'{f}:{v}')
        elif op in ("=", "=~"):
            parts.append(f'{f}:"{v}"')
        elif op == "!=":
            parts.append(f'-{f}:"{v}"')

    q = " +".join(parts) if parts else query
    return q


# FOFA 字段 → Shodan 字段映射
_FOFA_TO_SHODAN = {
    "title": "title",
    "body": "http.html",
    "domain": "hostname",
    "host": "hostname",
    "ip": "ip",
    "port": "port",
    "org": "org",
    "protocol": "http",
    "server": "http.server",
    "country": "country",
    "city": "city",
    "app": "product",
    "os": "os",
    "header": "http.response_header",
    "cert.subject.org": "ssl.cert.subject.cn",
    "cert.issuer.org": "ssl.cert.issuer.cn",
}


def fofa_to_shodan(query: str) -> str:
    """将 FOFA 语法翻译为 Shodan 语法。"""
    tokens = _tokenize_fofa(query)
    if not tokens:
        return query

    parts = []
    for t in tokens:
        f = _FOFA_TO_SHODAN.get(t["field"], t["field"])
        op = t["op"]
        v = t["value"]
        if t["field"] == "port":
            parts.append(f'{f}:{v}')
        elif op in ("=", "=~"):
            parts.append(f'{f}:"{v}"')
        elif op == "!=":
            parts.append(f'-{f}:"{v}"')

    q = " ".join(parts) if parts else query
    return q


# FOFA 字段 → Censys 字段映射
_FOFA_TO_CENSYS = {
    "title": "services.http.response.html_title",
    "body": "services.http.response.body",
    "domain": "dns.names",
    "host": "dns.names",
    "ip": "ip",
    "port": "services.port",
    "org": "location.country",
    "protocol": "services.service_name",
    "server": "services.http.response.headers.server",
    "country": "location.country",
    "city": "location.city",
    "app": "services.software.product",
    "os": "services.software.operating_system",
    "cert.subject.org": "services.tls.certificates.leaf_data.subject.organization",
    "cert.issuer.org": "services.tls.certificates.leaf_data.issuer.organization",
}


def fofa_to_censys(query: str) -> str:
    """将 FOFA 语法翻译为 Censys 语法。"""
    tokens = _tokenize_fofa(query)
    if not tokens:
        return query

    parts = []
    for t in tokens:
        f = _FOFA_TO_CENSYS.get(t["field"], t["field"])
        op = t["op"]
        v = t["value"]
        if t["field"] == "port":
            v = v.lstrip("0") or "0"
            parts.append(f'{f}:{v}')
        elif op in ("=", "=~"):
            parts.append(f'{f}:"{v}"')
        elif op == "!=":
            parts.append(f'NOT {f}:"{v}"')

    q = " AND ".join(parts) if parts else query
    q = re.sub(r'\s*&&\s*', ' AND ', q)
    q = re.sub(r'\s*\|\|\s*', ' OR ', q)
    return q


# ── 引擎分发表 ────────────────────────────────────────────────

_FOFA_TRANSLATORS = {
    "quake": fofa_to_quake,
    "hunter": fofa_to_hunter,
    "zoomeye": fofa_to_zoomeye,
    "shodan": fofa_to_shodan,
    "censys": fofa_to_censys,
}


def translate_fofa_query(query: str, target_engine: str) -> str:
    """将 FOFA 语法翻译为目标引擎语法。若目标引擎为 fofa 则原样返回。"""
    if not query or target_engine == "fofa":
        return query
    translator = _FOFA_TRANSLATORS.get(target_engine)
    if translator is None:
        return query
    try:
        return translator(query)
    except Exception:
        return query