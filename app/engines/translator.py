"""FOFA 语法解析器：将 FOFA 查询语法解析为结构化中间表示，再翻译成各引擎原生语法。

产品约定：任务框统一按 FOFA 语法书写；collector 在调用非 FOFA 引擎前必须走本模块翻译。
若输入本身不像 FOFA（解析不到 field= / != / =~ 条件），则原样透传，避免误伤用户原生语法。
"""
from __future__ import annotations

import re
from typing import Any


# field 操作符 value；value 可为双引号 / 单引号 / 无空格裸值
_TOKEN_RE = re.compile(
    r'([a-zA-Z_][\w.]*)\s*(!=~|!=|=~|==|=)\s*'
    r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s&|()]+)'
)


def parse_fofa_query(query: str) -> tuple[list[dict[str, str]], list[str]]:
    """解析 FOFA 风格条件，保留条件之间的 && / ||。

    返回 (tokens, joins)：
      tokens: [{field, op, value}, ...]
      joins:  长度 len(tokens)-1，元素为 '&&' 或 '||'
    """
    q = (query or "").strip()
    if not q:
        return [], []

    matches = list(_TOKEN_RE.finditer(q))
    if not matches:
        return [], []

    tokens: list[dict[str, str]] = []
    joins: list[str] = []
    for i, m in enumerate(matches):
        raw_val = m.group(3)
        if (raw_val.startswith('"') and raw_val.endswith('"')) or (
            raw_val.startswith("'") and raw_val.endswith("'")
        ):
            value = raw_val[1:-1].replace(r"\"", '"').replace(r"\'", "'").replace(r"\\", "\\")
        else:
            value = raw_val
        tokens.append({
            "field": m.group(1).lower().strip(),
            "op": m.group(2),
            "value": value,
        })
        if i > 0:
            between = q[matches[i - 1].end(): m.start()]
            joins.append("||" if "||" in between else "&&")
    return tokens, joins


def _join_parts(parts: list[str], joins: list[str], and_word: str, or_word: str) -> str:
    if not parts:
        return ""
    out = [parts[0]]
    for i, part in enumerate(parts[1:]):
        op = joins[i] if i < len(joins) else "&&"
        out.append(f" {or_word if op == '||' else and_word} ")
        out.append(part)
    return "".join(out)


def _eq_ops(op: str) -> bool:
    return op in ("=", "==", "=~")


def _neq_ops(op: str) -> bool:
    return op in ("!=", "!=~")


# ── Quake ────────────────────────────────────────────────────
# 官方 DSL：field:value / field:"value"，逻辑 AND / OR / NOT
# domain 是独立字段（勿映射成 hostname）；protocol → service.name
_FOFA_TO_QUAKE = {
    "title": "title",
    "body": "body",
    "domain": "domain",
    "host": "hostname",
    "ip": "ip",
    "port": "port",
    "org": "org",
    "protocol": "service",
    "server": "server",
    "country": "country",
    "city": "city",
    "header": "headers",
    "app": "app",
    "os": "os",
    "cert": "cert",
    "cert.subject": "cert",
    "cert.subject.cn": "cert",
    "cert.subject.org": "cert",
    "icon_hash": "favicon",
    "icp": "icp",
    "base_protocol": "transport",
}


def fofa_to_quake(query: str) -> str:
    tokens, joins = parse_fofa_query(query)
    if not tokens:
        return query

    parts: list[str] = []
    kept_joins: list[str] = []
    for i, t in enumerate(tokens):
        f = _FOFA_TO_QUAKE.get(t["field"])
        if f is None:
            # 未知字段：尽量透传字段名（Quake 也可能认识）
            f = t["field"]
        if f == "":
            continue
        op, v = t["op"], t["value"]
        if t["field"] == "port":
            v = (v.lstrip("0") or "0")
            piece = f"{f}:{v}"
        elif t["field"] in ("ip",) and "/" not in v:
            piece = f"{f}:\"{v}\"" if _eq_ops(op) else f"NOT {f}:\"{v}\""
        elif _eq_ops(op):
            piece = f'{f}:"{v}"'
        elif _neq_ops(op):
            piece = f'NOT {f}:"{v}"'
        else:
            continue
        if parts:
            kept_joins.append(joins[i - 1] if i - 1 < len(joins) else "&&")
        parts.append(piece)
    return _join_parts(parts, kept_joins, "AND", "OR") or query


# ── Hunter (鹰图) ─────────────────────────────────────────────
# 语法接近 FOFA：field="value"，&& / ||；常用 web.title / domain.suffix
_FOFA_TO_HUNTER = {
    "title": "web.title",
    "body": "web.body",
    "domain": "domain.suffix",
    "host": "domain",
    "ip": "ip",
    "port": "port",
    "org": "ip.company",
    "protocol": "protocol",
    "server": "header.server",
    "country": "ip.country",
    "city": "ip.city",
    "app": "web.app",
    "header": "header",
    "os": "os",
    "cert": "cert",
    "cert.subject": "cert.subject",
    "cert.subject.cn": "cert.subject",
    "cert.subject.org": "cert.subject_org",
    "icon_hash": "web.icon",
    "icp": "icp.number",
    "status_code": "web.status_code",
}


def fofa_to_hunter(query: str) -> str:
    tokens, joins = parse_fofa_query(query)
    if not tokens:
        return query

    parts: list[str] = []
    kept_joins: list[str] = []
    for i, t in enumerate(tokens):
        f = _FOFA_TO_HUNTER.get(t["field"], t["field"])
        op, v = t["op"], t["value"]
        # Hunter: = 模糊，== 精确；FOFA =~ 接近模糊 =
        if t["field"] == "port":
            piece = f'{f}="{v}"' if _eq_ops(op) else f'{f}!="{v}"'
        elif op == "==":
            piece = f'{f}=="{v}"'
        elif op in ("=", "=~"):
            piece = f'{f}="{v}"'
        elif op == "!==":
            piece = f'{f}!=="{v}"'
        elif _neq_ops(op):
            piece = f'{f}!="{v}"'
        else:
            continue
        if parts:
            kept_joins.append(joins[i - 1] if i - 1 < len(joins) else "&&")
        parts.append(piece)
    return _join_parts(parts, kept_joins, "&&", "||") or query


# ── ZoomEye（v2 语法已对齐 FOFA：field="value" &&/||）────────
_FOFA_TO_ZOOMEYE = {
    "title": "title",
    "body": "body",
    "domain": "domain",
    "host": "hostname",
    "ip": "ip",
    "port": "port",
    "org": "org",
    "protocol": "service",
    "server": "server",
    "country": "country",
    "city": "city",
    "app": "app",
    "header": "header",
    "os": "os",
    "cert": "ssl",
    "icon_hash": "iconhash",
}


def fofa_to_zoomeye(query: str) -> str:
    tokens, joins = parse_fofa_query(query)
    if not tokens:
        return query

    parts: list[str] = []
    kept_joins: list[str] = []
    for i, t in enumerate(tokens):
        f = _FOFA_TO_ZOOMEYE.get(t["field"], t["field"])
        op, v = t["op"], t["value"]
        if t["field"] == "port":
            piece = f'{f}={v}' if _eq_ops(op) else f'{f}!={v}'
        elif op == "==":
            piece = f'{f}=="{v}"'
        elif _eq_ops(op):
            piece = f'{f}="{v}"'
        elif _neq_ops(op):
            piece = f'{f}!="{v}"'
        else:
            continue
        if parts:
            kept_joins.append(joins[i - 1] if i - 1 < len(joins) else "&&")
        parts.append(piece)
    return _join_parts(parts, kept_joins, "&&", "||") or query


# ── Shodan ────────────────────────────────────────────────────
# filter:value，空格连接；否定前缀 -
_FOFA_TO_SHODAN = {
    "title": "http.title",
    "body": "http.html",
    "domain": "hostname",
    "host": "hostname",
    "ip": "net",
    "port": "port",
    "org": "org",
    "protocol": "",  # 无对等 filter；常见 http/https 由其它条件覆盖
    "server": "product",
    "country": "country",
    "city": "city",
    "app": "product",
    "os": "os",
    "header": "http.component",
    "cert": "ssl",
    "cert.subject": "ssl.cert.subject.cn",
    "cert.subject.cn": "ssl.cert.subject.cn",
    "cert.subject.org": "ssl.cert.subject.cn",
    "cert.issuer.org": "ssl.cert.issuer.cn",
    "icon_hash": "http.favicon.hash",
}


def fofa_to_shodan(query: str) -> str:
    tokens, joins = parse_fofa_query(query)
    if not tokens:
        return query

    # Shodan 无 OR 连接 filter 的标准写法；遇到 || 时用 OR 分组尽量保留
    and_groups: list[list[str]] = [[]]
    for i, t in enumerate(tokens):
        if i > 0 and i - 1 < len(joins) and joins[i - 1] == "||":
            and_groups.append([])
        f = _FOFA_TO_SHODAN.get(t["field"], t["field"])
        if f == "":
            continue
        op, v = t["op"], t["value"]
        if t["field"] == "ip" and "/" not in v:
            v = f"{v}/32"
        if t["field"] == "port":
            piece = f"{f}:{v}"
        elif t["field"] == "country" and len(v) != 2:
            # Shodan country 要两字母码；非码值降级为全文
            piece = f'"{v}"'
        elif _eq_ops(op):
            piece = f'{f}:"{v}"' if (" " in v or not v.isalnum()) else f"{f}:{v}"
            # hostname / 带点域名需要引号更稳
            if t["field"] in ("domain", "host", "title", "body", "org", "server", "app", "header") or "." in v or " " in v:
                piece = f'{f}:"{v}"'
        elif _neq_ops(op):
            piece = f'-{f}:"{v}"'
        else:
            continue
        and_groups[-1].append(piece)

    groups = [" ".join(g) for g in and_groups if g]
    if not groups:
        return query
    if len(groups) == 1:
        return groups[0]
    return " OR ".join(f"({g})" for g in groups)


# ── Censys（Legacy Search Language / v2 hosts search）─────────
_FOFA_TO_CENSYS = {
    "title": "services.http.response.html_title",
    "body": "services.http.response.body",
    "domain": "dns.names",
    "host": "dns.names",
    "ip": "ip",
    "port": "services.port",
    "org": "autonomous_system.organization",
    "protocol": "services.service_name",
    "server": "services.http.response.headers.server",
    "country": "location.country",
    "city": "location.city",
    "app": "services.software.product",
    "os": "services.software.uniform_resource_identifier",
    "header": "services.http.response.headers",
    "cert.subject.org": "services.tls.certificates.leaf.names",
    "cert.subject.cn": "services.tls.certificates.leaf.names",
    "cert": "services.tls.certificates.leaf.names",
}


def fofa_to_censys(query: str) -> str:
    tokens, joins = parse_fofa_query(query)
    if not tokens:
        return query

    parts: list[str] = []
    kept_joins: list[str] = []
    for i, t in enumerate(tokens):
        f = _FOFA_TO_CENSYS.get(t["field"], t["field"])
        op, v = t["op"], t["value"]
        if t["field"] == "port":
            v = v.lstrip("0") or "0"
            piece = f"{f}:{v}"
        elif t["field"] == "protocol":
            piece = f'{f}:{v.upper()}'
        elif _eq_ops(op):
            piece = f'{f}:"{v}"'
        elif _neq_ops(op):
            piece = f'not {f}:"{v}"'
        else:
            continue
        if parts:
            kept_joins.append(joins[i - 1] if i - 1 < len(joins) else "&&")
        parts.append(piece)
    return _join_parts(parts, kept_joins, "and", "or") or query


_FOFA_TRANSLATORS = {
    "quake": fofa_to_quake,
    "hunter": fofa_to_hunter,
    "zoomeye": fofa_to_zoomeye,
    "shodan": fofa_to_shodan,
    "censys": fofa_to_censys,
}


def translate_fofa_query(query: str, target_engine: str) -> str:
    """将 FOFA 语法翻译为目标引擎语法。目标为 fofa / 空则原样返回。"""
    if not query:
        return query
    engine = (target_engine or "fofa").strip().lower()
    if engine in ("", "fofa"):
        return query
    translator = _FOFA_TRANSLATORS.get(engine)
    if translator is None:
        return query
    try:
        out = translator(query)
        return out if out else query
    except Exception:
        return query


def looks_like_fofa_syntax(query: str) -> bool:
    """粗判是否像 FOFA 字段条件（供 UI / 调试）。"""
    tokens, _ = parse_fofa_query(query)
    return bool(tokens)
