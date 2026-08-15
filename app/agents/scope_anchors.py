"""从用户查询里提取域名/证书锚点，供搜集入库前做范围过滤。

不能把引擎字段名（ip.isp、header.status_code、web.title）当成域名白名单，
否则 Hunter/Quake 官网语法会把整页结果误判成「范围外」。
"""
from __future__ import annotations

import re

from app.agents import target_cluster

_FIELD_ASSIGN_RE = re.compile(
    r"[a-zA-Z_][\w.]*\s*(?:!=~|!=|=~|==|=|:)\s*(?:\"[^\"]*\"|'[^']*'|[^\s&|()]+)"
)
_EXACT_DOMAIN_FIELD_RE = re.compile(
    r"(?<![\w.])(?:domain|host)(?![\w.])\s*[=:]\s*\"([^\"]+)\"",
    re.I,
)
_CERT_ORG_RE = re.compile(r'cert\.subject\.org\s*=\s*"([^"]+)"', re.I)
_BARE_DOMAIN_RE = re.compile(
    r"[*]?\.?[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)+",
    re.I,
)
_FIELD_LIKE_RE = re.compile(
    r"^(?:ip|web|header|cert|domain|host|icp|os|protocol|port|title|body|app|org|"
    r"icon|status|base_protocol|server|country|city|isp)(?:\.|$)",
    re.I,
)
_PLAUSIBLE_TLD_RE = re.compile(
    r"\.(?:com|net|org|edu|gov|cn|io|info|xyz|top|cc|me|co|hk|tw|jp|kr|uk|us|de|ru|in|au)"
    r"(?:\.[a-z]{2})?$",
    re.I,
)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_real_domain(token: str) -> bool:
    t = (token or "").strip().strip("\"'").lstrip("*.").strip(".").lower()
    if not t or "." not in t:
        return False
    if _FIELD_LIKE_RE.match(t):
        return False
    if _IPV4_RE.fullmatch(t):
        return True
    return bool(_PLAUSIBLE_TLD_RE.search(t))


def _add_domain(token: str, domains: list[str], seen: set[str]) -> None:
    t = (token or "").strip().strip("\"'").lstrip("*.").strip(".").lower()
    if not _is_real_domain(t):
        return
    root = target_cluster.root_domain(t)
    if root and root not in seen:
        seen.add(root)
        domains.append(root)


def extract_enterprise_domains(raw: str) -> list[str]:
    """从企业资产范围描述里提取根域名。忽略引擎字段名，保留 domain=/host= 与裸域名。"""
    return extract_scope_anchors(raw).get("domains") or []


def extract_scope_anchors(raw: str) -> dict[str, list[str]]:
    """提取精确锚点：domain=/host= 值、裸写真实域名、cert.subject.org。"""
    raw = (raw or "").strip()
    if not raw:
        return {"domains": [], "cert_orgs": []}

    cert_orgs: list[str] = []
    seen_org: set[str] = set()
    for m in _CERT_ORG_RE.finditer(raw):
        v = m.group(1).strip()
        if v and v not in seen_org:
            seen_org.add(v)
            cert_orgs.append(v)

    domains: list[str] = []
    seen_dom: set[str] = set()
    for m in _EXACT_DOMAIN_FIELD_RE.finditer(raw):
        _add_domain(m.group(1), domains, seen_dom)

    stripped = _FIELD_ASSIGN_RE.sub(" ", raw)
    for tok in _BARE_DOMAIN_RE.findall(stripped.lower()):
        _add_domain(tok, domains, seen_dom)

    return {"domains": domains, "cert_orgs": cert_orgs}
