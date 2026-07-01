"""WAF 指纹与 payload 变形建议。

这是一个纯本地 advisor：不发网络请求，不自动绕过，只根据已有响应和当前
payload 给 worker 少量可验证的候选变形。真正验证仍必须走 http_request。
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any
from urllib.parse import quote


_MAX_PAYLOAD_LEN = 800
_MAX_BODY_LEN = 4000


@dataclass(frozen=True)
class WafSignature:
    name: str
    body_keywords: tuple[str, ...] = ()
    header_keys: tuple[str, ...] = ()
    header_values: dict[str, tuple[str, ...]] | None = None
    status_codes: tuple[int, ...] = (403, 406, 429, 501, 503)
    priorities: tuple[str, ...] = ("space", "encoding", "keyword", "header")


_SIGNATURES: tuple[WafSignature, ...] = (
    WafSignature(
        "cloudflare",
        body_keywords=("cloudflare", "cf-ray", "just a moment", "__cf_bm", "ray id"),
        header_keys=("cf-ray",),
        priorities=("encoding", "ua", "header", "space", "keyword"),
    ),
    WafSignature(
        "modsecurity",
        body_keywords=("mod_security", "modsecurity", "not acceptable", "406 not"),
        header_keys=("x-modsecurity",),
        priorities=("space", "keyword", "encoding", "header"),
    ),
    WafSignature(
        "nginx_openresty",
        body_keywords=("406 not acceptable", "openresty"),
        header_values={"server": ("nginx", "openresty")},
        status_codes=(403, 406),
        priorities=("space", "keyword", "encoding"),
    ),
    WafSignature(
        "aws_waf",
        body_keywords=("request blocked", "x-amzn-requestid", "aws"),
        header_keys=("x-amzn-requestid",),
        priorities=("encoding", "header", "space", "keyword"),
    ),
    WafSignature(
        "imperva",
        body_keywords=("imperva", "incapsula", "request denied by incapsula", "_imf", "incap_ses"),
        header_keys=("x-iinfo",),
        priorities=("ua", "header", "encoding", "space"),
    ),
    WafSignature(
        "f5_bigip",
        body_keywords=("the requested url was rejected", "f5"),
        header_keys=("x-cnection",),
        priorities=("space", "keyword", "encoding"),
    ),
    WafSignature(
        "safedog",
        body_keywords=("安全狗", "safedog", "safe3waf"),
        priorities=("encoding", "space", "keyword", "header"),
    ),
    WafSignature(
        "d_shield",
        body_keywords=("d盾", "d_shield", "iis防火墙"),
        priorities=("encoding", "keyword", "space", "header"),
    ),
    WafSignature(
        "generic",
        body_keywords=("access denied", "forbidden", "blocked", "firewall", "security violation", "拦截", "阻断", "攻击"),
        priorities=("space", "encoding", "keyword", "header"),
    ),
)


_BLOCK_STATUSES = {400, 403, 406, 429, 501, 503}


def suggest_waf_bypass(
    *,
    payload: str,
    status_code: int | None = None,
    response_headers: dict[str, Any] | None = None,
    response_body: str = "",
    context: str = "generic",
) -> dict[str, Any]:
    """返回 WAF 指纹和少量候选变形。

    context 只影响候选排序，不改变安全边界；支持 generic/sqli/xss/path/json/header。
    """
    raw_payload = (payload or "")[:_MAX_PAYLOAD_LEN]
    if not raw_payload:
        return {
            "ok": False,
            "kind": "arg_error",
            "error": "payload 不能为空",
            "guidance": "把被 WAF 拦截的最小 payload 或可控参数值传进来。",
        }

    normalized_headers = _normalize_headers(response_headers or {})
    body = (response_body or "")[:_MAX_BODY_LEN]
    status = int(status_code or 0)
    signature, evidence = _detect_waf(status, normalized_headers, body)
    priorities = _priorities_for_context(signature.priorities, context)

    variants = _generate_payload_variants(raw_payload, priorities, context)
    header_variants = _header_variants(priorities)

    return {
        "ok": True,
        "detected": signature.name != "none",
        "waf_type": signature.name,
        "evidence": evidence,
        "blocked_likely": status in _BLOCK_STATUSES or signature.name != "none",
        "strategy_priority": list(priorities),
        "payload_variants": variants[:12],
        "header_variants": header_variants[:6],
        "guidance": (
            "这是纯本地建议，不代表已绕过。只挑 1-3 个最贴近当前验证链的变形，"
            "用 http_request 复测 baseline vs variant；只有响应差异能证明真实危害时才提交。"
        ),
    }


def _normalize_headers(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v).lower() for k, v in headers.items()}


def _detect_waf(status: int, headers: dict[str, str], body: str) -> tuple[WafSignature, str]:
    body_lower = body.lower()
    for sig in _SIGNATURES:
        for key in sig.header_keys:
            if key.lower() in headers:
                return sig, f"命中响应头 `{key}`"
        for header, values in (sig.header_values or {}).items():
            hv = headers.get(header.lower(), "")
            if hv and any(v.lower() in hv for v in values):
                if status in sig.status_codes or any(k in body_lower for k in sig.body_keywords):
                    return sig, f"响应头 `{header}: {hv[:80]}` + HTTP {status}"
        for keyword in sig.body_keywords:
            if keyword.lower() in body_lower:
                return sig, f"命中响应体关键词 `{keyword}`"
        if sig.name != "generic" and status in sig.status_codes and body:
            # 非 generic 仅靠状态码不够，避免把普通 403 误判成某具体 WAF。
            continue
    if status in _BLOCK_STATUSES:
        generic = next(s for s in _SIGNATURES if s.name == "generic")
        return generic, f"HTTP {status} 疑似拦截"
    return WafSignature("none", priorities=("space", "encoding", "keyword")), "未见明确 WAF 指纹"


def _priorities_for_context(base: tuple[str, ...], context: str) -> tuple[str, ...]:
    ctx = (context or "generic").lower()
    preferred: tuple[str, ...]
    if ctx in ("sqli", "sql", "sql_injection"):
        preferred = ("space", "keyword", "encoding", "operator", "header")
    elif ctx in ("xss", "html"):
        preferred = ("encoding", "case", "html", "header")
    elif ctx in ("path", "lfi", "download"):
        preferred = ("path", "encoding", "header")
    elif ctx in ("json", "api"):
        preferred = ("json", "encoding", "header", "space")
    else:
        preferred = base
    merged: list[str] = []
    for item in preferred + base:
        if item not in merged:
            merged.append(item)
    return tuple(merged)


def _generate_payload_variants(payload: str, priorities: tuple[str, ...], context: str) -> list[dict[str, str]]:
    variants: list[dict[str, str]] = []
    seen = {payload}

    def add(strategy: str, technique: str, value: str) -> None:
        if not value or value in seen:
            return
        seen.add(value)
        variants.append({"strategy": strategy, "technique": technique, "payload": value})

    for strategy in priorities:
        if strategy == "space":
            add(strategy, "space_to_comment", payload.replace(" ", "/**/"))
            add(strategy, "space_to_tab", payload.replace(" ", "%09"))
            add(strategy, "space_to_newline", payload.replace(" ", "%0a"))
        elif strategy in ("keyword", "case"):
            add(strategy, "mixed_case", _mixed_case_keywords(payload))
            add(strategy, "keyword_inline_comment", _keyword_inline_comment(payload))
            add(strategy, "union_newline", re.sub(r"\bUNION\s+SELECT\b", "UNION%0aSELECT", payload, flags=re.I))
        elif strategy == "operator":
            add(strategy, "logical_operator", re.sub(r"\bAND\b", "&&", re.sub(r"\bOR\b", "||", payload, flags=re.I), flags=re.I))
            add(strategy, "comparison_noise", re.sub(r"\b1\s*=\s*1\b", "GREATEST(1,1)=1", payload, flags=re.I))
        elif strategy == "encoding":
            add(strategy, "url_encode", quote(payload, safe=""))
            add(strategy, "double_url_encode", quote(quote(payload, safe=""), safe=""))
            add(strategy, "quote_unicode_escape", payload.replace("'", "%u0027").replace('"', "%u0022"))
        elif strategy == "html":
            add(strategy, "html_entity_angles", payload.replace("<", "&lt;").replace(">", "&gt;"))
            add(strategy, "slash_entity", payload.replace("/", "&#x2f;"))
        elif strategy == "path":
            add(strategy, "dot_slash", payload.replace("/", "/./"))
            add(strategy, "double_slash", payload.replace("/", "//"))
            add(strategy, "encoded_slash", payload.replace("/", "%2f"))
        elif strategy == "json":
            add(strategy, "json_string_escape", payload.replace("\\", "\\\\").replace('"', '\\"'))

    return variants


_SQL_KEYWORDS = re.compile(r"\b(select|union|and|or|from|where|order|sleep|benchmark|if)\b", re.I)


def _mixed_case_keywords(payload: str) -> str:
    def repl(match: re.Match[str]) -> str:
        word = match.group(0)
        return "".join(ch.upper() if i % 2 == 0 else ch.lower() for i, ch in enumerate(word))

    return _SQL_KEYWORDS.sub(repl, payload)


def _keyword_inline_comment(payload: str) -> str:
    return _SQL_KEYWORDS.sub(lambda m: f"/*!{m.group(0)}*/", payload)


def _header_variants(priorities: tuple[str, ...]) -> list[dict[str, str]]:
    if "header" not in priorities and "ua" not in priorities:
        return []
    variants = [
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Forwarded-Proto": "https"},
        {"X-Requested-With": "XMLHttpRequest"},
    ]
    return variants


def render_waf_advice(result: dict[str, Any]) -> str:
    """给调试/日志用的简短 markdown。"""
    if not result.get("ok"):
        return str(result.get("error", ""))
    lines = [
        f"WAF: {result.get('waf_type')} ({result.get('evidence')})",
        "策略优先级: " + ", ".join(result.get("strategy_priority", [])),
        "候选 payload:",
    ]
    for item in result.get("payload_variants", [])[:8]:
        lines.append(f"- {item['strategy']}/{item['technique']}: {item['payload']}")
    if result.get("header_variants"):
        lines.append("候选 header:")
        for item in result["header_variants"][:4]:
            lines.append(f"- {item}")
    return "\n".join(lines)
