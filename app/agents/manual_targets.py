"""手动清单清理分析：把用户粘贴的杂乱文本规范成可入队目标。

支持的常见脏格式（EduSRC / 资产梳理现场很常见）：
- 裸域名 / 带协议 URL / 带路径查询串
- 行尾中文/英文备注：`https://b.xxx.cn/ 港澳台`
- 单独一行的解析 IP：`(203.0.113.10)`（作为独立目标入队）
- 同行尾随括号 IP：`host.example.com (1.2.3.4)`
- `#` 注释行、空行、全角空格

返回保序去重后的条目；同 host 多条时优先保留带路径的 URL（深链入口更有价值）。
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlunparse

from app.urlnorm import ensure_scheme, is_unusable_host, normalize_host, safe_urlparse

# 单独一行的 (IPv4)
_PAREN_IP_LINE = re.compile(
    r"^\(\s*(\d{1,3}(?:\.\d{1,3}){3})(?:\s*:\s*(\d{1,5}))?\s*\)$"
)
# 行尾 / 同行的 (IPv4) 备注
_TRAILING_PAREN_IP = re.compile(
    r"\s*\(\s*(\d{1,3}(?:\.\d{1,3}){3})(?:\s*:\s*(\d{1,5}))?\s*\)\s*$"
)
# 行首 token（URL/host）与其后备注
_TOKEN_NOTE = re.compile(r"^(\S+)(?:\s+(.+))?$")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?$")


def _split_lines(raw: list[str] | str) -> list[str]:
    if isinstance(raw, str):
        text = raw
    else:
        text = "\n".join(str(x) for x in (raw or []))
    # 统一全角空格，按行切
    text = text.replace("\u3000", " ")
    return [ln.strip() for ln in text.splitlines()]


def _looks_like_target_token(token: str) -> bool:
    t = (token or "").strip()
    if not t or t.startswith("#"):
        return False
    if "://" in t:
        return True
    if _IPV4.match(t):
        return True
    # 至少带一个点的域名 / 通配残余
    if "." in t and re.search(r"[a-zA-Z0-9]", t):
        return True
    return False


def _normalize_url(token: str) -> tuple[str, str]:
    """返回 (url, host)。保留用户给的路径/查询；裸 host 补 http://。"""
    raw = (token or "").strip().rstrip(",;，；")
    if not raw:
        return "", ""
    # 去掉误粘的尾部斜杠过多：保留单斜杠语义由后面处理
    host = normalize_host(raw)
    if not host or is_unusable_host(raw) or is_unusable_host(host):
        return "", ""
    if "://" in raw:
        parsed = safe_urlparse(raw)
        # 重建：保留 scheme/netloc/path/query，丢掉 fragment
        path = parsed.path or ""
        # 根路径 `/` 可省略，避免无意义差异
        if path == "/":
            path = ""
        url = urlunparse((
            parsed.scheme or "http",
            parsed.netloc,
            path,
            "",
            parsed.query or "",
            "",
        ))
        return url, host
    return ensure_scheme(host), host


def _prefer_url(existing: str, candidate: str) -> str:
    """同 host 去重时：带路径/查询的优先于裸站。"""
    def score(u: str) -> tuple[int, int]:
        p = safe_urlparse(u)
        has_path = 1 if (p.path and p.path not in ("", "/")) else 0
        has_query = 1 if p.query else 0
        return (has_path + has_query, len(u))
    return candidate if score(candidate) > score(existing) else existing


def parse_manual_targets(raw: list[str] | str) -> list[dict[str, Any]]:
    """清理分析手动清单。

    返回：[{url, host, note, raw_line}]，按首次出现顺序，host 级去重。
    """
    lines = _split_lines(raw)
    # host -> entry（用于去重时升级 URL）
    by_host: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    def _add(url: str, host: str, note: str, raw_line: str) -> None:
        if not url or not host:
            return
        key = host.lower()
        if key in by_host:
            prev = by_host[key]
            better = _prefer_url(prev["url"], url)
            if better != prev["url"]:
                prev["url"] = better
                prev["raw_line"] = raw_line
            if note and not prev.get("note"):
                prev["note"] = note
            return
        by_host[key] = {
            "url": url,
            "host": host,
            "note": note or "",
            "raw_line": raw_line,
        }
        order.append(key)

    for line in lines:
        if not line or line.startswith("#"):
            continue

        # 1) 整行就是 (IP)
        m_ip = _PAREN_IP_LINE.match(line)
        if m_ip:
            ip = m_ip.group(1)
            port = m_ip.group(2)
            token = f"{ip}:{port}" if port else ip
            url, host = _normalize_url(token)
            _add(url, host, "", line)
            continue

        # 2) 行尾剥离 (IP)，IP 也入队
        trailing_ip = ""
        m_trail = _TRAILING_PAREN_IP.search(line)
        if m_trail:
            ip = m_trail.group(1)
            port = m_trail.group(2)
            trailing_ip = f"{ip}:{port}" if port else ip
            line = line[: m_trail.start()].rstrip()

        m = _TOKEN_NOTE.match(line)
        if not m:
            continue
        token, note = m.group(1), (m.group(2) or "").strip()
        # 备注里若仍是括号 IP，已在上面剥过；纯备注保留
        if note.startswith("(") and _PAREN_IP_LINE.match(note):
            note = ""
        if not _looks_like_target_token(token):
            continue
        url, host = _normalize_url(token)
        _add(url, host, note, line)
        if trailing_ip:
            ip_url, ip_host = _normalize_url(trailing_ip)
            _add(ip_url, ip_host, f"解析自 {host}" if host else "", trailing_ip)

    return [by_host[k] for k in order]


def clean_manual_target_list(raw: list[str] | str) -> list[str]:
    """供创建/编辑任务落库：返回清理后的 URL 列表（保序去重）。"""
    return [item["url"] for item in parse_manual_targets(raw)]
