"""URL / host 归一化工具：统一处理裸 IPv6，避免 urlparse().port 抛 ValueError。

背景：FOFA/引擎结果里会出现裸 IPv6（如 `250:4809:3:fcfc:feff:febc:b092`）。
直接 `urlparse("http://" + ip)` 再取 `.port`，解析器会把最后一段当端口，抛
`ValueError: Port could not be cast to integer value as '...'`，把主循环打崩。
这里提供带方括号补全的安全解析，所有涉及 host:port 拆分的地方都应走这里。
"""
from __future__ import annotations

import ipaddress
from urllib.parse import ParseResult, urlparse


def _looks_like_ipv6(h: str) -> bool:
    """宽松判定「像裸 IPv6」：≥2 个冒号，各段都是十六进制（允许 :: 产生空段）。

    注意不能只用 ipaddress.IPv6Address 严格校验：FOFA/引擎有时给出截断/非规范
    的 IPv6（如 7 段的 `250:4809:3:fcfc:feff:febc:b092`），严格校验会判 False，
    但它照样有多个冒号，拼进 URL 一样会把主循环打崩，必须一并加括号处理。
    """
    if h.count(":") < 2 or "/" in h or "@" in h or "." in h.split(":")[0]:
        # 含 '.' 的首段基本是域名/IPv4:port，排除
        return False
    for seg in h.split(":"):
        if seg == "":
            continue  # :: 压缩产生的空段
        if len(seg) > 4:
            return False
        try:
            int(seg, 16)
        except ValueError:
            return False
    return True


def is_bare_ipv6(host: str) -> bool:
    h = (host or "").strip()
    if not h or h.startswith("["):
        return False
    # 先试严格校验（标准 IPv6 / :: 压缩），再退回宽松启发式（截断/非规范 IPv6）
    try:
        ipaddress.IPv6Address(h)
        return True
    except Exception:
        pass
    return _looks_like_ipv6(h)


def bracket_ipv6_host(host: str) -> str:
    """裸 IPv6 → `[IPv6]`；已带括号 / host:port / 域名 / IPv4 原样返回。

    只对「像 IPv6」的裸串加括号（含截断/畸形），方便 host:port 拼接不歧义；
    是否真的可用由 is_valid_ipv6 / is_unusable_host 判定。
    """
    h = (host or "").strip()
    return f"[{h}]" if is_bare_ipv6(h) else h


_EMPTY_PARSE = ParseResult(scheme="", netloc="", path="", params="", query="", fragment="")


def ensure_scheme(url_or_host: str, default_scheme: str = "http") -> str:
    """补全协议头。仅对**合法** IPv6 加方括号；畸形 IPv6 原样（交由上层判不可用）。

    Python 3.14 的 urlparse 会在遇到 `[非法IPv6]` 时直接抛 ValueError，所以这里
    绝不给畸形 IPv6 加括号，避免把异常引入解析。
    """
    s = (url_or_host or "").strip()
    if not s:
        return ""
    if "://" in s:
        return s
    host = f"[{s}]" if is_valid_ipv6(s) else s
    return f"{default_scheme}://{host}"


def safe_urlparse(url_or_host: str) -> ParseResult:
    """安全 urlparse：任何畸形输入都不抛异常，失败返回空 ParseResult。"""
    try:
        return urlparse(ensure_scheme(url_or_host))
    except ValueError:
        return _EMPTY_PARSE


def safe_hostname(parsed_or_url) -> str:
    """取 hostname 且不抛异常。

    Python 3.14 的 urlparse 会对 `[...]` 内的非法 IPv6 在取 .hostname 时抛
    ValueError（截断/畸形 IPv6）。这里吞掉异常返回空串，交由上层判定「不可用」。
    """
    p = parsed_or_url if isinstance(parsed_or_url, ParseResult) else safe_urlparse(str(parsed_or_url))
    try:
        return (p.hostname or "").lower()
    except ValueError:
        return ""


def safe_port(parsed_or_url) -> int | None:
    """取端口且不抛异常。入参可为 ParseResult 或字符串。"""
    p = parsed_or_url if isinstance(parsed_or_url, ParseResult) else safe_urlparse(str(parsed_or_url))
    try:
        return p.port
    except ValueError:
        return None


def is_valid_ipv6(host: str) -> bool:
    """严格校验：是否为标准可用的 IPv6 地址。"""
    h = (host or "").strip().lstrip("[").rstrip("]")
    try:
        ipaddress.IPv6Address(h)
        return True
    except Exception:
        return False


def is_unusable_host(url_or_host: str) -> bool:
    """目标 host 是否根本无法作为 URL 主机使用（应直接跳过，不派 worker）。

    典型：FOFA/引擎返回的截断/畸形 IPv6（如 7 段的 250:4809:...:b092），
    既不是合法 IPv6，也不是域名/IPv4，拼进 URL 必崩，扫了也没意义。
    """
    s = (url_or_host or "").strip()
    if not s:
        return True
    bare = s.split("://", 1)[-1].split("/")[0].split("?")[0].split("#")[0].strip("[]")
    # 像 IPv6 但不是合法 IPv6（截断/畸形）→ 拼进 URL 必崩，判不可用
    if _looks_like_ipv6(bare) and not is_valid_ipv6(bare):
        return True
    return not bool(safe_hostname(s))


def normalize_host(url_or_host: str) -> str:
    """归一化为 host（去协议、小写；非 80/443 端口保留 host:port；IPv6 保留括号形式）。

    对畸形 IPv6 等无法解析出主机名的输入，返回原始裸串（小写去斜杠），
    不抛异常；是否跳过由 is_unusable_host / 上层判定。
    """
    p = safe_urlparse(url_or_host)
    host = safe_hostname(p)
    if not host:
        # 解析不出（畸形 IPv6 等）：退回裸串，保证不抛异常
        raw = (url_or_host or "").strip().lower()
        return raw.split("://", 1)[-1].split("/")[0]
    disp = f"[{host}]" if is_bare_ipv6(host) else host
    port = safe_port(p)
    if port and port not in (80, 443):
        return f"{disp}:{port}"
    return disp
