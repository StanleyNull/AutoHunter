"""出站 URL 的 SSRF 校验。

仅用于 **AutoHunter 自身携带凭证的配置探测请求**（如拉取模型商 /models 列表、
FOFA base_url 探测）——这类请求会把真实 API Key / FOFA Key 放进 Authorization/query，
一旦 base_url 被篡改指向内网或云元数据，就会造成密钥外泄 + 内网探测。

注意：Worker/killsweep/report_assistant 主动挖洞的 http_request/run_shell 属于产品语义
（就是要打目标，可能含内网），不走本模块。
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

_ALLOWED_SCHEMES = {"http", "https"}
# 云厂商元数据地址（link-local + 部分厂商特例）。
_METADATA_HOSTS = {
    "169.254.169.254",
    "100.100.100.200",       # 阿里云
    "metadata.google.internal",
    "metadata.tencentyun.com",
}


class SsrfBlocked(ValueError):
    """出站地址命中 SSRF 黑名单。"""


def _ip_is_forbidden(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def assert_safe_outbound_url(url: str, *, allow_extra_hosts: set[str] | None = None) -> str:
    """校验并返回原 URL；不安全时抛 SsrfBlocked。

    allow_extra_hosts：显式放行的 host（如用户在 env 里配置的私有 FOFA 代理域名）。
    """
    raw = str(url or "").strip()
    if not raw:
        raise SsrfBlocked("空 URL")
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise SsrfBlocked(f"不允许的协议: {scheme or '(空)'}")
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise SsrfBlocked("URL 缺少主机名")

    extra = {h.strip().lower() for h in (allow_extra_hosts or set()) if h}
    if host in extra:
        return raw

    if host in _METADATA_HOSTS:
        raise SsrfBlocked("目标为云元数据地址，已拦截")

    # 逐个解析出的 IP 校验（含 IPv6、DNS 到内网的情形）。
    from app.urlnorm import safe_port
    port = safe_port(parsed) or (443 if scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise SsrfBlocked(f"主机解析失败: {host}") from exc

    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SsrfBlocked(f"无效 IP: {ip_str}")
        if _ip_is_forbidden(ip):
            raise SsrfBlocked(f"目标解析到私有/保留地址({ip_str})，已拦截")
    return raw
