"""出站 URL 的 SSRF / 回环校验。

`assert_safe_outbound_url` 仅用于 **AutoHunter 自身携带凭证的配置探测请求**
（如拉取模型商 /models 列表、FOFA base_url 探测）——这类请求会把真实 API Key /
FOFA Key 放进 Authorization/query，一旦 base_url 被篡改指向内网或云元数据，
就会造成密钥外泄 + 内网探测。

Worker/killsweep/report_assistant 主动挖洞的 http_request/run_shell 属于产品语义
（就是要打目标，可能含内网），**不走** `assert_safe_outbound_url`，以免误杀
校园网 / 实验室 RFC1918 目标。

但挖洞请求必须走 `is_loopback_target`：域名若解析到 127.0.0.1/::1，worker 会打到
AutoHunter 自己，产出「未授权访问 / 泄露漏洞报告」之类假洞（Issue #49）。
只拦回环与未指定地址，不拦 10/8、192.168/16。

代理软件（Clash/mihomo/sing-box 等）的 fake-ip 模式会把公网域名解析到
198.18.0.0/15，本模块会把它当成私有地址误杀。用 `OUTBOUND_ALLOWED_HOSTS`
（逗号分隔，按 hostname 精确匹配）显式放行这类域名；`FOFA_ALLOWED_HOSTS`
作为兼容别名一并生效。
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re
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


def _normalize_host_entry(entry: str) -> str:
    """把白名单条目归一化成小写 hostname（容忍粘贴成 URL / 带端口 / 带方括号）。"""
    value = (entry or "").strip().lower()
    if not value:
        return ""
    if "://" in value:
        try:
            value = (urlparse(value).hostname or "").strip().lower()
        except ValueError:
            return ""
    elif value.startswith("["):
        end = value.find("]")
        if end > 0:
            value = value[1:end]
    elif value.count(":") == 1:
        left, right = value.rsplit(":", 1)
        if right.isdigit():
            value = left
    return value.rstrip(".")


def _env_allowed_hosts() -> set[str]:
    """读取环境变量白名单；每次调用时读取，容器重启/测试改 env 都即时生效。"""
    raw = " ".join(
        (
            os.environ.get("OUTBOUND_ALLOWED_HOSTS", ""),
            os.environ.get("FOFA_ALLOWED_HOSTS", ""),
        )
    )
    hosts: set[str] = set()
    for part in re.split(r"[,;\s]+", raw):
        host = _normalize_host_entry(part)
        if host:
            hosts.add(host)
    return hosts


def assert_safe_outbound_url(url: str, *, allow_extra_hosts: set[str] | None = None) -> str:
    """校验并返回原 URL；不安全时抛 SsrfBlocked。

    allow_extra_hosts：显式放行的 host（如用户在 env 里配置的私有 FOFA 代理域名）。
    环境变量 OUTBOUND_ALLOWED_HOSTS / FOFA_ALLOWED_HOSTS 的白名单同样生效，
    用于放行被代理 fake-ip 解析到 198.18.0.0/15 的公网域名。
    """
    raw = str(url or "").strip()
    if not raw:
        raise SsrfBlocked("空 URL")
    try:
        parsed = urlparse(raw)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").strip().lower()
    except ValueError as exc:
        # 畸形方括号 IPv6（如 http://[250:4809:...:b092]）会让 urlparse 在解析期抛
        # ValueError；调用方(settings_service.fetch_models)只捕获 SsrfBlocked，裸
        # ValueError 会一路冒泡打崩配置探测。这里 fail-closed 转成 SsrfBlocked。
        raise SsrfBlocked(f"URL 无法解析（疑似畸形 IPv6）: {raw[:80]}") from exc
    if scheme not in _ALLOWED_SCHEMES:
        raise SsrfBlocked(f"不允许的协议: {scheme or '(空)'}")
    if not host:
        raise SsrfBlocked("URL 缺少主机名")

    if host in _METADATA_HOSTS:
        raise SsrfBlocked("目标为云元数据地址，已拦截")

    extra = {_normalize_host_entry(h) for h in (allow_extra_hosts or set()) if h}
    if host in (extra | _env_allowed_hosts()):
        return raw

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


# ---------------------------------------------------------------------------
# Worker 侧回环拦截（Issue #49）
# 只拦 loopback / unspecified，不拦 RFC1918。DNS 任一结果命中即拦。
# ---------------------------------------------------------------------------

_LOOPBACK_HOSTNAMES = frozenset({
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
})

LOOPBACK_BLOCK_ERROR = "目标指向本机回环地址（127.0.0.1/::1），已拦截"
LOOPBACK_SKIP_REASON = "目标指向本机回环地址（127.0.0.1/::1），自动跳过"

_CMD_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_CMD_TOOL_LOOPBACK_RE = re.compile(
    r"\b(?:curl|wget|httpie|http|nc|ncat|netcat|ssh|nmap|masscan|ffuf|gobuster|sqlmap)\b"
    r"[^\n]{0,240}(?<![A-Za-z0-9_.-])"
    r"(?:127(?:\.\d+){3}|\[::1\]|::1|localhost(?:\.localdomain)?)"
    r"(?![A-Za-z0-9_.-])",
    re.I,
)


def _ip_is_loopback(ip: ipaddress._BaseAddress) -> bool:
    if ip.is_loopback or ip.is_unspecified:
        return True
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None and (mapped.is_loopback or mapped.is_unspecified):
        return True
    return False


def _parse_ip(text: str) -> ipaddress._BaseAddress | None:
    raw = (text or "").strip().lstrip("[").rstrip("]")
    if not raw:
        return None
    try:
        return ipaddress.ip_address(raw)
    except ValueError:
        return None


def is_loopback_ip(value: str) -> bool:
    """字面 IP 是否为本机回环 / 未指定地址（含 IPv4-mapped IPv6）。"""
    ip = _parse_ip(value)
    return bool(ip and _ip_is_loopback(ip))


def _extract_host(host_or_url: str) -> str:
    from app.urlnorm import safe_hostname

    raw = (host_or_url or "").strip()
    if not raw:
        return ""
    host = safe_hostname(raw)
    if host:
        return host.rstrip(".")
    s = raw.split("/")[0].split("?")[0].split("#")[0]
    if s.startswith("[") and "]" in s:
        return s[1:s.index("]")].rstrip(".")
    if s.count(":") == 1:
        left, right = s.rsplit(":", 1)
        if right.isdigit():
            s = left
    return s.lower().rstrip(".")


def is_loopback_target(host_or_url: str) -> bool:
    """主机或 URL 是否指向本机回环。

    - localhost / 127.0.0.0/8 / ::1 / 0.0.0.0 / ::
    - 域名 DNS 解析到上述任一地址（Issue #49 真实场景）
    - 解析失败返回 False，交给探活处理死链，避免把暂时解析不了的目标误跳过
    """
    host = _extract_host(host_or_url)
    if not host:
        return False
    if host in _LOOPBACK_HOSTNAMES:
        return True
    ip = _parse_ip(host)
    if ip is not None:
        return _ip_is_loopback(ip)
    # collector.refill / 派发跑在 asyncio 事件循环上。这里禁止阻塞 DNS：
    # 字面 127.0.0.1 / localhost 已在上面拦掉（Issue #49 真场景）。
    # 域名解析到回环只在 worker 线程里做（那边没有 running loop）。
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        parsed = _parse_ip(info[4][0])
        if parsed is not None and _ip_is_loopback(parsed):
            return True
    return False


def command_hits_loopback(cmd: str) -> bool:
    """shell 命令是否明显在打回环（URL 或 curl/wget 等工具的主机参数）。"""
    text = cmd or ""
    for match in _CMD_URL_RE.finditer(text):
        if is_loopback_target(match.group(0).rstrip(").,;")):
            return True
    return bool(_CMD_TOOL_LOOPBACK_RE.search(text))
