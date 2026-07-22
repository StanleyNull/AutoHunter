"""机械预筛：在入队前过滤无挖掘价值的资产。

只做确定性的机械判断（不耗 LLM）：
0. 敏感域名（.gov / .mil / 军政公安关键词等）→ 跳过（永不攻击）
1. CDN / 对象存储 / 云 WAF 域名特征 → 跳过
2. 死链 / 连接超时 / 无响应 → 跳过
3. 纯前端静态站（无任何后端交互特征，且是 SPA/静态托管）→ 跳过

判断尽量保守：拿不准就放行（宁可多挖，不要误杀有价值目标）。
例外：敏感域名一律跳过，无例外。
"""
from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse

import httpx

# CDN / 对象存储 / 静态托管 域名特征（命中即跳过）
_CDN_MARKERS = (
    "cdn", "cloudfront", "akamai", "fastly", "cloudflare", "qiniucdn", "kunlun",
    "alikunlun", "wscdn", "bsgslb", "cdngslb", "aliyuncs.com", "myqcloud.com",
    "cos.ap-", "oss-cn-", "obs.cn-", "bcebos.com", "ksyuncdn", "wcs.cn",
    "github.io", "gitee.io", "pages.dev", "netlify.app", "vercel.app",
)

# 纯静态托管 Server 头特征
_STATIC_SERVERS = ("githubpages", "netlify", "vercel", "cloudflare", "amazons3", "aliyunoss")

# 敏感公共后缀第二级标签（*.gov / *.gov.cn / *.mil.cn …）
_SENSITIVE_PUBLIC_LABELS = frozenset({"gov", "mil"})

# 主机名中出现即视为敏感（偏军政/政法，避免误伤普通 edu 业务）
_SENSITIVE_KEYWORDS = (
    "gongan", "jiancha", "jiwei", "chinamil", "guofang", "wujing",
    "mps.gov", "mod.gov", "court.gov", "spp.gov", "ccdi.gov",
    "公安", "检察", "法院", "纪委", "国安", "国防", "武警", "军事",
    "政法委", "人大常委会", "中央军委", "解放军",
)

_SENSITIVE_SKIP_REASON = "敏感域名（政府/军政/政法等），自动跳过"
# 兼容旧常量名
_GOV_SKIP_REASON = _SENSITIVE_SKIP_REASON


def _extra_sensitive_suffixes() -> tuple[str, ...]:
    """环境变量 AUTOHUNTER_SENSITIVE_HOSTS：逗号分隔额外后缀/完整域名。"""
    raw = os.environ.get("AUTOHUNTER_SENSITIVE_HOSTS", "") or ""
    out = []
    for part in raw.split(","):
        p = part.strip().lower().lstrip(".")
        if p:
            out.append(p)
    return tuple(out)


def _host_only(host_or_url: str) -> str:
    s = (host_or_url or "").strip().lower()
    if not s:
        return ""
    if "://" in s:
        try:
            s = urlparse(s).hostname or ""
        except Exception:
            s = ""
        return (s or "").rstrip(".")
    s = s.split("/")[0].split("?")[0].split("#")[0]
    if s.startswith("[") and "]" in s:
        return s[1:s.index("]")].rstrip(".")
    # host:port（避免误伤裸 IPv6）
    if s.count(":") == 1:
        left, right = s.rsplit(":", 1)
        if right.isdigit():
            s = left
    return s.rstrip(".")


def _is_sensitive_public_suffix(h: str) -> bool:
    """*.gov / *.gov.cn / *.mil / *.mil.cn / *.gov.ac.uk 等。"""
    if not h:
        return False
    parts = h.split(".")
    for label in _SENSITIVE_PUBLIC_LABELS:
        if h == label or h.endswith(f".{label}"):
            return True
        # example.gov.cn / a.b.mil.uk
        if len(parts) >= 3 and parts[-2] == label and parts[-1].isalpha() and 2 <= len(parts[-1]) <= 4:
            return True
        # *.gov.ac.uk
        if len(parts) >= 4 and parts[-3] == label:
            return True
    return False


def is_sensitive_host(host_or_url: str) -> bool:
    """是否敏感域名：政府/军队/政法等，打了不合规也不该碰。

    覆盖：
    - *.gov / *.gov.cn / *.mil / *.mil.cn …
    - 主机名含公安/检察/法院/纪委/国防/武警等关键词
    - 环境变量 AUTOHUNTER_SENSITIVE_HOSTS 追加的后缀
    """
    h = _host_only(host_or_url)
    if not h:
        return False
    try:
        ipaddress.ip_address(h)
        return False
    except ValueError:
        pass
    if _is_sensitive_public_suffix(h):
        return True
    if any(k in h for k in _SENSITIVE_KEYWORDS):
        return True
    for suf in _extra_sensitive_suffixes():
        if h == suf or h.endswith("." + suf):
            return True
    return False


def is_gov_host(host_or_url: str) -> bool:
    """兼容旧接口：等价于敏感域名判断（含 .gov 及更广军政范围）。"""
    return is_sensitive_host(host_or_url)


def is_cdn_host(host: str) -> bool:
    h = (host or "").lower()
    return any(m in h for m in _CDN_MARKERS)


def probe(url: str, timeout: float = 8.0) -> dict:
    """探活：返回 {alive, status, server, body_len, is_spa}。失败则 alive=False。"""
    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as c:
            r = c.get(url, headers={"User-Agent": "Mozilla/5.0 (compatible; AutoHunter)"})
            body = r.text or ""
            server = r.headers.get("server", "").lower()
            # 粗判 SPA/纯前端：body 很短 + 含 <div id=app/root> + 几乎无表单/接口痕迹
            low = body.lower()
            is_spa = (
                len(body) < 3000
                and ('id="app"' in low or 'id="root"' in low or "<script" in low)
                and "<form" not in low
                and "login" not in low
            )
            import re
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            title = (m.group(1).strip()[:200] if m else "")
            return {
                "alive": True, "status": r.status_code, "server": server,
                "body_len": len(body), "is_spa": is_spa,
                "title": title, "body_snippet": body[:4000],
            }
    except Exception:
        return {"alive": False, "status": 0, "server": "", "body_len": 0,
                "is_spa": False, "title": "", "body_snippet": ""}


def should_skip(host: str, url: str) -> tuple[bool, str]:
    """返回 (是否跳过, 原因)。机械确定性判断，保守放行。"""
    skip, reason, _info = should_skip_ex(host, url)
    return skip, reason


def should_skip_ex(host: str, url: str) -> tuple[bool, str, dict]:
    """同 should_skip，但额外返回首页探测信息(供评分复用，避免重复发包)。"""
    # 敏感域名最先拦：不探活、不发包、不派 worker
    if is_sensitive_host(host) or is_sensitive_host(url):
        return True, _SENSITIVE_SKIP_REASON, {}
    if is_cdn_host(host):
        return True, "CDN/对象存储/静态托管域名", {}
    info = probe(url)
    if not info["alive"]:
        return True, "死链/连接超时/无响应", info
    # 5xx 暂时挂了，跳过本轮（不彻底淘汰，可后续重试）
    if info["status"] >= 500:
        return True, f"服务异常({info['status']})", info
    if any(s in info["server"] for s in _STATIC_SERVERS) and info["is_spa"]:
        return True, "纯前端静态托管站", info
    return False, "", info
