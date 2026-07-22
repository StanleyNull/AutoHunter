"""机械预筛：在入队前过滤无挖掘价值的资产。

只做确定性的机械判断（不耗 LLM）：
0. 政府/政务 .gov 域名 → 跳过（永不攻击）
1. CDN / 对象存储 / 云 WAF 域名特征 → 跳过
2. 死链 / 连接超时 / 无响应 → 跳过
3. 纯前端静态站（无任何后端交互特征，且是 SPA/静态托管）→ 跳过

判断尽量保守：拿不准就放行（宁可多挖，不要误杀有价值目标）。
例外：.gov 域名一律跳过，无例外。
"""
from __future__ import annotations

import ipaddress
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

_GOV_SKIP_REASON = "政府/政务域名（.gov），自动跳过"


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


def is_gov_host(host_or_url: str) -> bool:
    """是否政府/政务域名：*.gov / *.gov.cn / *.gov.uk 等。

    只看域名标签，不把 government.com、mygov.edu.cn 误判进来。
    """
    h = _host_only(host_or_url)
    if not h:
        return False
    try:
        ipaddress.ip_address(h)
        return False
    except ValueError:
        pass
    if h == "gov" or h.endswith(".gov"):
        return True
    parts = h.split(".")
    # example.gov.cn / a.b.gov.uk
    if len(parts) >= 3 and parts[-2] == "gov" and parts[-1].isalpha() and 2 <= len(parts[-1]) <= 4:
        return True
    # 少见：*.gov.ac.uk
    if len(parts) >= 4 and parts[-3] == "gov":
        return True
    return False


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
    # .gov 最先拦：不探活、不发包、不派 worker
    if is_gov_host(host) or is_gov_host(url):
        return True, _GOV_SKIP_REASON, {}
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
