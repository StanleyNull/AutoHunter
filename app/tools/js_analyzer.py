"""静态 JS/前端文本分析器。

目标不是替代真实验证，而是把前端 JS 中最容易发展成 SRC 漏洞的点位
归并成可执行的攻击链提示：接口、凭证、云存储、Parse/BaaS、验证码/改密等。
"""
from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
import base64
import codecs
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import tempfile
import time
from typing import Any, Iterator
from urllib.request import Request, url2pathname, urlopen
from urllib.parse import urljoin, urlparse


_MAX_CONTEXT = 180

# ===== 解析输入/匹配上限：防止纯 CPU 正则在巨型 JS bundle 上长时间持 GIL，
#       饿死事件循环触发看门狗重启（历史事故根因 #5）。 =====
# 单次分析的文本硬上限：超过即截断。1.5MB 足够覆盖压缩后的前端 bundle，
# 又能把每个正则的单次扫描时间压到亚秒级。
_MAX_ANALYZE_BYTES = 1_500_000
# 单个 finditer 循环最多处理的匹配数，避免海量匹配累计耗时。
_MAX_MATCHES = 5000
# 单个 finder 的挂钟预算（秒）：即使是线性正则，在 150 万个连续合法起始位置上
# （如超长单 token）也可能累计到秒级。超预算即停，保证不会长时间持 GIL。
_FINDER_TIME_BUDGET = 1.5
# 单次远程抓取的字节硬上限（流式读取，超过即停）。
_MAX_FETCH_BYTES = 2_500_000
# 仅允许远程抓取 http/https；file:// 只允许工作区/临时目录内普通文件（用于本地分析/测试）。
_ALLOWED_FETCH_SCHEMES = ("http", "https")

# 所有正则均为线性、无嵌套量词/交替回溯结构（历史事故根因 #5 已整改）。
_URL_RE = re.compile(r"""https?://[^\s"'`<>\\)]{1,400}""", re.I)
# 高价值路径前缀白名单：覆盖鉴权、支付、订单、版本化 API、文件、验证码等。
_PATH_RE = re.compile(
    r"""(?P<path>/(?:api|admin|manager|user|users|auth|login|logout|oauth|sso|config|parse|classes|upload|files?|download|export|import|sms|phone|mobile|captcha|password|passwd|reset|forget|common|system|front|order|orders|pay|payment|refund|withdraw|account|wallet|v\d{1,2})[A-Za-z0-9_./?=&:%-]{1,220})""",
    re.I,
)
# key: 'value' / key = "value"。key/value 均用否定字符类，线性匹配，不回溯。
_KEY_VALUE_RE = re.compile(
    r"""(?P<kq>['"`]?)(?P<key>[A-Za-z_$][\w$-]{1,80})(?P=kq)\s*[:=]\s*(?P<q>['"`])(?P<value>[^'"`\\\n]{1,500})(?P=q)""",
    re.S,
)
_HEADER_RE = re.compile(r"""X-Parse-Application-Id|Authorization|Bearer|X-Token|X-Auth|token""", re.I)
_JS_REF_RE = re.compile(
    r"""(?:import\s*\(|from\s+|import\s+|src\s*=)\s*['"`]([^'"`\n]{1,400}?\.(?:js|mjs|map)(?:\?[^'"`\n]{0,200})?)['"`]|sourceMappingURL=([^\s'"`]{1,800})""",
    re.I,
)
_SOURCE_MAP_URL_RE = re.compile(r"sourceMappingURL=([^\s'\"`]{1,800})", re.I)
_STRING_LITERAL_RE = re.compile(
    r""""(?P<dq>(?:\\.|[^"\\\n]){0,600})"|'(?P<sq>(?:\\.|[^'\\\n]){0,600})'|`(?P<bq>(?:\\.|[^`\\]){0,600})`""",
    re.S,
)
_ATOB_RE = re.compile(r"""atob\s*\(\s*(['"`])([A-Za-z0-9+/=_-]{8,500})\1\s*\)""", re.I)
_STRING_CONCAT_RE = re.compile(
    r"""(?P<expr>(?:['"`](?:\\.|[^'"`\\\n]){1,200}['"`]\s*\+\s*){1,8}['"`](?:\\.|[^'"`\\\n]){1,200}['"`])""",
    re.S,
)
_ARRAY_LITERAL_RE = re.compile(
    r"""(?:const|let|var)\s+(?P<name>[_$A-Za-z][\w$]{0,80})\s*=\s*\[(?P<body>(?:\s*['"`](?:\\.|[^'"`\\\n]){0,300}['"`]\s*,?){2,80})\]""",
    re.S,
)
# secret 判定的负向排除：避免把 base64 数据/长 URL/CSS/纯哈希误报成硬编码敏感键。
_SECRET_VALUE_EXCLUDE_RE = re.compile(
    r"""^(?:https?://|data:|/[^\s]*|#[0-9a-fA-F]{3,8}$|[0-9a-fA-F]{32}$|[0-9a-fA-F]{40}$|[0-9a-fA-F]{64}$)""",
)
# 常见 base64 图片/数据块特征头：PNG=iVBOR、JPEG=/9j/、GIF=R0lGOD、PDF=JVBER。
_SECRET_DATA_BLOB_RE = re.compile(r"^(?:iVBOR|/9j/|R0lGOD|JVBER|data:)")
# 真实硬编码密钥通常较短（几十字符）；纯 base64 且超长（>120）几乎都是内联数据块。
_SECRET_MAX_BLOB_LEN = 120
_SECRET_HINT_RE = re.compile(r"(?i)(bearer|appid|appkey|secret|token|password|upload_token)")
_SECRET_BLOB_RE = re.compile(r"^[A-Za-z0-9_\-:+=/]{24,}$")
_MAX_STATIC_DEOBF_BYTES = 350_000
_MAX_STATIC_EXTRAS = 300


def _iter_matches(pattern: re.Pattern[str], text: str, limit: int = _MAX_MATCHES) -> Iterator[re.Match[str]]:
    """带全局匹配数上限 + 挂钟预算的 finditer。

    双保险：匹配数封顶防"海量成功匹配"，挂钟预算防"海量失败尝试"（如超长单
    token 上每个位置都尝试匹配再回退），两者都会长时间持 GIL 饿死事件循环。
    """
    count = 0
    deadline = time.monotonic() + _FINDER_TIME_BUDGET
    for m in pattern.finditer(text):
        count += 1
        if count > limit:
            break
        # 每 256 次检查一次挂钟，避免频繁系统调用拖慢正常路径。
        if (count & 0xFF) == 0 and time.monotonic() > deadline:
            break
        yield m


class _ScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        attrs_dict = {k.lower(): v for k, v in attrs}
        src = attrs_dict.get("src")
        if src:
            self.scripts.append(src)


@dataclass
class JsFinding:
    kind: str
    title: str
    severity: str
    score: int
    evidence: str
    context: str = ""
    value: str = ""
    location: str = ""
    tags: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)


@dataclass
class JsChain:
    kind: str
    title: str
    confidence: str
    severity_hint: str
    reason: str
    evidence: list[str]
    probes: list[str]


def analyze_javascript(text: str, *, base_url: str = "", source: str = "inline") -> dict[str, Any]:
    """分析 JS/HTML/Markdown 文本，返回结构化结果。

    base_url 可用于把相对路径补成完整 URL。source 仅用于结果标记。
    """
    raw = text or ""
    # 输入硬上限：巨型 bundle 直接截断，把正则单次扫描时间压到亚秒级，
    # 杜绝纯 CPU 正则长时间持 GIL 饿死事件循环。
    if len(raw) > _MAX_ANALYZE_BYTES:
        raw = raw[:_MAX_ANALYZE_BYTES]
    normalized = _strip_noise(raw)
    try:
        normalized = _augment_static_strings(normalized)
    except Exception:
        # 静态反混淆只是增益能力，失败时保持原始分析继续，不能影响 worker 主流程。
        pass
    findings: list[JsFinding] = []

    findings.extend(_find_key_values(normalized, source))
    findings.extend(_find_urls_and_paths(normalized, base_url, source))
    findings.extend(_find_framework_signatures(normalized, base_url, source))
    findings = _dedupe_findings(findings)
    chains = _build_chains(findings, base_url)
    endpoint_inventory = _endpoint_inventory(findings)
    summary = _summary(findings, chains, endpoint_inventory)
    return {
        "source": source,
        "base_url": base_url,
        "summary": summary,
        "chains": [asdict(c) for c in chains],
        "endpoint_inventory": endpoint_inventory,
        "findings": [asdict(f) for f in sorted(findings, key=lambda x: x.score, reverse=True)],
    }


def analyze_url(
    url: str,
    *,
    max_depth: int = 2,
    timeout: float = 8.0,
    max_assets: int = 80,
) -> dict[str, Any]:
    """从入口 URL 深入抓取 HTML/JS，合并全部 JS 后分析。"""
    bundle = collect_js_bundle(url, max_depth=max_depth, timeout=timeout, max_assets=max_assets)
    base_url = _origin(url)
    result = analyze_javascript(bundle["text"], base_url=base_url, source=url)
    result["assets"] = bundle["assets"]
    result["fetch_errors"] = bundle["errors"]
    result["summary"]["assets"] = len(bundle["assets"])
    result["summary"]["fetch_errors"] = len(bundle["errors"])
    return result


def collect_js_bundle(
    url: str,
    *,
    max_depth: int = 2,
    timeout: float = 8.0,
    max_assets: int = 80,
) -> dict[str, Any]:
    """抓入口 HTML 和关联 JS，返回合并文本。"""
    queue: deque[tuple[str, int]] = deque([(url, 0)])
    seen: set[str] = set()
    assets: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    chunks: list[str] = []
    total_bytes = 0

    while queue and len(seen) < max_assets:
        cur, depth = queue.popleft()
        if cur in seen or depth > max_depth:
            continue
        seen.add(cur)
        # 合并文本已达上限：停止再抓，避免堆出巨型 bundle 拖垮后续正则解析。
        if total_bytes >= _MAX_ANALYZE_BYTES:
            break
        try:
            body, content_type = _fetch_text(cur, timeout=timeout)
        except Exception as e:
            errors.append({"url": cur, "error": f"{type(e).__name__}: {e}"})
            continue

        is_map = _looks_like_sourcemap(cur, content_type)
        is_js = _looks_like_js(cur, content_type)
        total_bytes += len(body)
        kind = "sourcemap" if is_map else "js" if is_js else "html"
        assets.append({"url": cur, "depth": depth, "bytes": len(body), "kind": kind})
        if is_map:
            extracted = _extract_sourcemap_sources(body)
            chunks.append(f"\n/* ===== SOURCE MAP: {cur} ({len(extracted)} sources) ===== */\n{extracted}\n")
        else:
            chunks.append(f"\n/* ===== SOURCE: {cur} ===== */\n{body}\n")

        refs = _extract_js_refs(body, cur, is_js=is_js)
        for ref in refs:
            if ref not in seen and len(seen) + len(queue) < max_assets:
                queue.append((ref, depth + 1))

    return {"text": "\n".join(chunks), "assets": assets, "errors": errors}


def render_markdown(result: dict[str, Any]) -> str:
    s = result["summary"]
    lines = [
        "# JS 分析结果",
        "",
        f"- 来源：`{result.get('source') or 'inline'}`",
        f"- 高价值链路：{s['chains']} 条",
        f"- 合并资产：{s.get('assets', 0)} 个",
        f"- 接口清单：{s.get('endpoints', 0)} 个",
        f"- 点位总数：{s['findings']} 个",
        f"- 最高风险：{s['top_severity']}",
        "",
    ]
    if result["chains"]:
        lines.append("## 高价值攻击链")
        for c in result["chains"]:
            lines += [
                "",
                f"### [{c['severity_hint']}] {c['title']}",
                f"- 类型：`{c['kind']}` / 信度：`{c['confidence']}`",
                f"- 依据：{c['reason']}",
                f"- 证据：{'; '.join(c['evidence'][:5])}",
            ]
            if c["probes"]:
                lines.append("- 建议验证：")
                lines.extend(f"  - `{p}`" for p in c["probes"][:6])
    if result.get("endpoint_inventory"):
        lines += ["", "## 统一接口清单 Top 30"]
        for ep in result["endpoint_inventory"][:30]:
            lines.append(
                f"- [{ep['severity']}] `{ep['kind']}` `{ep['url']}`"
            )
    if result["findings"]:
        lines += ["", "## 原始点位 Top 20"]
        for f in result["findings"][:20]:
            lines.append(
                f"- [{f['severity']}] `{f['kind']}` {f['title']} -> `{_short(f.get('value') or f.get('evidence'), 120)}`"
            )
    return "\n".join(lines).strip() + "\n"


# 超长连续无空白 token（minified 数据块/base64 blob/超长字符串字面量）会让
# 后续正则在其内部每个位置反复尝试匹配，累计到秒级且无法被匹配数上限拦住
# （卡在单次 finditer 扫描里）。这里把超过阈值的连续非空白串截短，
# 既消除 CPU 热点，又保留足够前缀供密钥/URL 识别。
_LONG_TOKEN_RE = re.compile(r"\S{2001,}")
_LONG_TOKEN_KEEP = 2000


def _truncate_long_token(m: re.Match[str]) -> str:
    return m.group(0)[:_LONG_TOKEN_KEEP]


def _strip_noise(text: str) -> str:
    # Markdown 里很多 curl/report 文本也有价值，不能只提代码块；这里去掉超长空白，
    # 并折叠超长连续 token，防止正则在其内部长时间持 GIL。
    text = _LONG_TOKEN_RE.sub(_truncate_long_token, text)
    return re.sub(r"\n{3,}", "\n\n", text)


def _augment_static_strings(text: str) -> str:
    """补充可静态还原的字符串，不执行目标 JS。

    借鉴常见 deobfuscator 的低风险步骤：字符串字面量 unescape、atob 常量解码、
    简单字符串数组索引展开。只把还原出的文本 append 到分析输入，供原有接口/secret
    规则命中；不改写/执行原始代码。
    """
    scan_text = text[:_MAX_STATIC_DEOBF_BYTES]
    extras: list[str] = []
    seen: set[str] = set()

    def add(value: str, label: str) -> None:
        if len(extras) >= _MAX_STATIC_EXTRAS:
            return
        value = (value or "").strip()
        if len(value) < 4 or value in seen:
            return
        if not any(x in value.lower() for x in (
            "/", "api", "token", "secret", "password", "upload", "login", "admin",
            "captcha", "sms", "appid", "appkey", "authorization", "bearer",
        )):
            return
        seen.add(value)
        extras.append(f"\n/* decoded:{label} */\n{value}\n")

    for raw_value in _iter_string_values(scan_text, limit=900):
        value = _unescape(raw_value)
        if value != raw_value:
            add(value, "escape")

    for m in _iter_matches(_ATOB_RE, scan_text, limit=250):
        decoded = _decode_base64_text(m.group(2))
        if decoded:
            add(decoded, "atob")

    for m in _iter_matches(_STRING_CONCAT_RE, scan_text, limit=250):
        parts = [_unescape(value) for value in _iter_string_values(m.group("expr"), limit=12)]
        if len(parts) >= 2:
            add("".join(parts), "concat")

    for extracted in _extract_inline_sourcemap_sources(scan_text):
        add(extracted, "inline-sourcemap")

    for arr in _iter_matches(_ARRAY_LITERAL_RE, scan_text, limit=120):
        name = arr.group("name")
        values = [_unescape(value) for value in _iter_string_values(arr.group("body"), limit=120)]
        if not values:
            continue
        ref_re = re.compile(rf"""{re.escape(name)}\s*\[\s*(0x[0-9a-fA-F]+|\d{{1,4}})\s*\]""")
        for ref in _iter_matches(ref_re, scan_text, limit=500):
            try:
                idx = int(ref.group(1), 0)
            except ValueError:
                continue
            if 0 <= idx < len(values):
                add(values[idx], f"{name}[{idx}]")

    if not extras:
        return text
    return text + "\n/* ===== STATIC DEOBFUSCATION HINTS ===== */\n" + "\n".join(extras)


def _match_string_value(match: re.Match[str]) -> str:
    if match.group("dq") is not None:
        return match.group("dq")
    if match.group("sq") is not None:
        return match.group("sq")
    return match.group("bq") or ""


def _iter_string_values(text: str, *, limit: int) -> Iterator[str]:
    for match in _iter_matches(_STRING_LITERAL_RE, text, limit=limit):
        yield _match_string_value(match)


def _extract_inline_sourcemap_sources(text: str) -> list[str]:
    out: list[str] = []
    for m in _iter_matches(_SOURCE_MAP_URL_RE, text, limit=20):
        ref = m.group(1)
        if not ref.startswith("data:") or "base64," not in ref[:120].lower():
            continue
        encoded = ref.split(",", 1)[1]
        decoded = _decode_base64_text(encoded, max_len=500_000)
        if decoded:
            sources = _extract_sourcemap_sources(decoded)
            if sources:
                out.append(sources)
    return out[:5]


def _decode_base64_text(value: str, *, max_len: int = 1000) -> str:
    s = (value or "").strip().replace("-", "+").replace("_", "/")
    if len(s) > max_len:
        return ""
    pad = "=" * (-len(s) % 4)
    try:
        raw = base64.b64decode(s + pad, validate=False)
    except Exception:
        return ""
    if not raw or sum(1 for b in raw if b in (9, 10, 13) or 32 <= b <= 126) / max(1, len(raw)) < 0.85:
        return ""
    return raw.decode("utf-8", errors="ignore")


def _find_key_values(text: str, source: str) -> list[JsFinding]:
    findings: list[JsFinding] = []
    for m in _iter_matches(_KEY_VALUE_RE, text):
        key = m.group("key")
        value = _unescape(m.group("value")).strip()
        if not value:
            continue
        lk = key.lower()
        ctx = _context(text, m.start(), m.end())
        if _looks_like_secret_key(lk, value):
            findings.append(JsFinding(
                "secret",
                f"疑似前端硬编码敏感键 `{key}`",
                _secret_severity(lk, value),
                _secret_score(lk, value),
                f"{key}={_short(value)}",
                ctx,
                value,
                source,
                ["secret", lk],
                ["确认该值是否能直接调用后端/第三方接口", "不要只提交泄露本身，优先验证能否伪造签名、上传文件或读取受限数据"],
            ))
        if lk in {"upload_token", "uptoken", "qiniu_token", "qiniutoken"}:
            findings.append(JsFinding(
                "cloud_upload_token",
                "七牛/云存储上传 token 暴露",
                "high",
                92,
                f"{key}={_short(value)}",
                ctx,
                value,
                source,
                ["qiniu", "upload", "xss_candidate"],
                ["结合 qiniu_upload_url 上传 HTML/JS 文件", "结合 qiniu_domain 访问返回 key，验证是否以 text/html 执行"],
            ))
        if lk in {"qiniu_upload_url", "uploadurl", "upload_url"} or "qiniup.com" in value:
            findings.append(JsFinding(
                "cloud_upload_endpoint",
                "云存储上传入口",
                "medium",
                72,
                f"{key}={_short(value)}",
                ctx,
                value,
                source,
                ["qiniu", "upload"],
            ))
        if lk in {"qiniu_domain", "file_domain", "cdn_domain", "bucket_domain"}:
            findings.append(JsFinding(
                "cloud_file_domain",
                "云存储文件访问域名",
                "medium",
                70,
                f"{key}={_short(value)}",
                ctx,
                value,
                source,
                ["qiniu", "bucket"],
            ))
        if ("parse" in lk and "id" in lk) or lk in {"application_id", "appid", "app_id"}:
            if len(value) >= 6:
                findings.append(JsFinding(
                    "parse_app_id",
                    "Parse/BaaS Application ID",
                    "medium",
                    78,
                    f"{key}={_short(value)}",
                    ctx,
                    value,
                    source,
                    ["parse", "baas"],
                    ["尝试带 X-Parse-Application-Id 访问 /parse/classes/_User?count=1&limit=0"],
                ))
    return findings


def _find_urls_and_paths(text: str, base_url: str, source: str) -> list[JsFinding]:
    findings: list[JsFinding] = []
    seen: set[str] = set()
    for pattern in (_URL_RE, _PATH_RE):
        for m in _iter_matches(pattern, text):
            if pattern is _PATH_RE and m.start() > 0 and text[m.start() - 1] in {":", "/"}:
                continue
            raw = (m.groupdict().get("path") or m.group(0)).strip().rstrip(";,")
            if not raw or raw in seen:
                continue
            seen.add(raw)
            full = _absolute_url(raw, base_url)
            kind, title, sev, score, tags, steps = _classify_endpoint(raw)
            findings.append(JsFinding(kind, title, sev, score, raw, _context(text, m.start(), m.end()), full, source, tags, steps))
    return findings


def _find_framework_signatures(text: str, base_url: str, source: str) -> list[JsFinding]:
    findings: list[JsFinding] = []
    low = text.lower()
    if "x-parse-application-id" in low or "/parse/classes/" in low or "parse.initialize" in low:
        findings.append(JsFinding(
            "parse_signature",
            "发现 Parse Server 前端调用特征",
            "medium",
            76,
            "X-Parse-Application-Id / /parse/classes",
            _context(text, max(0, low.find("parse")), max(0, low.find("parse")) + 80),
            _absolute_url("/parse/classes/_User?count=1&limit=0", base_url),
            source,
            ["parse", "baas", "unauthorized_candidate"],
            ["用前端 App ID 验证 _User、短信验证码表、ACL 是否可读"],
        ))
    if "runtimeconfig" in low and "upload_token" in low:
        findings.append(JsFinding(
            "runtime_config_upload_token",
            "runtimeConfig 暴露上传配置",
            "high",
            90,
            "runtimeConfig + upload_token",
            _context(text, low.find("runtimeconfig"), low.find("runtimeconfig") + 140),
            _absolute_url("/config", base_url),
            source,
            ["config", "qiniu", "upload"],
            ["访问 /config 获取最新 token", "验证 token 是否可上传 HTML 文件并通过文件域名访问"],
        ))
    header_match = _HEADER_RE.search(text)
    if header_match:
        findings.append(JsFinding(
            "auth_header",
            "发现认证/Token Header 逻辑",
            "info",
            35,
            _short(header_match.group(0)),
            "",
            "",
            source,
            ["auth"],
        ))
    return findings


def _classify_endpoint(path: str) -> tuple[str, str, str, int, list[str], list[str]]:
    p = path.lower()
    if "/config" in p or p.endswith("config"):
        return "config_endpoint", "配置接口候选", "high", 86, ["config", "secret"], ["访问接口检查是否未授权返回 token/key/domain"]
    if "get_user_by_phone" in p or ("user" in p and "phone" in p):
        return "user_lookup_by_phone", "手机号查用户接口候选", "critical", 96, ["idor", "account_takeover"], ["无登录态调用并检查是否返回 password_md5/isAdmin/token"]
    if "/user/login" in p or p.endswith("/login") or "/auth/login" in p:
        return "login_endpoint", "登录接口", "medium", 60, ["auth"], ["结合泄露哈希/token/默认口令验证是否可登录"]
    if "password" in p or "reset" in p or "forget" in p:
        return "password_reset_endpoint", "找回/重置密码接口候选", "high", 82, ["password_reset"], ["检查 code/token/userId 是否可控，必须证明状态真实改变"]
    # 收紧 code 判定：仅命中明确的验证码/短信码语义，避免 /encode /qrcode /barcode 等误报。
    if (
        "phone_code" in p or "sms" in p or "captcha" in p
        or "verifycode" in p or "verify_code" in p or "smscode" in p
        or "sms_code" in p or "authcode" in p or "auth_code" in p
        or "sendcode" in p or "send_code" in p or "getcode" in p or "get_code" in p
        or p.endswith("/code") or "/code/" in p
    ):
        return "otp_or_code_endpoint", "验证码/短信码接口候选", "high", 80, ["otp", "captcha"], ["区分图形码和短信 OTP，重点验证响应是否回显手机验证码"]
    if "/parse/classes/_user" in p or "_user" in p:
        return "parse_user_table", "Parse _User 表访问候选", "critical", 94, ["parse", "user_data"], ["带 X-Parse-Application-Id 验证 count 和 keys=username/sessionToken/password"]
    if "/parse/classes/" in p:
        return "parse_class_endpoint", "Parse class 访问候选", "high", 84, ["parse", "baas"], ["枚举 class 表，检查 _User、验证码、订单等敏感表 ACL"]
    if "upload" in p or "file" in p:
        return "upload_endpoint", "上传/文件接口候选", "high", 78, ["upload", "file"], ["检查未授权上传、上传 token、文件解析执行或对象存储 HTML 执行"]
    if "admin" in p or "manager" in p:
        return "admin_endpoint", "后台/管理接口候选", "medium", 68, ["admin"], ["检查未授权、弱口令或普通用户垂直越权"]
    if "/api/" in p:
        return "api_endpoint", "API 接口", "info", 30, ["api"], []
    return "endpoint", "前端路径/接口", "info", 20, [], []


def _build_chains(findings: list[JsFinding], base_url: str) -> list[JsChain]:
    chains: list[JsChain] = []
    by_kind: dict[str, list[JsFinding]] = {}
    for f in findings:
        by_kind.setdefault(f.kind, []).append(f)

    if by_kind.get("cloud_upload_token") or by_kind.get("runtime_config_upload_token"):
        evidence = _evidence(findings, {"cloud_upload_token", "cloud_upload_endpoint", "cloud_file_domain", "runtime_config_upload_token"})
        probes = _qiniu_probes(findings)
        chains.append(JsChain(
            "qiniu_upload_xss",
            "配置泄露云存储 upload_token，可发展为对象存储 HTML/XSS",
            "high",
            "高危",
            "同时出现上传 token / 上传入口 / 文件访问域名，符合本地成功报告中的 /config → 七牛桶 XSS 链路。",
            evidence,
            probes,
        ))

    if by_kind.get("parse_signature") or by_kind.get("parse_app_id") or by_kind.get("parse_user_table"):
        probes = [_curl(_absolute_url("/parse/classes/_User?count=1&limit=0", base_url), {"X-Parse-Application-Id": "<APP_ID>"})]
        probes.append(_curl(_absolute_url("/parse/classes/v5_phone_code?count=1&limit=0", base_url), {"X-Parse-Application-Id": "<APP_ID>"}))
        chains.append(JsChain(
            "parse_unauthorized_read",
            "前端暴露 Parse Application ID，可验证 Parse 表未授权读取",
            "high",
            "高危",
            "出现 Parse App ID / X-Parse-Application-Id / /parse/classes 特征，命中成功报告中的 Parse _User 与短信码读取链路。",
            _evidence(findings, {"parse_signature", "parse_app_id", "parse_user_table", "parse_class_endpoint"}),
            probes,
        ))

    if by_kind.get("user_lookup_by_phone") and by_kind.get("login_endpoint"):
        chains.append(JsChain(
            "account_takeover_by_hash",
            "手机号查用户 + 登录接口组合，疑似管理员哈希登录链",
            "high",
            "高危",
            "同时发现按手机号查用户接口和登录接口，命中成功报告中的 get_user_by_phone → password_md5 → login 链路。",
            _evidence(findings, {"user_lookup_by_phone", "login_endpoint"}),
            [
                _curl(_absolute_url("/user/get_user_by_phone", base_url), json_body='{"phone":"13800138000"}'),
                _curl(_absolute_url("/user/login", base_url), json_body='{"username":"admin","password_md5":"<HASH>"}'),
            ],
        ))

    if by_kind.get("password_reset_endpoint") or by_kind.get("otp_or_code_endpoint"):
        chains.append(JsChain(
            "password_reset_or_otp",
            "验证码/密码重置相关接口，需要进一步实证状态变化",
            "medium",
            "中高危候选",
            "发现 code/sms/password/reset 相关接口。此类不能只靠 JS 推断，必须证明短信 OTP 回显或改密真实成功。",
            _evidence(findings, {"password_reset_endpoint", "otp_or_code_endpoint"}),
            ["构造基线请求和变体请求，对比 code/token/userId 是否可控", "若是改密链，必须用新密码登录或证明状态已改变"],
        ))

    secrets = [f for f in findings if f.kind == "secret" and f.score >= 70]
    if secrets:
        chains.append(JsChain(
            "frontend_secret_followup",
            "前端硬编码高价值 secret，需要验证可用性",
            "medium",
            "待实证",
            "发现高风险 key/secret，但按 EduSRC 口径需进一步证明能实际调用接口、伪造签名或读取受限数据。",
            [f.evidence for f in secrets[:6]],
            ["搜索签名函数 md5/sha/hmac/sign", "用 secret 复现一次受限 API 调用，拿到真实响应证据"],
        ))
    return chains


def _qiniu_probes(findings: list[JsFinding]) -> list[str]:
    upload = next((f.value for f in findings if f.kind == "cloud_upload_endpoint"), "https://up-z2.qiniup.com")
    domain = next((f.value for f in findings if f.kind == "cloud_file_domain"), "<qiniu_domain>")
    return [
        f'curl -F "token=<UPLOAD_TOKEN>" -F "file=@poc.html;filename=poc.html;type=text/html" "{upload}"',
        f"访问 {domain.rstrip('/')}/<返回key>，确认 Content-Type 与 JS 是否执行",
    ]


def _endpoint_inventory(findings: list[JsFinding]) -> list[dict[str, Any]]:
    endpoint_kinds = {
        "config_endpoint",
        "user_lookup_by_phone",
        "login_endpoint",
        "password_reset_endpoint",
        "otp_or_code_endpoint",
        "parse_user_table",
        "parse_class_endpoint",
        "upload_endpoint",
        "admin_endpoint",
        "api_endpoint",
        "endpoint",
    }
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in sorted(findings, key=lambda x: x.score, reverse=True):
        if f.kind not in endpoint_kinds or not f.value:
            continue
        fp = f.value
        if fp in seen:
            continue
        seen.add(fp)
        out.append({
            "url": f.value,
            "kind": f.kind,
            "title": f.title,
            "severity": f.severity,
            "score": f.score,
            "tags": f.tags,
            "suggested_tests": f.next_steps,
        })
    return out


def _summary(findings: list[JsFinding], chains: list[JsChain], endpoint_inventory: list[dict[str, Any]]) -> dict[str, Any]:
    top_score = max([f.score for f in findings] + [0])
    top = "critical" if top_score >= 94 else "high" if top_score >= 80 else "medium" if top_score >= 60 else "info"
    return {
        "findings": len(findings),
        "chains": len(chains),
        "endpoints": len(endpoint_inventory),
        "top_severity": top,
        "kinds": sorted({f.kind for f in findings}),
    }


def _fetch_text(url: str, *, timeout: float) -> tuple[str, str]:
    # 协议白名单：远程只允许 http/https；file:// 走受限本地读取，杜绝任意本地文件读取。
    scheme = (urlparse(url).scheme or "").lower()
    if scheme == "file":
        return _fetch_local_file(url)
    if scheme not in _ALLOWED_FETCH_SCHEMES:
        raise ValueError(f"不支持的抓取协议: {scheme or '(空)'}")
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; AutoHunter-JSAnalyzer)"})
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310 - 协议已白名单，本地工具只读取内容
        # 流式读取并设硬上限，避免超大响应一次性吃满内存。
        raw = resp.read(_MAX_FETCH_BYTES)
        content_type = resp.headers.get("content-type", "")
    return raw.decode("utf-8", errors="replace"), content_type


def _fetch_local_file(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    if parsed.netloc not in ("", "localhost"):
        raise ValueError("file:// 只允许本机普通文件")
    path = Path(url2pathname(parsed.path)).resolve()
    allowed_roots = [
        Path.cwd().resolve(),
        Path(tempfile.gettempdir()).resolve(),
        (Path.home() / ".cache" / "autohunter").resolve(),
    ]
    if not any(path == root or root in path.parents for root in allowed_roots):
        raise ValueError("file:// 只允许读取当前工作区或临时目录内文件")
    if not path.is_file():
        raise ValueError("file:// 目标不是普通文件")
    raw = path.read_bytes()[:_MAX_FETCH_BYTES]
    suffix = path.suffix.lower()
    content_type = "application/javascript" if suffix == ".js" else "text/html" if suffix in {".html", ".htm"} else "text/plain"
    return raw.decode("utf-8", errors="replace"), content_type


def _looks_like_js(url: str, content_type: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith((".js", ".mjs")) or "javascript" in (content_type or "").lower()


def _looks_like_sourcemap(url: str, content_type: str) -> bool:
    path = urlparse(url).path.lower()
    ct = (content_type or "").lower()
    return path.endswith(".map") or "source-map" in ct


def _extract_sourcemap_sources(text: str) -> str:
    try:
        data = json.loads(text)
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    chunks: list[str] = []
    for i, content in enumerate(contents[:80]):
        if not isinstance(content, str) or not content.strip():
            continue
        name = sources[i] if i < len(sources) else f"source-{i}"
        chunks.append(f"\n/* sourcemap source: {name} */\n{content[:120_000]}\n")
    return "\n".join(chunks)[:_MAX_ANALYZE_BYTES]


def _extract_js_refs(text: str, base_url: str, *, is_js: bool) -> list[str]:
    refs: list[str] = []
    if not is_js:
        parser = _ScriptParser()
        try:
            parser.feed(text)
        except Exception:
            pass
        refs.extend(parser.scripts)
    for m in _iter_matches(_JS_REF_RE, text):
        ref = m.group(1) or m.group(2) or ""
        refs.append(ref)
    out: list[str] = []
    seen: set[str] = set()
    for ref in refs:
        if ref.startswith(("blob:", "javascript:")):
            continue
        if ref.startswith("data:"):
            # inline sourcemap 可能很大；这里不加入抓取队列，避免把 data: 当 URL 递归。
            continue
        absolute = urljoin(base_url, ref)
        if absolute not in seen and (
            _looks_like_js(absolute, "application/javascript") or _looks_like_sourcemap(absolute, "")
        ):
            seen.add(absolute)
            out.append(absolute)
    return out


def _origin(url: str) -> str:
    p = urlparse(url)
    if p.scheme == "file":
        return url.rsplit("/", 1)[0] + "/"
    if not p.scheme or not p.netloc:
        return url
    return f"{p.scheme}://{p.netloc}"


def _looks_like_secret_key(key: str, value: str) -> bool:
    # 1) key 名本身带敏感语义：高置信，直接判正。
    if any(x in key for x in ("secret", "token", "key", "appid", "app_id", "password", "passwd", "ak", "sk")):
        return True
    # 2) value 内含敏感关键字：判正。
    if _SECRET_HINT_RE.search(value):
        return True
    # 3) 长随机串兜底：先排除 URL/路径/data:/颜色码/纯哈希、base64 图片数据块、
    #    以及超长 base64（几乎都是内联数据而非密钥），避免误报"硬编码敏感键"。
    if _SECRET_VALUE_EXCLUDE_RE.match(value):
        return False
    if _SECRET_DATA_BLOB_RE.match(value):
        return False
    if len(value) > _SECRET_MAX_BLOB_LEN:
        return False
    return bool(_SECRET_BLOB_RE.match(value))


def _secret_score(key: str, value: str) -> int:
    if "upload_token" in key or "password" in key:
        return 90
    if "secret" in key or "token" in key:
        return 82
    if "appid" in key or "app_id" in key:
        return 70
    return 55 if len(value) < 16 else 68


def _secret_severity(key: str, value: str) -> str:
    score = _secret_score(key, value)
    if score >= 90:
        return "high"
    if score >= 70:
        return "medium"
    return "info"


def _dedupe_findings(findings: list[JsFinding]) -> list[JsFinding]:
    out: list[JsFinding] = []
    seen: set[str] = set()
    for f in findings:
        fp = hashlib.sha1(f"{f.kind}|{f.value or f.evidence}".encode()).hexdigest()
        if fp in seen:
            continue
        seen.add(fp)
        out.append(f)
    return out


def _evidence(findings: list[JsFinding], kinds: set[str]) -> list[str]:
    return [_short(f.evidence or f.value, 140) for f in findings if f.kind in kinds][:8]


def _context(text: str, start: int, end: int) -> str:
    left = max(0, start - _MAX_CONTEXT // 2)
    right = min(len(text), end + _MAX_CONTEXT // 2)
    return text[left:right].replace("\n", " ").strip()


def _absolute_url(path_or_url: str, base_url: str) -> str:
    if not path_or_url:
        return ""
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        return path_or_url
    if not base_url:
        return path_or_url
    base = base_url if base_url.endswith("/") else base_url + "/"
    return urljoin(base, path_or_url.lstrip("/"))


def _curl(url: str, headers: dict[str, str] | None = None, json_body: str | None = None) -> str:
    parts = [f'curl -i "{url}"']
    for k, v in (headers or {}).items():
        parts.append(f'-H "{k}: {v}"')
    if json_body:
        parts.append('-H "Content-Type: application/json"')
        parts.append(f"-d '{json_body}'")
    return " \\\n  ".join(parts)


def _unescape(value: str) -> str:
    s = value.replace(r"\/", "/").replace(r"\"", '"').replace(r"\'", "'")
    if "\\" not in s:
        return s
    try:
        return codecs.decode(s, "unicode_escape")
    except Exception:
        return s


def _short(value: Any, limit: int = 80) -> str:
    s = str(value or "").replace("\n", " ").strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def result_to_json(result: dict[str, Any]) -> str:
    return json.dumps(result, ensure_ascii=False, indent=2)
