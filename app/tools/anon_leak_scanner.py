"""侦察期匿名可访问端点敏感数据泄露嗅探（纯本地、无副作用、可单测）。

对某个 HTTP 响应正文做保守的关键词/正则命中，识别“疑似泄露的敏感数据”，
供 worker 在首轮就把线索带给 LLM 核实，并在审核侧作为降过杀的救援锚点。
原则：只标记、不实锤；命中仅代表“值得核实”，最终判洞仍交由 worker 取证与审核把关。
"""
from __future__ import annotations

import re

# (标签, 正则)。各正则已内联 (?i)。保守起见按“长得像敏感数据”匹配。
_LEAK_PATTERNS: list[tuple[str, str]] = [
    ("令牌/Bearer", r"(?i)(authorization|bearer|x-api-key|api[_-]?key|token)['\"]?\s*[:=]\s*['\"]?(?:bearer\s+)?[a-z0-9._\-]{12,}['\"]?"),
    ("密钥/口令", r"(?i)(password|passwd|pwd|secret)['\"]?\s*[:=]\s*['\"][^\s'\"<>]{6,}['\"]"),
    ("私钥", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("AWS 凭证", r"(?i)(AKIA[0-9A-Z]{16}|aws_access_key_id|aws_secret_access_key)"),
    ("数据库连接串", r"(?i)(jdbc:|mysql://|postgres://|mongodb(\+srv)?://|redis://)[^\s'\"<>]+"),
    ("对象存储端点", r"(?i)[a-z0-9.\-]+\.s3[.\-][a-z0-9\-]*\.amazonaws\.com"),
    ("Slack/GitHub 令牌", r"(?i)(xox[baprs]-[0-9a-z\-]{10,}|gh[pousr]_[0-9a-z]{20,})"),
    ("内存/SSN/身份证", r"(?i)(id_card|idcard|identity_card|ssn)['\"]?\s*[:=]\s*['\"][0-9]{6,}['\"]"),
]

_COMPILED: list[tuple[str, re.Pattern]] = [
    (label, re.compile(pattern)) for label, pattern in _LEAK_PATTERNS
]


def scan_body(body: str) -> list[str]:
    """在响应正文中命中疑似敏感数据，返回去重后的命中标签列表（可能为空）。"""
    if not body:
        return []
    text = body if isinstance(body, str) else str(body)
    hits = [label for label, rx in _COMPILED if rx.search(text)]
    seen: list[str] = []
    for label in hits:
        if label not in seen:
            seen.append(label)
    return seen


def has_sensitive_leak(body: str) -> bool:
    return bool(scan_body(body))