"""疑似被黑 / backdoor_compromised 证据门槛。

历史误报：新闻配图走外部图床、CDN/OSS 静态资源，也被当成服务器被攻陷。
只有本站 HTML 标题/正文被替换或 webshell 可执行，才允许交这一类。
"""
from __future__ import annotations

from typing import Any

from app.agents.edu_scope import _s, finding_text

WEAK_BACKDOOR_REASON = (
    "这不是服务器被黑。站点引用图床/CDN/OSS/外部图片或第三方 JS/CSS/字体/统计，是正常前端资源，"
    "不能提交 backdoor_compromised。"
    "只有本站【自身 HTML 标题或正文】被替换成赌博/色情/彩票、出现 hacked by/deface、"
    "或 webshell 可执行命令，才算被攻陷。"
)

_CLAIM_TYPE = ("backdoor", "compromised", "挂马")
_CLAIM_TEXT = (
    "疑似被黑", "疑似后门", "服务器被攻陷", "被攻陷", "被挂马",
    "网页被篡改", "页面被篡改", "被黑", "植入暗链",
)
_WEAK = (
    "图床", "外链图片", "外部图片", "外部图床", "图片床",
    "imgur", "sm.ms", "smms", "qiniu", "七牛", "又拍云", "upyun",
    "aliyuncs", "aliyun oss", "myqcloud", "qcloud", "oss-cn-",
    "jsdelivr", "unpkg", "bootcdn", "cdnjs", "gravatar",
    "fonts.google", "fontawesome", "staticfile.org",
    "引用外部", "使用了图床", "图片存在图床", "cdn 配图",
    "第三方图片", "第三方图床",
)
_STRONG = (
    "赌博", "博彩", "色情", "彩票", "slot", "casino", "porn",
    "webshell", "hacked by", "deface", "defaced",
    "首页被替换", "页面被替换", "原站内容消失", "原站内容被",
    "挂马页面", "暗链注入", "seo 暗链", "博彩暗链",
    "可执行命令", "命令执行结果", "kentang", "slot thailand",
)


def _blob(finding: Any) -> str:
    return "\n".join([
        finding_text(finding),
        _s(getattr(finding, "raw_response", "")),
        _s(getattr(finding, "raw_request", "")),
    ]).lower()


def is_backdoor_claim(finding: Any) -> bool:
    vuln = _s(getattr(finding, "vuln_type", "")).lower()
    if any(token in vuln for token in _CLAIM_TYPE):
        return True
    text = _blob(finding)
    return any(marker in text for marker in _CLAIM_TEXT)


def has_strong_compromise_evidence(finding: Any) -> bool:
    text = _blob(finding)
    return any(marker in text for marker in _STRONG)


def looks_like_weak_backdoor(finding: Any) -> bool:
    """声称被黑，但没有页面被替换/webshell 实锤。"""
    if not is_backdoor_claim(finding):
        return False
    if has_strong_compromise_evidence(finding):
        return False
    return True


def weak_backdoor_block_reason(finding: Any) -> str:
    return WEAK_BACKDOOR_REASON if looks_like_weak_backdoor(finding) else ""
