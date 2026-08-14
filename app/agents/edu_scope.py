"""EduSRC 硬性不收口径（代码闸门，不单靠提示词）。

短信/邮箱轰炸：发送验证码或通知的接口无频率限制，只能刷短信/邮件。
EduSRC 明确不收。短信 OTP 明文回显并能打通登录/改密是另一类，仍收。
"""
from __future__ import annotations

from typing import Any

_BOMBING_EXPLICIT = (
    "短信轰炸", "邮箱轰炸", "邮件轰炸", "短信炸弹", "邮件炸弹", "验证码轰炸",
    "sms bomb", "email bomb", "sms bombing", "email bombing",
)
_BOMBING_RATE = (
    "无频率", "没有频率", "频率限制缺失", "无限制发送", "无限发送",
    "可连发", "可以连发", "可刷短信", "可刷邮件", "可刷邮箱",
    "对任意手机号发送", "对任意邮箱发送", "任意手机号轰炸", "任意邮箱轰炸",
)
_SMS_MAIL = (
    "短信", "邮件", "邮箱", "sms", "email", "sendsms", "sendmail",
    "send_sms", "send_mail", "send-sms", "smtp",
)
_OTP_ECHO = (
    "明文回显", "响应回显", "返回验证码", "回显验证码", "otp 回显",
    "otp回显", "验证码写在响应", "响应里返回验证码", "响应中返回验证码",
)

BOMBING_BLOCK_REASON = (
    "EduSRC 不收短信轰炸/邮箱轰炸/邮件轰炸（发送验证码或通知的接口无频率限制、只能刷短信或邮件）。"
    "不要连发取证，也不要当洞提交。"
    "若同一接口把短信/手机 OTP 明文写在 HTTP 响应里，并能打通任意用户登录或改密，按 OTP 回显提交，不要写成轰炸。"
)


def _s(value: Any) -> str:
    return str(value or "")


def finding_text(finding: Any) -> str:
    evidence = getattr(finding, "evidence", None)
    sample = notes = ""
    if evidence is not None:
        sample = _s(getattr(evidence, "extracted_data_sample", "") or "")
        notes = _s(getattr(evidence, "notes", "") or "")
        if isinstance(evidence, dict):
            sample = _s(evidence.get("extracted_data_sample"))
            notes = _s(evidence.get("notes"))
    return "\n".join([
        _s(getattr(finding, "vuln_type", "")),
        _s(getattr(finding, "title", "")),
        _s(getattr(finding, "target_url", "")),
        _s(getattr(finding, "description", "")),
        _s(getattr(finding, "poc", "")),
        sample,
        notes,
    ]).lower()


def looks_like_otp_echo(finding: Any) -> bool:
    """短信/手机 OTP 写在 HTTP 响应里——这是可收的接管类，不是轰炸。"""
    text = finding_text(finding)
    if not any(token in text for token in _OTP_ECHO):
        return False
    return any(token in text for token in ("短信", "手机验证码", "otp", "sms"))


def looks_like_edu_bombing(finding: Any) -> bool:
    """仅「能刷短信/邮件」；OTP 回显优先按可收洞，不按轰炸拦。"""
    if looks_like_otp_echo(finding):
        return False
    text = finding_text(finding)
    if any(marker in text for marker in _BOMBING_EXPLICIT):
        return True
    if any(marker in text for marker in _BOMBING_RATE) and any(token in text for token in _SMS_MAIL):
        return True
    return False


def edu_bombing_block_reason(finding: Any) -> str:
    return BOMBING_BLOCK_REASON if looks_like_edu_bombing(finding) else ""
