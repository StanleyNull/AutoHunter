"""两段式入库的第一道闸门：确定性预筛（Stage-0）。

把明显是垃圾 / 半成品的提交挡在 Finding 主表之外，只记一条 TaskEvent 日志，
随后 Review 作为第二道闸门（AI 初审 + 人工终审）继续把关。

原则：全确定性、无副作用、无 IO，可单测。宁可少拦、绝不误杀真洞——
拿不准的一律放行进评审，交给第二段去裁定。
"""
from __future__ import annotations

EMPTY_SHELL = "empty_shell"
NO_VULN_NEGATION = "no_vuln_negation"

# 表示"这里其实没洞 / 没利用成功"的措辞，命中且无实证即判垃圾。
_NO_VULN_PHRASES = (
    "未发现漏洞", "未发现相关漏洞", "未发现可利用", "未发现可利用漏洞",
    "无漏洞", "没有漏洞", "未找到漏洞", "不存在漏洞", "不存在该漏洞",
    "not vulnerable", "no vulnerability", "vulnerability not found",
    "none found", "not exploitable", "no issue found",
)

# 视为"实证"的字段：任一非空即放行进评审，避免误杀。
_EVIDENCE_FIELDS = ("poc", "raw_request", "raw_response", "steps")


def screen_submission(f) -> tuple[bool, str]:
    """对单个待落库 finding 做第一道预筛。

    返回 (ok, reason)：ok=False 表示应挡在 Finding 主表之外（记日志即可），
    ok=True 表示可进入落库（pending_review），交由第二段评审。
    """
    if not isinstance(f, dict):
        return False, EMPTY_SHELL

    def s(key: str) -> str:
        return str(f.get(key) or "").strip()

    vuln_type = s("vuln_type")
    title = s("title")
    description = s("description")
    haystack = " ".join((title, description)).lower()

    has_evidence = any(s(k) for k in _EVIDENCE_FIELDS) or bool(f.get("evidence"))

    if not has_evidence and not vuln_type and not title and not description:
        return False, EMPTY_SHELL

    if not has_evidence and any(p in haystack for p in _NO_VULN_PHRASES):
        return False, NO_VULN_NEGATION

    return True, ""