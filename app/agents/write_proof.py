"""写/删/改漏洞的无害证据契约。

越权删除/修改最容易走进死结：
- 安全：不许改真实/他人数据
- 审核：只返回 200/success 不算洞
- 旧闸门：把「不存在 / data:0」和 URL 里的 delete 一律当失败

于是无害证法被自己拦掉，高危删除因 PoC 含 delete 跳过复现再被降成 deepen，
最后沉进「AI 未采纳」。本模块用同一套分类同时约束 worker 闸门和 reviewer 改判。
"""
from __future__ import annotations

import re
from typing import Any

KIND_NONE = "none"
KIND_WEAK = "weak"
KIND_SENTINEL = "sentinel"
KIND_IDEMPOTENT = "idempotent"
KIND_SIDE_READ = "side_read"
KIND_AUTHZ_DIFF = "authz_diff"

STRONG_KINDS = frozenset({
    KIND_SENTINEL, KIND_IDEMPOTENT, KIND_SIDE_READ, KIND_AUTHZ_DIFF,
})

# 不用裸 "del"：会误伤 delivery / model 等
_WRITE_TYPE_MARKERS = ("unauthorized", "idor", "auth", "access", "越权", "未授权")
_WRITE_TEXT_MARKERS = (
    "updatedel", "delete", "remove", "update", "modify", "edit", "save",
    "insert", "create", "删除", "修改", "更新", "写操作", "新增", "重置密码",
)
_WRITE_UI_MARKERS = (
    "删除", "修改", "更新", "新增", "保存", "reset", "delete", "update",
    "remove", "save", "updatedel",
)

_ZERO_EFFECT_RE = (
    re.compile(r'"data"\s*:\s*0\b', re.I),
    re.compile(r'"affected(?:rows)?"\s*:\s*0\b', re.I),
    re.compile(r'"row(?:s|count)?"\s*:\s*0\b', re.I),
    re.compile(r'"count"\s*:\s*0\b', re.I),
    re.compile(r"\b0\s+rows?\b", re.I),
    re.compile(r"影响\s*0"),
    re.compile(r"0\s*行"),
)
_WEAK_CLAIM_RE = (
    re.compile(r"不存在"),
    re.compile(r"未实证"),
    re.compile(r"未证明"),
)
_UNSAFE_REPLAY_RE = (
    re.compile(r"\bdrop\s+(table|database|schema)\b", re.I),
    re.compile(r"\btruncate\s+table\b", re.I),
    re.compile(r"\bdelete\s+from\b", re.I),
    re.compile(r"sqlmap.{0,80}--(?:dump|os-shell|file-write|sql-shell)", re.I),
    re.compile(r"\brm\s+-rf\b", re.I),
)

HARMLESS_PROTOCOL = (
    "不要删改真实/他人数据。按无害证法补证据："
    "① 自建带唯一标识的哨兵（如 SRC_TEST_<rand>），增→改→删只碰自己这条，旁路 GET/列表回读 before→after；"
    "② 未登录/无 token 对照：写接口应 401/403，带低权登录态应变 200/授权通过；"
    "③ 只能碰已有对象时幂等回写原值，看 affectedRows≥1 或授权通过且值未变。"
    "做不到就 finish(deepen_lead) 写清缺哪一步，禁止硬删真数据凑证据。"
)


def _s(value: Any) -> str:
    return str(value or "")


def finding_blob(finding: Any) -> str:
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
        _s(getattr(finding, "raw_request", "")),
        _s(getattr(finding, "raw_response", "")),
        sample,
        notes,
    ])


def is_write_finding(finding: Any) -> bool:
    """worker 闸门用：未授权/越权类 + 写/删/改语义。"""
    vuln_type = _s(getattr(finding, "vuln_type", "")).lower()
    if not any(marker in vuln_type for marker in _WRITE_TYPE_MARKERS):
        return False
    low = finding_blob(finding).lower()
    return any(marker in low for marker in _WRITE_TEXT_MARKERS)


def looks_like_write_op(
    title: str = "",
    url: str = "",
    vuln_type: str = "",
    description: str = "",
) -> bool:
    """列表置顶用：标题/URL/类型像写删改即可，不要求已是越权洞。"""
    blob = f"{title}\n{url}\n{vuln_type}\n{description}".lower()
    return any(marker in blob for marker in _WRITE_UI_MARKERS)


def classify_write_proof(finding: Any) -> str:
    if not is_write_finding(finding):
        return KIND_NONE
    text = finding_blob(finding)
    low = text.lower()
    if _has_sentinel(text, low):
        return KIND_SENTINEL
    if _has_authz_diff(text, low):
        return KIND_AUTHZ_DIFF
    if _has_idempotent(text, low):
        return KIND_IDEMPOTENT
    if _has_side_read(text, low):
        return KIND_SIDE_READ
    if _has_zero_effect(low) or any(p.search(text) for p in _WEAK_CLAIM_RE):
        return KIND_WEAK
    return KIND_NONE


def has_strong_write_proof(finding: Any) -> bool:
    return classify_write_proof(finding) in STRONG_KINDS


def weak_write_block_reason(finding: Any) -> str:
    """仅拦截「成功文案 + 零影响、且没有无害证据」的半成品。"""
    if classify_write_proof(finding) != KIND_WEAK:
        return ""
    return (
        "写/删/改接口证据不足：当前只有成功文案或 data:0/对象不存在，"
        "不能证明具备写授权。请改用无害证法，不要删改真实数据。"
        + HARMLESS_PROTOCOL
    )


def should_skip_live_replay(finding: Any, poc: str = "") -> tuple[bool, str]:
    """现场复放写/删 PoC 既不安全，也会把已取证的高危洞误降成 deepen。"""
    blob = f"{poc}\n{finding_blob(finding)}"
    if any(p.search(blob) for p in _UNSAFE_REPLAY_RE):
        return True, "destructive_sql"
    if is_write_finding(finding) or looks_like_write_op(
        title=_s(getattr(finding, "title", "")),
        url=_s(getattr(finding, "target_url", "")),
        vuln_type=_s(getattr(finding, "vuln_type", "")),
        description=_s(getattr(finding, "poc", "")),
    ):
        return True, "write_delete"
    return False, ""


def _has_sentinel(text: str, low: str) -> bool:
    if "src_test_" not in low and "哨兵" not in text and "自建测试" not in text:
        return False
    return _has_side_read(text, low) or bool(re.search(
        r"(新增|创建|insert|create).{0,40}(成功|id|返回)", text, re.I,
    ))


def _has_authz_diff(text: str, low: str) -> bool:
    denied = bool(re.search(r"\b401\b|\b403\b|没有权限|无权|无权限|login required", text, re.I))
    allowed = bool(re.search(r"\b200\b|操作成功|授权通过|affected(?:rows)?\"\s*:\s*[1-9]", text, re.I))
    contrast = any(token in low for token in (
        "未登录", "无cookie", "无 cookie", "不带token", "不带 token", "不带授权",
        "对照", "对比", "登出", "clear=true", "未携带", "匿名",
    ))
    return denied and allowed and contrast


def _has_idempotent(text: str, low: str) -> bool:
    if not any(token in low for token in ("幂等", "写回原值", "原值写回", "同一值", "值未变")):
        return False
    return bool(re.search(
        r"affected(?:rows)?\"\s*:\s*[1-9]|授权通过|操作成功", text, re.I,
    ))


def _has_side_read(text: str, low: str) -> bool:
    return bool(re.search(
        r"(再次查询|删除后查询|修改后查询|旁路|before.{0,12}after|前后对比|状态变化)"
        r".{0,40}(不存在|消失|已删除|已更新|已修改|新值|旧值)",
        text,
        re.I,
    )) or bool(re.search(
        r"(before|after|前后对比|状态变化|修改后查询|删除后查询)",
        low,
    ))


def _has_zero_effect(low: str) -> bool:
    return any(p.search(low) for p in _ZERO_EFFECT_RE)
