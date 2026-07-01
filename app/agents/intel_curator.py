"""Intel Curator：全局情报库维护器。

目标：
- 写入前拦截明显垃圾，防止情报库越积越脏；
- 支持人工触发维护，清理历史脏数据；
- 规则必须可解释、保守，宁可少删也不误删已验证/高复用情报。

当前版本是确定性规则维护器，不依赖 LLM，避免额外 token 成本和不稳定性。
后续可在 `assess_intel` 的边界项上再接 LLM 评分。
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:  # 仅类型检查用，运行期不强依赖 sqlalchemy，便于纯规则单测。
    from sqlalchemy.ext.asyncio import AsyncSession

_LOW_SIGNAL_TEXT = (
    "无漏洞", "未发现", "无法利用", "无法复现", "失败", "已失效", "不构成",
    "公开信息", "公开数据", "普通配置", "仅返回公开", "无敏感", "不敏感",
    "not vulnerable", "not exploitable", "failed", "public only",
)
_BAD_MATCH_KEYS = {"", "-", "unknown", "none", "null", "all", "test", "localhost", "127.0.0.1"}
_STATIC_EXT_RE = re.compile(r"\.(?:css|js|map|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot)(?:$|\?)", re.I)
_PUBLIC_ENDPOINTS = {
    "/", "/favicon.ico", "/robots.txt", "/sitemap.xml", "/health", "/api/auth/status",
    "/login", "/logout", "/index.html",
}
_PLACEHOLDER_VALUES = {"", "-", "?", "unknown", "none", "null", "test", "todo", "待确认", "未知"}
# 高价值信号：summary/vuln_type 命中这些词，说明情报本身已被验证为有效漏洞/敏感泄露，
# 即使路径看起来"通用"或"静态"也有复用价值，不应被结构性软规则误判为垃圾。
_HIGH_VALUE_SIGNAL = (
    "未授权", "未鉴权", "越权", "泄露", "硬编码", "密钥", "密码", "凭证", "token",
    "secret", "apikey", "api key", "ak/sk", "ak sk", "accesskey",
    "unauth", "unauthorized", "idor", "rce", "ssrf", "sqli", "注入", "getshell",
    "敏感", "可查询", "可读取", "可下载", "可登录", "弱口令", "默认口令",
)


def _has_high_value_signal(*parts: str) -> bool:
    blob = " ".join(p for p in parts if p).lower()
    return any(marker.lower() in blob for marker in _HIGH_VALUE_SIGNAL)


# 内容硬伤：即使情报被标记 verified 也必须拦（不做软豁免）。
_NEVER_WAIVE = {
    "未知情报类型", "match_key 为空或过于泛化", "payload 为空",
    "摘要/内容包含低价值或失败结论",
    "endpoint 是公开/静态/通用路径", "endpoint 缺少有效 path",
    "凭证字段为空/占位/过短", "画像内容为空/过短", "画像键过于泛化",
}


@dataclass
class IntelAssessment:
    ok: bool
    reasons: list[str] = field(default_factory=list)
    payload: dict = field(default_factory=dict)


def _text(value: object) -> str:
    return str(value or "").strip()


def _norm_payload(payload: dict) -> dict:
    out = {}
    for k, v in (payload or {}).items():
        key = _text(k)[:50]
        val = _text(v)[:300]
        if key and val:
            out[key] = val
    return out


def _contains_low_signal(*parts: str) -> bool:
    blob = " ".join(p for p in parts if p).lower()
    return any(marker.lower() in blob for marker in _LOW_SIGNAL_TEXT)


def _endpoint_path(raw: str) -> str:
    s = _text(raw)
    if not s:
        return ""
    if "://" in s:
        try:
            return (urlparse(s).path or "").rstrip("/") or "/"
        except Exception:
            return ""
    return s.split("?", 1)[0].rstrip("/") or "/"


def assess_intel(kind: str, match_key: str, payload: dict, summary: str = "", confidence: str = "likely") -> IntelAssessment:
    """返回情报是否值得入库，以及必要时的规范化 payload。

    规则保守：先拦通用硬伤（类型/键/内容为空、失败结论），再按类型做轻量校验。
    """
    kind = _text(kind).lower()
    match_key = _text(match_key).lower()
    summary = _text(summary)
    confidence = _text(confidence).lower() or "likely"
    payload = _norm_payload(payload)
    reasons: list[str] = []

    # 通用硬伤
    if kind not in {"cred", "fingerprint", "endpoint", "profile"}:
        reasons.append("未知情报类型")
    if match_key in _BAD_MATCH_KEYS:
        reasons.append("match_key 为空或过于泛化")
    if not payload:
        reasons.append("payload 为空")
    if _contains_low_signal(summary, str(payload)):
        reasons.append("摘要/内容包含低价值或失败结论")

    # 按类型轻量校验
    if kind == "cred":
        username = payload.get("username", "")
        password = payload.get("password", "")
        if username.lower() in _PLACEHOLDER_VALUES or password.lower() in _PLACEHOLDER_VALUES or len(username) < 2 or len(password) < 3:
            reasons.append("凭证字段为空/占位/过短")
        if confidence != "verified":
            reasons.append("凭证未标记 verified")

    elif kind == "endpoint":
        path = _endpoint_path(payload.get("path") or payload.get("url") or "")
        if path:
            payload["path"] = path
        if not path or not path.startswith("/"):
            reasons.append("endpoint 缺少有效 path")
        elif not _has_high_value_signal(summary, payload.get("vuln_type", "")):
            # 非高价值信号时，过滤公开/静态/区分度不足的通用路径
            if path in _PUBLIC_ENDPOINTS or _STATIC_EXT_RE.search(path) or len([p for p in path.split("/") if p]) < 2:
                reasons.append("endpoint 是公开/静态/通用路径")
        if not (payload.get("vuln_type") or summary):
            reasons.append("endpoint 缺少漏洞类型或说明")

    elif kind == "fingerprint":
        if len(payload.get("tactic", "")) < 8 or not (payload.get("vuln_type") or summary):
            reasons.append("打法摘要过短或缺漏洞类型")
        if confidence != "verified":
            reasons.append("打法未验证")

    elif kind == "profile":
        key = payload.get("key", "")
        value = payload.get("value", "")
        # 有效内容 = value 或 summary（很多画像把详情写在 summary 里）
        if max(len(value), len(summary)) < 8 and not _has_high_value_signal(summary, value):
            reasons.append("画像内容为空/过短")
        if key in {"标题", "title", "状态", "status"} and not summary:
            reasons.append("画像键过于泛化")

    # verified 历史情报更保守：可豁免"长度/区分度"软问题，但内容硬伤仍拦。
    hard = [r for r in reasons if r in _NEVER_WAIVE]
    if confidence == "verified" and reasons and not hard and kind != "cred":
        return IntelAssessment(True, [], payload)

    return IntelAssessment(not reasons, reasons, payload)


async def curate_intel(session: "AsyncSession", *, apply: bool = False, limit: int = 1000) -> dict:
    """扫描并可选清理历史垃圾情报。"""
    from sqlalchemy import select

    from app.db.models import Intel

    rows = (await session.execute(
        select(Intel).order_by(Intel.last_seen.desc()).limit(limit)
    )).scalars().all()
    flagged: list[dict] = []
    deleted = 0
    for item in rows:
        # 高复用情报不自动删，只在报告里提示，避免误伤。
        assess = assess_intel(item.kind, item.match_key, item.payload or {}, item.summary or "", item.confidence or "likely")
        if assess.ok:
            continue
        rec = {
            "id": item.id,
            "kind": item.kind,
            "match_key": item.match_key,
            "summary": item.summary,
            "hit_count": item.hit_count or 1,
            "confidence": item.confidence or "likely",
            "reasons": assess.reasons,
        }
        flagged.append(rec)
        # 能进 flagged 的都是规则确认的真垃圾（assess_intel 已对 verified 软问题做豁免，
        # 还能被标记说明是内容硬伤）。apply 时清理；仅对高频复用项(hit_count>=3)保留并提示，
        # 避免误删已被多个 worker 反复当线索用过的情报。
        if apply and (item.hit_count or 1) < 3:
            await session.delete(item)
            deleted += 1
    if apply and deleted:
        await session.commit()
    kept_hot = sum(1 for r in flagged if (r["hit_count"] or 1) >= 3)
    return {
        "examined": len(rows),
        "flagged": len(flagged),
        "deleted": deleted,
        "kept_hot": kept_hot,
        "items": flagged[:100],
    }
