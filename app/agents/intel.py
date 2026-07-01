"""全局情报库（跨任务共享）：写入 + 触发式检索 + 轻量指纹识别。

设计要点（对应用户决策）：
- 全局跨任务共享（决策一）。
- 四类：cred / fingerprint / endpoint / profile（决策二 A/B/C/F）。
- 触发式检索（决策三）：不主动全量注入，按当前目标的 root域/系统指纹命中才给。
- 不冗余：结构化字段 + 强去重(dedup_hash) + 命中计数 + 质量门槛 + 限量注入。

安全（吸取 js_analyzer 教训）：
- 指纹识别纯字符串 `in` 匹配，无正则、无回溯、无网络、纯内存。
- 写入/检索全 try/except 降级，绝不阻断 worker 主流程。
- 注入有硬字数上限、每类有数量上限。
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.intel_curator import assess_intel
from app.db.models import Intel

# ============ 轻量指纹关键词表（纯字符串匹配，无正则） ============
# 命中规则：把 title/server/body 片段/host 拼成一个小写大串，逐个 in 判断。
# value 是归一化的「系统指纹标识」，作为 fingerprint/endpoint 类情报的 match_key。
# 只放高频、好识别、有复用价值的系统，宁缺毋滥（不冗余）。
_FINGERPRINT_KEYWORDS: list[tuple[tuple[str, ...], str]] = [
    # 统一身份认证 / SSO
    (("统一身份认证", "统一认证", "cas/login", "/cas/", "single sign"), "sso_cas"),
    # 邮件系统
    (("coremail", "/coremail/",), "mail_coremail"),
    (("exchange", "owa/auth", "/owa/"), "mail_exchange"),
    # 常见国产框架/CMS
    (("若依", "ruoyi", "ry-", "若依管理"), "framework_ruoyi"),
    (("thinkphp", "think_template", "x-powered-by: thinkphp"), "framework_thinkphp"),
    (("fastadmin",), "framework_fastadmin"),
    (("springboot", "whitelabel error page", "/actuator"), "framework_springboot"),
    (("jeecg", "jeecg-boot", "jeecgboot"), "framework_jeecg"),
    (("seeyon", "致远", "/seeyon/"), "oa_seeyon"),
    (("泛微", "weaver", "/weaver/", "ecology"), "oa_weaver"),
    (("通达", "tongda", "/ispirit/"), "oa_tongda"),
    # 教务/校园业务系统
    (("强智", "jwgl", "教务系统", "academic"), "edu_jwgl"),
    (("正方", "zfsoft", "/jwglxt/"), "edu_zhengfang"),
    (("迎新", "yxxt", "新生报到"), "edu_freshman"),
    # VPN / 网关
    (("sslvpn", "/+cscoe+/", "anyconnect"), "vpn_cisco"),
    (("sangfor", "深信服", "/por/login"), "vpn_sangfor"),
    (("webvpn",), "vpn_webvpn"),
    # 数据库/中间件管理
    (("phpmyadmin",), "db_phpmyadmin"),
    (("druid", "/druid/index"), "mw_druid"),
    (("swagger-ui", "swagger-ui.html", "/v2/api-docs"), "api_swagger"),
    (("nacos", "/nacos/"), "mw_nacos"),
    (("grafana",), "mw_grafana"),
    (("kibana",), "mw_kibana"),
]

# 注入上限（防 prompt 膨胀 / 不冗余）
_MAX_PER_KIND = int(os.environ.get("INTEL_MAX_PER_KIND", "4"))
_MAX_INJECT_CHARS = int(os.environ.get("INTEL_MAX_INJECT_CHARS", "1800"))
# 内容字段写入前的硬截断（防异常超长）
_MAX_FIELD = 300


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _clip(s, n: int = _MAX_FIELD) -> str:
    if not isinstance(s, str):
        s = str(s or "")
    return s[:n]


def detect_fingerprints(*parts: str) -> list[str]:
    """从 title/server/body/host 等文本里识别系统指纹（纯字符串匹配，无正则）。

    返回去重后的指纹标识列表（可能多个）。无匹配返回空。
    """
    blob = " ".join(p for p in parts if p).lower()
    if not blob:
        return []
    # 限制扫描长度，防异常超长 body（纯 in 匹配本就线性，这里再加一道保险）。
    blob = blob[:20000]
    hits: list[str] = []
    for keywords, fp in _FINGERPRINT_KEYWORDS:
        for kw in keywords:
            if kw in blob:
                hits.append(fp)
                break
    # 去重保序
    seen = set()
    out = []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _dedup_hash(kind: str, match_key: str, payload: dict) -> str:
    """内容指纹：同类+同检索键下，内容相同的视为一条（去重）。"""
    if kind == "cred":
        sig = f"{payload.get('username', '')}|{payload.get('password', '')}"
    elif kind == "endpoint":
        sig = f"{payload.get('path', '')}|{payload.get('vuln_type', '')}"
    elif kind == "fingerprint":
        sig = f"{payload.get('tactic', '')}"
    else:  # profile
        sig = f"{payload.get('key', '')}|{payload.get('value', '')}"
    raw = f"{kind}|{match_key}|{sig}".lower()
    return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()


async def record_intel(
    session: AsyncSession,
    kind: str,
    match_key: str,
    payload: dict,
    summary: str = "",
    source_host: str = "",
    source_task_id: str = "",
    confidence: str = "likely",
) -> bool:
    """写入一条情报（去重 + 计数）。已存在则 +hit_count 并更新 last_seen/confidence。

    返回是否成功（失败降级返回 False，绝不抛异常）。
    """
    try:
        kind = (kind or "").strip().lower()
        match_key = _clip((match_key or "").strip().lower(), 255)
        if kind not in ("cred", "fingerprint", "endpoint", "profile") or not match_key:
            return False
        if not isinstance(payload, dict) or not payload:
            return False
        # 内容字段硬截断
        payload = {k: _clip(v) for k, v in payload.items() if v not in (None, "")}
        if not payload:
            return False
        assessment = assess_intel(kind, match_key, payload, summary, confidence)
        if not assessment.ok:
            return False
        payload = assessment.payload
        dh = _dedup_hash(kind, match_key, payload)

        existing = (await session.execute(
            select(Intel).where(
                Intel.kind == kind, Intel.match_key == match_key, Intel.dedup_hash == dh
            )
        )).scalar_one_or_none()

        if existing:
            existing.hit_count = (existing.hit_count or 1) + 1
            existing.last_seen = _now()
            # verified 优先级高于 likely：一旦验证过就升级，不回退。
            if confidence == "verified":
                existing.confidence = "verified"
            return True

        session.add(Intel(
            kind=kind, match_key=match_key, dedup_hash=dh,
            payload=payload, summary=_clip(summary, 500),
            source_host=_clip(source_host, 255), source_task_id=_clip(source_task_id, 32),
            confidence="verified" if confidence == "verified" else "likely",
        ))
        return True
    except Exception:
        return False


async def lookup_intel(
    session: AsyncSession,
    root: str,
    fingerprints: list[str] | None = None,
) -> dict[str, list[Intel]]:
    """触发式检索：按 root域 + 系统指纹命中相关情报。命中才返回，不冗余。

    返回 {cred:[], fingerprint:[], endpoint:[], profile:[]}，每类按 verified优先+hit_count 排序、限量。
    任何失败降级返回空 dict。
    """
    out: dict[str, list[Intel]] = {"cred": [], "fingerprint": [], "endpoint": [], "profile": []}
    try:
        root = (root or "").strip().lower()
        fps = [f for f in (fingerprints or []) if f]

        # cred / profile 按 root 域命中
        if root:
            for kind in ("cred", "profile"):
                rows = (await session.execute(
                    select(Intel).where(Intel.kind == kind, Intel.match_key == root)
                    .order_by(Intel.confidence.desc(), Intel.hit_count.desc(), Intel.last_seen.desc())
                    .limit(_MAX_PER_KIND)
                )).scalars().all()
                out[kind] = list(rows)

        # fingerprint / endpoint 按系统指纹命中
        if fps:
            for kind in ("fingerprint", "endpoint"):
                rows = (await session.execute(
                    select(Intel).where(Intel.kind == kind, Intel.match_key.in_(fps))
                    .order_by(Intel.confidence.desc(), Intel.hit_count.desc(), Intel.last_seen.desc())
                    .limit(_MAX_PER_KIND)
                )).scalars().all()
                out[kind] = list(rows)
        return out
    except Exception:
        return out


def render_intel_block(intel: dict[str, list[Intel]]) -> str:
    """把检索到的情报渲染成注入 worker 的 prompt 块（限量、去重、不冗余）。

    完全没命中则返回空串（绝大多数新目标的常态，零开销）。
    """
    cred = intel.get("cred") or []
    fp = intel.get("fingerprint") or []
    ep = intel.get("endpoint") or []
    profile = intel.get("profile") or []
    if not (cred or fp or ep or profile):
        return ""

    lines = ["# 情报库命中（其它 worker 沉淀的可复用情报，按可信度排序）"]

    if fp:
        lines.append("\n## 同类系统打法（历史出洞验证）")
        for it in fp:
            tag = "✓验证" if it.confidence == "verified" else "·疑似"
            lines.append(f"- [{tag}] {it.summary or it.payload.get('tactic', '')}")

    if ep:
        lines.append("\n## 同类系统有效端点")
        for it in ep:
            p = it.payload or {}
            lines.append(f"- {p.get('path', '')}  {('('+p.get('vuln_type', '')+')') if p.get('vuln_type') else ''} {it.summary}".rstrip())

    if cred:
        lines.append("\n## 本域历史有效凭证（验证过可登录，可直接撞库）")
        for it in cred:
            p = it.payload or {}
            tag = "✓验证" if it.confidence == "verified" else "·疑似"
            lines.append(f"- [{tag}] {p.get('username', '')} : {p.get('password', '')}  {it.summary}".rstrip())

    if profile:
        lines.append("\n## 本域画像（技术栈/WAF/突破口）")
        for it in profile:
            p = it.payload or {}
            lines.append(f"- {p.get('key', '')}: {p.get('value', '')}")

    lines.append("\n注意：情报仅供参考、可能已失效；它只是其中一个攻击面，别因此忽略其它洞，也别盲目照搬。")
    block = "\n".join(lines)
    # 硬字数上限，防膨胀。
    if len(block) > _MAX_INJECT_CHARS:
        block = block[:_MAX_INJECT_CHARS] + "\n…(情报过多已截断)"
    return block + "\n\n"
