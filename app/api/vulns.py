"""全局漏洞库 API：跨任务聚合「人工审核通过」的漏洞。

收录范围（用户复审通过 user_status == "passed"）：
- 已提交 SRC：Review.submitted == True
- 未提交但过审：Review.submitted == False（即待提交）
排除 Finding.status == "superseded"（深挖让位项，不算正式漏洞）。

该接口含 PoC/证据等敏感数据，鉴权同 /api/intel：full/readonly 可看，
observer 不在白名单（middleware 直接 403）。分页结构与硬骨头库一致。
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Finding, Review, Task
from app.db.session import get_session

router = APIRouter(prefix="/api/vulns", tags=["vulns"])


def _base_conds():
    """全局漏洞库基础筛选：人工审核通过、非 superseded。"""
    return [
        Review.user_status == "passed",
        Finding.status != "superseded",
    ]


def _vuln_dict(f: Finding, r: Review, task_name: str = "") -> dict:
    user_edits = r.user_edits or {}
    title = user_edits.get("title") or f.title
    return {
        "id": f.id,
        "task_id": f.task_id,
        "task_name": task_name or "",
        "target_id": f.target_id,
        "vuln_type": f.vuln_type,
        "title": title,
        "target_url": f.target_url,
        "owner": f.owner,
        "severity_claimed": f.severity_claimed,
        "kill_chain": [
            {"method": str(s.get("method") or ""), "detail": str(s.get("detail") or "")}
            for s in (f.kill_chain or [])
            if isinstance(s, dict) and s.get("method")
        ],
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "confidence": r.confidence,
        "score": r.score,
        "effective_severity": r.user_severity or r.severity_final,
        "submitted": r.submitted,
        "user_reviewed_at": r.user_reviewed_at.isoformat() if r.user_reviewed_at else None,
    }


@router.get("/stats")
async def vuln_stats(session: AsyncSession = Depends(get_session)):
    """全局漏洞库总览：总数、已提交、待提交、各等级分布。"""
    conds = _base_conds()
    total = (await session.execute(
        select(func.count())
        .select_from(Finding)
        .join(Review, Review.finding_id == Finding.id)
        .where(and_(*conds))
    )).scalar() or 0
    submitted = (await session.execute(
        select(func.count())
        .select_from(Finding)
        .join(Review, Review.finding_id == Finding.id)
        .where(and_(*conds, Review.submitted.is_(True)))
    )).scalar() or 0
    by_sev: dict[str, int] = {}
    sev_expr = func.coalesce(Review.user_severity, Review.severity_final)
    rows = await session.execute(
        select(sev_expr, func.count())
        .select_from(Finding)
        .join(Review, Review.finding_id == Finding.id)
        .where(and_(*conds))
        .group_by(sev_expr)
    )
    for sev, cnt in rows.all():
        by_sev[sev or "未定级"] = cnt
    return {
        "total": total,
        "submitted": submitted,
        "ready": total - submitted,
        "by_severity": by_sev,
    }


@router.get("")
async def list_vulns(
    submitted: str = Query("all", pattern="^(all|yes|no)$"),
    severity: Optional[str] = Query(None),
    q: str | None = Query(None),
    limit: int = Query(100, ge=1),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
):
    """分页列出全局漏洞库。submitted: all/yes(已提交)/no(待提交)。"""
    safe_limit = max(1, min(int(limit or 100), 200))
    safe_offset = max(0, int(offset or 0))
    conds = _base_conds()
    if submitted == "yes":
        conds.append(Review.submitted.is_(True))
    elif submitted == "no":
        conds.append(Review.submitted.is_(False))
    if severity:
        conds.append(func.coalesce(Review.user_severity, Review.severity_final) == severity)
    needle = (q or "").strip()
    if needle:
        like = f"%{needle}%"
        conds.append(or_(
            Finding.title.ilike(like),
            Finding.vuln_type.ilike(like),
            Finding.target_url.ilike(like),
            Finding.owner.ilike(like),
            Task.name.ilike(like),
        ))

    total = (await session.execute(
        select(func.count())
        .select_from(Finding)
        .join(Review, Review.finding_id == Finding.id)
        .outerjoin(Task, Task.id == Finding.task_id)
        .where(and_(*conds))
    )).scalar() or 0

    stmt = (
        select(Finding, Review, Task.name)
        .join(Review, Review.finding_id == Finding.id)
        .outerjoin(Task, Task.id == Finding.task_id)
        .where(and_(*conds))
        .order_by(Review.submitted, Review.score.desc(), Finding.created_at.desc())
        .offset(safe_offset)
        .limit(safe_limit)
    )
    rows = (await session.execute(stmt)).all()
    out = [_vuln_dict(f, r, task_name) for f, r, task_name in rows]
    return {
        "items": out,
        "total": total,
        "limit": safe_limit,
        "offset": safe_offset,
        "has_more": safe_offset + len(out) < total,
    }
