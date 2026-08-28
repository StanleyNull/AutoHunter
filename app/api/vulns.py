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

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Finding, Review, Task, to_cst_iso
from app.db.session import get_session

router = APIRouter(prefix="/api/vulns", tags=["vulns"])

# 置顶排序用的等级权重：严重 > 高危 > 中危 > 低危 > 其它。
# effective_severity = coalesce(Review.user_severity, Review.severity_final)，
# 存的是中文等级字符串，用 case 映射成整数做 DESC 排序。
_SEVERITY_RANK = case(
    (func.coalesce(Review.user_severity, Review.severity_final) == "严重", 4),
    (func.coalesce(Review.user_severity, Review.severity_final) == "高危", 3),
    (func.coalesce(Review.user_severity, Review.severity_final) == "中危", 2),
    (func.coalesce(Review.user_severity, Review.severity_final) == "低危", 1),
    else_=0,
)


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
        "created_at": to_cst_iso(f.created_at),
        "llm_model": getattr(f, "llm_model", "") or "",
        "llm_base_url": getattr(f, "llm_base_url", "") or "",
        "confidence": r.confidence,
        "score": r.score,
        "effective_severity": r.user_severity or r.severity_final,
        "submitted": r.submitted,
        "is_top": bool(getattr(f, "is_top", False)),
        "user_reviewed_at": to_cst_iso(r.user_reviewed_at),
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
        # 排序规则：置顶优先 → 等级降序(高危>中危>低危) → 创建时间降序。
        # 保证置顶的高危漏洞永远排最前，且对筛选/搜索结果同样生效。
        .order_by(
            Finding.is_top.desc(),
            _SEVERITY_RANK.desc(),
            Finding.created_at.desc(),
        )
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


class TopRequest(BaseModel):
    """单条置顶/取消置顶请求体。"""
    is_top: bool


class BatchTopRequest(BaseModel):
    """批量置顶/取消置顶请求体。ids 为漏洞 id 列表。"""
    ids: list[str]
    is_top: bool


# 鉴权说明：本路由所有 PATCH 写操作由 main.py 的 security_middleware 统一拦截，
# 仅 full 令牌（管理员）可执行；readonly/observer 会被中间件直接 403。
# 这与项目现有写接口（restore/user_review/invalidate 等）的权限模型完全一致。


@router.patch("/batch/top")
async def batch_top_vulns(req: BatchTopRequest, session: AsyncSession = Depends(get_session)):
    """批量置顶/取消置顶漏洞。

    参数:
        req: { ids: list[str], is_top: bool } —— 待操作的漏洞 id 列表与目标置顶状态。
    返回:
        { ok: True, success_count: int, failed_ids: list[str] } —— 成功条数与失败 id。
    """
    # 参数校验：ids 必须非空且全部为有效字符串（去空白去重）。
    raw_ids = req.ids or []
    if not raw_ids:
        raise HTTPException(400, "ids 不能为空")
    ids = list(dict.fromkeys(str(i).strip() for i in raw_ids if str(i).strip()))
    if not ids:
        raise HTTPException(400, "ids 不能为空")
    target_value = bool(req.is_top)
    success_count = 0
    failed_ids: list[str] = []
    for vid in ids:
        f = await session.get(Finding, vid)
        if not f:
            failed_ids.append(vid)
            continue
        f.is_top = target_value
        success_count += 1
    if success_count:
        await session.commit()
    return {
        "ok": True,
        "success_count": success_count,
        "failed_ids": failed_ids,
    }


@router.patch("/{vuln_id}/top")
async def top_vuln(vuln_id: str, req: TopRequest, session: AsyncSession = Depends(get_session)):
    """单条漏洞置顶/取消置顶。

    参数:
        vuln_id: 漏洞 id（32 位 UUID hex）。
        req: { is_top: bool } —— True 置顶，False 取消置顶。
    返回:
        { ok: True, id: str, is_top: bool } —— 操作后的最新置顶状态。
    """
    f = await session.get(Finding, vuln_id)
    if not f:
        raise HTTPException(404, "记录不存在")
    f.is_top = bool(req.is_top)
    await session.commit()
    return {"ok": True, "id": f.id, "is_top": f.is_top}
