"""全局情报库 API：列表 / 统计 / 删除。

情报库是跨任务共享的可复用知识沉淀（cred/fingerprint/endpoint/profile）。
提供给前端「情报库控制台」浏览、筛选、清理。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.intel_curator import curate_intel
from app.db.models import Intel, to_cst_iso
from app.db.session import get_session

router = APIRouter(prefix="/api/intel", tags=["intel"])

_KINDS = ("cred", "fingerprint", "endpoint", "profile")


def _intel_to_dict(it: Intel) -> dict:
    return {
        "id": it.id,
        "kind": it.kind,
        "match_key": it.match_key,
        "payload": it.payload or {},
        "summary": it.summary or "",
        "source_host": it.source_host or "",
        "source_task_id": it.source_task_id or "",
        "confidence": it.confidence or "likely",
        "hit_count": it.hit_count or 1,
        "first_seen": to_cst_iso(it.first_seen),
        "last_seen": to_cst_iso(it.last_seen),
    }


@router.get("/stats")
async def intel_stats(session: AsyncSession = Depends(get_session)):
    """情报库总览：总条数、各类别数、已验证数、被复用(hit>1)数。"""
    total = (await session.execute(select(func.count()).select_from(Intel))).scalar() or 0
    by_kind = {}
    rows = await session.execute(select(Intel.kind, func.count()).group_by(Intel.kind))
    for kind, cnt in rows.all():
        by_kind[kind] = cnt
    verified = (await session.execute(
        select(func.count()).select_from(Intel).where(Intel.confidence == "verified")
    )).scalar() or 0
    reused = (await session.execute(
        select(func.count()).select_from(Intel).where(Intel.hit_count > 1)
    )).scalar() or 0
    return {
        "total": total,
        "by_kind": {k: by_kind.get(k, 0) for k in _KINDS},
        "verified": verified,
        "reused": reused,
    }


@router.get("")
async def list_intel(
    kind: str = Query("all"),
    confidence: str = Query("all", pattern="^(all|verified|likely)$"),
    q: str | None = Query(None),
    limit: int = Query(0, ge=0, le=5000),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
):
    """情报列表：按类别/可信度筛选 + 关键词搜索（match_key/summary/source_host/payload）。
    支持分页（limit/offset）：limit=0 返回全量列表（向后兼容），limit>0 返回 {items, has_more}。"""
    stmt = select(Intel)
    if kind in _KINDS:
        stmt = stmt.where(Intel.kind == kind)
    if confidence in ("verified", "likely"):
        stmt = stmt.where(Intel.confidence == confidence)
    stmt = stmt.order_by(
        Intel.confidence.desc(), Intel.hit_count.desc(), Intel.last_seen.desc()
    )
    needle = (q or "").strip().lower()
    if not needle and limit:
        # 无搜索关键词：DB 层分页，多取 1 条判断 has_more
        stmt = stmt.offset(offset).limit(limit + 1)
        rows = (await session.execute(stmt)).scalars().all()
        out = [_intel_to_dict(it) for it in rows]
        return {
            "items": out[:limit],
            "has_more": len(out) > limit,
            "limit": limit,
            "offset": offset,
        }
    # 有搜索关键词或无分页：全量加载后内存过滤（安全上限 5000）
    stmt = stmt.limit(5000)
    rows = (await session.execute(stmt)).scalars().all()
    out = [_intel_to_dict(it) for it in rows]
    if needle:
        out = [
            d for d in out
            if (needle in (d["match_key"] or "").lower()
                or needle in (d["summary"] or "").lower()
                or needle in (d["source_host"] or "").lower()
                or needle in str(d["payload"]).lower())
        ]
    if limit:
        page = out[offset:offset + limit]
        return {
            "items": page,
            "has_more": offset + limit < len(out),
            "limit": limit,
            "offset": offset,
        }
    return out


@router.get("/curate")
async def preview_curate_intel(
    limit: int = Query(1000, ge=1, le=5000),
    session: AsyncSession = Depends(get_session),
):
    """预览 Intel Curator 将清理的低价值情报（不删除）。"""
    return await curate_intel(session, apply=False, limit=limit)


@router.post("/curate")
async def apply_curate_intel(
    limit: int = Query(1000, ge=1, le=5000),
    session: AsyncSession = Depends(get_session),
):
    """执行 Intel Curator 清理。仅 full 令牌可调用（中间件禁止 readonly/observer 写操作）。"""
    return await curate_intel(session, apply=True, limit=limit)


@router.delete("/{intel_id}")
async def delete_intel(intel_id: str, session: AsyncSession = Depends(get_session)):
    """删除一条情报（清理失效/误存的脏数据）。"""
    it = await session.get(Intel, intel_id)
    if not it:
        raise HTTPException(404, "情报不存在")
    await session.delete(it)
    await session.commit()
    return {"ok": True}


@router.delete("")
async def clear_intel(
    kind: str = Query("all"),
    session: AsyncSession = Depends(get_session),
):
    """批量清空（按类别或全部）。谨慎使用。"""
    stmt = select(Intel)
    if kind in _KINDS:
        stmt = stmt.where(Intel.kind == kind)
    rows = (await session.execute(stmt)).scalars().all()
    n = 0
    for it in rows:
        await session.delete(it)
        n += 1
    await session.commit()
    return {"ok": True, "deleted": n}
