"""全局运行异常日志 API。

基于 task_events 汇总跨任务运行异常：LLM 错误、审核异常、worker 取消/收敛、
安全启动暂停等。该接口仅供 full/readonly 角色查看；observer 不在安全白名单中。
"""
from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Task, TaskEvent
from app.db.session import get_session

router = APIRouter(prefix="/api/runtime-logs", tags=["runtime-logs"])

_SECRET_RE = re.compile(r"\b(sk-[A-Za-z0-9_-]{8,}|Bearer\s+[A-Za-z0-9._-]{12,})\b")
_ANOMALY_PATTERNS = (
    "%LLM%", "%异常%", "%error%", "%Error%", "%Traceback%", "%tool_choice%",
    "%自动收敛%", "%取消%", "%超时%", "%timeout%", "%deferred%", "%failed%",
)


def _mask_text(value: str, limit: int = 1200) -> str:
    text = _SECRET_RE.sub("<masked>", value or "")
    return text[:limit]


def _mask_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k)[:80]: _mask_payload(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_payload(v) for v in value[:50]]
    if isinstance(value, str):
        return _mask_text(value, 800)
    return value


def _event_to_dict(ev: TaskEvent, task: Task | None = None) -> dict:
    return {
        "id": ev.id,
        "task_id": ev.task_id,
        "task_name": task.name if task else "",
        "task_status": task.status if task else "",
        "agent": ev.agent,
        "level": ev.level,
        "kind": ev.kind,
        "message": _mask_text(ev.message, 1600),
        "payload": _mask_payload(ev.payload or {}),
        "ts": ev.ts.isoformat() if ev.ts else None,
    }


def _anomaly_filter():
    return or_(
        TaskEvent.level.in_(["warn", "error"]),
        TaskEvent.kind.like("%error%"),
        TaskEvent.kind.like("%deferred%"),
        *(TaskEvent.message.like(p) for p in _ANOMALY_PATTERNS),
    )


@router.get("/stats")
async def runtime_log_stats(session: AsyncSession = Depends(get_session)):
    """异常日志总览。"""
    anomaly = _anomaly_filter()
    total = (await session.execute(
        select(func.count()).select_from(TaskEvent).where(anomaly)
    )).scalar() or 0
    errors = (await session.execute(
        select(func.count()).select_from(TaskEvent).where(and_(anomaly, TaskEvent.level == "error"))
    )).scalar() or 0
    warns = (await session.execute(
        select(func.count()).select_from(TaskEvent).where(and_(anomaly, TaskEvent.level == "warn"))
    )).scalar() or 0
    by_agent = {}
    rows = await session.execute(
        select(TaskEvent.agent, func.count()).where(anomaly).group_by(TaskEvent.agent)
    )
    for agent, cnt in rows.all():
        by_agent[agent or "unknown"] = cnt
    return {"total": total, "errors": errors, "warns": warns, "by_agent": by_agent}


@router.get("")
async def list_runtime_logs(
    level: str = Query("all", pattern="^(all|info|warn|error)$"),
    agent: str = Query("all"),
    q: str | None = Query(None),
    limit: int = Query(100, ge=1),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
):
    """按级别/agent/关键词分页列出全局运行异常日志（与硬骨头库一致的分页结构）。"""
    safe_limit = max(1, min(int(limit or 100), 200))
    safe_offset = max(0, int(offset or 0))
    conds = [_anomaly_filter()]
    if level != "all":
        conds.append(TaskEvent.level == level)
    if agent != "all":
        conds.append(TaskEvent.agent == agent)
    if q:
        needle = f"%{q.strip()}%"
        conds.append(or_(
            TaskEvent.message.like(needle),
            TaskEvent.kind.like(needle),
            TaskEvent.agent.like(needle),
            Task.name.like(needle),
            TaskEvent.task_id.like(needle),
        ))

    total = (await session.execute(
        select(func.count())
        .select_from(TaskEvent)
        .outerjoin(Task, Task.id == TaskEvent.task_id)
        .where(and_(*conds))
    )).scalar() or 0

    stmt = (
        select(TaskEvent, Task)
        .outerjoin(Task, Task.id == TaskEvent.task_id)
        .where(and_(*conds))
        .order_by(TaskEvent.ts.desc())
        .offset(safe_offset)
        .limit(safe_limit)
    )
    rows = (await session.execute(stmt)).all()
    out = [_event_to_dict(ev, task) for ev, task in rows]
    return {
        "items": out,
        "total": total,
        "limit": safe_limit,
        "offset": safe_offset,
        "has_more": safe_offset + len(out) < total,
    }
