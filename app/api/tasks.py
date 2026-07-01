"""任务相关 API：创建 / 列表 / 详情 / 启停。"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import case, delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dto import CreateTaskRequest, TaskResponse, TaskStats, UpdateTaskRequest
from app.agents.prompts import normalize_src_type
from app.db.models import Finding, Killsweep, Review, Target, Task, TaskEvent
from app.db.session import get_session
from app.llm.usage import usage_snapshot
from app.orchestrator import manager
from app.security import resolve_role, token_from_headers
from app.settings_service import resolve_fofa_defaults, resolve_llm_config, resolve_worker_prompt_version

router = APIRouter(prefix="/api/tasks", tags=["tasks"])


def _iso_utc(dt: datetime | None) -> str | None:
    """DB 里的时间是 UTC naive（存的是 _now()=UTC，但列无时区信息）。
    输出时补上 UTC 时区标识（…+00:00），前端 new Date 才能正确换算本地时区。
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


# Activity Stream 历史回放：过滤高频低价值事件（与前端 BoardView 规则对齐）。
_STREAM_NOISE_KINDS = frozenset({"refill", "cluster_cooldown_skip", "skip", "ping"})
_STREAM_IMPORTANT_KINDS = frozenset({
    "collector_phase",
    "target_done", "target_requeued", "timeout", "auto_deepen", "salvage",
    "coverage_reported", "site_followups_spawned",
    "review_done", "review_deferred", "review_cancelled",
    "reclaim", "recover", "workers_cancelled", "quota_stop",
    "killsweep_done", "killsweep_dedup", "killsweep_error", "killsweep_cancelled",
})


def _stream_event_visible(kind: str, level: str) -> bool:
    if kind in _STREAM_NOISE_KINDS:
        return False
    if level in ("warn", "error"):
        return True
    return kind in _STREAM_IMPORTANT_KINDS or kind == "error"


def _is_observer(request: Request | None) -> bool:
    return bool(request and resolve_role(token_from_headers(request.headers)) == "observer")


def _observer_model_config() -> dict:
    return {"base_url": "", "model": "hidden", "api_key_set": False}


def _observer_fofa_config() -> dict:
    return {
        "max_pages": 0, "page_size": 0, "intent_mode": "",
        "key_set": False, "current_query": "", "cursor": 0,
        "collector_phase": "", "collector_phase_text": "",
    }


def _mask_label(label: str) -> str:
    """观摩展示用：单个域名 label 保留少量轮廓，其余打 *。"""
    label = (label or "").strip()
    if not label:
        return ""
    if len(label) <= 2:
        return label[:1] + "*"
    if len(label) <= 4:
        return label[:1] + ("*" * (len(label) - 1))
    return label[:1] + ("*" * (len(label) - 2)) + label[-1:]


def _observer_host(host: str) -> str:
    """观摩模式域名/IP 部分打码，保留后缀结构但隐藏关键资产名。"""
    s = (host or "").strip().lower()
    if not s:
        return ""
    port = ""
    if ":" in s and not s.startswith("["):
        h, maybe_port = s.rsplit(":", 1)
        if maybe_port.isdigit():
            s, port = h, f":{maybe_port}"
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:2] + ["*", "*"]) + port
    if len(parts) <= 1:
        return _mask_label(s) + port
    # 保留公共后缀，业务/学校/子域 label 全部局部打码，例如 xb.ymun.edu.cn -> x*.y**n.edu.cn
    keep_suffix = 2 if parts[-2:] in (["edu", "cn"], ["com", "cn"], ["net", "cn"], ["org", "cn"], ["gov", "cn"]) else 1
    masked = [_mask_label(p) for p in parts[:-keep_suffix]] + parts[-keep_suffix:]
    return ".".join(masked) + port


def _observer_url(url: str, host: str = "") -> str:
    """观摩模式只展示 host 级目标，不展示 path/query。"""
    if host:
        return _observer_host(host)
    s = (url or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    return _observer_host(s.split("/", 1)[0])


def _observer_text(text: str) -> str:
    """观摩模式隐藏站点标题、单位名等可直接识别目标的文本。"""
    return "" if (text or "").strip() else ""


def _observer_task_name(name: str, task_id: str = "") -> str:
    """观摩模式任务名可能含目标关键词，统一替换为匿名编号。"""
    suffix = (task_id or "")[:8] or "unknown"
    return f"任务 {suffix}"


def _observer_ip(ip: str) -> str:
    """观摩模式 IP 只保留前两段。"""
    parts = (ip or "").strip().split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.*.*"
    return ""


def _public_model_config(task: Task) -> dict:
    cfg = resolve_llm_config(task)
    return {
        "base_url": cfg.base_url,
        "model": cfg.model,
        "api_key_set": bool(cfg.api_key),
        "prompt_version": resolve_worker_prompt_version(task),
    }


def _public_fofa_config(task: Task) -> dict:
    cfg = dict(task.fofa_config or {})
    eff = resolve_fofa_defaults(task)
    return {
        "base_url": eff["base_url"],
        "max_pages": eff["max_pages"],
        "page_size": eff["page_size"],
        "intent_mode": eff["intent_mode"],
        "key_set": bool(eff["key"]),
        "current_query": cfg.get("current_query", ""),
        "cursor": cfg.get("cursor", 0),
        "collector_phase": cfg.get("collector_phase", ""),
        "collector_phase_text": cfg.get("collector_phase_text", ""),
        "last_target_filter_total": cfg.get("last_target_filter_total", 0),
        "last_target_filter_evaluated": cfg.get("last_target_filter_evaluated", 0),
        "last_skipped_filter": cfg.get("last_skipped_filter", 0),
    }


def _task_to_dto(t: Task, stats: TaskStats | None = None,
                 pending_user_review: int = 0, observer: bool = False) -> TaskResponse:
    model_config = _public_model_config(t)
    if observer:
        model_config = _observer_model_config()
    return TaskResponse(
        id=t.id, name=_observer_task_name(t.name, t.id) if observer else t.name, status=t.status, src_type=t.src_type,
        vuln_types=t.vuln_types or [], target_source=t.target_source,
        fofa_query="" if observer else t.fofa_query, concurrency=t.concurrency,
        src_rules="" if observer else (t.src_rules or ""),
        manual_targets=[] if observer else (t.manual_targets or []),
        model_config_data=model_config,
        fofa_config=_observer_fofa_config() if observer else _public_fofa_config(t),
        llm_usage={} if observer else usage_snapshot(t.id, model_config.get("model", "")),
        created_at=t.created_at.isoformat(), updated_at=t.updated_at.isoformat(),
        stats=stats, pending_user_review=pending_user_review,
    )


async def _compute_stats(session: AsyncSession, task_id: str) -> TaskStats:
    stats = TaskStats()
    rows = await session.execute(
        select(Target.status, func.count()).where(Target.task_id == task_id).group_by(Target.status)
    )
    for status, cnt in rows.all():
        if status == "queued":
            stats.queued += cnt
        elif status in ("assigned", "scanning"):
            stats.scanning += cnt
        elif status == "done":
            stats.done += cnt
        elif status == "dead":
            stats.dead += cnt
        elif status == "skipped":
            stats.skipped += cnt

    # findings 两项计数合并为一次扫表（conditional aggregation）：
    # findings_total 排除 superseded（被打回深挖让位的旧线索，不算真实漏洞）。
    frow = (await session.execute(
        select(
            func.count(case((Finding.status != "superseded", 1))),
            func.count(case((Finding.status == "pending_review", 1))),
        ).where(Finding.task_id == task_id)
    )).one()
    stats.findings_total = frow[0] or 0
    stats.pending_review = frow[1] or 0

    # reviews 一次 GROUP BY 同时算出 verdict 维度计数（accepted/ignored/deepen）
    # 与用户复审维度计数（review_pending/submit_ready/rejected），避免两次扫表。
    ur_rows = await session.execute(
        select(Review.verdict, Review.user_status, Review.submitted, func.count())
        .where(Review.task_id == task_id)
        .group_by(Review.verdict, Review.user_status, Review.submitted)
    )
    for verdict, user_status, submitted, cnt in ur_rows.all():
        if verdict == "accepted":
            stats.accepted += cnt
        elif verdict == "ignored":
            stats.ignored += cnt
        elif verdict == "deepen":
            stats.deepen += cnt
        if verdict == "accepted" and user_status == "pending":
            stats.review_pending += cnt
        if user_status == "passed" and not submitted:
            stats.submit_ready += cnt
        elif user_status == "rejected":
            stats.rejected += cnt
    stats.killsweep = (await session.execute(
        select(func.count()).select_from(Killsweep).where(
            Killsweep.task_id == task_id, Killsweep.is_killsweep == True)  # noqa: E712
    )).scalar() or 0
    return stats


@router.post("", response_model=TaskResponse)
async def create_task(req: CreateTaskRequest, session: AsyncSession = Depends(get_session)):
    if req.target_source not in {"fofa", "manual", "both", "site"}:
        raise HTTPException(400, "target_source 必须是 fofa/manual/both/site")
    task = Task(
        name=req.name, src_type=normalize_src_type(req.src_type), vuln_types=req.vuln_types,
        src_rules=req.src_rules, target_source=req.target_source,
        fofa_query=req.fofa_query, manual_targets=req.manual_targets,
        model_config_json=req.model_config_data.model_dump(exclude_defaults=True),
        fofa_config=req.fofa_config.model_dump(exclude_defaults=True), concurrency=req.concurrency,
        status="created",
    )
    session.add(task)
    await session.commit()
    await session.refresh(task)
    return _task_to_dto(task)


@router.get("", response_model=list[TaskResponse])
async def list_tasks(request: Request, session: AsyncSession = Depends(get_session)):
    rows = await session.execute(select(Task).order_by(Task.created_at.desc()))
    tasks = rows.scalars().all()
    # 一条聚合查询拿到所有任务的「待人工复审」数（AI accepted 且用户 pending），避免 N+1。
    pending_map: dict[str, int] = {}
    pr_rows = await session.execute(
        select(Review.task_id, func.count())
        .where(Review.verdict == "accepted", Review.user_status == "pending")
        .group_by(Review.task_id)
    )
    for tid, cnt in pr_rows.all():
        pending_map[tid] = cnt
    observer = _is_observer(request)
    return [_task_to_dto(t, pending_user_review=pending_map.get(t.id, 0), observer=observer) for t in tasks]


@router.get("/hard-targets")
async def global_hard_targets(
    request: Request,
    status: str = Query("all", pattern="^(all|dead|skipped)$"),
    q: str | None = Query(None),
    limit: int = Query(100, ge=1),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
):
    """全局硬骨头库：跨任务聚合 dead/skipped 目标，便于回捞和复盘。

    搜索 q 下推到 SQL（LIKE），避免「先取 limit 条再内存过滤」导致只能搜到最新 N 条的问题。
    """
    statuses = ["dead", "skipped"] if status == "all" else [status]
    safe_limit = max(1, min(int(limit or 100), 100))
    safe_offset = max(0, int(offset or 0))
    observer = _is_observer(request)
    stmt = (
        select(Target, Task.name)
        .join(Task, Task.id == Target.task_id)
        .where(Target.status.in_(statuses))
    )
    needle = (q or "").strip()
    if needle:
        like = f"%{needle}%"
        stmt = stmt.where(or_(
            Target.host.ilike(like),
            Target.url.ilike(like),
            *([] if observer else [
                Target.org.ilike(like),
                Target.school.ilike(like),
                Target.title.ilike(like),
                Target.dead_reason.ilike(like),
                Target.last_error.ilike(like),
                Target.priority_reason.ilike(like),
                Task.name.ilike(like),
            ]),
        ))
    total = (await session.execute(
        select(func.count()).select_from(stmt.subquery())
    )).scalar() or 0
    stmt = (
        stmt.order_by(Target.updated_at.desc(), Target.priority_score.desc())
        .offset(safe_offset)
        .limit(safe_limit)
    )
    rows = (await session.execute(stmt)).all()
    out = []
    for t, task_name in rows:
        out.append({
            "id": t.id,
            "task_id": t.task_id,
            "task_name": _observer_task_name(task_name, t.task_id) if observer else task_name,
            "url": _observer_url(t.url, t.host) if observer else t.url,
            "host": _observer_host(t.host) if observer else t.host,
            "ip": _observer_ip(t.ip) if observer else t.ip,
            "org": _observer_text(t.org) if observer else t.org,
            "school": _observer_text(t.school) if observer else t.school,
            "title": _observer_text(t.title) if observer else t.title,
            "source": "" if observer else t.source,
            "status": t.status,
            "verdict": t.verdict,
            "retry_count": t.retry_count,
            "priority_score": t.priority_score,
            "priority_reason": "" if observer else t.priority_reason,
            "dead_reason": "" if observer else t.dead_reason,
            "last_error": "" if observer else t.last_error,
            "created_at": t.created_at.isoformat(),
            "updated_at": t.updated_at.isoformat() if t.updated_at else None,
        })
    return {
        "items": out,
        "total": total,
        "limit": safe_limit,
        "offset": safe_offset,
        "has_more": safe_offset + len(out) < total,
    }


@router.get("/{task_id}", response_model=TaskResponse)
async def get_task(task_id: str, request: Request, session: AsyncSession = Depends(get_session)):
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    stats = await _compute_stats(session, task_id)
    return _task_to_dto(task, stats, observer=_is_observer(request))


@router.patch("/{task_id}", response_model=TaskResponse)
async def update_task(task_id: str, req: UpdateTaskRequest, session: AsyncSession = Depends(get_session)):
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")

    if req.name is not None:
        task.name = req.name.strip() or task.name
    if req.src_type is not None:
        task.src_type = normalize_src_type(req.src_type)
    if req.vuln_types is not None:
        task.vuln_types = [v.strip() for v in req.vuln_types if str(v).strip()]
    if req.src_rules is not None:
        task.src_rules = req.src_rules
    if req.target_source is not None:
        if req.target_source not in {"fofa", "manual", "both", "site"}:
            raise HTTPException(400, "target_source 必须是 fofa/manual/both/site")
        task.target_source = req.target_source
    if req.manual_targets is not None:
        task.manual_targets = [t.strip() for t in req.manual_targets if str(t).strip()]
    if req.concurrency is not None:
        task.concurrency = max(1, min(int(req.concurrency), 20))

    old_query = task.fofa_query or ""
    if req.fofa_query is not None:
        task.fofa_query = req.fofa_query

    if req.model_config_data is not None:
        patch = req.model_config_data.model_dump(exclude_unset=True)
        cfg = dict(task.model_config_json or {})
        for key in ("base_url", "model"):
            if key in patch and patch[key] is not None:
                cfg[key] = str(patch[key]).strip()
        if str(patch.get("api_key") or "").strip():
            cfg["api_key"] = str(patch["api_key"]).strip()
        task.model_config_json = cfg

    if req.fofa_config is not None:
        patch = req.fofa_config.model_dump(exclude_unset=True)
        cfg = dict(task.fofa_config or {})
        if "key" in patch and str(patch.get("key") or "").strip():
            cfg["key"] = str(patch["key"]).strip()
        if "base_url" in patch and patch["base_url"] is not None:
            cfg["base_url"] = str(patch["base_url"]).strip()
        if "max_pages" in patch and patch["max_pages"] is not None:
            cfg["max_pages"] = max(1, min(int(patch["max_pages"]), 200))
        if "page_size" in patch and patch["page_size"] is not None:
            cfg["page_size"] = max(1, min(int(patch["page_size"]), 1000))
        if "intent_mode" in patch and patch["intent_mode"] is not None:
            intent_mode = str(patch["intent_mode"]).strip()
            if intent_mode not in {"", "syntax", "intent"}:
                raise HTTPException(400, "intent_mode 必须是空/syntax/intent")
            cfg["intent_mode"] = intent_mode
        if req.fofa_query is not None and req.fofa_query != old_query:
            cfg.pop("current_query", None)
            cfg["cursor"] = 0
            cfg["history"] = []
        task.fofa_config = cfg

    await session.commit()
    await session.refresh(task)
    stats = await _compute_stats(session, task_id)
    return _task_to_dto(task, stats)


@router.delete("/{task_id}", status_code=204)
async def delete_task(task_id: str, session: AsyncSession = Depends(get_session)):
    """删除任务及其全部关联数据（目标 / 漏洞 / 审核 / 通杀 / 事件）。

    - 先停掉运行时（终止后台 worker/collector），避免删除过程中仍有写入产生脏数据。
    - 全局情报库（Intel）为跨任务共享知识，不随任务删除。
    """
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")

    # 1) 先彻底停掉该任务的运行时，确保没有后台协程再往这些表写数据。
    await manager.stop(task_id)

    # 2) 手动删除没有 ORM 级联关系的关联表（Killsweep / TaskEvent）。
    await session.execute(delete(Killsweep).where(Killsweep.task_id == task_id))
    await session.execute(delete(TaskEvent).where(TaskEvent.task_id == task_id))

    # 3) 删除任务本体：Target -> Finding -> Review 通过 ORM cascade 一并删除。
    await session.delete(task)
    await session.commit()
    return None


@router.get("/{task_id}/board")
async def task_board(task_id: str, request: Request, session: AsyncSession = Depends(get_session)):
    """实时看板快照：在跑 worker 活态 + 目标进度 + 最近事件（用于刷新后恢复）。"""
    from app.db.models import TaskEvent
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")

    runner = manager.get_runner(task_id)
    observer = _is_observer(request)
    live = runner.live_workers() if runner else []
    if observer:
        safe_live = []
        for w in live:
            raw_action = str(w.get("action") or "")
            if "HTTP" in raw_action or "$" in raw_action or "发现" in raw_action or "漏洞" in raw_action:
                action = "正在验证目标"
            elif "思考" in raw_action or "💭" in raw_action:
                action = "正在分析目标"
            else:
                action = raw_action[:40] or "运行中"
            safe_live.append({
                "worker_id": w.get("worker_id", ""),
                "target": _observer_url(w.get("target", "")),
                "status": w.get("status", ""),
                "action": action,
                "score": w.get("score", 0),
                "score_reason": "",
                "mode": w.get("mode", ""),
            })
        live = safe_live

    stats = await _compute_stats(session, task_id)

    # 最近重要事件（倒序，给前端做历史回放；多取一些再过滤噪音）
    ev_rows = (await session.execute(
        select(TaskEvent).where(TaskEvent.task_id == task_id)
        .order_by(TaskEvent.id.desc()).limit(200)
    )).scalars().all()
    events = []
    for e in ev_rows:
        if not _stream_event_visible(e.kind or "", e.level or "info"):
            continue
        events.append({
            "agent": e.agent, "kind": e.kind, "level": e.level,
            "message": "" if observer else e.message,
            "ts": _iso_utc(e.ts),
        })
        if len(events) >= 60:
            break

    return {
        "task_status": task.status,
        "live_workers": live,
        "stats": stats.model_dump(),
        "fofa_config": _observer_fofa_config() if observer else _public_fofa_config(task),
        "model_config_data": _observer_model_config() if observer else _public_model_config(task),
        "llm_usage": {} if observer else usage_snapshot(task.id, resolve_llm_config(task).model),
        "events": events,
    }


@router.get("/{task_id}/targets")
async def list_targets(task_id: str, request: Request, status: str | None = None, limit: int = 200,
                       session: AsyncSession = Depends(get_session)):
    """目标库查询。status 过滤：
       不传=全部 / queued+assigned+scanning=在挖 / dead=硬骨头库 / skipped=低分跳过 / done=已完成。"""
    q = select(Target).where(Target.task_id == task_id)
    if status == "alive":
        q = q.where(Target.status.in_(["queued", "assigned", "scanning"]))
    elif status:
        q = q.where(Target.status == status)
    q = q.order_by(Target.priority_score.desc(), Target.created_at.desc()).limit(min(limit, 1000))
    rows = (await session.execute(q)).scalars().all()
    observer = _is_observer(request)
    return [{
        "id": t.id, "url": _observer_url(t.url, t.host) if observer else t.url,
        "host": _observer_host(t.host) if observer else t.host,
        "ip": _observer_ip(t.ip) if observer else t.ip,
        "org": _observer_text(t.org) if observer else t.org,
        "school": _observer_text(t.school) if observer else t.school,
        "title": _observer_text(t.title) if observer else t.title,
        "status": t.status, "verdict": t.verdict,
        "is_edu": t.is_edu, "priority_score": t.priority_score,
        "priority_reason": "" if observer else t.priority_reason, "retry_count": t.retry_count,
        "deepen_count": t.deepen_count, "dead_reason": "" if observer else t.dead_reason,
        "last_error": "" if observer else t.last_error,
        "created_at": t.created_at.isoformat(),
    } for t in rows]

@router.post("/{task_id}/start", response_model=TaskResponse)
async def start_task(task_id: str, session: AsyncSession = Depends(get_session)):
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    task.status = "running"
    await session.commit()
    await manager.ensure_running(task_id)
    await session.refresh(task)
    return _task_to_dto(task)


@router.post("/{task_id}/pause", response_model=TaskResponse)
async def pause_task(task_id: str, session: AsyncSession = Depends(get_session)):
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    task.status = "paused"
    await session.commit()
    await manager.pause(task_id)
    await session.refresh(task)
    return _task_to_dto(task)


@router.post("/{task_id}/stop", response_model=TaskResponse)
async def stop_task(task_id: str, session: AsyncSession = Depends(get_session)):
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    task.status = "stopped"
    await session.commit()
    await manager.stop(task_id)
    await session.refresh(task)
    return _task_to_dto(task)
