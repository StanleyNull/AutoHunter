"""全局资产（硬骨头库）写操作 API：置顶、删除、深挖回炉。

资产在本项目中对应 Target 表（host 级目标）。全局资产列表查询仍在
tasks.py 的 /api/tasks/hard-targets 提供（含置顶排序与 is_top 输出）；
本路由只承担写操作，路径与漏洞置顶（/api/vulns/.../top）对称。

删除（#61）与深挖（#62）都只在「硬骨头库里已经存在的终态目标」上开放：
这样「正在挖」的目标不会被误删/误回炉，那类操作属于任务看板里的 skip。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.deepen import deepen_cap_for
from app.db.models import Finding, Target, Task, TaskEvent
from app.db.session import get_session

router = APIRouter(prefix="/api/assets", tags=["assets"])


class TopRequest(BaseModel):
    """单条置顶/取消置顶请求体。"""
    is_top: bool


class BatchTopRequest(BaseModel):
    """批量置顶/取消置顶请求体。ids 为资产 id 列表。"""
    ids: list[str]
    is_top: bool


class DeepenRequest(BaseModel):
    """硬骨头深挖回炉请求体。directive 告诉 worker 这一轮去把什么打穿。"""
    directive: str


class BatchDeleteRequest(BaseModel):
    """批量删除请求体。ids 为资产 id 列表。"""
    ids: list[str]


# 硬骨头库的成员就是这两个终态；派发只取 queued、终止态目标不会被再派发。
HARD_TARGET_STATUSES = ("dead", "skipped")
_SETTLED_TARGET_STATUSES = ("dead", "skipped", "queued")
_STATUS_TEXT = {
    "queued": "排队待挖", "assigned": "已派发", "scanning": "挖掘中",
    "done": "已完成", "skipped": "已跳过", "dead": "硬骨头",
}


# 鉴权说明：本路由所有写操作由 main.py 的 security_middleware 统一拦截，
# 仅 full 令牌（管理员）可执行；readonly/observer 会被中间件直接 403。
# 这与项目现有写接口（skip/directive/invalidate 等）的权限模型完全一致。


def _clean_ids(raw_ids: object) -> list[str]:
    """去空白去重，得到可直接使用的 id 列表。"""
    values = raw_ids if isinstance(raw_ids, list) else []
    return list(dict.fromkeys(str(i).strip() for i in values if str(i).strip()))


async def _live_finding_count(session: AsyncSession, target_id: str) -> int:
    """未归档漏洞数（superseded 是深挖让位的旧线索，随目标一起清掉无妨）。"""
    return int((await session.execute(
        select(func.count())
        .select_from(Finding)
        .where(Finding.target_id == target_id, Finding.status != "superseded")
    )).scalar() or 0)


def _reject_not_hard_bone(tgt: Target) -> None:
    """硬骨头库操作的前置校验：只放行库内终态目标。"""
    if tgt.status not in HARD_TARGET_STATUSES:
        label = _STATUS_TEXT.get(tgt.status, tgt.status)
        raise HTTPException(
            409,
            f"该目标当前是「{label}」状态，不在硬骨头库里，不能在这里删除。"
            f"正在挖掘的目标请到任务看板里删除/跳过。",
        )


@router.patch("/batch/top")
async def batch_top_assets(req: BatchTopRequest, session: AsyncSession = Depends(get_session)):
    """批量置顶/取消置顶资产。

    参数:
        req: { ids: list[str], is_top: bool } —— 待操作的资产 id 列表与目标置顶状态。
    返回:
        { ok: True, success_count: int, failed_ids: list[str] } —— 成功条数与失败 id。
    """
    # 参数校验：ids 必须非空且全部为有效字符串（去空白去重）。
    raw_ids = req.ids or []
    if not raw_ids:
        raise HTTPException(400, "ids 不能为空")
    ids = _clean_ids(raw_ids)
    if not ids:
        raise HTTPException(400, "ids 不能为空")
    target_value = bool(req.is_top)
    success_count = 0
    failed_ids: list[str] = []
    for tid in ids:
        t = await session.get(Target, tid)
        if not t:
            failed_ids.append(tid)
            continue
        t.is_top = target_value
        success_count += 1
    if success_count:
        await session.commit()
    return {
        "ok": True,
        "success_count": success_count,
        "failed_ids": failed_ids,
    }


@router.patch("/{target_id}/top")
async def top_asset(target_id: str, req: TopRequest, session: AsyncSession = Depends(get_session)):
    """单条资产置顶/取消置顶。

    参数:
        target_id: 资产 id（32 位 UUID hex）。
        req: { is_top: bool } —— True 置顶，False 取消置顶。
    返回:
        { ok: True, id: str, is_top: bool } —— 操作后的最新置顶状态。
    """
    t = await session.get(Target, target_id)
    if not t:
        raise HTTPException(404, "记录不存在")
    t.is_top = bool(req.is_top)
    await session.commit()
    return {"ok": True, "id": t.id, "is_top": t.is_top}


@router.delete("/{target_id}")
async def delete_asset(target_id: str, session: AsyncSession = Depends(get_session)):
    """从硬骨头库删除（物理删除）一条目标记录。

    防误删：①只允许删除硬骨头库内的终态目标，库中看不到的目标一律拒绝；
    ②目标上仍挂着有效漏洞时拒绝，避免顺手连带删掉已确认的洞；
    ③删除会落一条 TaskEvent，事后可从活动流追溯。

    注意：Target.findings 配置了 cascade delete-orphan，所以这里前置拒绝了带漏洞的目标，
    superseded（深挖让位的旧线索）会随目标一起清掉。
    """
    tgt = await session.get(Target, target_id)
    if not tgt:
        raise HTTPException(404, "记录不存在")
    _reject_not_hard_bone(tgt)
    live = await _live_finding_count(session, target_id)
    if live:
        raise HTTPException(
            409,
            f"该目标还挂着 {live} 条漏洞记录，删除目标会连带删掉这些漏洞。"
            f"请先到漏洞库确认（不需要的先驳回归档），再回来删除。",
        )
    host = tgt.host or tgt.url or target_id
    session.add(TaskEvent(
        task_id=tgt.task_id,
        agent="user",
        kind="target_deleted",
        level="warn",
        message=f"用户从硬骨头库删除目标 {host}（原状态 {tgt.status}，原因：{tgt.dead_reason or '无记录'}）",
        payload={"target_id": target_id, "host": host, "status": tgt.status},
    ))
    await session.delete(tgt)
    await session.commit()
    return {"ok": True, "id": target_id, "host": host}


@router.post("/batch/delete")
async def batch_delete_assets(req: BatchDeleteRequest, session: AsyncSession = Depends(get_session)):
    """批量删除硬骨头库里的目标。

    逐条独立校验：不满足条件的目标（不在库内 / 仍挂漏洞 / 已不存在）会被跳过并在
    failed 里给出原因，其余照常删除，不会因为一条不合条件就整批失败。
    """
    ids = _clean_ids(req.ids)
    if not ids:
        raise HTTPException(400, "ids 不能为空")
    success_count = 0
    failed: list[dict[str, str]] = []
    for tid in ids:
        tgt = await session.get(Target, tid)
        if not tgt:
            failed.append({"id": tid, "reason": "记录不存在"})
            continue
        try:
            _reject_not_hard_bone(tgt)
        except HTTPException as exc:
            failed.append({"id": tid, "reason": str(exc.detail)})
            continue
        live = await _live_finding_count(session, tid)
        if live:
            failed.append({"id": tid, "reason": f"仍挂着 {live} 条漏洞记录"})
            continue
        host = tgt.host or tgt.url or tid
        session.add(TaskEvent(
            task_id=tgt.task_id,
            agent="user",
            kind="target_deleted",
            level="warn",
            message=f"用户从硬骨头库批量删除目标 {host}（原状态 {tgt.status}）",
            payload={"target_id": tid, "host": host, "status": tgt.status},
        ))
        await session.delete(tgt)
        success_count += 1
    if success_count:
        await session.commit()
    return {"ok": True, "success_count": success_count, "failed": failed}


@router.post("/{target_id}/deepen")
async def deepen_asset(target_id: str, req: DeepenRequest,
                       session: AsyncSession = Depends(get_session)):
    """硬骨头深挖回炉：给目标一条定向指令，把它重新塞回自己任务的挖掘队列队首。

    与 AI 审核/人工复审的深挖共用 deepen_count + 任务 deepen_cap 计数（防死循环），
    所以自然也被任务的「深挖次数」上限约束。
    """
    directive = (req.directive or "").strip()
    if not directive:
        raise HTTPException(400, "请填写深挖指令（告诉 worker 这一轮去把什么打穿）")
    tgt = await session.get(Target, target_id)
    if not tgt:
        raise HTTPException(404, "记录不存在")
    if tgt.status in ("assigned", "scanning"):
        raise HTTPException(409, "该目标正在挖掘中，请等本轮结束或先停止任务再回炉")
    if tgt.status not in _SETTLED_TARGET_STATUSES:
        raise HTTPException(409, f"目标状态为 {tgt.status}，无法回炉重挖")
    task_row = await session.get(Task, tgt.task_id)
    cap = deepen_cap_for(task_row)
    if cap <= 0:
        raise HTTPException(409, "该任务已关闭深挖回炉（深挖次数=0），请先在任务配置里调大")
    if tgt.deepen_count >= cap:
        raise HTTPException(409, f"深挖次数已达上限({cap})，不再回炉")

    host = tgt.host or tgt.url or target_id
    tgt.deepen_context = {
        "directive": directive,
        "vuln_type": "",
        "original_title": "",
        "original_summary": (tgt.dead_reason or tgt.last_error or "")[:1000],
        "from_finding_id": "",
        "source": "user",
    }
    tgt.deepen_count += 1
    tgt.status = "queued"
    # 回炉前清干净上一轮的终态残留，否则会被当成死目标/已完成。
    tgt.verdict = ""
    tgt.dead_reason = ""
    tgt.last_error = ""
    tgt.assigned_worker = ""
    tgt.heartbeat_at = None
    tgt.retry_count = 0
    tgt.priority_score = (tgt.priority_score or 0) + 100.0
    tgt.priority_reason = f"[人工深挖#{tgt.deepen_count}] {directive[:80]}"
    session.add(TaskEvent(
        task_id=tgt.task_id,
        agent="user",
        kind="target_deepen",
        level="info",
        message=f"用户把硬骨头 {host} 打回深挖#{tgt.deepen_count}：{directive[:80]}",
        payload={"target_id": target_id, "host": host, "deepen_count": tgt.deepen_count},
    ))
    await session.commit()
    running = bool(task_row and getattr(task_row, "status", "") == "running")
    return {
        "ok": True,
        "id": target_id,
        "host": host,
        "deepen_count": tgt.deepen_count,
        "message": f"已打回深挖#{tgt.deepen_count}：{directive[:80]}",
        "queued_now": running,
    }
