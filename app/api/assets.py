"""全局资产（硬骨头库）置顶 API：单条/批量置顶与取消置顶。

资产在本项目中对应 Target 表（host 级目标）。全局资产列表查询仍在
tasks.py 的 /api/tasks/hard-targets 提供（含置顶排序与 is_top 输出）；
本路由只承担置顶写操作，路径与漏洞置顶（/api/vulns/.../top）对称。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Target
from app.db.session import get_session

router = APIRouter(prefix="/api/assets", tags=["assets"])


class TopRequest(BaseModel):
    """单条置顶/取消置顶请求体。"""
    is_top: bool


class BatchTopRequest(BaseModel):
    """批量置顶/取消置顶请求体。ids 为资产 id 列表。"""
    ids: list[str]
    is_top: bool


# 鉴权说明：本路由所有 PATCH 写操作由 main.py 的 security_middleware 统一拦截，
# 仅 full 令牌（管理员）可执行；readonly/observer 会被中间件直接 403。
# 这与项目现有写接口（skip/directive/invalidate 等）的权限模型完全一致。


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
    ids = list(dict.fromkeys(str(i).strip() for i in raw_ids if str(i).strip()))
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
