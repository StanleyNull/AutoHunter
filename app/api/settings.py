"""全局系统配置 API。"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dto import SettingsUpdateRequest
from app.db.session import get_session
from app.settings_service import (
    list_available_models,
    public_settings_view,
    refresh_cache,
    update_settings,
)

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
async def get_settings(session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    return public_settings_view()


class ModelsProbeRequest(BaseModel):
    base_url: str | None = None
    api_key: str | None = None


@router.post("/models")
async def probe_models(
    body: ModelsProbeRequest,
    session: AsyncSession = Depends(get_session),
):
    """拉取模型商可用模型列表，供前端下拉选择。base_url/api_key 留空用有效配置。
    注意：api_key 为脱敏占位（如 ****）时视为未传，回退到服务端已存的真实 key。"""
    await refresh_cache(session)
    key = (body.api_key or "").strip()
    if key and set(key) <= {"*", "•", "·", "●"}:
        key = ""  # 前端回显的脱敏占位，丢弃
    return await list_available_models(base_url=body.base_url, api_key=key or None)


@router.put("")
async def put_settings(
    body: SettingsUpdateRequest,
    session: AsyncSession = Depends(get_session),
):
    payload = body.model_dump(exclude_unset=True)
    return await update_settings(session, payload)
