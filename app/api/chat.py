"""大厅 wumi 聊天 API：会话 CRUD + SSE 流式对话（单用户）。

聊天用独立的 XiaoQi 模型配置（app.settings_service.resolve_xiaoqi_config）。
流式复用报告助手的「后台线程 + asyncio.Queue + StreamingResponse」模式。
"""
from __future__ import annotations

import asyncio
import json
import threading
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_runtime import AGENT_EXECUTOR, agent_semaphore
from app.chat_prompts import SYSTEM_PROMPT_GUARD
from app.db.models import ChatMessage, ChatSession, to_cst_iso
from app.db.session import SessionLocal, get_session
from app.llm.client import LLMError
from app.settings_service import (
    llm_client_for_xiaoqi,
    resolve_xiaoqi_config,
    xiaoqi_system_prompt,
)

router = APIRouter(prefix="/api/chat", tags=["chat"])

_MAX_MESSAGE = 8000
_WALL_TIMEOUT = float(120)

# 单用户模式：所有聊天会话统一归属该固定用户（无多用户系统，无需隔离）。
LOCAL_UID = "local"


def _uid(request: Request) -> str:
    return LOCAL_UID


async def _owned_session(session: AsyncSession, session_id: str, user_id: str) -> ChatSession:
    cs = await session.scalar(
        select(ChatSession).where(ChatSession.id == session_id, ChatSession.user_id == user_id)
    )
    if cs is None:
        raise HTTPException(404, "会话不存在")
    return cs


def _sse(event: dict) -> str:
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n"


def _session_to_dict(cs: ChatSession, preview: str = "") -> dict:
    return {
        "id": cs.id,
        "title": cs.title or "新对话",
        "preview": preview,
        "created_at": to_cst_iso(cs.created_at),
        "updated_at": to_cst_iso(cs.updated_at),
    }


@router.get("/sessions")
async def list_sessions(
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """当前用户会话列表（倒序，含首条消息预览）。"""
    uid = _uid(request)
    rows = (await session.execute(
        select(ChatSession).where(ChatSession.user_id == uid)
        .order_by(ChatSession.updated_at.desc())
    )).scalars().all()
    out = []
    for cs in rows:
        preview = (await session.execute(
            select(ChatMessage.content).where(
                ChatMessage.session_id == cs.id, ChatMessage.role == "user"
            ).order_by(ChatMessage.created_at.asc()).limit(1)
        )).scalar_one_or_none() or ""
        out.append(_session_to_dict(cs, preview[:60]))
    return out


class CreateSessionRequest(BaseModel):
    title: str = Field(default="", max_length=200)


@router.post("/sessions", status_code=201)
async def create_session(
    req: CreateSessionRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    uid = _uid(request)
    cs = ChatSession(user_id=uid, title=(req.title or "").strip() or "新对话")
    session.add(cs)
    await session.commit()
    await session.refresh(cs)
    return _session_to_dict(cs)


@router.get("/sessions/{session_id}/messages")
async def list_messages(
    session_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    uid = _uid(request)
    await _owned_session(session, session_id, uid)
    rows = (await session.execute(
        select(ChatMessage).where(ChatMessage.session_id == session_id)
        .order_by(ChatMessage.created_at.asc())
    )).scalars().all()
    return [{
        "id": m.id,
        "role": m.role,
        "content": m.content,
        "created_at": to_cst_iso(m.created_at),
    } for m in rows]


@router.delete("/sessions/{session_id}", status_code=204)
async def delete_session(
    session_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    uid = _uid(request)
    await _owned_session(session, session_id, uid)
    await session.execute(delete(ChatMessage).where(ChatMessage.session_id == session_id))
    await session.execute(delete(ChatSession).where(ChatSession.id == session_id))
    await session.commit()
    return None


class SendMessageRequest(BaseModel):
    message: str = Field(default="", max_length=_MAX_MESSAGE + 16)


@router.post("/sessions/{session_id}/messages")
async def send_message(
    session_id: str,
    req: SendMessageRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """发送消息，SSE 流式返回 XiaoQi 回复（逐 token 推送给前端）。"""
    uid = _uid(request)
    cs = await _owned_session(session, session_id, uid)

    msg = (req.message or "").strip()
    if not msg:
        raise HTTPException(422, "消息不能为空")
    if len(msg) > _MAX_MESSAGE:
        raise HTTPException(422, f"消息不能超过 {_MAX_MESSAGE} 字")

    # XiaoQi 独立模型配置检查
    xq = resolve_xiaoqi_config()
    if not xq.api_key:
        raise HTTPException(400, "未配置 XiaoQi 模型，请先在「系统配置」页面填写模型 API Key")

    # 持久化用户消息
    user_msg = ChatMessage(session_id=session_id, user_id=uid, role="user", content=msg)
    session.add(user_msg)
    # 首条消息自动生成会话标题（取前 20 字）
    if (cs.title or "").strip() in ("", "新对话"):
        cs.title = msg[:20] + ("…" if len(msg) > 20 else "")
    await session.commit()

    # 读取完整历史（含刚存的 user 消息）构造对话
    history_rows = (await session.execute(
        select(ChatMessage).where(ChatMessage.session_id == session_id)
        .order_by(ChatMessage.created_at.asc())
    )).scalars().all()
    system_prompt = xiaoqi_system_prompt()
    # 强制追加系统安全指令（人设之后、权重最高），防提示词/人设泄露，用户无法覆盖
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "system", "content": SYSTEM_PROMPT_GUARD},
    ] + [
        {"role": m.role, "content": m.content} for m in history_rows
    ]

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    cancel_event = threading.Event()

    def _emit(ev: dict) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, ev)

    def _run() -> None:
        llm = llm_client_for_xiaoqi()
        full: list[str] = []
        try:
            for token in llm.chat_stream(messages, temperature=xq.temperature):
                full.append(token)
                _emit({"type": "token", "content": token})
            _emit({"type": "done", "content": "".join(full)})
        except LLMError as e:
            _emit({"type": "error", "content": f"XiaoQi 暂时没反应：{e.message}"})
        except Exception:
            _emit({"type": "error", "content": "XiaoQi 暂时没反应，稍后再试"})
        finally:
            _emit({"type": "__done__"})

    async def _gen():
        assistant_content: str = ""
        sem = agent_semaphore("lobby_chat")
        await sem.acquire()
        try:
            future = loop.run_in_executor(AGENT_EXECUTOR, _run)
        except BaseException:
            sem.release()
            raise

        def _release(_f) -> None:
            sem.release()

        future.add_done_callback(_release)
        assistant_content: str = ""
        try:
            while True:
                try:
                    ev = await asyncio.wait_for(queue.get(), timeout=_WALL_TIMEOUT)
                except asyncio.TimeoutError:
                    cancel_event.set()
                    yield _sse({"type": "error", "content": "wumi 思考超时，请重试"})
                    break
                et = ev.get("type")
                if et == "__done__":
                    break
                if et == "done":
                    assistant_content = ev.get("content") or ""
                elif et == "error":
                    assistant_content = ev.get("content") or ""
                elif et == "token":
                    assistant_content += ev.get("content") or ""  # 累计，供停止/中断时落库半截
                yield _sse(ev)
        finally:
            cancel_event.set()
            # 落库已生成内容（正常完成 / 前端停止 / 中断时都保留，有内容才存）
            if assistant_content.strip():
                try:
                    async with SessionLocal() as s:
                        s.add(ChatMessage(session_id=session_id, user_id=uid,
                                          role="assistant", content=assistant_content.strip()))
                        cs2 = await s.get(ChatSession, session_id)
                        if cs2:
                            cs2.updated_at = datetime.now(timezone.utc)
                        await s.commit()
                except Exception:
                    pass
            try:
                await asyncio.shield(future)
            except asyncio.CancelledError:
                pass

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
