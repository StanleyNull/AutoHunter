"""WebSocket 实时事件流（看板）。"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from app.events import bus
from app.security import auth_enabled, resolve_role, token_from_headers

router = APIRouter(tags=["stream"])


def _observer_event(event: dict) -> dict:
    """观摩模式 WebSocket 脱敏：只保留事件基本轮廓，不透出 URL/命令/漏洞标题/凭证等 payload。"""
    return {
        "agent": event.get("agent", ""),
        "kind": event.get("kind", ""),
        "level": event.get("level", "info"),
        "message": event.get("message", ""),
        "ts": event.get("ts"),
    }


@router.websocket("/api/tasks/{task_id}/stream")
async def task_stream(websocket: WebSocket, task_id: str):
    token = websocket.query_params.get("token") or token_from_headers(websocket.headers)
    role = resolve_role(token)
    if auth_enabled() and role is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    await websocket.accept()
    q = bus.subscribe(task_id)
    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=30)
                await websocket.send_json(_observer_event(event) if role == "observer" else event)
            except asyncio.TimeoutError:
                await websocket.send_json({"kind": "ping"})  # 保活
    except WebSocketDisconnect:
        pass
    finally:
        bus.unsubscribe(task_id, q)
