"""事件总线：agent 实时动作 → WebSocket 推送 + 落库 TaskEvent。

24x7 设计：事件既推前端（实时看板），也落库（审计 + 重启后可回看）。
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any


class EventBus:
    def __init__(self) -> None:
        # task_id -> set[asyncio.Queue]  每个 WebSocket 连接一个队列
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)

    def subscribe(self, task_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers[task_id].add(q)
        return q

    def unsubscribe(self, task_id: str, q: asyncio.Queue) -> None:
        self._subscribers[task_id].discard(q)
        if not self._subscribers[task_id]:
            self._subscribers.pop(task_id, None)

    async def publish(self, task_id: str, event: dict[str, Any]) -> None:
        for q in list(self._subscribers.get(task_id, ())):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass  # 慢消费者丢弃，不阻塞


bus = EventBus()
