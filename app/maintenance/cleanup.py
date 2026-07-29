"""任务数据清理：worker 结束后回收细粒度轨迹。

摘要事件（start/finish/finding_*）保留；细粒度（thought/http/shell/llm_round…）删除。
work_dir 不在本模块处理。
"""
from __future__ import annotations

import logging
import os

from sqlalchemy import delete, func, select

from app.db.models import TaskEvent
from app.db.session import SessionLocal

logger = logging.getLogger(__name__)

# 结束后仍保留的 worker 摘要 kinds（活动流可回看开/结/出洞）。
TRACE_SUMMARY_KINDS = frozenset({
    "worker_start",
    "worker_finish",
    "worker_cancelled",
    "worker_auto_finish",
    "finding_submitted",
    "finding_duplicate",
    "finding_invalid",
})

# 结束后删除的细粒度 kinds。
TRACE_FINE_KINDS = frozenset({
    "worker_thought", "worker_directive", "worker_resume",
    "tool_http", "tool_shell", "tool_shell_blocked", "tool_arg_error",
    "tool_exception", "tool_js_analyze", "tool_decode", "tool_waf_advice",
    "tool_fofa_lookup", "tool_session_set",
    "llm_round_start", "llm_error", "llm_soft_retry", "llm_interrupt",
    "auth_status", "finish_blocked",
})


def trace_keep_after_finish() -> bool:
    """TRACE_KEEP_AFTER_FINISH=1 时跳过清理（调试用）。"""
    return os.environ.get("TRACE_KEEP_AFTER_FINISH", "0").lower() in {"1", "true", "yes"}


async def prune_target_traces(task_id: str, target_id: str) -> int:
    """删除某目标的细粒度 worker 轨迹，保留摘要。返回删除行数。"""
    if not task_id or not target_id or trace_keep_after_finish():
        return 0
    kinds = sorted(TRACE_FINE_KINDS)
    try:
        async with SessionLocal() as session:
            # SQLite：payload 为 JSON；落库时必带 target_id（见 _persist_worker_trace）。
            stmt = (
                delete(TaskEvent)
                .where(
                    TaskEvent.task_id == task_id,
                    TaskEvent.agent == "worker",
                    TaskEvent.kind.in_(kinds),
                    func.json_extract(TaskEvent.payload, "$.target_id") == target_id,
                )
            )
            result = await session.execute(stmt)
            await session.commit()
            deleted = int(result.rowcount or 0)
            if deleted:
                logger.info(
                    "pruned %d fine traces task=%s target=%s",
                    deleted, task_id[:8], target_id[:8],
                )
            return deleted
    except Exception:
        logger.debug(
            "prune_target_traces failed task=%s target=%s",
            task_id[:8], target_id[:8], exc_info=True,
        )
        return 0


async def count_target_fine_traces(task_id: str, target_id: str) -> int:
    """测试/诊断：统计某目标仍残留的细粒度轨迹条数。"""
    async with SessionLocal() as session:
        q = await session.execute(
            select(func.count())
            .select_from(TaskEvent)
            .where(
                TaskEvent.task_id == task_id,
                TaskEvent.agent == "worker",
                TaskEvent.kind.in_(sorted(TRACE_FINE_KINDS)),
                func.json_extract(TaskEvent.payload, "$.target_id") == target_id,
            )
        )
        return int(q.scalar() or 0)
