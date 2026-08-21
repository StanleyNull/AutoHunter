"""深挖回炉的共享逻辑：AI 审核打回 与 人工复审「继续深挖」都走这一套。

把原 finding 标 superseded（让位、不再审/不入队/不参与 dedup），改写其 dedup_key
腾出唯一槽，再把原 target 带上定向指令重新入队并拉到队首。防死循环靠 deepen_count。
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.db.models import Finding, Target

DEEPEN_CAP_DEFAULT = 2  # 单 target 被打回深挖的默认次数（人工 + AI + worker deepen_lead 合计）
DEEPEN_CAP_MAX = 10
DEEPEN_CAP = DEEPEN_CAP_DEFAULT  # 兼容旧引用


def clamp_deepen_cap(value: object, default: int = DEEPEN_CAP_DEFAULT) -> int:
    """任务/设置里的深挖次数：0=关闭自动/人工深挖回炉，最大 10。"""
    try:
        n = int(value) if value is not None else default
    except (TypeError, ValueError):
        n = default
    return max(0, min(n, DEEPEN_CAP_MAX))


def deepen_cap_for(task: object | None) -> int:
    if task is None:
        return DEEPEN_CAP_DEFAULT
    return clamp_deepen_cap(getattr(task, "deepen_cap", None))


def apply_deepen(session, finding: Finding, tgt: Target | None, directive: str,
                 source: str = "ai", cap: int | None = None) -> tuple[bool, str]:
    """执行一次深挖回炉。返回 (是否生效, 日志后缀)。

    session: 调用方持有的 session（同步操作 ORM 对象属性，由调用方 commit）。
    source: 'ai' / 'user'，用于 priority_reason 标注来源。
    cap: 该任务的深挖上限；缺省用默认值 2。
    """
    limit = clamp_deepen_cap(cap)
    directive = (directive or "").strip()
    if not tgt or not directive or tgt.deepen_count >= limit:
        finding.status = "reviewed"
        if tgt and tgt.deepen_count >= limit:
            why = f"深挖次数已达上限({limit})"
        elif not directive:
            why = "未给深挖指令"
        else:
            why = "目标已不存在"
        return False, f" → 深挖未生效({why})，归档"

    finding.status = "superseded"
    if finding.dedup_key:
        finding.dedup_key = f"{finding.dedup_key}:sup:{finding.id[:8]}"
    tgt.deepen_context = {
        "directive": directive,
        "vuln_type": finding.vuln_type,
        "original_title": finding.title,
        "original_summary": (finding.description or "")[:1000],
        "from_finding_id": finding.id,
        "source": source,
    }
    tgt.deepen_count += 1
    tgt.status = "queued"
    tgt.assigned_worker = ""
    tgt.retry_count = 0
    # 回队前清掉上一轮的终态残留：done 目标带的旧 verdict=found、心跳、dead_reason
    # 都要归零，否则会污染派发/统计（如被当成已完成或死目标）。
    tgt.verdict = ""
    tgt.heartbeat_at = None
    tgt.dead_reason = ""
    tgt.priority_score = (tgt.priority_score or 0) + 100.0
    tag = "人工深挖" if source == "user" else "深挖"
    tgt.priority_reason = f"[{tag}#{tgt.deepen_count}] {directive[:80]}"
    return True, f" → 打回{tag}#{tgt.deepen_count}：{directive[:80]}"
