"""深挖回炉的共享逻辑：AI 审核打回 与 人工复审「继续深挖」都走这一套。

把原 finding 标 superseded（让位、不再审/不入队/不参与 dedup），改写其 dedup_key
腾出唯一槽，再把原 target 带上定向指令重新入队并拉到队首。防死循环靠 deepen_count。
"""
from __future__ import annotations

from app.db.models import Finding, Target

DEEPEN_CAP = 2  # 单 target 被打回深挖的最大次数（人工 + AI 合计）


def apply_deepen(session, finding: Finding, tgt: Target | None, directive: str,
                 source: str = "ai") -> tuple[bool, str]:
    """执行一次深挖回炉。返回 (是否生效, 日志后缀)。

    session: 调用方持有的 session（同步操作 ORM 对象属性，由调用方 commit）。
    source: 'ai' / 'user'，用于 priority_reason 标注来源。
    """
    directive = (directive or "").strip()
    if not tgt or not directive or tgt.deepen_count >= DEEPEN_CAP:
        finding.status = "reviewed"
        if tgt and tgt.deepen_count >= DEEPEN_CAP:
            why = f"深挖次数已达上限({DEEPEN_CAP})"
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
    tgt.priority_score = (tgt.priority_score or 0) + 100.0
    tag = "人工深挖" if source == "user" else "深挖"
    tgt.priority_reason = f"[{tag}#{tgt.deepen_count}] {directive[:80]}"
    return True, f" → 打回{tag}#{tgt.deepen_count}：{directive[:80]}"
