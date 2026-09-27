"""Shared queue eligibility for dispatch and collector backpressure."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.sql.elements import ColumnElement

from app.db.models import Target


def ready_queue_clause(now: datetime | None = None) -> ColumnElement[bool]:
    """Cooling targets remain queued but do not block collecting usable work."""
    now = now or datetime.now(timezone.utc)
    return (Target.status == "queued") & (
        Target.prefilter_retry_at.is_(None) | (Target.prefilter_retry_at <= now)
    )
