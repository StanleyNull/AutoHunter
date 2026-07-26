"""LLM 端点运行时健康状态：失败计数、冷却与 half-open 探测。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import math
import os
import threading
from typing import Any


_HEALTH: dict[str, dict[str, Any]] = {}
_LOCK = threading.Lock()
_FAIL_THRESHOLD = max(1, int(os.environ.get("LLM_PROVIDER_FAIL_THRESHOLD", "5")))
_BEHAVIOR_FAIL_THRESHOLD = max(1, int(os.environ.get("LLM_PROVIDER_BEHAVIOR_FAIL_THRESHOLD", "3")))
_FAILED_RETRY_SECONDS = max(1, int(os.environ.get("LLM_PROVIDER_FAILED_RETRY_SECONDS", "60")))
_TRANSPORT_PROBE_SECONDS = max(1, int(os.environ.get("LLM_PROVIDER_PROBE_SECONDS", "120")))
_BEHAVIOR_PROBE_SECONDS = max(1, int(os.environ.get("LLM_PROVIDER_BEHAVIOR_PROBE_SECONDS", "900")))


def _cooldown_steps() -> list[int]:
    values: list[int] = []
    for raw in os.environ.get("LLM_PROVIDER_COOLDOWN_SECONDS", "300,900,1800,3600").split(","):
        try:
            value = int(raw.strip())
        except ValueError:
            continue
        if value > 0:
            values.append(value)
    return values or [300]


_COOLDOWN_STEPS = _cooldown_steps()


def provider_ref(
    base_url: str,
    model: str,
    api_key: str = "",
    protocol: str = "auto",
) -> str:
    raw = "|".join([
        str(base_url or "").strip().rstrip("/"),
        str(model or "").strip(),
        str(api_key or "").strip(),
        str(protocol or "auto").strip().lower(),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat()


def _cooldown_seconds(count: int) -> int:
    return _COOLDOWN_STEPS[min(max(0, count), len(_COOLDOWN_STEPS) - 1)]


def _base_row(ref: str, base_url: str, model: str, protocol: str) -> dict[str, Any]:
    return {
        "ref": ref,
        "base_url": str(base_url or "").strip().rstrip("/"),
        "model": str(model or "").strip(),
        "protocol": str(protocol or "auto").strip().lower(),
    }


def _transport_status(row: dict[str, Any]) -> str:
    if "transport_status" in row:
        return str(row.get("transport_status") or "ok")
    if "behavior_status" in row:
        return "ok"
    return str(row.get("status") or "ok")


def _refresh_status(row: dict[str, Any], now: datetime | None = None) -> str:
    now_ts = (now or _now()).timestamp()
    transport = _transport_status(row)
    behavior = str(row.get("behavior_status") or "ok")
    if transport == "cooldown" and float(row.get("cooldown_until_ts") or 0) > now_ts:
        status = "cooldown"
    elif behavior == "cooldown" and float(row.get("behavior_cooldown_until_ts") or 0) > now_ts:
        status = "cooldown"
    elif transport == "half_open" or behavior == "half_open":
        status = "half_open"
    elif transport == "failed" or behavior == "failed":
        status = "failed"
    else:
        status = "ok"
    row["status"] = status
    return status


def _refresh_expired_probes(row: dict[str, Any], now: datetime) -> None:
    now_ts = now.timestamp()
    transport = _transport_status(row)
    if transport == "failed" and float(row.get("failed_retry_at_ts") or 0) <= now_ts:
        row["transport_status"] = "half_open"
        row["half_open_inflight"] = False
    elif transport == "cooldown" and float(row.get("cooldown_until_ts") or 0) <= now_ts:
        row["transport_status"] = "half_open"
        row["half_open_inflight"] = False
    elif (
        transport == "half_open"
        and row.get("half_open_inflight")
        and float(row.get("half_open_until_ts") or 0) <= now_ts
    ):
        row["half_open_inflight"] = False
        row["half_open_until_ts"] = 0

    behavior = str(row.get("behavior_status") or "ok")
    if behavior == "failed" and float(row.get("behavior_retry_at_ts") or 0) <= now_ts:
        row["behavior_status"] = "half_open"
        row["behavior_probe_owner"] = ""
        row["behavior_probe_until_ts"] = 0
    elif behavior == "cooldown" and float(row.get("behavior_cooldown_until_ts") or 0) <= now_ts:
        row["behavior_status"] = "half_open"
        row["behavior_probe_owner"] = ""
        row["behavior_probe_until_ts"] = 0
    elif behavior == "half_open" and float(row.get("behavior_probe_until_ts") or 0) <= now_ts:
        row["behavior_probe_owner"] = ""
        row["behavior_probe_until_ts"] = 0
    _refresh_status(row, now)


def acquire_provider_slot(
    base_url: str,
    model: str,
    api_key: str = "",
    protocol: str = "auto",
    owner: str = "",
) -> tuple[bool, str]:
    """申请一次调用资格；冷却到期后仅放行一个 half-open 请求。"""
    ref = provider_ref(base_url, model, api_key, protocol)
    now = _now()
    with _LOCK:
        row = _HEALTH.get(ref)
        if not row:
            return True, "ready"
        _refresh_expired_probes(row, now)
        transport_status = _transport_status(row)
        if transport_status == "failed":
            return False, "failed"
        if transport_status == "cooldown":
            return False, "cooldown"
        if transport_status == "half_open" and row.get("half_open_inflight"):
            return False, "half_open_inflight"

        behavior_status = str(row.get("behavior_status") or "ok")
        if behavior_status == "cooldown":
            return False, "behavior_cooldown"
        if behavior_status == "failed":
            return False, "behavior_failed"
        if behavior_status == "half_open":
            probe_owner = str(row.get("behavior_probe_owner") or "")
            if probe_owner and probe_owner != owner:
                return False, "behavior_half_open_inflight"
            if not probe_owner:
                row["behavior_probe_owner"] = owner or "anonymous"
                row["behavior_probe_until_ts"] = now.timestamp() + _BEHAVIOR_PROBE_SECONDS
            _refresh_status(row, now)

        if transport_status == "half_open":
            row["half_open_inflight"] = True
            row["half_open_until_ts"] = now.timestamp() + _TRANSPORT_PROBE_SECONDS
            row["last_seen"] = _iso(now)
            _refresh_status(row, now)
            return True, "half_open"
        _refresh_status(row, now)
        return True, "ready"


def provider_retry_after_seconds(
    base_url: str, model: str, api_key: str = "", protocol: str = "auto"
) -> int:
    ref = provider_ref(base_url, model, api_key, protocol)
    now_ts = _now().timestamp()
    with _LOCK:
        row = _HEALTH.get(ref) or {}
        delays: list[float] = []
        if row.get("behavior_status") == "failed":
            delays.append(float(row.get("behavior_retry_at_ts") or 0) - now_ts)
        if row.get("behavior_status") == "cooldown":
            delays.append(float(row.get("behavior_cooldown_until_ts") or 0) - now_ts)
        if _transport_status(row) == "failed":
            delays.append(float(row.get("failed_retry_at_ts") or 0) - now_ts)
        if _transport_status(row) == "cooldown":
            delays.append(float(row.get("cooldown_until_ts") or 0) - now_ts)
        if row.get("half_open_inflight"):
            delays.append(min(5.0, float(row.get("half_open_until_ts") or 0) - now_ts))
        if row.get("behavior_probe_owner"):
            delays.append(min(5.0, float(row.get("behavior_probe_until_ts") or 0) - now_ts))
    positive = [delay for delay in delays if delay > 0]
    return max(1, int(math.ceil(min(positive)))) if positive else 1


def mark_provider_ok(
    base_url: str, model: str, api_key: str = "", protocol: str = "auto"
) -> dict[str, Any]:
    ref = provider_ref(base_url, model, api_key, protocol)
    now = _now()
    with _LOCK:
        row = _HEALTH.setdefault(ref, {})
        row.update({
            **_base_row(ref, base_url, model, protocol),
            "transport_status": "ok",
            "last_error": "",
            "error_kind": "",
            "last_seen": _iso(now),
            "consecutive_failures": 0,
            "cooldown_count": 0,
            "cooldown_seconds": 0,
            "cooldown_until": "",
            "cooldown_until_ts": 0,
            "failed_retry_at_ts": 0,
            "half_open_inflight": False,
            "half_open_until_ts": 0,
        })
        _refresh_status(row, now)
        return dict(row)


def mark_provider_behavior_failed(
    base_url: str,
    model: str,
    error: str,
    api_key: str = "",
    protocol: str = "auto",
    *,
    kind: str = "model_behavior",
) -> dict[str, Any]:
    ref = provider_ref(base_url, model, api_key, protocol)
    now = _now()
    with _LOCK:
        row = _HEALTH.setdefault(ref, {})
        if (
            row.get("behavior_status") == "cooldown"
            and now.timestamp() < float(row.get("behavior_cooldown_until_ts") or 0)
        ):
            row.update({
                **_base_row(ref, base_url, model, protocol),
                "behavior_last_error": " ".join(str(error or "").split())[:500],
                "behavior_error_kind": kind,
                "last_seen": _iso(now),
            })
            return {**row, "transition": "behavior_cooldown_suppressed"}
        strikes = int(row.get("behavior_strikes") or 0) + 1
        status = "failed"
        cooldown_seconds = 0
        cooldown_until = ""
        cooldown_until_ts = 0.0
        transition = "behavior_failure_recorded"
        retry_at_ts = now.timestamp() + _FAILED_RETRY_SECONDS
        if strikes >= _BEHAVIOR_FAIL_THRESHOLD:
            status = "cooldown"
            cooldown_seconds = _cooldown_seconds(int(row.get("behavior_cooldown_count") or 0))
            until = now + timedelta(seconds=cooldown_seconds)
            cooldown_until = _iso(until)
            cooldown_until_ts = until.timestamp()
            row["behavior_cooldown_count"] = int(row.get("behavior_cooldown_count") or 0) + 1
            transition = "behavior_cooldown_started"
            retry_at_ts = 0
        row.update({
            **_base_row(ref, base_url, model, protocol),
            "behavior_status": status,
            "behavior_strikes": strikes,
            "behavior_last_error": " ".join(str(error or "").split())[:500],
            "behavior_error_kind": kind,
            "behavior_cooldown_until": cooldown_until,
            "behavior_cooldown_until_ts": cooldown_until_ts,
            "behavior_retry_at_ts": retry_at_ts,
            "behavior_probe_owner": "",
            "behavior_probe_until_ts": 0,
            "last_seen": _iso(now),
        })
        _refresh_status(row, now)
        return {
            **row,
            "transition": transition,
            "consecutive_failures": strikes,
            "cooldown_seconds": cooldown_seconds,
        }


def mark_provider_behavior_ok(
    base_url: str, model: str, api_key: str = "", protocol: str = "auto"
) -> dict[str, Any]:
    ref = provider_ref(base_url, model, api_key, protocol)
    with _LOCK:
        row = _HEALTH.setdefault(ref, {})
        row.update({
            **_base_row(ref, base_url, model, protocol),
            "behavior_status": "ok",
            "behavior_strikes": 0,
            "behavior_last_error": "",
            "behavior_error_kind": "",
            "behavior_cooldown_until": "",
            "behavior_cooldown_until_ts": 0,
            "behavior_retry_at_ts": 0,
            "behavior_cooldown_count": 0,
            "behavior_probe_owner": "",
            "behavior_probe_until_ts": 0,
        })
        _refresh_status(row)
        return dict(row)


def mark_provider_failed(
    base_url: str,
    model: str,
    error: str,
    api_key: str = "",
    protocol: str = "auto",
    *,
    kind: str = "",
) -> dict[str, Any]:
    ref = provider_ref(base_url, model, api_key, protocol)
    now = _now()
    with _LOCK:
        row = _HEALTH.get(ref)
        if str(kind or "").strip().lower() == "invalid_request":
            # A 400/422 describes this request, not endpoint availability. It
            # may still trigger same-call failover, but must not suppress the
            # endpoint for unrelated workers. If this was a half-open probe,
            # release the lease without changing the prior health counters.
            if row is None:
                return {
                    **_base_row(ref, base_url, model, protocol),
                    "transport_status": "ok",
                    "behavior_status": "ok",
                    "status": "ok",
                    "consecutive_failures": 0,
                    "cooldown_seconds": 0,
                    "transition": "request_rejected",
                }
            if _transport_status(row) == "half_open" and row.get("half_open_inflight"):
                row["half_open_inflight"] = False
                row["half_open_until_ts"] = 0
            if str(row.get("behavior_status") or "") == "half_open":
                row["behavior_probe_owner"] = ""
                row["behavior_probe_until_ts"] = 0
            _refresh_status(row, now)
            return {**row, "transition": "request_rejected"}

        row = _HEALTH.setdefault(ref, {})
        previous_status = _transport_status(row)
        if previous_status == "cooldown" and now.timestamp() < float(row.get("cooldown_until_ts") or 0):
            row.update({
                **_base_row(ref, base_url, model, protocol),
                "transport_status": "cooldown",
                "last_error": " ".join(str(error or "").split())[:500],
                "error_kind": str(kind or ""),
                "last_seen": _iso(now),
                "half_open_inflight": False,
                "half_open_until_ts": 0,
            })
            return {**row, "transition": "cooldown_suppressed"}

        consecutive = int(row.get("consecutive_failures") or 0) + 1
        cooldown_count = int(row.get("cooldown_count") or 0)
        status = "failed"
        cooldown_seconds = 0
        cooldown_until = ""
        cooldown_until_ts = 0.0
        transition = "failure_recorded"
        failed_retry_at_ts = now.timestamp() + _FAILED_RETRY_SECONDS
        if consecutive >= _FAIL_THRESHOLD:
            status = "cooldown"
            cooldown_seconds = _cooldown_seconds(cooldown_count)
            until = now + timedelta(seconds=cooldown_seconds)
            cooldown_until = _iso(until)
            cooldown_until_ts = until.timestamp()
            cooldown_count += 1
            transition = "cooldown_probe_failed" if previous_status == "half_open" else "cooldown_started"
            failed_retry_at_ts = 0

        if row.get("behavior_status") == "half_open":
            row.update({
                "behavior_status": "failed",
                "behavior_retry_at_ts": now.timestamp() + _FAILED_RETRY_SECONDS,
                "behavior_probe_owner": "",
                "behavior_probe_until_ts": 0,
            })

        row.update({
            **_base_row(ref, base_url, model, protocol),
            "transport_status": status,
            "last_error": " ".join(str(error or "").split())[:500],
            "error_kind": str(kind or ""),
            "last_seen": _iso(now),
            "consecutive_failures": consecutive,
            "cooldown_count": cooldown_count,
            "cooldown_seconds": cooldown_seconds,
            "cooldown_until": cooldown_until,
            "cooldown_until_ts": cooldown_until_ts,
            "failed_retry_at_ts": failed_retry_at_ts,
            "half_open_inflight": False,
            "half_open_until_ts": 0,
        })
        _refresh_status(row, now)
        return {**row, "transition": transition}


def snapshot() -> dict[str, dict[str, Any]]:
    with _LOCK:
        now = _now()
        for row in _HEALTH.values():
            _refresh_expired_probes(row, now)
        return {ref: dict(row) for ref, row in _HEALTH.items()}
