"""通杀列状态辅助：启动失败/无命中可重启，不必改复审状态。"""
from __future__ import annotations


def killsweep_retryable(status: str, is_killsweep: bool) -> bool:
    """失败/取消/无命中/中途卡住都可以重启；已有通杀命中或人工无效则不必。"""
    st = (status or "").strip()
    if st == "invalid":
        return False
    if st == "done" and is_killsweep:
        return False
    return True
