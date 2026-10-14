"""Escalation 闭环收口：升级结果空发射守卫。

扩大危害深挖虽然过了显著性门槛，仍可能返回空结果（升级猎人空跑/未带回任何实证）。
这类空升级洞若直接落库会污染报告。此守卫做保守判断：只要还带了任一实证
（poc / raw_request / raw_response / description），都放行进评审；全部为空才判为
空发射。全确定性、无副作用、可单测。
"""
from __future__ import annotations

_EMISSION_FIELDS = ("poc", "raw_request", "raw_response", "description")


def has_emission(res) -> bool:
    """升级结果是否携带实证。返回 False 表示应放弃落库（空发射）。"""
    if not isinstance(res, dict):
        return False
    return any(str(res.get(k) or "").strip() for k in _EMISSION_FIELDS)