from __future__ import annotations

from app.agents.worker import Worker


def _worker_with(deepen_context=None, enterprise=False) -> Worker:
    w = Worker.__new__(Worker)
    w.deepen_context = deepen_context
    w._enterprise = enterprise
    w.target_meta = {}
    return w


def test_route_rounds_foothold_relaxes_budget():
    w = _worker_with(deepen_context={"directive": "继续打登录后接口"})
    max_r, soft_r = w._route_rounds(90, 45)
    assert max_r >= 150
    assert soft_r >= 100


def test_route_rounds_enterprise_foothold_relaxes_budget():
    w = _worker_with(deepen_context={"directive": "x"}, enterprise=True)
    max_r, soft_r = w._route_rounds(110, 60)
    assert max_r >= 180
    assert soft_r >= 120


def test_route_rounds_non_foothold_keeps_default():
    w = _worker_with(deepen_context=None)
    max_r, soft_r = w._route_rounds(90, 45)
    assert max_r == 90
    assert soft_r == 45
