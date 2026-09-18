"""proxy_service 轮转/冷却/排除记忆单元测试（内存态，不碰 DB）。"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from app import proxy_service as ps


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _cfg(*entries: dict, enabled: bool = True) -> dict:
    return {"enabled": enabled, "proxies": list(entries)}


def _px(idx: int, **kw) -> dict:
    base = {
        "id": f"px-{idx}",
        "name": f"p{idx}",
        "protocol": "http",
        "host": f"10.0.0.{idx}",
        "port": 8080,
        "username": "",
        "password": "",
        "enabled": True,
    }
    base.update(kw)
    return base


class ProxyServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        ps.apply_config({})

    tearDown = setUp

    def test_acquire_round_robin_order(self) -> None:
        ps.apply_config(_cfg(_px(1), _px(2), _px(3)))
        got = [ps.acquire()["id"] for _ in range(3)]
        self.assertEqual(sorted(got), {"px-1", "px-2", "px-3"})
        # 再转一轮应重新覆盖全部
        got2 = {ps.acquire()["id"] for _ in range(3)}
        self.assertEqual(got2, {"px-1", "px-2", "px-3"})

    def test_acquire_randomize_uses_random_candidate(self) -> None:
        ps.apply_config(_cfg(_px(1), _px(2), _px(3)))
        with patch.object(ps._RANDOM, "choice", return_value="px-3"):
            got = ps.acquire(randomize=True)
        self.assertEqual(got["id"], "px-3")

    def test_acquire_skips_disabled(self) -> None:
        ps.apply_config(_cfg(_px(1), _px(2, enabled=False)))
        for _ in range(4):
            self.assertEqual(ps.acquire()["id"], "px-1")

    def test_acquire_returns_none_when_disabled_or_empty(self) -> None:
        ps.apply_config(_cfg(_px(1), enabled=False))
        self.assertIsNone(ps.acquire())
        ps.apply_config(_cfg())
        self.assertIsNone(ps.acquire())

    def test_acquire_excludes_ids(self) -> None:
        ps.apply_config(_cfg(_px(1), _px(2), _px(3)))
        seen = set()
        for _ in range(2):
            got = ps.acquire(exclude_ids=seen)
            self.assertIsNotNone(got)
            seen.add(got["id"])
        self.assertIsNone(ps.acquire(exclude_ids=seen))

    def test_acquire_skips_cooldown_and_recovers(self) -> None:
        ps.apply_config(_cfg(_px(1), _px(2)))
        # 模拟 px-1 与 px-2 都进冷却
        with ps._LOCK:
            ps._health_of("px-1")["cooldown_until"] = __import__("time").time() + 999
            ps._health_of("px-2")["cooldown_until"] = __import__("time").time() + 999
        self.assertIsNone(ps.acquire())
        # 冷却结束恢复
        with ps._LOCK:
            ps._health_of("px-1")["cooldown_until"] = 0.0
        got = ps.acquire()
        self.assertEqual(got["id"], "px-1")
        self.assertIn("http://10.0.0.1:8080", got["url"])

    def test_report_failure_triggers_cooldown_after_threshold(self) -> None:
        ps.apply_config(_cfg(_px(1), _px(2)))
        for _ in range(ps.FAIL_THRESHOLD - 1):
            self.assertFalse(ps.report_failure("px-1"))
        self.assertTrue(ps.report_failure("px-1"))  # 达阈值 → 冷却
        # 冷却中被跳过
        ids = {ps.acquire()["id"] for _ in range(4)}
        self.assertNotIn("px-1", ids)
        # 成功上报清零恢复
        ps.clear_cooldown("px-1")
        self.assertEqual(ps.snapshot_view()["proxies"][0]["status"], "ok")

    def test_report_success_resets_fail_counter(self) -> None:
        ps.apply_config(_cfg(_px(1)))
        ps.report_failure("px-1")
        ps.report_failure("px-1")
        ps.report_success("px-1")
        self.assertFalse(ps.report_failure("px-1"))  # 计数已清零，未达阈值

    def test_unknown_proxy_id_is_ignored(self) -> None:
        ps.apply_config(_cfg(_px(1)))
        self.assertFalse(ps.report_failure("nope"))
        ps.report_success("nope")  # 不抛异常

    def test_snapshot_view_masks_password(self) -> None:
        ps.apply_config(_cfg(_px(1, password="super-secret")))
        view = ps.snapshot_view()
        row = view["proxies"][0]
        self.assertEqual(row["password"], "")
        self.assertTrue(row["password_set"])
        self.assertNotIn("super-secret", str(view))
        self.assertEqual(row["display"], "http://10.0.0.1:8080")

    def test_available_count(self) -> None:
        ps.apply_config(_cfg(_px(1), _px(2), _px(3, enabled=False)))
        self.assertEqual(ps.available_count(), 2)
        self.assertEqual(ps.available_count(exclude_ids={"px-1"}), 1)
        ps.apply_config(_cfg(_px(1), enabled=False))
        self.assertEqual(ps.available_count(), 0)

    def test_normalize_proxies_payload_preserves_masked_password(self) -> None:
        old = [_px(1, password="real-pass")]
        out = ps.normalize_proxies_payload(
            [{**_px(1), "password": "••••••••"}], old_proxies=old
        )
        self.assertEqual(out[0]["password"], "real-pass")
        out = ps.normalize_proxies_payload([{**_px(1), "password": "new-pass"}], old)
        self.assertEqual(out[0]["password"], "new-pass")

    def test_duplicate_ids_dropped_on_apply(self) -> None:
        ps.apply_config(_cfg(_px(1), _px(1)))
        self.assertEqual(len(ps.snapshot_view()["proxies"]), 1)


if __name__ == "__main__":
    unittest.main()
