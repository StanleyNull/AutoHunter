import unittest
from types import SimpleNamespace

from app.agents.deepen import apply_deepen, clamp_deepen_cap, deepen_cap_for


class DeepenCapTest(unittest.TestCase):
    def test_clamp_default_and_bounds(self):
        self.assertEqual(clamp_deepen_cap(None), 2)
        self.assertEqual(clamp_deepen_cap(0), 0)
        self.assertEqual(clamp_deepen_cap(10), 10)
        self.assertEqual(clamp_deepen_cap(99), 10)
        self.assertEqual(clamp_deepen_cap(-3), 0)
        self.assertEqual(clamp_deepen_cap("5"), 5)
        self.assertEqual(clamp_deepen_cap("nope"), 2)

    def test_deepen_cap_for_task(self):
        self.assertEqual(deepen_cap_for(None), 2)
        self.assertEqual(deepen_cap_for(SimpleNamespace()), 2)
        self.assertEqual(deepen_cap_for(SimpleNamespace(deepen_cap=5)), 5)
        self.assertEqual(deepen_cap_for(SimpleNamespace(deepen_cap=99)), 10)

    def _apply(self, count, cap, directive="继续打登录"):
        finding = SimpleNamespace(
            status="pending", dedup_key="k", id="abcdef12xxxx",
            vuln_type="idor", title="t", description="d",
        )
        tgt = SimpleNamespace(
            deepen_count=count, deepen_context=None, status="done",
            assigned_worker="w", retry_count=1, verdict="found",
            heartbeat_at="x", dead_reason="y",
            priority_score=1.0, priority_reason="",
        )
        ok, suffix = apply_deepen(None, finding, tgt, directive, source="user", cap=cap)
        return ok, suffix, finding, tgt

    def test_cap2_blocks_when_count_already_2(self):
        ok, suffix, finding, tgt = self._apply(2, 2)
        self.assertFalse(ok)
        self.assertIn("上限(2)", suffix)
        self.assertEqual(finding.status, "reviewed")
        self.assertEqual(tgt.deepen_count, 2)

    def test_cap5_allows_when_count_is_2(self):
        ok, suffix, finding, tgt = self._apply(2, 5)
        self.assertTrue(ok)
        self.assertEqual(finding.status, "superseded")
        self.assertEqual(tgt.deepen_count, 3)
        self.assertEqual(tgt.status, "queued")

    def test_cap0_disables_deepen(self):
        ok, suffix, finding, tgt = self._apply(0, 0)
        self.assertFalse(ok)
        self.assertIn("上限(0)", suffix)
        self.assertEqual(finding.status, "reviewed")
        self.assertEqual(tgt.deepen_count, 0)
