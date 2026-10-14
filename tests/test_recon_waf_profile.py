"""WAF/风控指纹画像：拦截响应聚类 → waf_advisor 识别 → target_meta['waf_profile'] → 首轮注入。

覆盖 worker.profile_waf / _recon_leads_block 以及 executor.detect_waf_profiling。
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from app.agents.worker import Worker
from app.tools.executor import ToolExecutor


def _worker(target_meta=None) -> Worker:
    w = Worker.__new__(Worker)
    w.target = "https://example.edu.cn/"
    w.target_meta = {"recon_blocked": []} if target_meta is None else target_meta
    w.executor = None
    return w


class Ctx:  # patch 上下文：executor 桩
    def __init__(self, detect=None, live_probe=None):
        self._detect = [] if detect is None else detect
        self._live = live_probe

    def http_request(self, **kw):
        if self._live is not None:
            return self._live
        return {"ok": False}

    def detect_waf_profiling(self, *a, **k):
        out = self._detect[0] if self._detect else {"ok": True, "detected": False}
        if self._detect:
            self._detect.pop(0)
        return out


class WorkerWafProfileTest(unittest.TestCase):
    def test_profile_waf_sets_profile_and_flag(self):
        w = _worker({
            "recon_blocked": [
                {"status_code": 403, "headers": {"content-type": "text/html"}, "body": "Request blocked by WAF"},
            ]
        })
        w.executor = Ctx(detect=[{
            "ok": True, "detected": True, "waf_type": "cloudflare", "evidence": "challenge",
            "blocked_likely": True, "strategy_priority": ["xff"], "header_variants": [{"X-Forwarded-For": "127.0.0.1"}],
        }], live_probe=None)
        profile = w.profile_waf()
        self.assertEqual(profile["waf_type"], "cloudflare")
        self.assertEqual(w.target_meta["recon_waf_present"], True)
        self.assertEqual(w.target_meta["waf_profile"]["waf_type"], "cloudflare")

    def test_profile_waf_no_detection_leaves_empty(self):
        w = _worker({"recon_blocked": [{"status_code": 403, "headers": {}, "body": "denied"}]})
        w.executor = Ctx(detect=[{"ok": True, "detected": False, "waf_type": "none",
                                  "evidence": "", "blocked_likely": True, "strategy_priority": [], "header_variants": []}],
                         live_probe=None)
        profile = w.profile_waf()
        self.assertEqual(profile, {})
        self.assertNotIn("recon_waf_present", w.target_meta)

    def test_profile_waf_uses_live_probe(self):
        w = _worker({"recon_blocked": [{"status_code": 403, "headers": {}, "body": "x"}]})
        w.executor = Ctx(detect=[{
            "ok": True, "detected": True, "waf_type": "aliyun-waf", "evidence": "taobao default",
            "blocked_likely": True, "strategy_priority": ["ua"], "header_variants": [{"User-Agent": "Mozilla/5.0"}],
        }], live_probe={"ok": True, "status_code": 406, "response_headers": {}, "body": "suspected"})
        profile = w.profile_waf()
        self.assertEqual(profile["waf_type"], "aliyun-waf")

    def test_recon_leads_block_injects_waf_strategy(self):
        w = _worker({
            "waf_profile": {
                "waf_type": "cloudflare", "evidence": "challenge",
                "strategy_priority": ["xff"], "header_variants": [{"X-Forwarded-For": "127.0.0.1"}],
            }
        })
        block = w._recon_leads_block()
        self.assertIn("cloudflare", block)
        self.assertIn("X-Forwarded-For", block)

    def test_recon_leads_block_word_when_no_waf(self):
        w = _worker({"waf_profile": {}})
        self.assertEqual(w._recon_leads_block(), "")


class ExecutorDetectWafProfilingTest(unittest.TestCase):
    def test_detect_waf_profiling_map_fields(self):
        ex = ToolExecutor.__new__(ToolExecutor)
        with patch("app.tools.executor._suggest_waf_bypass", return_value={
            "detected": True, "waf_type": "cloudflare", "evidence": "challenge",
            "blocked_likely": True, "strategy_priority": ["xff"], "header_variants": [{"X-Forwarded-For": "127.0.0.1"}],
        }):
            out = ex.detect_waf_profiling(403, {"server": "cloudflare"}, "cf-challenge")
        self.assertTrue(out["ok"])
        self.assertTrue(out["detected"])
        self.assertEqual(out["waf_type"], "cloudflare")
        self.assertEqual(out["header_variants"], [{"X-Forwarded-For": "127.0.0.1"}])

    def test_detect_waf_profiling_error_is_graceful(self):
        ex = ToolExecutor.__new__(ToolExecutor)
        with patch("app.tools.executor._suggest_waf_bypass", side_effect=RuntimeError("boom")):
            out = ex.detect_waf_profiling(403, {}, "body")
        self.assertFalse(out["ok"])
        self.assertIn("error", out)


if __name__ == "__main__":
    unittest.main()