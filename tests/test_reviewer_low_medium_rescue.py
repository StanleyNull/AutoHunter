"""审核降过杀救援：匿名泄露 / WAF 实锤的中低危 ignored 改判 deepen，且救援链次序正确。

anon_leak 救援 > waf 救援 > 通用救援；互相独立、不冲突。
"""
from __future__ import annotations

import unittest

from app.agents.reviewer import (
    Reviewer,
    _has_some_evidence,
    _maybe_deepen_ignored,
    _maybe_rescue_recon_anon_leak,
    _maybe_rescue_recon_waf,
)
from app.schemas import Finding, Review


def _finding(**kwargs) -> Finding:
    base = {
        "vuln_type": "unauthorized_access",
        "title": "匿名接口疑似泄露",
        "severity_claimed": "中危",
        "target_url": "https://example.edu.cn/api/export",
        "owner": "测试学校",
        "description": "侦察期匿名可访问端点疑似返回敏感数据。",
        "steps": ["GET 探测"],
        "poc": "",
        "raw_request": "",
        "raw_response": "",
        "evidence": {},
        "affected_scope": "待确认",
        "kill_chain": [],
        "self_check": {
            "is_reflected_xss": False,
            "needs_admin_login": False,
            "needs_mitm": False,
            "is_pure_info_leak": False,
            "scanner_only_no_poc": False,
            "is_public_interface": False,
            "info_leak_hits_strict_list": False,
            "recon_anon_leak": False,
            "recon_waf_present": False,
        },
    }
    base.update(kwargs)
    return Finding(**base)


def _ignored_review(**kwargs) -> Review:
    base = {
        "verdict": "ignored",
        "confidence": "uncertain",
        "score": 1.5,
        "in_scope": True,
        "is_duplicate": False,
        "ignore_reasons": ["证据不足"],
        "reviewer_notes": "不够 accepted。",
    }
    base.update(kwargs)
    return Review(**base)


class ReconAnonLeakRescueTest(unittest.TestCase):
    def test_rescues_medium_ignored_fragmentary_anon_leak(self):
        finding = _finding(
            title="匿名导出接口疑似泄露",
            self_check=_sc({"recon_anon_leak": True}),
        )
        review = _ignored_review()
        self.assertTrue(_maybe_rescue_recon_anon_leak(finding, review))
        self.assertEqual(review.verdict.value, "deepen")
        self.assertIn("匿名端点", review.deepen_directive)
        self.assertEqual(review.ignore_reasons, [])
        self.assertEqual(review.confidence.value, "uncertain")

    def test_does_not_rescue_when_evidence_complete(self):
        finding = _finding(
            self_check=_sc({"recon_anon_leak": True}),
            raw_response='HTTP/1.1 200 OK\n\n{"token":"x"}',
            evidence={"extracted_data_sample": "AKIAIOSFODNN7EXAMPLE"},
        )
        review = _ignored_review()
        self.assertFalse(_maybe_rescue_recon_anon_leak(finding, review))
        self.assertEqual(review.verdict.value, "ignored")

    def test_does_not_rescue_high_severity(self):
        finding = _finding(
            self_check=_sc({"recon_anon_leak": True}),
            severity_claimed="高危",
        )
        review = _ignored_review()
        self.assertFalse(_maybe_rescue_recon_anon_leak(finding, review))

    def test_does_not_rescue_without_anchor(self):
        finding = _finding(self_check=_sc({}))
        review = _ignored_review()
        self.assertFalse(_maybe_rescue_recon_anon_leak(finding, review))

    def test_does_not_rescue_duplicate_or_out_of_scope(self):
        finding = _finding(self_check=_sc({"recon_anon_leak": True}))
        self.assertFalse(_maybe_rescue_recon_anon_leak(finding, _ignored_review(is_duplicate=True)))
        self.assertFalse(_maybe_rescue_recon_anon_leak(finding, _ignored_review(in_scope=False)))


class ReconWafRescueTest(unittest.TestCase):
    def test_rescues_ignored_with_waf_anchor_and_evidence(self):
        finding = _finding(
            vuln_type="sql_injection",
            self_check=_sc({"recon_waf_present": True}),
            poc="curl 'https://example.edu.cn/a?id=1'",
            raw_request="GET /a?id=1 HTTP/1.1",
        )
        review = _ignored_review()
        self.assertTrue(_maybe_rescue_recon_waf(finding, review))
        self.assertEqual(review.verdict.value, "deepen")
        self.assertIn("X-Forwarded-For", review.deepen_directive)
        self.assertIn("WAF", review.reviewer_notes)

    def test_does_not_rescue_no_evidence(self):
        finding = _finding(
            self_check=_sc({"recon_waf_present": True}),
            poc="", raw_request="", raw_response="", evidence={}, kill_chain=[],
        )
        review = _ignored_review()
        self.assertFalse(_maybe_rescue_recon_waf(finding, review))

    def test_does_not_rescue_without_anchor(self):
        finding = _finding(self_check=_sc({}), poc="curl x")
        review = _ignored_review()
        self.assertFalse(_maybe_rescue_recon_waf(finding, review))


class RescueChainOrderTest(unittest.TestCase):
    def test_chain_anon_leak_before_general_deepen(self):
        finding = _finding(self_check=_sc({"recon_anon_leak": True}))
        review = _ignored_review()
        self.assertTrue(_maybe_rescue_recon_anon_leak(finding, review))
        # 已被匿名救援接管后，不应再触发通用救援改判
        self.assertFalse(_maybe_deepen_ignored(finding, review, "edusrc"))

    def test_chain_waf_after_anon_leak(self):
        finding = _finding(
            vuln_type="sql_injection",
            self_check=_sc({"recon_anon_leak": True, "recon_waf_present": True}),
            poc="curl x", raw_request="GET /a?id=1",
        )
        review = _ignored_review()
        # 带匿名锚点且证据残缺（无响应/样本）时，anon_leak 优先
        self.assertTrue(_maybe_rescue_recon_anon_leak(finding, review))
        self.assertEqual(review.verdict.value, "deepen")

    def test_has_some_evidence_helper(self):
        self.assertFalse(_has_some_evidence(_finding(poc="", raw_request="", raw_response="", evidence={})))
        self.assertTrue(_has_some_evidence(_finding(poc="curl x")))

    def test_reviewer_emits_anon_rescue_event(self):
        from unittest.mock import patch

        finding = _finding(self_check=_sc({"recon_anon_leak": True}))
        events = []
        reviewer = Reviewer(
            llm=object(),
            on_event=lambda kind, data: events.append((kind, data)),
            enable_reproduce=False,
        )
        with patch.object(reviewer, "_llm_review", return_value=_ignored_review()):
            review = reviewer.review(finding)
        self.assertEqual(review.verdict.value, "deepen")
        self.assertIn("review_auto_rescue_recon_anon_leak", [k for k, _ in events])
        self.assertIn("review_done", [k for k, _ in events])


def _sc(overrides: dict) -> dict:
    base = {
        "is_reflected_xss": False,
        "needs_admin_login": False,
        "needs_mitm": False,
        "is_pure_info_leak": False,
        "scanner_only_no_poc": False,
        "is_public_interface": False,
        "info_leak_hits_strict_list": False,
        "recon_anon_leak": False,
        "recon_waf_present": False,
    }
    base.update(overrides)
    return base


if __name__ == "__main__":
    unittest.main()