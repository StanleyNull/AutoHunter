import unittest
from unittest import mock

from app.agents.reviewer import (
    _has_complete_evidence,
    _maybe_rescue_low_medium_evidenced,
    _maybe_rescue_recon_anon_leak,
    _maybe_rescue_recon_waf,
)
from app.agents.deepen import apply_deepen
from app.schemas import Finding, Review, ReviewVerdict, Severity


def _finding(severity="中危", **kwargs) -> Finding:
    base = {
        "vuln_type": "unauthorized_access",
        "title": "测试系统未授权线索",
        "severity_claimed": severity,
        "target_url": "https://example.edu.cn/api/test",
        "owner": "测试学校",
        "description": "无需登录可访问接口。",
        "steps": ["访问接口"],
        "poc": "curl https://example.edu.cn/api/test",
        "raw_request": "GET /api/test HTTP/1.1",
        "raw_response": "HTTP/1.1 200 OK\n\n{}",
        "evidence": {"notes": "接口真实存在"},
        "affected_scope": "待确认",
        "kill_chain": [{"method": "接口验证", "detail": "接口无需登录"}],
        "self_check": {
            "is_reflected_xss": False,
            "needs_admin_login": False,
            "needs_mitm": False,
            "is_pure_info_leak": False,
            "scanner_only_no_poc": False,
            "is_public_interface": False,
            "info_leak_hits_strict_list": False,
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
        "ignore_reasons": ["未实证下游危害"],
        "reviewer_notes": "不够 accepted。",
    }
    base.update(kwargs)
    return Review(**base)


class ReviewerLowMediumRescueTest(unittest.TestCase):
    def test_rescue_low_medium_with_evidence(self):
        f = _finding(severity="低危")
        r = _ignored_review()
        self.assertTrue(_maybe_rescue_low_medium_evidenced(f, r, "edusrc"))
        self.assertEqual(r.verdict, ReviewVerdict.deepen)
        self.assertIn("降过杀", r.reviewer_notes)

    def test_no_rescue_high_severity(self):
        f = _finding(severity="高危")
        r = _ignored_review()
        self.assertFalse(_maybe_rescue_low_medium_evidenced(f, r, "edusrc"))
        self.assertEqual(r.verdict, ReviewVerdict.ignored)

    def test_no_rescue_duplicate(self):
        f = _finding(severity="中危")
        r = _ignored_review(is_duplicate=True)
        self.assertFalse(_maybe_rescue_low_medium_evidenced(f, r, "edusrc"))
        self.assertEqual(r.verdict, ReviewVerdict.ignored)

    def test_no_rescue_out_of_scope(self):
        f = _finding(severity="中危")
        r = _ignored_review(in_scope=False)
        self.assertFalse(_maybe_rescue_low_medium_evidenced(f, r, "edusrc"))
        self.assertEqual(r.verdict, ReviewVerdict.ignored)

    def test_no_rescue_without_evidence(self):
        f = _finding(
            severity="中危",
            raw_request="",
            raw_response="",
            poc="",
            kill_chain=[],
        )
        r = _ignored_review()
        self.assertFalse(_maybe_rescue_low_medium_evidenced(f, r, "edusrc"))
        self.assertEqual(r.verdict, ReviewVerdict.ignored)

    def test_no_rescue_non_ignored(self):
        f = _finding(severity="中危")
        r = _ignored_review(verdict="accepted")
        self.assertFalse(_maybe_rescue_low_medium_evidenced(f, r, "edusrc"))
        self.assertEqual(r.verdict, ReviewVerdict.accepted)

    def test_has_complete_evidence_poc_only(self):
        f = _finding(raw_request="", raw_response="")
        self.assertTrue(_has_complete_evidence(f))

    def test_has_complete_evidence_kill_chain_only(self):
        f = _finding(raw_request="", raw_response="", poc="", kill_chain=[])
        self.assertFalse(_has_complete_evidence(f))
        f2 = _finding(
            raw_request="", raw_response="", poc="",
            kill_chain=[{"method": "x", "detail": ""}],
        )
        self.assertFalse(_has_complete_evidence(f2))
        f3 = _finding(
            raw_request="", raw_response="", poc="",
            kill_chain=[{"method": "x", "detail": "真实命中"}],
        )
        self.assertTrue(_has_complete_evidence(f3))


class ReconAnonLeakRescueTest(unittest.TestCase):
    """侦察实锤匿名泄露的端点，其低/中危线索被判 ignored 时应优先救援（降过杀增强）。"""

    def test_rescue_recon_anon_leak_low_medium(self):
        # 仅带残缺证据（有 raw_response 但无完整 req/resp 对、无 poc），但打 recon_anon_leak 标记。
        f = _finding(
            severity="中危",
            raw_request="",
            poc="",
            kill_chain=[],
            self_check={
                "is_reflected_xss": False, "needs_admin_login": False, "needs_mitm": False,
                "is_pure_info_leak": False, "scanner_only_no_poc": False,
                "is_public_interface": False, "info_leak_hits_strict_list": False,
                "recon_anon_leak": True,
            },
        )
        r = _ignored_review()
        self.assertTrue(_maybe_rescue_recon_anon_leak(f, r, "edusrc"))
        self.assertEqual(r.verdict, ReviewVerdict.deepen)
        self.assertIn("recon实锤", r.reviewer_notes)

    def test_no_rescue_recon_anon_leak_without_flag(self):
        # 同等证据但不带 recon_anon_leak 标记 → 走通用救援门槛（此处残缺证据不达标，不救援）。
        f = _finding(
            severity="中危",
            raw_request="", poc="", kill_chain=[],
            self_check={
                "is_reflected_xss": False, "needs_admin_login": False, "needs_mitm": False,
                "is_pure_info_leak": False, "scanner_only_no_poc": False,
                "is_public_interface": False, "info_leak_hits_strict_list": False,
                "recon_anon_leak": False,
            },
        )
        r = _ignored_review()
        self.assertFalse(_maybe_rescue_recon_anon_leak(f, r, "edusrc"))
        self.assertEqual(r.verdict, ReviewVerdict.ignored)

    def test_no_rescue_recon_anon_leak_high_severity(self):
        f = _finding(severity="高危", self_check={
            "is_reflected_xss": False, "needs_admin_login": False, "needs_mitm": False,
            "is_pure_info_leak": False, "scanner_only_no_poc": False,
            "is_public_interface": False, "info_leak_hits_strict_list": False,
            "recon_anon_leak": True,
        })
        r = _ignored_review()
        # 高/严重不在本救援范围内（走各自硬规则），不救援。
        self.assertFalse(_maybe_rescue_recon_anon_leak(f, r, "edusrc"))

    def test_no_rescue_recon_anon_leak_no_evidence_at_all(self):
        # 既无 recon 实锤外的任何证据，也不满足放宽门槛（无 raw_response/evidence）→ 不救援。
        f = _finding(
            severity="低危",
            raw_request="", raw_response="", poc="", kill_chain=[],
            evidence={"extracted_data_sample": None, "tool_output": None, "notes": ""},
            self_check={
                "is_reflected_xss": False, "needs_admin_login": False, "needs_mitm": False,
                "is_pure_info_leak": False, "scanner_only_no_poc": False,
                "is_public_interface": False, "info_leak_hits_strict_list": False,
                "recon_anon_leak": True,
            },
        )
        r = _ignored_review()
        self.assertFalse(_maybe_rescue_recon_anon_leak(f, r, "edusrc"))


class ReconWafRescueTest(unittest.TestCase):
    """侦察实锤目标前方有 WAF 时，其『证据残缺』的低/中危线索被判 ignored 应优先救援（降过杀增强）。"""

    def test_rescue_recon_waf_present_low_medium(self):
        # 仅带残缺证据（有 raw_response 但无完整 req/resp 对、无 poc），但打 recon_waf_present 标记。
        # 证据残缺很可能源于被 WAF 拦截，应放宽门槛救援带变形补证。
        f = _finding(
            severity="中危",
            raw_request="", poc="", kill_chain=[],
            self_check={
                "is_reflected_xss": False, "needs_admin_login": False, "needs_mitm": False,
                "is_pure_info_leak": False, "scanner_only_no_poc": False,
                "is_public_interface": False, "info_leak_hits_strict_list": False,
                "recon_waf_present": True,
            },
        )
        r = _ignored_review()
        self.assertTrue(_maybe_rescue_recon_waf(f, r, "edusrc"))
        self.assertEqual(r.verdict, ReviewVerdict.deepen)
        self.assertIn("recon实锤WAF", r.reviewer_notes)

    def test_no_rescue_recon_waf_without_flag(self):
        # 同等残缺证据但不带 recon_waf_present 标记 → 走通用救援门槛（此处不达标，不救援）。
        f = _finding(
            severity="中危",
            raw_request="", poc="", kill_chain=[],
            self_check={
                "is_reflected_xss": False, "needs_admin_login": False, "needs_mitm": False,
                "is_pure_info_leak": False, "scanner_only_no_poc": False,
                "is_public_interface": False, "info_leak_hits_strict_list": False,
                "recon_waf_present": False,
            },
        )
        r = _ignored_review()
        self.assertFalse(_maybe_rescue_recon_waf(f, r, "edusrc"))

    def test_no_rescue_recon_waf_high_severity(self):
        # 高/严重不在本救援范围内（走各自硬规则），即使有 WAF 标记也不救援。
        f = _finding(severity="高危", self_check={
            "is_reflected_xss": False, "needs_admin_login": False, "needs_mitm": False,
            "is_pure_info_leak": False, "scanner_only_no_poc": False,
            "is_public_interface": False, "info_leak_hits_strict_list": False,
            "recon_waf_present": True,
        })
        r = _ignored_review()
        self.assertFalse(_maybe_rescue_recon_waf(f, r, "edusrc"))

    def test_no_rescue_recon_waf_no_evidence_at_all(self):
        # 完全无任何证据（无 raw_response/evidence/notes）→ 即便有 WAF 标记也不救援（避免滥用）。
        f = _finding(
            severity="低危",
            raw_request="", raw_response="", poc="", kill_chain=[],
            evidence={"extracted_data_sample": None, "tool_output": None, "notes": ""},
            self_check={
                "is_reflected_xss": False, "needs_admin_login": False, "needs_mitm": False,
                "is_pure_info_leak": False, "scanner_only_no_poc": False,
                "is_public_interface": False, "info_leak_hits_strict_list": False,
                "recon_waf_present": True,
            },
        )
        r = _ignored_review()
        self.assertFalse(_maybe_rescue_recon_waf(f, r, "edusrc"))


class DeepenReDispatchTest(unittest.TestCase):
    """降过杀端到端闭环：救援为 deepen 的洞必须真被重新派 worker 补证，而非只在状态间挪动。"""

    def test_apply_deepen_redispatch_target_not_just_archive(self):
        # 被救援的原 finding（done 态残留）与 target：apply_deepen 必须把 target 重新拉回队列队首，
        # 让派发器 _pop_queued 能拾取并重派 worker，而不是把 finding 直接归档了事。
        from types import SimpleNamespace
        finding = SimpleNamespace(
            id="abc12345deadbeef", status="pending", dedup_key="k",
            vuln_type="idor", title="测试系统越权线索", description="原始线索摘要",
        )
        tgt = mock.MagicMock()
        tgt.deepen_count = 0
        tgt.deepen_context = None
        tgt.status = "done"
        tgt.assigned_worker = "w1"
        tgt.retry_count = 1
        tgt.verdict = "found"
        tgt.priority_score = 10.0
        tgt.priority_reason = ""

        ok, suffix = apply_deepen(None, finding, tgt, directive="专攻越权打穿利用链", source="ai", cap=4)

        self.assertTrue(ok)
        # 原 finding 让位（不再入队/不参与 dedup），但 target 被重新入队并清掉分配标记 → 派发器会重派。
        self.assertEqual(finding.status, "superseded")
        self.assertEqual(tgt.status, "queued")
        self.assertEqual(tgt.assigned_worker, "")
        self.assertEqual(tgt.retry_count, 0)
        self.assertEqual(tgt.verdict, "")
        self.assertGreater(tgt.priority_score, 10.0)  # 拉到队首，优先补证
        # 定向指令随 deepen_context 带下去，worker._deepen_brief 会消费它做补证而非重挖。
        self.assertIsNotNone(tgt.deepen_context)
        self.assertEqual(tgt.deepen_context["directive"], "专攻越权打穿利用链")
        self.assertEqual(tgt.deepen_context["from_finding_id"], "abc12345deadbeef")
        self.assertIn("打回深挖", suffix)


if __name__ == "__main__":
    unittest.main()
