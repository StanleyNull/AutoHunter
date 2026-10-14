"""覆盖两段式入库第一道闸门：Stage-0 确定性预筛 screen_submission。

原则是可单测、无副作用，且宁可少拦也不误杀真洞。
"""
import unittest

from app.tools import intake_screen


def _finding(**overrides) -> dict:
    base = {
        "vuln_type": "sql_injection",
        "title": "某接口存在 SQL 注入",
        "severity_claimed": "高危",
        "description": "参数未过滤导致报错注入",
        "steps": ["GET /id=1'"],
        "poc": "<script>alert(1)</script>",
        "raw_response": "<html>500 error</html>",
        "evidence": {"marker": "sql syntax error"},
    }
    base.update(overrides)
    return base


class TestIntakeScreen(unittest.TestCase):
    def test_accepts_full_finding_with_poc(self):
        ok, reason = intake_screen.screen_submission(_finding())
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_accepts_finding_with_description_and_steps(self):
        ok, reason = intake_screen.screen_submission(_finding(poc="", raw_response="", evidence={}))
        self.assertTrue(ok, reason)

    def test_rejects_fully_empty_shell(self):
        ok, reason = intake_screen.screen_submission({})
        self.assertFalse(ok)
        self.assertEqual(reason, intake_screen.EMPTY_SHELL)

    def test_rejects_no_vuln_negation_without_evidence(self):
        junk = _finding(poc="", raw_response="", steps=[], evidence={},
                        vuln_type="", title="未发现漏洞", description="尝试注入无响应")
        ok, reason = intake_screen.screen_submission(junk)
        self.assertFalse(ok)
        self.assertEqual(reason, intake_screen.NO_VULN_NEGATION)

    def test_keeps_negation_phrase_when_evidence_present(self):
        # 标题里带"未利用成功"措辞，但有完整 poc 实证 → 不误杀，放行给评审。
        ok, reason = intake_screen.screen_submission(_finding(title="布尔盲注未利用成功但存在"))    
        self.assertTrue(ok, reason)

    def test_rejects_non_dict(self):
        ok, reason = intake_screen.screen_submission(None)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()