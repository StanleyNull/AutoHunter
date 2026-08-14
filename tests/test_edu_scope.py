import unittest

from app.agents.edu_scope import edu_bombing_block_reason, looks_like_edu_bombing
from app.agents.reviewer import _maybe_deepen_ignored, _maybe_reject_edu_bombing
from app.schemas import Finding, Review, ReviewVerdict


def _finding(**kwargs) -> Finding:
    base = {
        "vuln_type": "business_logic",
        "title": "测试系统接口",
        "severity_claimed": "中危",
        "target_url": "https://example.edu.cn/api/sms/send",
        "owner": "测试学校",
        "description": "接口可调用。",
        "steps": ["访问接口"],
        "poc": "curl https://example.edu.cn/api/sms/send",
        "raw_request": "POST /api/sms/send HTTP/1.1",
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


def _review(**kwargs) -> Review:
    base = {
        "verdict": "accepted",
        "confidence": "likely",
        "score": 6.0,
        "in_scope": True,
        "is_duplicate": False,
        "severity_final": "中危",
        "ignore_reasons": [],
        "reviewer_notes": "LLM 误收。",
    }
    base.update(kwargs)
    return Review(**base)


class EduBombingScopeTest(unittest.TestCase):
    def test_sms_bomb_is_out_of_scope(self):
        finding = _finding(
            title="短信接口无频率限制可短信轰炸",
            description="sendSms 无验证码、无频率限制，可对任意手机号连发验证码。",
        )
        self.assertTrue(looks_like_edu_bombing(finding))
        self.assertTrue(edu_bombing_block_reason(finding))

    def test_email_bomb_is_out_of_scope(self):
        finding = _finding(
            title="邮箱轰炸：找回密码接口可刷邮件",
            target_url="https://example.edu.cn/api/mail/send",
            description="无频率限制可对任意邮箱发送重置邮件。",
        )
        self.assertTrue(looks_like_edu_bombing(finding))

    def test_rate_limit_sms_without_bomb_word(self):
        finding = _finding(
            title="发送短信接口无频率限制",
            description="可对任意手机号发送验证码，没有频率限制。",
        )
        self.assertTrue(looks_like_edu_bombing(finding))

    def test_otp_echo_is_not_bombing(self):
        finding = _finding(
            title="短信验证码明文回显可任意用户登录",
            description="发送短信验证码接口把 OTP 明文回显在 HTTP 响应里，可读任意手机号验证码并登录。",
            raw_response='{"code":"832911","msg":"ok"}',
            evidence={"notes": "响应回显验证码 832911"},
        )
        self.assertFalse(looks_like_edu_bombing(finding))
        self.assertEqual(edu_bombing_block_reason(finding), "")

    def test_reviewer_overrides_accepted_bombing(self):
        finding = _finding(
            title="短信轰炸可刷验证码",
            description="短信接口无频率限制，可连发。",
        )
        review = _review()
        self.assertTrue(_maybe_reject_edu_bombing(finding, review, "edusrc"))
        self.assertEqual(review.verdict, ReviewVerdict.ignored)
        self.assertIn("EduSRC不收短信/邮箱轰炸", review.ignore_reasons)

    def test_enterprise_not_auto_rejected(self):
        finding = _finding(
            title="短信轰炸可刷验证码",
            description="短信接口无频率限制，可连发。",
        )
        review = _review()
        self.assertFalse(_maybe_reject_edu_bombing(finding, review, "enterprise"))
        self.assertEqual(review.verdict, ReviewVerdict.accepted)

    def test_bombing_stays_ignored_not_deepened(self):
        finding = _finding(
            title="未授权短信轰炸",
            description="无需登录即可短信轰炸任意手机号。",
        )
        review = _review(verdict="ignored", ignore_reasons=["短信轰炸价值低"])
        self.assertFalse(_maybe_deepen_ignored(finding, review, "edusrc"))
        self.assertEqual(review.verdict.value, "ignored")


if __name__ == "__main__":
    unittest.main()
