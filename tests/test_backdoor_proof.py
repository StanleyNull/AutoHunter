import unittest

from app.agents.backdoor_proof import looks_like_weak_backdoor, weak_backdoor_block_reason
from app.agents.reviewer import _maybe_reject_weak_backdoor
from app.schemas import Finding, Review, ReviewVerdict


def _finding(**kwargs) -> Finding:
    base = {
        "vuln_type": "unauthorized_access",
        "title": "测试系统接口",
        "severity_claimed": "中危",
        "target_url": "https://example.edu.cn/",
        "owner": "测试学校",
        "description": "页面可访问。",
        "steps": ["打开首页"],
        "poc": "curl https://example.edu.cn/",
        "raw_request": "GET / HTTP/1.1",
        "raw_response": "HTTP/1.1 200 OK\n\n<html><body>学校新闻</body></html>",
        "evidence": {"notes": "首页正常"},
        "affected_scope": "待确认",
        "kill_chain": [{"method": "打开首页", "detail": "页面可访问"}],
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
        "score": 8.0,
        "in_scope": True,
        "is_duplicate": False,
        "severity_final": "高危",
        "ignore_reasons": [],
        "reviewer_notes": "LLM 误收被黑。",
    }
    base.update(kwargs)
    return Review(**base)


class WeakBackdoorProofTest(unittest.TestCase):
    def test_image_host_is_not_compromised(self):
        finding = _finding(
            vuln_type="backdoor_compromised",
            title="疑似被黑：页面使用外部图床",
            description="新闻配图 src 指向 sm.ms 图床，疑似被挂马。",
            raw_response='<img src="https://i.loli.net/2024/a.jpg">学校新闻标题',
        )
        self.assertTrue(looks_like_weak_backdoor(finding))
        self.assertTrue(weak_backdoor_block_reason(finding))

    def test_cdn_assets_are_not_compromised(self):
        finding = _finding(
            vuln_type="backdoor_compromised",
            title="页面引用 jsdelivr CDN 疑似被黑",
            description="script 指向 cdn.jsdelivr.net。",
        )
        self.assertTrue(looks_like_weak_backdoor(finding))

    def test_gambling_homepage_is_strong(self):
        finding = _finding(
            vuln_type="backdoor_compromised",
            title="高校子域首页被替换成赌博页",
            description="首页正文变成印尼赌博 KentangBet Slot Thailand，原站内容消失。",
            raw_response="<html><title>KentangBet Slot</title><body>赌博 彩票 casino</body></html>",
        )
        self.assertFalse(looks_like_weak_backdoor(finding))
        self.assertEqual(weak_backdoor_block_reason(finding), "")

    def test_webshell_is_strong(self):
        finding = _finding(
            vuln_type="backdoor_compromised",
            title="发现可执行 webshell",
            description="访问 /cmd.php 返回命令执行结果。",
            raw_response="uid=33(www-data) webshell",
        )
        self.assertFalse(looks_like_weak_backdoor(finding))

    def test_idor_not_treated_as_backdoor(self):
        finding = _finding(
            title="水平越权查看他人成绩",
            description="改 id 可看他人数据。",
        )
        self.assertFalse(looks_like_weak_backdoor(finding))

    def test_reviewer_overrides_image_host(self):
        finding = _finding(
            vuln_type="backdoor_compromised",
            title="疑似被黑使用外部图床",
            description="图片存在图床。",
        )
        review = _review()
        self.assertTrue(_maybe_reject_weak_backdoor(finding, review))
        self.assertEqual(review.verdict, ReviewVerdict.ignored)
        self.assertIn("图床/CDN不是被黑", review.ignore_reasons)


if __name__ == "__main__":
    unittest.main()
