"""敏感域名跳过单测。"""
from __future__ import annotations

import os
import unittest

from app.agents.prefilter import is_gov_host, is_sensitive_host, should_skip


class SensitiveSkipTests(unittest.TestCase):
    def test_gov_positive(self):
        for h in (
            "www.gov.cn",
            "gjzwfw.gov.cn",
            "foo.gov",
            "a.b.gov.uk",
            "https://service.gov.au/path",
        ):
            self.assertTrue(is_sensitive_host(h), h)
            self.assertTrue(is_gov_host(h), h)

    def test_mil_positive(self):
        for h in ("www.mil.cn", "portal.mil", "a.unit.mil.uk"):
            self.assertTrue(is_sensitive_host(h), h)

    def test_keyword_positive(self):
        for h in (
            "gongan.example.com",
            "xxjiancha.org.cn",
            "chinamil.com.cn",
            "某市公安局.example.com",
        ):
            self.assertTrue(is_sensitive_host(h), h)

    def test_negative(self):
        for h in (
            "government.com",
            "mygov.edu.cn",
            "gov.example.com",
            "example.com",
            "1.2.3.4",
            "school.edu.cn",
            "court.student.edu.cn",  # 不含敏感关键词子串「法院」英文 court 不在列表
        ):
            self.assertFalse(is_sensitive_host(h), h)

    def test_extra_env_suffix(self):
        old = os.environ.get("AUTOHUNTER_SENSITIVE_HOSTS")
        try:
            os.environ["AUTOHUNTER_SENSITIVE_HOSTS"] = "sensitive.test,blocked.example"
            self.assertTrue(is_sensitive_host("a.sensitive.test"))
            self.assertTrue(is_sensitive_host("blocked.example"))
            self.assertFalse(is_sensitive_host("safe.example.com"))
        finally:
            if old is None:
                os.environ.pop("AUTOHUNTER_SENSITIVE_HOSTS", None)
            else:
                os.environ["AUTOHUNTER_SENSITIVE_HOSTS"] = old

    def test_should_skip_no_probe(self):
        skip, reason = should_skip("www.gov.cn", "https://www.gov.cn/")
        self.assertTrue(skip)
        self.assertIn("敏感", reason)


if __name__ == "__main__":
    unittest.main()
