"""gov 域名跳过单测。"""
from __future__ import annotations

import unittest

from app.agents.prefilter import is_gov_host, should_skip


class GovSkipTests(unittest.TestCase):
    def test_gov_positive(self):
        for h in (
            "www.gov.cn",
            "gjzwfw.gov.cn",
            "foo.gov",
            "a.b.gov.uk",
            "https://service.gov.au/path",
            "portal.gov.ac.uk",
        ):
            self.assertTrue(is_gov_host(h), h)

    def test_gov_negative(self):
        for h in (
            "government.com",
            "mygov.edu.cn",
            "gov.example.com",
            "example.com",
            "1.2.3.4",
            "school.edu.cn",
        ):
            self.assertFalse(is_gov_host(h), h)

    def test_should_skip_gov_no_probe(self):
        skip, reason = should_skip("www.gov.cn", "https://www.gov.cn/")
        self.assertTrue(skip)
        self.assertIn(".gov", reason)


if __name__ == "__main__":
    unittest.main()
