"""引擎请求解析单测（不打真实 API）。"""
from __future__ import annotations

import unittest

from app.engines.censys import _hit_row, _is_legacy_key
from app.engines.quake import extract_quake_row
from app.engines.translator import looks_like_fofa_syntax, looks_like_native_syntax


class QuakeParseTests(unittest.TestCase):
    def test_prefers_http_title(self):
        row = extract_quake_row({
            "ip": "203.0.113.10",
            "port": 443,
            "hostname": "www.example.edu.cn",
            "domain": "example.edu.cn",
            "org": "Example Univ",
            "service": {
                "name": "http/ssl",
                "http": {"host": "www.example.edu.cn", "title": "统一身份认证"},
            },
        })
        self.assertEqual(row[0], "www.example.edu.cn")
        self.assertEqual(row[1], "203.0.113.10")
        self.assertEqual(row[2], "443")
        self.assertEqual(row[3], "统一身份认证")
        self.assertEqual(row[4], "example.edu.cn")
        self.assertEqual(row[5], "Example Univ")

    def test_falls_back_to_ip(self):
        row = extract_quake_row({"ip": "203.0.113.10", "port": 22, "service": {"name": "ssh"}})
        self.assertEqual(row[0], "203.0.113.10")
        self.assertEqual(row[3], "ssh")


class CensysParseTests(unittest.TestCase):
    def test_legacy_key_detection(self):
        self.assertTrue(_is_legacy_key("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:secretvalue"))
        self.assertFalse(_is_legacy_key("censys_pat_only_token"))
        self.assertFalse(_is_legacy_key(""))

    def test_platform_host_hit(self):
        row = _hit_row({
            "host_v1": {
                "resource": {
                    "ip": "203.0.113.10",
                    "dns": {"names": ["www.example.edu.cn"]},
                    "autonomous_system": {"organization": "Example Univ"},
                },
                "matched_services": [
                    {"port": 443, "http": {"response": {"html_title": "Login"}}},
                ],
            }
        })
        self.assertEqual(row[0], "www.example.edu.cn")
        self.assertEqual(row[2], "443")
        self.assertEqual(row[3], "Login")


class NativeWrapGuardTests(unittest.TestCase):
    def test_native_quake_not_treated_as_fofa(self):
        q = 'title:"统一身份认证" AND country:"China"'
        self.assertTrue(looks_like_native_syntax("quake", q))
        self.assertFalse(looks_like_fofa_syntax(q))

    def test_fofa_query_still_recognized(self):
        q = 'title="统一身份认证"'
        self.assertTrue(looks_like_fofa_syntax(q))
        self.assertFalse(looks_like_native_syntax("quake", q))


if __name__ == "__main__":
    unittest.main()
