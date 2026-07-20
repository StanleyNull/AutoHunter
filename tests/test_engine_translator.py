"""引擎 FOFA→各引擎语法翻译单测。"""
from __future__ import annotations

import unittest

from app.engines.translator import (
    fofa_to_censys,
    fofa_to_hunter,
    fofa_to_quake,
    fofa_to_shodan,
    fofa_to_zoomeye,
    parse_fofa_query,
    translate_fofa_query,
)


class TranslatorTests(unittest.TestCase):
    def test_parse_preserves_or(self):
        tokens, joins = parse_fofa_query('title="A" || title="B" && domain=".edu.cn"')
        self.assertEqual(len(tokens), 3)
        self.assertEqual(joins, ["||", "&&"])

    def test_quake_domain_and_and(self):
        q = fofa_to_quake('title="统一身份认证" && domain=".edu.cn"')
        self.assertIn('title:"统一身份认证"', q)
        self.assertIn('domain:"edu.cn"', q)
        self.assertIn(" AND ", q)
        self.assertNotIn("hostname", q)

    def test_quake_or(self):
        q = fofa_to_quake('title="A" || title="B"')
        self.assertIn(" OR ", q)

    def test_hunter_fields(self):
        q = fofa_to_hunter('title="login" && domain="example.com" && port="443"')
        self.assertIn('web.title="login"', q)
        self.assertIn('domain.suffix="example.com"', q)
        self.assertIn('port="443"', q)
        self.assertIn("&&", q)

    def test_domain_dot_stripped(self):
        self.assertIn('domain.suffix="edu.cn"', fofa_to_hunter('domain=".edu.cn"'))
        self.assertIn('hostname:"edu.cn"', fofa_to_shodan('domain=".edu.cn"'))
        self.assertIn('domain="edu.cn"', fofa_to_zoomeye('domain=".edu.cn"'))

    def test_zoomeye_fofa_like(self):
        q = fofa_to_zoomeye('title="cisco vpn" && country="CN"')
        self.assertEqual(q, 'title="cisco vpn" && country="CN"')
        q2 = fofa_to_zoomeye('host="www.example.com"')
        self.assertIn('hostname="www.example.com"', q2)

    def test_shodan(self):
        q = fofa_to_shodan('title="nginx" && port="443" && country="CN"')
        self.assertIn("http.title:", q)
        self.assertIn("port:443", q)
        self.assertIn("country:CN", q)

    def test_censys(self):
        q = fofa_to_censys('title="Login" && port="80"')
        self.assertIn("services.http.response.html_title", q)
        self.assertIn("services.port:80", q)
        self.assertIn(" and ", q)

    def test_passthrough_native(self):
        native = 'title:"already quake" AND port:80'
        self.assertEqual(translate_fofa_query(native, "quake"), native)

    def test_fofa_unchanged(self):
        q = 'title="x" && domain=".edu.cn"'
        self.assertEqual(translate_fofa_query(q, "fofa"), q)

    def test_native_passthrough_quake(self):
        native = 'title:"登录" AND domain:"edu.cn" AND port:443'
        self.assertEqual(translate_fofa_query(native, "quake"), native)

    def test_native_passthrough_hunter(self):
        native = 'web.title="登录" && domain.suffix="edu.cn"'
        self.assertEqual(translate_fofa_query(native, "hunter"), native)

    def test_native_passthrough_shodan(self):
        native = 'http.title:"nginx" port:443 country:CN'
        self.assertEqual(translate_fofa_query(native, "shodan"), native)

    def test_native_passthrough_censys(self):
        native = 'services.http.response.html_title:"Login" and services.port:443'
        self.assertEqual(translate_fofa_query(native, "censys"), native)

    def test_native_passthrough_zoomeye(self):
        native = 'hostname="www.example.com" && title="login"'
        self.assertEqual(translate_fofa_query(native, "zoomeye"), native)

    def test_fofa_still_translates_on_quake(self):
        q = 'title="登录" && domain=".edu.cn"'
        out = translate_fofa_query(q, "quake")
        self.assertIn('title:"登录"', out)
        self.assertIn('domain:"edu.cn"', out)
        self.assertNotEqual(out, q)


if __name__ == "__main__":
    unittest.main()
