"""范围锚点提取：不能把引擎字段名当成域名白名单。"""
from __future__ import annotations

import unittest

from app.agents.scope_anchors import extract_enterprise_domains, extract_scope_anchors


class ScopeAnchorsTests(unittest.TestCase):
    def test_hunter_isp_query_has_no_domain_whitelist(self):
        q = 'ip.isp="中国教育网"&&header.status_code="200"'
        self.assertEqual(extract_scope_anchors(q)["domains"], [])
        self.assertEqual(extract_enterprise_domains(q), [])
        self.assertEqual(extract_scope_anchors(q)["cert_orgs"], [])

    def test_explicit_domain_field_is_kept(self):
        q = 'domain="example.edu.cn"'
        self.assertEqual(extract_scope_anchors(q)["domains"], ["example.edu.cn"])
        self.assertEqual(extract_enterprise_domains(q), ["example.edu.cn"])

    def test_bare_edu_domain_and_cert_org(self):
        q = 'example.edu.cn && cert.subject.org="某高校"'
        anchors = extract_scope_anchors(q)
        self.assertEqual(anchors["domains"], ["example.edu.cn"])
        self.assertEqual(anchors["cert_orgs"], ["某高校"])

    def test_domain_suffix_is_not_an_anchor(self):
        q = 'domain.suffix="edu.cn"'
        self.assertEqual(extract_scope_anchors(q)["domains"], [])
        self.assertEqual(extract_enterprise_domains(q), [])

    def test_engine_field_names_are_not_domains(self):
        q = 'web.title="登录" && ip.isp="中国教育网" && header.status_code="200"'
        self.assertEqual(extract_scope_anchors(q)["domains"], [])
        self.assertEqual(extract_enterprise_domains(q), [])


if __name__ == "__main__":
    unittest.main()
