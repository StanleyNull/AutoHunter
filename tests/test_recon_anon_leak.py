"""匿名泄露扫描：anon_open 端点敏感数据识别 → target_meta['anon_leak_leads'] → 首轮注入。

覆盖 worker.scan_anon_leaks / _recon_leads_block，以及 anon_leak_scanner 的正文特征识别。
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from app.agents.worker import Worker
from app.tools.anon_leak_scanner import has_sensitive_leak, scan_body


def _worker(target_meta=None) -> Worker:
    w = Worker.__new__(Worker)
    w.target_meta = {"anon_open": []} if target_meta is None else target_meta
    w.executor = None
    return w


class _Ex:
    """executor 桩：把 http_request 挂成实例属性，避免类方法绑定自动注入 self。"""

    def __init__(self, body_provider=lambda **kw: {"ok": False}):
        self.http_request = body_provider


class AnonLeakScannerTest(unittest.TestCase):
    def test_scans_token_bearer_header(self):
        self.assertIn("令牌/Bearer", scan_body('{"authorization":"Bearer eyJhbGciOiJIUzI1NiJ9.abc"}'))

    def test_scans_password_key(self):
        self.assertIn("密钥/口令", scan_body('"password":"P@ssw0rd123"'))

    def test_scans_private_key_block(self):
        self.assertIn("私钥", scan_body("-----BEGIN RSA PRIVATE KEY-----\nMIIxxx\n-----END-----"))

    def test_scans_aws_key(self):
        self.assertIn("AWS 凭证", scan_body("aws_access_key_id=AKIAIOSFODNN7EXAMPLE"))

    def test_scans_jdbc_connection(self):
        self.assertIn("数据库连接串", scan_body("jdbc:mysql://10.0.0.1:3306/appdb?user=root"))

    def test_no_leak_returns_empty(self):
        self.assertEqual(scan_body("<html>欢迎访问学校官网</html>"), [])
        self.assertFalse(has_sensitive_leak("普通页面无敏感字段"))

    def test_empty_body(self):
        self.assertEqual(scan_body(""), [])
        self.assertFalse(has_sensitive_leak(None))


class WorkerAnonLeakScanTest(unittest.TestCase):
    def test_scan_anon_leaks_writes_leads_and_flag(self):
        w = _worker({
            "anon_open": [
                {"url": "https://example.edu.cn/api/export"},
                {"url": "https://example.edu.cn/api/status"},
            ]
        })
        w.executor = _Ex(lambda **kw: {
            "ok": True,
            "status_code": 200,
            "body": "export" if kw["url"].endswith("export") else "status" if kw["url"].endswith("status") else "",
        })

        def fake_scan(body):
            return ["AWS 凭证"] if "export" in str(body) else []

        with patch("app.agents.worker._leak_scan_body", side_effect=fake_scan):
            leads = w.scan_anon_leaks()
        self.assertEqual(len(leads), 1)
        self.assertEqual(w.target_meta["recon_anon_leak"], True)
        self.assertEqual(leads[0]["url"], "https://example.edu.cn/api/export")

    def test_scan_anon_leaks_no_hits_writes_empty_and_no_flag(self):
        w = _worker({"anon_open": [{"url": "https://example.edu.cn/api/status"}]})
        w.executor = _Ex(lambda **kw: {"ok": True, "status_code": 200, "body": "<html>x</html>"})
        with patch("app.agents.worker._leak_scan_body", return_value=[]):
            leads = w.scan_anon_leaks()
        self.assertEqual(leads, [])
        self.assertEqual(w.target_meta["anon_leak_leads"], [])
        self.assertNotIn("recon_anon_leak", w.target_meta)

    def test_scan_anon_leaks_ignores_failed_requests(self):
        w = _worker({"anon_open": [{"url": "https://example.edu.cn/api/x"}]})
        w.executor = _Ex()
        leads = w.scan_anon_leaks()
        self.assertEqual(leads, [])
        self.assertNotIn("recon_anon_leak", w.target_meta)

    def test_recon_leads_block_injects_leak_line(self):
        w = _worker({
            "anon_leak_leads": [
                {"url": "https://example.edu.cn/api/export", "hits": ["AWS 凭证"]}
            ]
        })
        block = w._recon_leads_block()
        self.assertIn("AWS 凭证", block)
        self.assertIn("匿名泄露线索", block)

    def test_recon_leads_block_empty_when_no_leads(self):
        w = _worker({"anon_leak_leads": []})
        self.assertEqual(w._recon_leads_block(), "")


if __name__ == "__main__":
    unittest.main()