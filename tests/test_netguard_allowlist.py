"""netguard 出站白名单：放行被代理 fake-ip 解析到 198.18.0.0/15 的公网域名。"""
from __future__ import annotations

import os
import socket
import unittest
from unittest.mock import patch

from app.tools.netguard import SsrfBlocked, assert_safe_outbound_url

_URL = "https://opencode.ai/zen/go/v1/models"


def _fake_getaddrinfo(ip: str):
    def _inner(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port)),
        ]

    return _inner


class OutboundAllowlistTest(unittest.TestCase):
    def setUp(self):
        os.environ.pop("OUTBOUND_ALLOWED_HOSTS", None)
        os.environ.pop("FOFA_ALLOWED_HOSTS", None)

    def tearDown(self):
        os.environ.pop("OUTBOUND_ALLOWED_HOSTS", None)
        os.environ.pop("FOFA_ALLOWED_HOSTS", None)

    def test_fake_ip_blocked_without_allowlist(self):
        with patch("app.tools.netguard.socket.getaddrinfo", _fake_getaddrinfo("198.18.0.9")):
            with self.assertRaises(SsrfBlocked):
                assert_safe_outbound_url(_URL)

    def test_fake_ip_allowed_by_env(self):
        os.environ["OUTBOUND_ALLOWED_HOSTS"] = "opencode.ai"
        with patch("app.tools.netguard.socket.getaddrinfo", _fake_getaddrinfo("198.18.0.9")):
            self.assertEqual(assert_safe_outbound_url(_URL), _URL)

    def test_entries_tolerate_scheme_port_case_and_spaces(self):
        os.environ["OUTBOUND_ALLOWED_HOSTS"] = " HTTPS://OpenCode.AI:443 , api.deepseek.com "
        with patch("app.tools.netguard.socket.getaddrinfo", _fake_getaddrinfo("198.18.0.10")):
            self.assertEqual(assert_safe_outbound_url(_URL), _URL)

    def test_unlisted_host_still_blocked(self):
        os.environ["OUTBOUND_ALLOWED_HOSTS"] = "opencode.ai"
        with patch("app.tools.netguard.socket.getaddrinfo", _fake_getaddrinfo("198.18.0.9")):
            with self.assertRaises(SsrfBlocked):
                assert_safe_outbound_url("https://api.deepseek.com/v1/models")

    def test_exact_match_only_no_suffix_hijack(self):
        # opencode.ai 放行，不代表 evil-opencode.ai 也放行
        os.environ["OUTBOUND_ALLOWED_HOSTS"] = "opencode.ai"
        with patch("app.tools.netguard.socket.getaddrinfo", _fake_getaddrinfo("10.0.0.5")):
            with self.assertRaises(SsrfBlocked):
                assert_safe_outbound_url("https://evil-opencode.ai/v1/models")

    def test_private_target_allowed_only_when_listed(self):
        with patch("app.tools.netguard.socket.getaddrinfo", _fake_getaddrinfo("10.0.0.5")):
            with self.assertRaises(SsrfBlocked):
                assert_safe_outbound_url("http://fofa.internal/api")
            os.environ["OUTBOUND_ALLOWED_HOSTS"] = "fofa.internal"
            self.assertEqual(
                assert_safe_outbound_url("http://fofa.internal/api"),
                "http://fofa.internal/api",
            )

    def test_metadata_host_blocked_even_if_allowlisted(self):
        os.environ["OUTBOUND_ALLOWED_HOSTS"] = "169.254.169.254,metadata.google.internal"
        for url in (
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ):
            with self.assertRaises(SsrfBlocked):
                assert_safe_outbound_url(url)

    def test_fofa_allowed_hosts_env_still_works(self):
        os.environ["FOFA_ALLOWED_HOSTS"] = "fofa.internal"
        with patch("app.tools.netguard.socket.getaddrinfo", _fake_getaddrinfo("192.168.1.9")):
            self.assertEqual(
                assert_safe_outbound_url("http://fofa.internal/api", allow_extra_hosts=set()),
                "http://fofa.internal/api",
            )

    def test_invalid_scheme_and_empty_url_still_rejected(self):
        os.environ["OUTBOUND_ALLOWED_HOSTS"] = "opencode.ai"
        with self.assertRaises(SsrfBlocked):
            assert_safe_outbound_url("file:///etc/passwd")
        with self.assertRaises(SsrfBlocked):
            assert_safe_outbound_url("")


if __name__ == "__main__":
    unittest.main()
