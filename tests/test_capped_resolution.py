"""黑洞 DNS 防护：解析结果截断，不打真实网络。"""
from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

from app.agents.prefilter import capped_resolution, _capped_getaddrinfo


def _fake_addr(family=socket.AF_INET, n=5):
    # (family, type, proto, canonname, sockaddr)
    return [(family, socket.SOCK_STREAM, 6, "", ("203.0.113.%d" % i, 80)) for i in range(1, n + 1)]


class CappedResolutionTests(unittest.TestCase):
    def test_ipv4_results_are_capped_to_two(self):
        with patch("app.agents.prefilter._ORIG_GETADDRINFO", return_value=_fake_addr(n=5)):
            res = _capped_getaddrinfo("example.com", 80)
        self.assertEqual(len(res), 2)

    def test_ipv6_only_falls_back_then_caps(self):
        v6 = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 80, 0, 0))] * 4

        def _orig(host, port, family=0, type=0, proto=0, flags=0):
            if family == socket.AF_INET:
                raise OSError("no A record")
            return v6

        with patch("app.agents.prefilter._ORIG_GETADDRINFO", side_effect=_orig):
            res = _capped_getaddrinfo("ipv6-only.example", 80)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0][0], socket.AF_INET6)

    def test_context_manager_patches_and_restores_getaddrinfo(self):
        original = socket.getaddrinfo
        with capped_resolution():
            self.assertIsNot(socket.getaddrinfo, original)
        self.assertIs(socket.getaddrinfo, original)


if __name__ == "__main__":
    unittest.main()
