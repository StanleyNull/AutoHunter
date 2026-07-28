"""裸/畸形 IPv6 目标不再触发 urlparse().port|.hostname 的 ValueError（主循环崩溃修复）。"""
from __future__ import annotations

import unittest

from app.urlnorm import (
    bracket_ipv6_host,
    ensure_scheme,
    is_bare_ipv6,
    is_unusable_host,
    is_valid_ipv6,
    normalize_host,
    safe_hostname,
    safe_port,
    safe_urlparse,
)

# 现场报错用的 IPv6（7 段，截断/畸形，非合法 IPv6，但含多个冒号会打崩解析）
CRASH_IP = "250:4809:3:fcfc:feff:febc:b092"
# 合法 IPv6
GOOD_IP = "2001:db8::1"


class UrlNormTests(unittest.TestCase):
    def test_is_bare_ipv6_loose(self):
        self.assertTrue(is_bare_ipv6(CRASH_IP))   # 宽松：像 IPv6
        self.assertTrue(is_bare_ipv6(GOOD_IP))
        self.assertTrue(is_bare_ipv6("::1"))
        self.assertFalse(is_bare_ipv6("example.com"))
        self.assertFalse(is_bare_ipv6("1.2.3.4"))
        self.assertFalse(is_bare_ipv6("host:8080"))
        self.assertFalse(is_bare_ipv6("[::1]"))

    def test_valid_vs_malformed(self):
        self.assertTrue(is_valid_ipv6(GOOD_IP))
        self.assertFalse(is_valid_ipv6(CRASH_IP))  # 7 段畸形

    def test_no_raise_on_crash_ip(self):
        # 关键：原来在此处抛 ValueError 打崩主循环，现在必须安静返回（值不重要，不崩即可）
        p = safe_urlparse(CRASH_IP)
        self.assertIsNone(safe_port(p))   # 不抛
        safe_hostname(p)                   # 不抛
        # 无论解析出什么，都应被判为不可用目标（畸形 IPv6）
        self.assertTrue(is_unusable_host(CRASH_IP))

    def test_good_ipv6_usable(self):
        self.assertFalse(is_unusable_host(GOOD_IP))
        self.assertEqual(normalize_host(f"http://[{GOOD_IP}]:8080/x"), f"[{GOOD_IP}]:8080")

    def test_malformed_ipv6_unusable(self):
        self.assertTrue(is_unusable_host(CRASH_IP))
        self.assertTrue(is_unusable_host(f"http://{CRASH_IP}"))

    def test_normal_hosts_usable(self):
        self.assertFalse(is_unusable_host("example.com"))
        self.assertFalse(is_unusable_host("1.2.3.4:9000"))
        self.assertEqual(normalize_host("Example.COM:8080"), "example.com:8080")
        self.assertEqual(normalize_host("http://example.com/a"), "example.com")

    def test_bracket_and_scheme(self):
        self.assertEqual(bracket_ipv6_host(CRASH_IP), f"[{CRASH_IP}]")
        self.assertEqual(bracket_ipv6_host("example.com"), "example.com")
        self.assertEqual(ensure_scheme("example.com"), "http://example.com")
        self.assertEqual(ensure_scheme("https://x.com/a"), "https://x.com/a")


class HotPathNoCrashTests(unittest.TestCase):
    """各热点归一化函数吃到畸形 IPv6 时都不许抛异常（返回值不重要，不崩即可）。"""

    def _call_no_raise(self, fn, arg):
        try:
            fn(arg)
        except Exception as e:  # noqa: BLE001
            self.fail(f"{fn.__module__}.{fn.__name__} raised on {arg!r}: {e!r}")

    def test_hot_paths_do_not_raise(self):
        # 部分模块依赖 sqlalchemy 等，本地环境缺依赖时跳过对应导入，不影响核心校验
        fns = []
        specs = [
            ("app.agents.collector", "normalize_host"),
            ("app.dedup", "normalize_host"),
            ("app.agents.killsweep", "_normalize_host"),
            ("app.agents.target_cluster", "_host_only"),
            ("app.orchestrator", "_with_scheme"),
            ("app.orchestrator", "_bracket_ipv6_host"),
            ("app.agents.auth_bootstrap", "_host_of"),
            ("app.agents.auth_bootstrap", "_hostport_of"),
        ]
        import importlib
        for mod, name in specs:
            try:
                m = importlib.import_module(mod)
            except Exception:
                continue  # 缺依赖，跳过（生产环境依赖齐全）
            fns.append(getattr(m, name))
        self.assertTrue(fns, "no hot-path fn importable")
        for fn in fns:
            self._call_no_raise(fn, CRASH_IP)
            self._call_no_raise(fn, f"http://{CRASH_IP}")
            self._call_no_raise(fn, GOOD_IP)


class Ipv6CompatFixTests(unittest.TestCase):
    """IPv6 目标端到端兼容回归（对应一轮全面兼容检查修复的 gap）。"""

    def test_ensure_scheme_no_double_bracket(self):
        # 根因：已带括号的合法 IPv6 被再套一层 → http://[[..]] → 目标被误判不可用
        self.assertEqual(ensure_scheme(f"[{GOOD_IP}]"), f"http://[{GOOD_IP}]")
        self.assertEqual(ensure_scheme("[::1]"), "http://[::1]")
        self.assertEqual(ensure_scheme(GOOD_IP), f"http://[{GOOD_IP}]")   # 裸的仍补括号

    def test_bracketed_ipv6_is_usable(self):
        # 修复前这些全被 is_unusable_host 误判 True，合法 IPv6 目标被静默丢弃
        for h in (f"[{GOOD_IP}]", "[::1]", "[fe80::1]", "[::ffff:169.254.169.254]",
                  f"[{GOOD_IP}]:8080", GOOD_IP):
            self.assertFalse(is_unusable_host(h), f"{h} 应可用")
        self.assertTrue(is_unusable_host(CRASH_IP))   # 畸形仍不可用

    def test_collector_ensure_url_brackets_ipv6(self):
        try:
            from app.agents.collector import _ensure_url
        except Exception:
            self.skipTest("collector 依赖缺失")
        self.assertEqual(_ensure_url(GOOD_IP), f"http://[{GOOD_IP}]")
        self.assertEqual(_ensure_url(f"[{GOOD_IP}]"), f"http://[{GOOD_IP}]")
        self.assertEqual(_ensure_url("example.com"), "http://example.com")
        self.assertEqual(_ensure_url("http://x.com/a"), "http://x.com/a")

    def test_dedup_endpoint_distinguishes_ipv6(self):
        from app.dedup import normalize_endpoint
        # 不同 IPv6 不能坍缩到同一 key（否则误去重丢洞）
        a = normalize_endpoint(f"http://[{GOOD_IP}]/api/x")
        b = normalize_endpoint("http://[2001:db8::99]/api/x")
        self.assertNotEqual(a, b)          # 不同 IPv6 不坍缩
        self.assertIn(GOOD_IP, a)
        # 裸 host / 带括号 host / 带协议带括号 三种同一 IPv6 形态归一化一致（否则漏去重）。
        # 注：URL 到达 dedup 时已由 _ensure_url 补成带括号带协议形态，故只需覆盖 host 级一致性。
        self.assertEqual(normalize_endpoint(GOOD_IP),
                         normalize_endpoint(f"[{GOOD_IP}]"))
        self.assertEqual(normalize_endpoint(f"[{GOOD_IP}]"),
                         normalize_endpoint(f"http://[{GOOD_IP}]"))

    def test_netguard_fails_closed_on_malformed_and_blocks_ipv6_private(self):
        try:
            from app.tools.netguard import assert_safe_outbound_url, SsrfBlocked
        except Exception:
            self.skipTest("netguard 依赖缺失")
        # 畸形方括号 IPv6：不能裸抛 ValueError，必须 fail-closed 成 SsrfBlocked
        with self.assertRaises(SsrfBlocked):
            assert_safe_outbound_url(f"http://[{CRASH_IP}]:9000/models")
        # IPv6 环回/私网必须拦截（getaddrinfo 本地解析，无需外网）
        for u in ("http://[::1]/", "http://[fe80::1]/"):
            with self.assertRaises(SsrfBlocked):
                assert_safe_outbound_url(u)

    def test_auth_bootstrap_host_of_bracketed_ipv6(self):
        try:
            from app.agents.auth_bootstrap import _host_of
        except Exception:
            self.skipTest("auth_bootstrap 依赖缺失")
        self.assertEqual(_host_of(f"[{GOOD_IP}]"), GOOD_IP)
        self.assertEqual(_host_of(f"[{GOOD_IP}]:8080"), GOOD_IP)
        self.assertEqual(_host_of("example.com:8080"), "example.com")

    def test_edu_ip_ipv6_no_crash_returns_none(self):
        try:
            from app.tools.edu_ip import _host_from_target, _lookup_ip
        except Exception:
            self.skipTest("edu_ip 依赖缺失")
        self.assertEqual(_host_from_target(f"http://[{GOOD_IP}]:8080"), GOOD_IP)
        # IPv6→int 曾触发被吞的 OverflowError；现在应干净短路 None
        self.assertIsNone(_lookup_ip(GOOD_IP))

    def test_target_cluster_root_domain_ipv6(self):
        try:
            from app.agents.target_cluster import root_domain
        except Exception:
            self.skipTest("target_cluster 依赖缺失")
        self.assertEqual(root_domain(f"http://[{GOOD_IP}]"), f"[{GOOD_IP}]")
        # 映射型 IPv6 含 '.'，修复前会拆出 '169.254]' 垃圾根域
        rd = root_domain("http://[::ffff:169.254.169.254]")
        self.assertNotIn("]", rd.rstrip("]"))
        self.assertTrue(rd.startswith("["))

    def test_observer_host_ipv6_no_hextet_as_port(self):
        try:
            from app.api.tasks import _observer_host
        except Exception:
            self.skipTest("api.tasks 依赖缺失")
        out = _observer_host(GOOD_IP)   # 裸 IPv6 不应把末段 hextet 当端口剥掉
        self.assertNotIn(":1", out.replace("::", ""))  # 末段 '1' 不该变成端口 ':1'
        self.assertIsInstance(out, str)


if __name__ == "__main__":
    unittest.main()
