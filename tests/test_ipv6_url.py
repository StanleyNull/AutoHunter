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


if __name__ == "__main__":
    unittest.main()
