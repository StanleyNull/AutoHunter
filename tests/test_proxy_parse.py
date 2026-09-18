"""proxy_service.parse_proxy_line / parse_proxy_text / proxy_url 单元测试。"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.proxy_service import parse_proxy_line, parse_proxy_text, proxy_url  # noqa: E402


class ParseProxyLineTests(unittest.TestCase):
    def test_url_format_basic(self) -> None:
        item = parse_proxy_line("http://1.2.3.4:8080")
        self.assertEqual(item, {
            "protocol": "http", "host": "1.2.3.4", "port": 8080,
            "username": "", "password": "",
        })

    def test_url_format_socks5_with_auth(self) -> None:
        item = parse_proxy_line("socks5://alice:secret@10.0.0.1:1080")
        self.assertEqual(item["protocol"], "socks5")
        self.assertEqual(item["host"], "10.0.0.1")
        self.assertEqual(item["port"], 1080)
        self.assertEqual(item["username"], "alice")
        self.assertEqual(item["password"], "secret")

    def test_url_encoded_password(self) -> None:
        item = parse_proxy_line("http://user:p%40ss%3Aword@5.6.7.8:3128")
        self.assertEqual(item["username"], "user")
        self.assertEqual(item["password"], "p@ss:word")

    def test_pipe_format_with_protocol(self) -> None:
        item = parse_proxy_line("socks5|1.2.3.4|1080|u|p")
        self.assertEqual(item["protocol"], "socks5")
        self.assertEqual((item["host"], item["port"]), ("1.2.3.4", 1080))
        self.assertEqual((item["username"], item["password"]), ("u", "p"))

    def test_pipe_format_minimal_defaults_http(self) -> None:
        item = parse_proxy_line("1.2.3.4:8080")
        self.assertEqual(item["protocol"], "http")
        self.assertEqual((item["host"], item["port"]), ("1.2.3.4", 8080))
        self.assertEqual(item["username"], "")

    def test_pipe_format_host_port_user_pass(self) -> None:
        item = parse_proxy_line("1.2.3.4:8080|user|pass")
        self.assertEqual((item["username"], item["password"]), ("user", "pass"))

    def test_socks_scheme_alias(self) -> None:
        self.assertEqual(parse_proxy_line("socks://1.1.1.1:1080")["protocol"], "socks5")
        self.assertEqual(parse_proxy_line("socks5h://1.1.1.1:1080")["protocol"], "socks5")

    def test_comment_and_empty_lines(self) -> None:
        self.assertIsNone(parse_proxy_line(""))
        self.assertIsNone(parse_proxy_line("   "))
        self.assertIsNone(parse_proxy_line("# comment"))

    def test_invalid_lines(self) -> None:
        for line in (
            "not-a-proxy",
            "http://1.2.3.4",          # 缺端口
            "ftp://1.2.3.4:21",        # 协议不支持
            "http://1.2.3.4:99999",    # 端口越界
            "http://1.2.3.4:abc",      # 端口非数字
            "http://ho st:8080",       # host 含空格
        ):
            with self.subTest(line=line):
                self.assertIsNone(parse_proxy_line(line))


class ParseProxyTextTests(unittest.TestCase):
    def test_dedup_by_scheme_host_port_and_counts_invalid(self) -> None:
        text = "\n".join([
            "# pool",
            "http://1.2.3.4:8080",
            "1.2.3.4:8080",              # 与上一行同键（默认 http）→ 去重
            "socks5://1.2.3.4:8080",     # 协议不同 → 保留
            "broken-line",
            "",
        ])
        items, invalid = parse_proxy_text(text)
        self.assertEqual(len(items), 2)
        self.assertEqual(invalid, 2)  # 去重 1 + 非法 1
        self.assertEqual(items[0]["protocol"], "http")
        self.assertEqual(items[1]["protocol"], "socks5")

    def test_empty_text(self) -> None:
        self.assertEqual(parse_proxy_text(""), ([], 0))


class ProxyUrlTests(unittest.TestCase):
    def test_plain(self) -> None:
        self.assertEqual(
            proxy_url({"protocol": "http", "host": "1.2.3.4", "port": 8080, "username": "", "password": ""}),
            "http://1.2.3.4:8080",
        )

    def test_auth_url_encoded(self) -> None:
        url = proxy_url({
            "protocol": "socks5", "host": "1.2.3.4", "port": 1080,
            "username": "u", "password": "p@ss:word",
        })
        self.assertEqual(url, "socks5://u:p%40ss%3Aword@1.2.3.4:1080")


if __name__ == "__main__":
    unittest.main()
