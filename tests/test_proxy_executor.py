"""ToolExecutor 代理池集成测试：接入/自动轮换/封禁记忆/env 注入。"""
from __future__ import annotations

import itertools
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import httpx


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import proxy_service as ps  # noqa: E402
from app.tools.executor import ToolExecutor  # noqa: E402


TARGET = "http://target.example"


def _pool(*entries, enabled: bool = True) -> dict:
    return {"enabled": enabled, "proxies": list(entries)}


def _px(idx: int) -> dict:
    return {
        "id": f"px-{idx}", "name": f"p{idx}", "protocol": "http",
        "host": f"10.0.0.{idx}", "port": 8080,
        "username": "", "password": "", "enabled": True,
    }


def _fake_response() -> SimpleNamespace:
    url = "http://target.example/x"
    return SimpleNamespace(
        url=url,
        status_code=200,
        headers={"content-type": "text/html"},
        encoding="utf-8",
        iter_bytes=lambda: iter([b"ok"]),
        cookies=SimpleNamespace(jar=[], items=lambda: []),
        history=[],
        close=lambda: None,
    )


def _fake_request() -> SimpleNamespace:
    return SimpleNamespace(
        method="GET",
        url=SimpleNamespace(raw_path=b"/x", host="target.example"),
        headers={"User-Agent": "test"},
        content=b"",
    )


class FakeClient:
    is_closed = False

    def __init__(self, behavior):
        self._behavior = list(behavior)
        self.cookies = SimpleNamespace(clear=lambda: None, jar=[], set=lambda *a, **k: None)

    def build_request(self, method, url, **kwargs):
        return _fake_request()

    def send(self, request, **kwargs):
        item = self._behavior.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _executor() -> ToolExecutor:
    return ToolExecutor(TARGET, work_dir=tempfile.mkdtemp())


class ExecutorProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        ps.apply_config({})
        # 轮转计数器是模块级状态，与同进程其它测试文件共享；不重置的话
        # "首个拿到的代理是哪个"取决于执行顺序，test_connection_failure_* 会翻车。
        ps._rr = itertools.count()
        self.ex = _executor()

    def tearDown(self) -> None:
        ps.apply_config({})
        self.ex.close_http_client()

    def test_client_gets_proxy_url_when_pool_enabled(self) -> None:
        ps.apply_config(_pool(_px(1)))
        with patch("app.tools.executor.httpx.Client") as client_cls:
            client_cls.return_value = Mock(is_closed=False)
            self.ex._get_http_client()
        kwargs = client_cls.call_args.kwargs
        self.assertEqual(kwargs.get("proxy"), "http://10.0.0.1:8080")

    def test_client_direct_when_pool_disabled(self) -> None:
        ps.apply_config(_pool(_px(1), enabled=False))
        with patch("app.tools.executor.httpx.Client") as client_cls:
            client_cls.return_value = Mock(is_closed=False)
            self.ex._get_http_client()
        self.assertIsNone(client_cls.call_args.kwargs.get("proxy"))
        self.assertEqual(self.ex._proxy_id, "")

    def test_connection_failure_rotates_and_marks_used(self) -> None:
        ps.apply_config(_pool(_px(1), _px(2)))
        bad = FakeClient([httpx.ConnectError("proxy dead")])
        good = FakeClient([_fake_response()])
        with patch.object(ToolExecutor, "_get_http_client", side_effect=[bad, good]):
            result = self.ex.http_request("http://target.example/x")
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.ex._proxy_id, "px-2")
        self.assertIn("px-1", self.ex._used_proxy_ids)
        health = ps._health.get("px-1") or {}
        self.assertEqual(int(health.get("fails") or 0), 1)
        # 换 IP 动作落了工作目录日志
        logs = list(self.ex.work_dir.glob("shell_*.log"))
        self.assertTrue(any("[proxy]" in p.read_text(encoding="utf-8", errors="replace") for p in logs))

    def test_connection_failure_without_proxy_returns_error(self) -> None:
        # 直连失败（池未启用）：不应轮换，直接返回错误
        bad = FakeClient([httpx.ConnectError("refused")])
        with patch.object(ToolExecutor, "_get_http_client", side_effect=[bad]):
            result = self.ex.http_request("http://target.example/x")
        self.assertFalse(result["ok"])
        self.assertIn("HTTP 请求异常", result["error"])

    def test_rotate_proxy_tool_returns_direct_when_no_more_proxies(self) -> None:
        result = self.ex.rotate_proxy_tool(reason="被封")
        self.assertTrue(result["ok"])
        self.assertEqual(result["proxy"], "direct")
        self.assertIn("无可用出口", result["guidance"])

    def test_rotate_proxy_tool_picks_next_and_excludes_used(self) -> None:
        ps.apply_config(_pool(_px(1), _px(2), _px(3)))
        # 先让 executor 持有 px-2（模拟正在用）
        self.ex._proxy_id = "px-2"
        self.ex._proxy_url = "http://10.0.0.2:8080"
        result = self.ex.rotate_proxy_tool(reason="WAF 封 IP")
        self.assertTrue(result["ok"])
        self.assertNotEqual(result["proxy"], "http://10.0.0.2:8080")
        self.assertIn("px-2", self.ex._used_proxy_ids)
        # 后续 acquire 不会再给 px-2
        got = ps.acquire(exclude_ids=set(self.ex._used_proxy_ids))
        self.assertNotEqual(got and got["id"], "px-2")

    def test_success_reports_health(self) -> None:
        ps.apply_config(_pool(_px(1)))
        with ps._LOCK:
            ps._health_of("px-1")["fails"] = 2
        good = FakeClient([_fake_response()])
        with patch.object(ToolExecutor, "_get_http_client", side_effect=[good]):
            result = self.ex.http_request("http://target.example/x")
        self.assertTrue(result["ok"])
        self.assertEqual(int(ps._health["px-1"]["fails"]), 0)

    def test_shell_proxy_env_injection(self) -> None:
        ps.apply_config(_pool(_px(1)))
        proc = Mock()
        proc.stdout = Mock()
        proc.stdout.read1 = Mock(side_effect=[b""])
        proc.poll = Mock(return_value=0)
        proc.wait = Mock(return_value=0)
        proc.pid = 1
        with patch("app.tools.executor.subprocess.Popen") as popen, \
                patch("app.tools.executor.selectors.DefaultSelector") as selector:
            selector.return_value.select.return_value = []
            result = self.ex.run_shell("echo hi")
        self.assertTrue(result["ok"], result)
        env = popen.call_args.kwargs["env"]
        self.assertEqual(env["HTTP_PROXY"], "http://10.0.0.1:8080")
        self.assertEqual(env["HTTPS_PROXY"], env["HTTP_PROXY"])
        self.assertIn("127.0.0.1", env["NO_PROXY"])

    def test_shell_env_direct_has_no_http_proxy(self) -> None:
        proc = Mock()
        proc.stdout = Mock()
        proc.stdout.read1 = Mock(side_effect=[b""])
        proc.poll = Mock(return_value=0)
        proc.wait = Mock(return_value=0)
        proc.pid = 1
        with patch("app.tools.executor.subprocess.Popen") as popen, \
                patch("app.tools.executor.selectors.DefaultSelector") as selector:
            selector.return_value.select.return_value = []
            self.ex.run_shell("echo hi")
        self.assertNotIn("HTTP_PROXY", popen.call_args.kwargs["env"])


if __name__ == "__main__":
    unittest.main()
