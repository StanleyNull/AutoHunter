from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

from app.agents.worker import Worker


def _make_worker(target: str = "http://example.com") -> Worker:
    worker = Worker.__new__(Worker)
    worker.target = target
    worker.deepen_context = None
    worker._emit = Mock()
    return worker


def _executor_from_map(home, robots, probes, js=None):
    def http_request(url, method="GET", follow_redirects=False):
        if url.rstrip("/") in (home["url"].rstrip("/"),):
            return home
        if url.endswith("/robots.txt"):
            return robots
        if url.endswith("/sitemap.xml"):
            return {"ok": True, "status_code": 404}
        for path, resp in probes.items():
            if url.endswith(path):
                return resp
        return {"ok": False, "status_code": 404}

    return SimpleNamespace(
        http_request=http_request,
        analyze_javascript=Mock(return_value=js or {}),
    )


def test_recon_empty_when_no_executor():
    worker = _make_worker()
    # 完全不设 executor
    assert worker._run_mandatory_recon() == ""


def test_recon_empty_when_executor_lacks_http_request():
    worker = _make_worker()
    worker.executor = SimpleNamespace(session_status_block=Mock(return_value=""))
    assert worker._run_mandatory_recon() == ""


def test_recon_builds_report_from_responses():
    home = {
        "ok": True, "status_code": 200, "url": "http://example.com/",
        "final_url": "http://example.com/", "body": "<title>测试教务系统</title><script src=/app.js></script>",
        "response_headers": {"Server": "nginx/1.18", "X-Powered-By": "PHP/7.4"},
    }
    robots = {"ok": True, "status_code": 200, "body": "Disallow: /admin\nAllow: /public\nDisallow: /api/internal"}
    probes = {
        "/admin": {"ok": True, "status_code": 403},
        "/login": {"ok": True, "status_code": 200},
        "/api/v1": {"ok": True, "status_code": 401},
        "/swagger-ui.html": {"ok": True, "status_code": 404},
    }
    js = {"api_endpoints": ["/api/user", "/api/list"], "chains": [{"a": 1}]}
    worker = _make_worker()
    worker.executor = _executor_from_map(home, robots, probes, js)

    report = worker._run_mandatory_recon()

    assert "强制前置侦察报告" in report
    assert "测试教务系统" in report            # 标题
    assert "nginx" in report                   # Server 指纹
    assert "指纹命中" in report                # 命中 Nginx
    assert "首页不可达" not in report
    assert "/admin：403" in report             # 探测命中（需鉴权后台）
    assert "/api/v1：401" in report
    assert "robots.txt 暴露路径" in report     # robots 暴露路径
    assert "/admin" in report
    assert "前端 JS 暴露的接口线索" in report  # JS 接口线索
    assert "/api/user" in report


def test_recon_handles_unreachable_home():
    home = {"ok": False, "error": "connection timeout"}
    worker = _make_worker()
    worker.executor = _executor_from_map(home, {"ok": True, "status_code": 404}, {})

    report = worker._run_mandatory_recon()

    assert "首页不可达" in report
    assert "强制前置侦察报告" in report


def test_recon_no_js_block_when_no_js_signal():
    home = {
        "ok": True, "status_code": 200, "url": "http://example.com/",
        "final_url": "http://example.com/", "body": "<title>纯静态页</title><p>无脚本</p>",
        "response_headers": {"Server": "Apache"},
    }
    worker = _make_worker()
    exec_ns = _executor_from_map(home, {"ok": True, "status_code": 404}, {})
    worker.executor = exec_ns

    report = worker._run_mandatory_recon()

    assert "前端 JS 暴露的接口线索" not in report
    # 确认 JS 分析未被调用（无 JS 信号）
    exec_ns.analyze_javascript.assert_not_called()
