from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

from app.agents.worker import Worker


def _make_worker(target: str = "http://example.com") -> Worker:
    worker = Worker.__new__(Worker)
    worker.target = target
    worker.deepen_context = None
    worker.target_meta = {}
    worker._emit = Mock()
    return worker


def _executor(home, robots=None, sitemap=None, js_map=None):
    """js_map: dict[script_url, js_dict]，首页分析用 key='__home__'。"""
    js_map = js_map or {}

    def http_request(url, method="GET", follow_redirects=False):
        u = url.rstrip("/")
        if u == home["url"].rstrip("/"):
            return home
        if url.endswith("/robots.txt"):
            return robots or {"ok": True, "status_code": 404}
        if url.endswith("/sitemap.xml"):
            return sitemap or {"ok": True, "status_code": 404}
        return {"ok": False, "status_code": 404}

    def analyze_javascript(url, max_depth=1, max_assets=60):
        if url.rstrip("/") == home["url"].rstrip("/"):
            return js_map.get("__home__", {})
        return js_map.get(url.rstrip("/"), {})

    return SimpleNamespace(
        http_request=http_request,
        analyze_javascript=Mock(side_effect=analyze_javascript),
    )


def test_sitemap_loc_parsed_into_surface():
    home = {
        "ok": True, "status_code": 200, "url": "http://example.com/",
        "final_url": "http://example.com/", "body": "<title>SPA</title><script src=\"/main.js\"></script>",
        "response_headers": {},
    }
    sitemap = {
        "ok": True, "status_code": 200,
        "body": "<urlset><loc>http://example.com/admin</loc>"
                "<loc>http://example.com/api/users</loc>"
                "<loc>http://example.com/console/keys</loc></urlset>",
    }
    worker = _make_worker()
    worker.executor = _executor(home, sitemap=sitemap, js_map={"__home__": {}})

    report = worker._run_mandatory_recon()

    assert "sitemap.xml 暴露页面/接口" in report
    assert "http://example.com/admin" in report
    assert "http://example.com/api/users" in report
    assert "http://example.com/console/keys" in report


def test_sitemap_loc_capped_at_40():
    locs = "".join(f"<loc>http://example.com/p{i}</loc>" for i in range(80))
    home = {
        "ok": True, "status_code": 200, "url": "http://example.com/",
        "final_url": "http://example.com/", "body": "<title>x</title>",
        "response_headers": {},
    }
    sitemap = {"ok": True, "status_code": 200, "body": f"<urlset>{locs}</urlset>"}
    worker = _make_worker()
    worker.executor = _executor(home, sitemap=sitemap, js_map={"__home__": {}})

    report = worker._run_mandatory_recon()

    # 只取前 40，第 41 个不应出现
    assert "http://example.com/p39" in report
    assert "http://example.com/p40" not in report


def test_full_js_interface_from_external_scripts():
    home = {
        "ok": True, "status_code": 200, "url": "http://example.com/",
        "final_url": "http://example.com/",
        "body": "<title>SPA</title><script src=\"/chunk-a.js\"></script><script src=\"/chunk-b.js\"></script>",
        "response_headers": {},
    }
    js_map = {
        "__home__": {"api_endpoints": ["/api/home"]},
        "http://example.com/chunk-a.js": {"api_endpoints": ["/api/users", "/api/orders"]},
        "http://example.com/chunk-b.js": {"api_endpoints": ["/api/secrets"]},
    }
    worker = _make_worker()
    worker.executor = _executor(home, js_map=js_map)

    report = worker._run_mandatory_recon()

    # 首页 + 两个 chunk 的接口都应进入攻击面地图
    assert "/api/home" in report
    assert "/api/users" in report
    assert "/api/orders" in report
    assert "/api/secrets" in report
    # 外部脚本分析被实际调用（取调用的 url 关键字参数）
    called = {
        c.kwargs.get("url") or (c.args[0] if c.args else None)
        for c in worker.executor.analyze_javascript.call_args_list
    }
    assert "http://example.com/chunk-a.js" in called
    assert "http://example.com/chunk-b.js" in called


def test_js_dedupe_skips_irrelevant_sources():
    # 同源去重 + 排除 data:/blob:/无协议相对路径；绝对 http(s) 脚本（含跨域 CDN）保留。
    srcs = [
        "/app.js", "/app.js", "https://cdn.example.org/lib.js",
        "data:text/javascript,", "//cdn2.x/y.js", "blob:https://x/y",
    ]
    out = Worker._dedupe_script_srcs(srcs, "http://example.com")
    assert out == [
        "http://example.com/app.js",
        "https://cdn.example.org/lib.js",
    ]


def test_recon2_silent_on_exception():
    home = {
        "ok": True, "status_code": 200, "url": "http://example.com/",
        "final_url": "http://example.com/", "body": "<title>x</title><script src=/a.js></script>",
        "response_headers": {},
    }
    worker = _make_worker()
    # analyze_javascript 抛异常，应静默降级，不污染主流程
    worker.executor = SimpleNamespace(
        http_request=lambda url, method="GET", follow_redirects=False: (
            home if url.rstrip("/") == home["url"].rstrip("/") else {"ok": True, "status_code": 404}
        ),
        analyze_javascript=Mock(side_effect=RuntimeError("boom")),
    )

    report = worker._run_mandatory_recon()

    assert "强制前置侦察报告" in report
    assert "前端 JS 暴露的接口线索" not in report
