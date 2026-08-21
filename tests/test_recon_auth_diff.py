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


class _SessionExecutor:
    """模拟带会话态的 executor：清会话后匿名请求，恢复后登录态请求。

    responses: dict[url, (anon_code, authed_code)]
    """

    def __init__(self, responses: dict):
        self._responses = responses
        self._session_cookies: dict = {"JSESSIONID": "authed"}
        self._session_headers: dict = {}
        self.session_set = Mock(side_effect=self._do_set)
        self.http_request = Mock(side_effect=self._do_req)
        self._anon = False

    def _do_set(self, cookies=None, headers=None, clear=False):
        if clear:
            self._session_cookies = {}
            self._session_headers = {}
        else:
            if cookies:
                self._session_cookies = dict(cookies)
            if headers:
                self._session_headers = dict(headers)
        return {"ok": True, "active_cookies": sorted(self._session_cookies.keys())}

    def _do_req(self, url, method="GET", follow_redirects=False):
        u = url.rstrip("/")
        anon_code, authed_code = self._responses.get(u, (404, 404))
        code = anon_code if self._session_cookies == {} else authed_code
        return {"ok": True, "status_code": code, "url": url, "body": ""}


def test_auth_diff_probe_anon_open():
    # 匿名 200、登录态 403 → 疑似未授权暴露
    ex = _SessionExecutor({"http://example.com/api/data": (200, 403)})
    worker = _make_worker()
    worker.executor = ex

    d = worker._auth_diff_probe(ex, "http://example.com/api/data")

    assert d["gap"] == "anon_open"
    assert d["unauth_code"] == 200
    assert d["authed_code"] == 403
    assert d["reachable_anon"] is True
    assert d["reachable_auth"] is False
    # 会话态必须被恢复（清了再补回），否则后续主流程失去登录态
    assert ex._session_cookies.get("JSESSIONID") == "authed"


def test_auth_diff_probe_auth_only():
    # 匿名 401、登录态 200 → 受保护，越权主战场
    ex = _SessionExecutor({"http://example.com/admin": (401, 200)})
    worker = _make_worker()
    worker.executor = ex

    d = worker._auth_diff_probe(ex, "http://example.com/admin")

    assert d["gap"] == "auth_only"
    assert d["unauth_code"] == 401
    assert d["authed_code"] == 200
    assert ex._session_cookies.get("JSESSIONID") == "authed"


def test_auth_diff_probe_both_blocked_and_open():
    ex1 = _SessionExecutor({"http://example.com/x": (403, 403)})
    w1 = _make_worker()
    w1.executor = ex1
    assert w1._auth_diff_probe(ex1, "http://example.com/x")["gap"] == "both_blocked"

    ex2 = _SessionExecutor({"http://example.com/y": (200, 200)})
    w2 = _make_worker()
    w2.executor = ex2
    assert w2._auth_diff_probe(ex2, "http://example.com/y")["gap"] == "both_open"


def test_auth_diff_probe_session_restore_on_clear_failure():
    # session_set(clear=True) 抛异常时，应记 error 且不崩；恢复步骤也异常则同样降级。
    ex = _SessionExecutor({"http://example.com/api": (200, 403)})
    ex.session_set = Mock(side_effect=RuntimeError("boom"))
    worker = _make_worker()
    worker.executor = ex

    d = worker._auth_diff_probe(ex, "http://example.com/api")

    assert d["error"] != ""
    assert d["gap"] == "both_blocked"  # 拿不到双态，按最保守结论返回


def test_recon_auth_diff_block_wired_for_401_paths():
    # 探测命中 200 的入口（/admin）与选靶暴露端点（/api/data）都进入鉴权差异对比：
    # 会话态下探测返回的是「登录态」码；diff 清会话后拿「匿名」码，据此分类。
    home = {
        "ok": True, "status_code": 200, "url": "http://example.com/",
        "final_url": "http://example.com/", "body": "<title>x</title>",
        "response_headers": {},
    }
    # (anon_code, authed_code)：/admin 登录态 200、匿名 401 → auth_only；
    # /api/data 登录态 403、匿名 200 → anon_open（疑似未授权）。
    responses = {
        "http://example.com/admin": (401, 200),
        "http://example.com/api/data": (200, 403),
    }

    class _Ex(_SessionExecutor):
        def _do_req(self, url, method="GET", follow_redirects=False):
            u = url.rstrip("/")
            if u in responses:
                anon, authed = responses[u]
                code = anon if self._session_cookies == {} else authed
                return {"ok": True, "status_code": code, "url": url, "body": ""}
            if u == home["url"].rstrip("/"):
                return home
            if url.endswith(("/robots.txt", "/sitemap.xml")):
                return {"ok": True, "status_code": 404}
            # 固定探测路径清单里除 /admin 外的都 404
            return {"ok": False, "status_code": 404}

    worker = _make_worker()
    worker.executor = _Ex(responses)
    worker.target_meta = {
        "exposed_endpoints": ["http://example.com/api/data（暴露）", "http://example.com/export（需鉴权）"],
    }

    report = worker._run_mandatory_recon()

    assert "鉴权差异对比" in report
    assert "匿名即返回 200" in report       # anon_open 提示
    assert "确实受鉴权保护" in report        # auth_only 提示
    assert "http://example.com/api/data" in report
