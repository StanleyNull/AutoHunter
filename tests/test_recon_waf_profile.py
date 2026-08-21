from __future__ import annotations

from unittest.mock import Mock

from app.agents.worker import Worker


def _make_worker(target: str = "http://example.com") -> Worker:
    worker = Worker.__new__(Worker)
    worker.target = target
    worker.deepen_context = None
    worker.target_meta = {}
    worker._enterprise = False
    worker.duplicate_history = []
    worker.findings = []
    worker._emit = Mock()
    return worker


class _ReconExecutor:
    """模拟 recon 用 executor：http_request 按 url 返回预设响应；session_set 为桩。"""

    def __init__(self, pages: dict | None = None, anon_pages: dict | None = None):
        self._pages = pages or {}
        self._anon_pages = anon_pages or {}
        self.http_request = Mock(side_effect=self._do_req)
        self.session_set = Mock()

    def _do_req(self, url, method="GET", follow_redirects=False):
        key = url.rstrip("/")
        clear_called = bool(
            self.session_set.call_args and self.session_set.call_args.kwargs.get("clear")
        )
        table = self._anon_pages if clear_called else self._pages
        p = table.get(url) or table.get(key)
        if p is not None:
            return {
                "ok": True,
                "status_code": p.get("status_code", 200),
                "url": url,
                "final_url": url,
                "body": p.get("body", ""),
                "response_headers": p.get("response_headers", {}),
            }
        return {"ok": True, "status_code": 404, "url": url, "body": "", "response_headers": {}}


def test_looks_blocked_detects_generic_intercept():
    worker = _make_worker()
    assert worker._looks_blocked({"status_code": 406, "body": ""}) is True
    assert worker._looks_blocked({"status_code": 429, "body": ""}) is True
    assert worker._looks_blocked({"status_code": 200, "body": "<html>请求被拦截</html>"}) is True
    assert worker._looks_blocked({"status_code": 200, "body": "<h1>hello</h1>"}) is False
    assert worker._looks_blocked({}) is False


def test_collect_waf_profile_identifies_cloudflare():
    worker = _make_worker()
    blocked = [
        {
            "status_code": 403,
            "body": "<title>Just a moment...</title>",
            "response_headers": {"cf-ray": "abc123"},
        },
    ]
    profile = worker._collect_waf_profile(blocked)
    assert profile.get("detected") is True
    types = {p["waf_type"] for p in profile.get("profiles", [])}
    assert "cloudflare" in types
    # 证据与拦截码都被保留
    cf = next(p for p in profile["profiles"] if p["waf_type"] == "cloudflare")
    assert cf["blocked_statuses"] == [403]
    assert any("cf-ray" in e for e in cf["evidence"])


def test_collect_waf_profile_empty_when_no_blocked():
    worker = _make_worker()
    assert worker._collect_waf_profile([]) == {}
    # 全是 200 普通响应，无拦截特征
    ok = [{"status_code": 200, "body": "<h1>ok</h1>", "response_headers": {}}]
    assert worker._collect_waf_profile(ok) == {}


def test_waf_profile_block_renders_from_separate_field():
    worker = _make_worker()
    # 空字段返回空串（不污染首轮上下文）
    assert worker._waf_profile_block() == ""
    worker.target_meta = {
        "waf_profile": {
            "detected": True,
            "profiles": [
                {"waf_type": "safedog", "evidence": ["命中响应体关键词 `安全狗`"], "blocked_statuses": [403]},
            ],
            "guidance": "首轮探测请优先带 XFF 与 UA 变形。",
        },
    }
    block = worker._waf_profile_block()
    assert "安全狗" in block
    assert "403" in block
    assert "XFF" in block


def test_auth_diff_probe_returns_raw_responses():
    # step5 需把两端原始响应带回，供 step5.6 收集被拦响应做指纹聚类。
    # 匿名态（clear=True）读 anon_pages，登录态读 pages；这里把 admin 放 anon_pages 模拟匿名即被拦。
    anon_pages = {
        "http://example.com/admin": {
            "status_code": 403,
            "body": "<html>安全狗拦截</html>",
            "response_headers": {},
        },
    }
    worker = _make_worker()
    worker.executor = _ReconExecutor(anon_pages=anon_pages)
    d = worker._auth_diff_probe(worker.executor, "http://example.com/admin")
    assert d["gap"] == "both_blocked"
    assert isinstance(d.get("unauth_resp"), dict)
    assert d["unauth_resp"]["status_code"] == 403
    assert isinstance(d.get("authed_resp"), dict)


def test_submit_finding_stamps_recon_waf_present_when_profile_detected():
    # 侦察已实锤目标前方有 WAF：worker 提交 finding 时打 recon_waf_present 标记，
    # 让 reviewer 对该 finding 的「证据残缺」优先 rescue 带变形补证。
    from app.schemas import Finding, Severity

    worker = _make_worker()
    worker.target_meta = {
        "waf_profile": {"detected": True, "profiles": [{"waf_type": "safedog"}], "guidance": "x"},
    }
    f = Finding(
        vuln_type="idor", title="t", severity_claimed=Severity.medium,
        target_url="http://example.com/api/order/1",
        owner="o", description="d", steps=["s"], poc="curl x",
        raw_request="GET /api/order/1", raw_response="HTTP/1.1 403",
        kill_chain=[], self_check={},
    )
    res = worker._submit_finding(f.model_dump(mode="json"))
    assert res["ok"] is True
    assert worker.findings[0].self_check.recon_waf_present is True


def test_submit_finding_no_waf_stamp_when_profile_absent():
    from app.schemas import Finding, Severity

    worker = _make_worker()
    worker.target_meta = {}  # 无 waf_profile
    f = Finding(
        vuln_type="idor", title="t", severity_claimed=Severity.medium,
        target_url="http://example.com/api/order/1",
        owner="o", description="d", steps=["s"], poc="curl x",
        raw_request="GET /api/order/1", raw_response="HTTP/1.1 200",
        kill_chain=[], self_check={},
    )
    res = worker._submit_finding(f.model_dump(mode="json"))
    assert res["ok"] is True
    assert worker.findings[0].self_check.recon_waf_present is False
