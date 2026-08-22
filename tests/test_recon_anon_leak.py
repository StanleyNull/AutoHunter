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
        # 匿名态（已 clear）读 anon_pages，否则读普通 pages
        clear_called = bool(self.session_set.call_args and self.session_set.call_args.kwargs.get("clear"))
        table = self._anon_pages if clear_called else self._pages
        p = table.get(url) or table.get(key)
        if p is not None:
            return {"ok": True, "status_code": p.get("status_code", 200), "url": url,
                    "final_url": url, "body": p.get("body", ""), "response_headers": p.get("response_headers", {})}
        return {"ok": True, "status_code": 404, "url": url, "body": "", "response_headers": {}}


def test_anon_leak_scan_finds_email_and_idcard():
    # 匿名可达端点返回正文含邮箱与身份证号特征
    pages = {
        "http://example.com/api/user/list": {
            "status_code": 200,
            "body": '{"users":[{"id":1,"email":"a@b.com","idcard":"110101199001011234"}]}',
        },
    }
    worker = _make_worker()
    worker.executor = _ReconExecutor(anon_pages=pages)
    leads = worker._anon_leak_scan(worker.executor, ["http://example.com/api/user/list"])
    labels = {l["label"] for l in leads}
    assert "邮箱" in labels
    assert "身份证号" in labels
    # 每条线索带 url 与去敏样例
    assert all(l.get("url") and l.get("sample") for l in leads)


def test_anon_leak_scan_skips_empty_and_clean():
    pages = {"http://example.com/public/about": {"status_code": 200, "body": "<html><body>关于我们</body></html>"}}
    worker = _make_worker()
    worker.executor = _ReconExecutor(anon_pages=pages)
    leads = worker._anon_leak_scan(worker.executor, ["http://example.com/public/about"])
    assert leads == []


def test_anon_leak_scan_empty_input():
    worker = _make_worker()
    worker.executor = _ReconExecutor()
    assert worker._anon_leak_scan(worker.executor, []) == []


def test_anon_leak_block_renders_from_separate_field():
    worker = _make_worker()
    worker.target_meta = {
        "anon_leak_leads": [
            {"url": "http://example.com/api/user", "label": "邮箱", "sample": "user@example.com"},
        ],
    }
    block = worker._anon_leak_block()
    assert "匿名敏感数据泄露线索" in block
    assert "http://example.com/api/user" in block
    assert "邮箱" in block
    # 无字段时返回空（不刷屏）
    worker2 = _make_worker()
    worker2.target_meta = {}
    assert worker2._anon_leak_block() == ""


def test_recon_writes_anon_leak_to_separate_field():
    # 首页 + 一个匿名可达端点（含泄露特征）；auth_diff 触发 after，anon_leak 扫描命中独立字段。
    pages = {
        "http://example.com/": {"status_code": 200, "body": "<title>sensitive api</title>", "response_headers": {}},
        "http://example.com/robots.txt": {"status_code": 404},
        "http://example.com/sitemap.xml": {"status_code": 404},
    }
    # 匿名态（clear 后）读取该端点正文，含 JSON 裸数据 + 邮箱
    anon_pages = {
        "http://example.com/api/user/list": {
            "status_code": 200,
            "body": '{"id":1,"email":"leak@example.com"}',
        },
    }
    worker = _make_worker()
    worker.executor = _ReconExecutor(pages=pages, anon_pages=anon_pages)
    # 暴露端点直接复用，作为 auth_diff 候选（匿名可达）
    worker.target_meta = {
        "exposed_endpoints": ["http://example.com/api/user/list（暴露）"],
    }
    report = worker._run_mandatory_recon()
    assert report  # 至少首页块应产出
    leaks = worker.target_meta.get("anon_leak_leads") or []
    labels = {l["label"] for l in leaks}
    assert "邮箱" in labels or "JSON 接口裸数据" in labels


def test_submit_finding_stamps_recon_anon_leak_on_match():
    # 侦察已确认匿名泄露的端点写入 target_meta，worker 提交同端点 finding 时打 recon_anon_leak 标记。
    from app.schemas import Finding, Severity

    worker = _make_worker()
    worker.target_meta = {
        "anon_leak_leads": [
            {"url": "http://example.com/api/user/list", "label": "邮箱", "sample": "a@b.com"},
        ],
    }
    # 同端点（带 query 也不影响前缀匹配）
    f = Finding(
        vuln_type="unauthorized_access", title="t", severity_claimed=Severity.medium,
        target_url="http://example.com/api/user/list?page=1",
        owner="o", description="d", steps=["s"], poc="curl x",
        raw_request="GET /api/user/list HTTP/1.1", raw_response="HTTP/1.1 200",
        kill_chain=[], self_check={},
    )
    res = worker._submit_finding(f.model_dump(mode="json"))
    assert res["ok"] is True
    assert worker.findings[0].self_check.recon_anon_leak is True


def test_submit_finding_no_stamp_when_url_unrelated():
    from app.schemas import Finding, Severity

    worker = _make_worker()
    worker.target_meta = {
        "anon_leak_leads": [
            {"url": "http://example.com/api/user/list", "label": "邮箱", "sample": "a@b.com"},
        ],
    }
    f = Finding(
        vuln_type="idor", title="t", severity_claimed=Severity.medium,
        target_url="http://example.com/api/order/1",
        owner="o", description="d", steps=["s"], poc="curl x",
        raw_request="GET /api/order/1", raw_response="HTTP/1.1 200",
        kill_chain=[], self_check={},
    )
    res = worker._submit_finding(f.model_dump(mode="json"))
    assert res["ok"] is True
    assert worker.findings[0].self_check.recon_anon_leak is False
