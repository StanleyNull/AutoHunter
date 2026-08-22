from __future__ import annotations

from unittest.mock import Mock

from app.agents.worker import Worker


def _make_worker(target: str = "http://example.com") -> Worker:
    worker = Worker.__new__(Worker)
    worker.target = target
    worker.deepen_context = None
    worker.target_meta = {}
    worker._emit = Mock()
    return worker


class _ReconExecutor:
    """模拟 recon 用 executor：http_request 按 url 返回预设响应。

    payload_pages: dict[完整 probe url, dict(status_code, body)] —— 用于字典探测的精确匹配。
    """

    def __init__(self, probe_pages: dict | None = None):
        self._probe_pages = probe_pages or {}
        self.http_request = Mock(side_effect=self._do_req)
        self.session_set = Mock()

    def _do_req(self, url, method="GET", follow_redirects=False):
        p = self._probe_pages.get(url)
        if p is not None:
            return {
                "ok": True,
                "status_code": p.get("status_code", 200),
                "url": url,
                "final_url": url,
                "body": p.get("body", ""),
                "response_headers": p.get("response_headers", {}),
            }
        # 未预设的 url（如确认探测用的 autohunter_probe）一律 404，模拟「未确认」。
        return {"ok": True, "status_code": 404, "url": url, "body": "", "response_headers": {}}


def test_dict_probe_fires_only_on_confirmed_params():
    # id 在 _RECON_PARAM_PROBES 已知列表 → 发 payload 且命中 SQLi；
    # cmd 不在已知列表（即便传入 confirmed）也不发 payload，避免对静态/无关参数浪费发包。
    pages = {
        "http://example.com/?id='\"`": {
            "status_code": 200,
            "body": "You have an error in your SQL syntax",
        },
    }
    worker = _make_worker()
    worker.executor = _ReconExecutor(pages)

    hits = worker._param_dict_probe_block(worker.executor, "http://example.com", ["id", "cmd"])
    # id 命中 SQLi 特征
    assert any("`id`" in h and "SQLi" in h for h in hits)
    # cmd 不在 known 集合 → 不应产生任何以 cmd 开头的命中行
    assert not any("`cmd`" in h for h in hits)


def test_dict_probe_detects_sqli_signature():
    pages = {
        "http://example.com/?id='\"`": {
            "status_code": 200,
            "body": "MySQL server version for the right syntax to use near '",
        },
    }
    worker = _make_worker()
    worker.executor = _ReconExecutor(pages)

    hits = worker._param_dict_probe_block(worker.executor, "http://example.com", ["id"])
    assert any("`id`" in h and "SQLi" in h for h in hits)
    # 命中 signature 是 "mysql"（小写匹配），报告应含该特征与漏洞类。
    assert any("mysql" in h.lower() for h in hits)


def test_dict_probe_detects_ssti_evaluation():
    pages = {
        "http://example.com/?q={{7*7}}": {"status_code": 200, "body": "result=49 end"},
    }
    worker = _make_worker()
    worker.executor = _ReconExecutor(pages)

    hits = worker._param_dict_probe_block(worker.executor, "http://example.com", ["q"])
    assert any("SSTI" in h for h in hits)


def test_dict_probe_detects_reflected_xss():
    pages = {
        "http://example.com/?q=<svg/onload=alert(1)>": {
            "status_code": 200,
            "body": "<div><svg/onload=alert(1)></div>",
        },
    }
    worker = _make_worker()
    worker.executor = _ReconExecutor(pages)

    hits = worker._param_dict_probe_block(worker.executor, "http://example.com", ["q"])
    assert any("XSS" in h for h in hits)


def test_dict_probe_skips_5xx_and_empty():
    # 5xx 与空响应都应跳过，不产出命中。
    pages = {
        "http://example.com/?id='\"`": {"status_code": 500, "body": "traceback"},
    }
    worker = _make_worker()
    worker.executor = _ReconExecutor(pages)

    hits = worker._param_dict_probe_block(worker.executor, "http://example.com", ["id"])
    assert hits == []


def test_dict_probe_degrades_without_http_request():
    worker = _make_worker()
    worker.executor = None
    assert worker._param_dict_probe_block(worker.executor, "http://example.com", ["id"]) == []


def test_param_dict_leads_structured():
    # _param_dict_leads 返回结构化 dict（param/url/vuln_cls/signature），
    # 供 run() 后置注入首轮，模型不必重新 parse 文本。
    pages = {
        "http://example.com/?id='\"`": {
            "status_code": 200,
            "body": "You have an error in your SQL syntax",
        },
    }
    worker = _make_worker()
    worker.executor = _ReconExecutor(pages)

    leads = worker._param_dict_leads(worker.executor, "http://example.com", ["id"])
    assert len(leads) == 1
    lead = leads[0]
    assert lead["param"] == "id"
    assert lead["vuln_cls"] == "SQLi"
    assert "sql syntax" in lead["signature"].lower()
    assert lead["url"].startswith("http://example.com/?id=")
    # 文本版与结构化版一致（基于同一 leads 渲染）
    text = worker._param_dict_probe_block(worker.executor, "http://example.com", ["id"])
    assert any("`id`" in t and "SQLi" in t for t in text)


def test_probe_leads_block_renders_and_empty():
    worker = _make_worker()
    worker.target_meta = {
        "confirmed_probe_leads": [
            {"param": "id", "url": "http://example.com/?id='\"`",
             "vuln_cls": "SQLi", "signature": "sql syntax"},
        ]
    }
    block = worker._probe_leads_block()
    assert "确定性漏洞线索" in block
    assert "`id`" in block and "SQLi" in block
    assert "sql syntax" in block
    # 无 leads 时返回空（不刷屏）
    worker2 = _make_worker()
    worker2.target_meta = {}
    assert worker2._probe_leads_block() == ""
