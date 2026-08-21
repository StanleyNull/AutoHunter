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
    """模拟 recon 用 executor：http_request 按 url 返回预设响应；无 analyze_javascript。

    pages: dict[url, dict(status_code, body, response_headers)]
    """

    def __init__(self, pages: dict | None = None):
        self._pages = pages or {}
        self.http_request = Mock(side_effect=self._do_req)
        self.session_set = Mock()

    def _do_req(self, url, method="GET", follow_redirects=False):
        key = url.rstrip("/")
        p = self._pages.get(url) or self._pages.get(key)
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


def test_param_probe_block_flags_suspect_params():
    # /?id= /?file= 返回 200（疑似被解析），/?cmd= 返回 404（忽略）。
    pages = {
        "http://example.com/?id=autohunter_probe": {"status_code": 200, "body": "result"},
        "http://example.com/?file=autohunter_probe": {"status_code": 200, "body": "x"},
        "http://example.com/?cmd=autohunter_probe": {"status_code": 404, "body": "nf"},
    }
    worker = _make_worker()
    worker.executor = _ReconExecutor(pages)

    hits = worker._param_probe_block(worker.executor, "http://example.com")

    params = [h for h in hits if "`id=`" in h or "`file=`" in h]
    assert len(params) == 2
    assert all("HTTP 200" in h for h in params)
    assert not any("`cmd=`" in h for h in hits)


def test_param_probe_block_skips_empty_200_only():
    # 仅完全空响应的 200 视为无信息量而跳过；带任何正文（即便极短）都保留。
    pages = {
        "http://example.com/?token=autohunter_probe": {"status_code": 200, "body": ""},
    }
    worker = _make_worker()
    worker.executor = _ReconExecutor(pages)

    hits = worker._param_probe_block(worker.executor, "http://example.com")
    assert not any("`token=`" in h for h in hits)

    # 带正文（即便 "ok" 这种短响应）仍保留，因为说明参数被服务器接收处理。
    pages2 = {
        "http://example.com/?token=autohunter_probe": {"status_code": 200, "body": "ok"},
    }
    worker.executor = _ReconExecutor(pages2)
    hits2 = worker._param_probe_block(worker.executor, "http://example.com")
    assert any("`token=`" in h for h in hits2)


def test_sitemap_loc_parsed_and_samehost_paths_merged():
    # sitemap.xml 含 3 个 loc，其中 1 个同源 /api/users 应并入侦察面（step3 不再重复探）。
    sitemap_body = (
        '<?xml version="1.0"?><urlset>'
        "<loc>http://example.com/api/users</loc>"
        "<loc>http://example.com/admin/dashboard</loc>"
        "<loc>http://other.com/page</loc>"
        "</urlset>"
    )
    pages = {
        "http://example.com/": {"status_code": 200, "body": "<title>home</title>", "response_headers": {}},
        "http://example.com/sitemap.xml": {"status_code": 200, "body": sitemap_body},
        "http://example.com/robots.txt": {"status_code": 404},
    }
    worker = _make_worker()
    worker.executor = _ReconExecutor(pages)

    report = worker._run_mandatory_recon()

    assert "sitemap.xml 暴露页面/接口 3 个" in report
    assert "http://example.com/api/users" in report
    # 同源 /api/users 已并入侦察面 → step3 固定清单若含该路径不再发声（这里清单无，仅验证逻辑不崩）
    assert "疑似后台/API 接口" in report  # api 类 loc 被单列


def test_recon_param_probe_wired_into_report():
    # 全局 recon 报告应含「参数级探测」块，且命中参数进入鉴权差异候选（不崩）。
    pages = {
        "http://example.com/": {
            "status_code": 200,
            "body": "<title>home</title><script src='/app.js'></script>",
            "response_headers": {},
        },
        "http://example.com/robots.txt": {"status_code": 404},
        "http://example.com/sitemap.xml": {"status_code": 404},
        "http://example.com/?id=autohunter_probe": {"status_code": 200, "body": "row"},
    }
    worker = _make_worker()
    worker.executor = _ReconExecutor(pages)

    report = worker._run_mandatory_recon()

    assert "参数级探测" in report
    assert "`id=`" in report
    # 参数命中后不应因候选构造异常而崩；报告正常收尾。
    assert "请优先覆盖已暴露的高价值接口" in report


def test_recon_js_signal_triggers_interface_extraction_cap():
    # 首页含 JS 信号时，即使 analyze_javascript 不可用（无该属性），也应静默降级不崩。
    pages = {
        "http://example.com/": {
            "status_code": 200,
            "body": "<title>home</title><script src='/app.js'></script>",
            "response_headers": {},
        },
        "http://example.com/robots.txt": {"status_code": 404},
        "http://example.com/sitemap.xml": {"status_code": 404},
    }
    worker = _make_worker()
    ex = _ReconExecutor(pages)
    # 故意不提供 analyze_javascript，模拟能力缺失
    if hasattr(ex, "analyze_javascript"):
        delattr(ex, "analyze_javascript")
    worker.executor = ex

    report = worker._run_mandatory_recon()
    assert isinstance(report, str)
    assert "请优先覆盖已暴露的高价值接口" in report


def test_recon_param_dict_probe_wired_into_report():
    # 全局 recon：id 被确认响应后，字典探测应对其发只读 payload；当命中特征时报告含「字典探测」块。
    pages = {
        "http://example.com/": {
            "status_code": 200,
            "body": "<title>home</title>",
            "response_headers": {},
        },
        "http://example.com/robots.txt": {"status_code": 404},
        "http://example.com/sitemap.xml": {"status_code": 404},
        # 确认探测：id 有响应
        "http://example.com/?id=autohunter_probe": {"status_code": 200, "body": "row"},
        # 字典探测：id + SQLi payload 触发报错特征
        "http://example.com/?id='\"`": {
            "status_code": 200,
            "body": "You have an error in your SQL syntax",
        },
    }
    worker = _make_worker()
    worker.executor = _ReconExecutor(pages)

    report = worker._run_mandatory_recon()

    assert "参数级探测" in report
    assert "参数级漏洞字典探测" in report
    assert "SQLi" in report
    # 不应因字典探测异常而崩；报告正常收尾。
    assert "请优先覆盖已暴露的高价值接口" in report
