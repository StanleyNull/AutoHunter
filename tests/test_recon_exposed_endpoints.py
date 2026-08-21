from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

from app.agents.worker import Worker
from app.agents.scorer import parse_exposed_endpoints, score_target


def _make_worker(target: str = "http://example.com", exposed: list[str] | None = None) -> Worker:
    worker = Worker.__new__(Worker)
    worker.target = target
    worker.deepen_context = None
    worker.target_meta = {"exposed_endpoints": exposed or []}
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


def test_parse_exposed_endpoints_from_reason():
    reason = "[HIGH] +4 暴露端点:/actuator,/swagger-ui.html · +1 鉴权端点:/nacos/(需鉴权) · +2 login_form"
    out = parse_exposed_endpoints(reason)
    assert "/actuator" in out
    assert "/swagger-ui.html" in out
    assert "/nacos/(需鉴权)" in out
    assert len(out) == 3


def test_parse_exposed_endpoints_empty():
    assert parse_exposed_endpoints("") == []
    assert parse_exposed_endpoints("[LOW] 普通资产") == []


def test_score_target_returns_exposed_tuple():
    # 不实际发包：用不存活的 host 让探测失败，exposed 为空列表
    score, reason, exposed = score_target("http://127.0.0.1:1/nope", probe_endpoints=True, timeout=0.2)
    assert isinstance(score, float)
    assert isinstance(reason, str)
    assert isinstance(exposed, list)


def test_recon_lists_meta_exposed_and_skips_dup_probe():
    home = {
        "ok": True, "status_code": 200, "url": "http://example.com/",
        "final_url": "http://example.com/", "body": "<title>教务系统</title>",
        "response_headers": {"Server": "nginx"},
    }
    robots = {"ok": True, "status_code": 404}
    # 选靶阶段已探出 /actuator、/nacos/(需鉴权)；worker 不应再对 /actuator 发包
    meta_exposed = ["/actuator", "/nacos/(需鉴权)"]
    # 提供 /actuator 的响应以备万一（但应被跳过，不应命中），以及 /admin 的真实响应
    probes = {
        "/actuator": {"ok": True, "status_code": 200, "body": "SHOULD_NOT_BE_HIT"},
        "/admin": {"ok": True, "status_code": 403},
    }
    worker = _make_worker(exposed=meta_exposed)
    exec_ns = _executor_from_map(home, robots, probes)
    worker.executor = exec_ns

    report = worker._run_mandatory_recon()

    # 选靶入口被直接列出
    assert "选靶阶段已发现入口" in report
    assert "/actuator" in report
    assert "/nacos/" in report
    assert "需鉴权" in report
    # 重复路径不再出现在「后台/API/运维路径探测」里（被跳过）
    assert "SHOULD_NOT_BE_HIT" not in report
    # 未覆盖的路径仍正常探测
    assert "/admin：403" in report


def test_recon_no_meta_exposed_section_when_absent():
    home = {
        "ok": True, "status_code": 200, "url": "http://example.com/",
        "final_url": "http://example.com/", "body": "<title>系统</title>",
        "response_headers": {},
    }
    worker = _make_worker(exposed=None)
    worker.executor = _executor_from_map(home, {"ok": True, "status_code": 404}, {})

    report = worker._run_mandatory_recon()
    assert "选靶阶段已发现入口" not in report
