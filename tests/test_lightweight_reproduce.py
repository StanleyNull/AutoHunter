from __future__ import annotations

from types import SimpleNamespace

from app.orchestrator import _lightweight_reproduce_eligible


def _finding(severity: str, target_url: str = "", evidence: str = "") -> SimpleNamespace:
    return SimpleNamespace(
        severity_claimed=severity,
        target_url=target_url,
        detail=evidence,
        proof="",
        request_evidence="",
    )


def test_medium_with_evidence_and_url_is_eligible():
    f = _finding("中危", target_url="http://example.com/api", evidence="通过修改 id 参数越权获取到他人订单数据，响应返回 200 且含敏感字段。")
    assert _lightweight_reproduce_eligible(f) is True


def test_low_with_request_evidence_is_eligible():
    f = _finding("低危", target_url="http://example.com/x", evidence="请求返回 HTTP 200，暴露版本信息。")
    assert _lightweight_reproduce_eligible(f) is True


def test_high_not_eligible():
    # 高危走更重实锤验证，不在此确定性标记。
    f = _finding("高危", target_url="http://example.com/a", evidence="完整证据链" * 10)
    assert _lightweight_reproduce_eligible(f) is False


def test_missing_target_url_not_eligible():
    f = _finding("中危", target_url="", evidence="证据充分但无定位 URL，无法轻量复现。")
    assert _lightweight_reproduce_eligible(f) is False


def test_thin_evidence_not_eligible():
    # 证据过薄（<30 字且无 HTTP/请求 片段）→ 不标记，避免空壳洞被采信。
    f = _finding("中危", target_url="http://example.com/a", evidence="疑似有洞")
    assert _lightweight_reproduce_eligible(f) is False
