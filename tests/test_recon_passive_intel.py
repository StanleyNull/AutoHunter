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


class _IntelExecutor:
    """带 fofa_key 与可控 fofa_lookup 返回值的最小 executor 桩。

    response: dict | Exception —— 指定则 fofa_lookup 返回该 dict，或抛出该异常。
    recorded: list —— 记录实际传给 fofa_lookup 的 (query, size)。
    """

    def __init__(self, response=None, key: str = "k-fofa-123"):
        self.fofa_key = key
        self._response = response
        self.recorded = []

    def fofa_lookup(self, query: str = "", size: int = 10):
        self.recorded.append((query, size))
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


def test_passive_intel_domain_query_when_key_present():
    sample = [
        {"host": "app.example.com", "port": "8080", "title": "后台管理", "domain": "example.com", "org": "Example Inc"},
        {"host": "api.example.com", "port": "443", "title": "API Gateway", "domain": "example.com", "org": "Example Inc"},
    ]
    ex = _IntelExecutor(response={"ok": True, "size": 42, "sample": sample})
    out = _make_worker("http://example.com")._passive_intel_block(ex, "http://example.com")

    assert "被动情报补充攻击面" in out
    assert "domain=\"example.com\"" in out
    assert "app.example.com:8080" in out and "后台管理" in out
    assert "api.example.com" in out
    assert "命中规模约 42" in out
    # org 与 domain 不同，应附加归属信息
    assert "归属：Example Inc" in out


def test_passive_intel_ip_target_uses_ip_query():
    sample = [{"host": "1.2.3.4", "port": "9000", "title": "Admin"}]
    ex = _IntelExecutor(response={"ok": True, "size": 5, "sample": sample})
    out = _make_worker("http://1.2.3.4")._passive_intel_block(ex, "http://1.2.3.4")

    assert "ip=\"1.2.3.4\"" in out
    assert "1.2.3.4:9000" in out


def test_passive_intel_skips_when_no_key():
    ex = _IntelExecutor(response={"ok": True, "sample": [{"host": "x"}]}, key="")
    out = _make_worker()._passive_intel_block(ex, "http://example.com")
    assert out == ""
    assert ex.recorded == []  # 无 key 不应发起查询


def test_passive_intel_degrades_on_lookup_failure():
    ex = _IntelExecutor(response={"ok": False, "error": "额度不足"})
    out = _make_worker()._passive_intel_block(ex, "http://example.com")
    assert out == ""


def test_passive_intel_degrades_on_lookup_exception():
    ex = _IntelExecutor(response=RuntimeError("网络超时"))
    out = _make_worker()._passive_intel_block(ex, "http://example.com")
    assert out == ""


def test_passive_intel_empty_sample_yields_nothing():
    ex = _IntelExecutor(response={"ok": True, "size": 0, "sample": []})
    out = _make_worker()._passive_intel_block(ex, "http://example.com")
    assert out == ""


def test_passive_intel_dedup_by_host_port():
    sample = [
        {"host": "api.example.com", "port": "443", "title": "A"},
        {"host": "api.example.com", "port": "443", "title": "B"},  # 重复 (host,port)
        {"host": "api.example.com", "port": "8443", "title": "C"},
    ]
    ex = _IntelExecutor(response={"ok": True, "size": 3, "sample": sample})
    out = _make_worker()._passive_intel_block(ex, "http://example.com")
    # 仅出现 2 个独立 (host,port) 对
    assert out.count("api.example.com") == 2


def test_passive_intel_omits_org_when_same_as_domain():
    sample = [{"host": "api.example.com", "port": "443", "title": "X", "domain": "example.com", "org": "example.com"}]
    ex = _IntelExecutor(response={"ok": True, "size": 1, "sample": sample})
    out = _make_worker()._passive_intel_block(ex, "http://example.com")
    assert "归属：" not in out
