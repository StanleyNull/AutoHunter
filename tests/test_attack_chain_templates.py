from __future__ import annotations

from types import SimpleNamespace

import app.agents.attack_chain_templates as act


def _store(tmp_path, monkeypatch) -> str:
    path = str(tmp_path / "templates.json")
    monkeypatch.setattr(act, "_STORE_PATH_CACHE", path)
    return path


def test_record_and_match_by_fingerprint(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    act.record_success(["nacos"], "unauthorized_access", "未授权接口直接读配置", "某系统")
    hints = act.match_for(["nacos", "spring boot"])
    assert len(hints) == 1
    assert hints[0]["vuln_type"] == "unauthorized_access"
    assert "未授权" in hints[0]["attack_chain"]


def test_match_empty_when_no_fingerprint(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    act.record_success(["nacos"], "unauthorized_access", "链A")
    assert act.match_for(["unknown_fp"]) == []


def test_record_dedup_increments_hits(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    act.record_success(["nacos"], "idor", "链A")
    act.record_success(["nacos"], "idor", "链A")
    data = act.load_templates()
    assert len(data["templates"]) == 1
    assert data["templates"][0]["hits"] == 2


def test_record_different_chain_distinct(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    act.record_success(["nacos"], "idor", "链A")
    act.record_success(["nacos"], "idor", "链B")
    data = act.load_templates()
    assert len(data["templates"]) == 2


def test_record_accepted_finding_from_orm_like(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    finding = SimpleNamespace(
        target_url="http://example.com/login",
        title="Nacos 控制台",
        owner="某单位",
        vuln_type="unauthorized_access",
        steps=["访问 /nacos 未授权", "读取配置"],
        description="",
    )
    ok = act.record_accepted_finding(finding)
    assert ok is True
    data = act.load_templates()
    assert len(data["templates"]) == 1
    assert data["templates"][0]["vuln_type"] == "unauthorized_access"
    assert "访问 /nacos" in data["templates"][0]["attack_chain"]


def test_record_accepted_finding_falls_back_to_description(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    finding = SimpleNamespace(target_url="", title="", owner="",
                              vuln_type="sql_injection", steps=[], description="报错注入")
    ok = act.record_accepted_finding(finding)
    assert ok is True
    data = act.load_templates()
    assert data["templates"][0]["attack_chain"] == "报错注入"


def test_match_limit(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    for i in range(5):
        act.record_success(["fp"], "t", f"chain {i}")
    assert len(act.match_for(["fp"], limit=3)) == 3
