from __future__ import annotations

import app.agents.attack_chain_templates as act


def _store(tmp_path, monkeypatch) -> str:
    path = str(tmp_path / "templates.json")
    monkeypatch.setattr(act, "_STORE_PATH_CACHE", path)
    monkeypatch.setattr(act, "_SEEDED", False)  # 保证每次测试都重新触发播种
    return path


def test_seed_injects_expected_count(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    added = act.seed_default_chains()
    assert added == len(act._SEED_CHAINS)
    data = act.load_templates()
    assert len(data["templates"]) == added
    # 种子 owner 标记为 seed，便于区分用户沉淀
    assert all(t.get("owner") == "seed" for t in data["templates"])


def test_seed_idempotent_on_repeat(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    first = act.seed_default_chains()
    second = act.seed_default_chains()
    assert first == len(act._SEED_CHAINS)
    assert second == 0  # 第二次不重复插入
    data = act.load_templates()
    assert len(data["templates"]) == first


def test_seed_does_not_overwrite_user_template(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    # 用户已沉淀一条与若依种子同 sig 的模板（不同 owner、不同 chain 文本但归一化后一致）
    ruoyi_seed = next(s for s in act._SEED_CHAINS if "framework_ruoyi" in s["fingerprints"])
    act.record_success(["framework_ruoyi"], ruoyi_seed["vuln_type"], ruoyi_seed["attack_chain"])
    added = act.seed_default_chains()
    data = act.load_templates()
    seeds = [t for t in data["templates"] if t.get("owner") == "seed"]
    users = [t for t in data["templates"] if t.get("owner") != "seed"]
    # 用户模板仍保留（未被覆盖），种子因同 sig 跳过它 -> 种子数少 1
    assert len(users) == 1
    assert added == len(act._SEED_CHAINS) - 1
    assert len(seeds) == added


def test_seed_matches_by_specific_fingerprint(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    act.seed_default_chains()
    hits = act.match_for(["framework_ruoyi"])
    assert hits and any(t["vuln_type"] == "unauthorized_access" for t in hits)
    # 具体系统命中后，attack_chain 应包含该系统关键词
    assert any("若依" in t["attack_chain"] for t in hits)


def test_seed_matches_by_soft_type_fingerprint(tmp_path, monkeypatch):
    # 没有任何具体系统指纹，仅 type: 软指纹也应命中通用打法
    _store(tmp_path, monkeypatch)
    act.seed_default_chains()
    hits = act.match_for(["type:info_leak"])
    assert hits and any(t.get("owner") == "seed" for t in hits)


def test_seed_covers_key_fingerprints(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    act.seed_default_chains()
    data = act.load_templates()
    all_fps = set()
    for t in data["templates"]:
        all_fps.update(t.get("fingerprints") or [])
    for expected in ("framework_ruoyi", "framework_thinkphp", "framework_springboot",
                     "mw_nacos", "mw_druid", "api_swagger", "sso_cas", "edu_jwgl"):
        assert expected in all_fps, f"种子缺少关键指纹覆盖: {expected}"


def test_match_for_autoseed_once(tmp_path, monkeypatch):
    # match_for 首次调用应自动播种（懒注入），且不抛异常
    _store(tmp_path, monkeypatch)
    hits = act.match_for(["mw_nacos"])
    assert hits and any(t.get("owner") == "seed" for t in hits)
    # 第二次调用不再重复播种（_SEEDED 已置位，added=0 不报错）
    hits2 = act.match_for(["mw_druid"])
    assert hits2
