from __future__ import annotations

from app.agents.attack_chain_templates import match_for, seed_default_chains, load_templates


def setup_module(_):
    # 确保种子已注入（match_for 首次调用也会懒注入）；隔离不影响其它测试用同一 JSON 文件。
    seed_default_chains()


def test_match_for_by_business_stage_order():
    hints = match_for([], business_stages=["order"])
    sigs = [h.get("sig", "") for h in hints]
    assert any("biz:order" in (h.get("fingerprints") or []) for h in hints)
    assert any("idor" in s for s in sigs)


def test_match_for_by_business_stage_payment():
    hints = match_for([], business_stages=["payment"])
    assert any("biz:payment" in (h.get("fingerprints") or []) for h in hints)
    assert any("logic_flaw" in (h.get("vuln_type") or "") for h in hints)


def test_match_for_by_business_stage_user_center():
    hints = match_for([], business_stages=["user_center"])
    assert any("biz:user_center" in (h.get("fingerprints") or []) for h in hints)


def test_match_for_by_business_stage_auth():
    hints = match_for([], business_stages=["auth"])
    assert any("biz:auth" in (h.get("fingerprints") or []) for h in hints)
    assert any("auth_bypass" in (h.get("vuln_type") or "") for h in hints)


def test_match_for_empty_business_stages_returns_nothing():
    # 无任何指纹且无业务阶段 → 不命中（与既有语义一致）
    hints = match_for([], business_stages=[])
    assert hints == []
