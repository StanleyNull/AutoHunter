"""手动清单清理分析单测。"""
from __future__ import annotations

from app.agents.manual_targets import clean_manual_target_list, parse_manual_targets

# 合成资产清单：仅用 example.edu.cn / demo.edu.cn 等文档域名与 TEST-NET IP，
# 结构上覆盖裸域名 / http/https / 深链带查询 / 行尾备注 / 括号 IP / 重复行等脏格式。
SAMPLE = """
www.example.edu.cn
http://a.example.edu.cn
https://jpk.basic.example.edu.cn
https://h5-jpk.basic.example.edu.cn
https://ai.example.edu.cn
http://mrg.ai.example.edu.cn/
https://vlab.example.edu.cn/
https://portal.example.edu.cn/sys-review/viewGoodCase/viewGoodCase?code=2
ggfw.zj.example.edu.cn
xtyx.zj.example.edu.cn
system.example.edu.cn
passport.example.edu.cn
auth.example.edu.cn
api.example.edu.cn
test.system.example.edu.cn
(203.0.113.10)
test-sso.system.example.edu.cn
(203.0.113.10)
jbgzs.ykt.example.edu.cn
www.example.edu.cn
basic.example.edu.cn
www.demo.edu.cn
ykt.example.edu.cn
eschool.example.edu.cn
szjy.example.edu.cn
http://hlcwl.example.edu.cn
huodong.example.edu.cn
h5-huodong.example.edu.cn
https://teta.example.edu.cn
https://mobile.teta.example.edu.cn
res.teta.example.edu.cn
zhijiao.example.edu.cn
ca.example.edu.cn
https://jdsxj.example.edu.cn/
https://b.jdsxj.example.edu.cn/ 港澳台
https://c.jdsxj.example.edu.cn/ 海外组
zhyg.example.edu.cn
wdec.example.edu.cn
zhanlan.example.edu.cn
https://szyb.example.edu.cn/
reading.example.edu.cn
read.example.edu.cn
stem.example.edu.cn
lab.example.edu.cn
https://tjjxj.basic.example.edu.cn/
https://vparse.service.example.edu.cn
"""


def test_parse_strips_trailing_notes_and_paren_ip():
    items = parse_manual_targets(SAMPLE)
    by_host = {i["host"]: i for i in items}

    assert "b.jdsxj.example.edu.cn" in by_host
    assert by_host["b.jdsxj.example.edu.cn"]["url"].startswith("https://b.jdsxj.example.edu.cn")
    assert "港澳台" not in by_host["b.jdsxj.example.edu.cn"]["url"]
    assert by_host["b.jdsxj.example.edu.cn"]["note"] == "港澳台"

    assert "c.jdsxj.example.edu.cn" in by_host
    assert by_host["c.jdsxj.example.edu.cn"]["note"] == "海外组"

    # 单独成行的括号 IP 入队，重复只保留一次
    assert "203.0.113.10" in by_host
    assert sum(1 for i in items if i["host"] == "203.0.113.10") == 1


def test_parse_keeps_deep_path_and_query():
    items = parse_manual_targets(SAMPLE)
    hit = next(i for i in items if i["host"] == "portal.example.edu.cn")
    assert "/sys-review/viewGoodCase/viewGoodCase" in hit["url"]
    assert "code=2" in hit["url"]


def test_parse_fills_scheme_for_bare_host():
    items = parse_manual_targets(["www.example.edu.cn", "system.example.edu.cn"])
    assert items[0]["url"].startswith("http://www.example.edu.cn")
    assert items[1]["host"] == "system.example.edu.cn"


def test_clean_list_dedupes_and_drops_noise():
    cleaned = clean_manual_target_list(SAMPLE)
    assert all("港澳台" not in u and "海外组" not in u for u in cleaned)
    assert "(" not in "".join(cleaned)
    # 样本里两个相同括号 IP 行 → 清理后只剩一个 IP 目标
    assert sum(1 for u in cleaned if "203.0.113.10" in u) == 1
    # 数量应接近资产规模（去噪后仍有几十个）
    assert 35 <= len(cleaned) <= 55


def test_prefer_path_url_when_same_host_twice():
    items = parse_manual_targets([
        "https://portal.example.edu.cn/",
        "https://portal.example.edu.cn/sys-review/viewGoodCase/viewGoodCase?code=2",
    ])
    assert len(items) == 1
    assert "sys-review" in items[0]["url"]
