"""手动清单清理分析单测。"""
from __future__ import annotations

from app.agents.manual_targets import clean_manual_target_list, parse_manual_targets

SAMPLE = """
www.ncet.edu.cn
http://1s1kzs.eduyun.cn
https://jpk.basic.smartedu.cn
https://h5-jpk.basic.smartedu.cn
https://ai.eduyun.cn
http://mrg.ai.eduyun.cn/
https://vlab.eduyun.cn/
https://jjxm.eduyun.cn/sys-review/viewGoodCase/viewGoodCase?code=2
ggfw.zj.eduyun.cn
xtyx.zj.eduyun.cn
dsggfw.zj.eduyun.cn
zgmzs.eduyun.cn
https://www.smartedu.cn/
system.smartedu.cn
passport.smartedu.cn
auth.smartedu.cn
api.smartedu.cn
css.smartedu.cn
test.system.eduyun.cn
(211.153.76.118)
test-sso.system.eduyun.cn
(211.153.76.118)
jbgzs.ykt.eduyun.cn
www.eduyun.cn
basic.smartedu.cn
www.zxx.edu.cn
ykt.eduyun.cn
eschool.eduyun.cn
szjy.ncet.edu.cn
http://hlcwl.eduyun.cn
huodong.ncet.edu.cn
h5-huodong.ncet.edu.cn
e.eduyun.cn
gtt.eduyun.cn
https://teta.ncet.edu.cn
https://mobile.teta.ncet.edu.cn
res.teta.ncet.edu.cn
zhijiao.ncet.edu.cn
www.cetav.com.cn
ca.ncet.edu.cn
www.eschool.org.cn
www.cer.com.cn
demo.cer.com.cn
zc.cer.com.cn
www.cer.org.cn
yszy.eduyun.cn
h5-yszy.eduyun.cn
yszygl.n.eduyun.cn
https://xwpx.eduyun.cn/
https://app.eduyun.cn/
data.eduyun.cn
diaa.ncet.edu.cn
gj.eduyun.cn
gj.ncet.edu.cn
gp.eduyun.cn
test.gp.eduyun.cn
zjrh.eduyun.cn
zjrh.ncet.edu.cn
https://jdsxj.eduyun.cn/
https://b.jdsxj.eduyun.cn/ 港澳台
https://c.jdsxj.eduyun.cn/ 海外组
zhyg.eduyun.cn
wdec.smartedu.cn
zhanlan.ncet.edu.cn
https://www.csmartedu.cn
https://szyb.smartedu.cn/
reading.smartedu.cn
read.ncet.edu.cn
onlinecc.xwpx.eduyun.cn
onlineccbot.xwpx.eduyun.cn
resclip.ykt.eduyun.cn
aisearch.ykt.eduyun.cn
https://yxwh.gj.ncet.edu.cn/
stem.ncet.edu.cn
lab.ncet.edu.cn
https://tjjxj.basic.smartedu.cn/
https://vparse.service.eduyun.cn
"""


def test_parse_strips_trailing_notes_and_paren_ip():
    items = parse_manual_targets(SAMPLE)
    by_host = {i["host"]: i for i in items}

    assert "b.jdsxj.eduyun.cn" in by_host
    assert by_host["b.jdsxj.eduyun.cn"]["url"].startswith("https://b.jdsxj.eduyun.cn")
    assert "港澳台" not in by_host["b.jdsxj.eduyun.cn"]["url"]
    assert by_host["b.jdsxj.eduyun.cn"]["note"] == "港澳台"

    assert "c.jdsxj.eduyun.cn" in by_host
    assert by_host["c.jdsxj.eduyun.cn"]["note"] == "海外组"

    # 单独成行的括号 IP 入队，重复只保留一次
    assert "211.153.76.118" in by_host
    assert sum(1 for i in items if i["host"] == "211.153.76.118") == 1


def test_parse_keeps_deep_path_and_query():
    items = parse_manual_targets(SAMPLE)
    hit = next(i for i in items if i["host"] == "jjxm.eduyun.cn")
    assert "/sys-review/viewGoodCase/viewGoodCase" in hit["url"]
    assert "code=2" in hit["url"]


def test_parse_fills_scheme_for_bare_host():
    items = parse_manual_targets(["www.ncet.edu.cn", "system.smartedu.cn"])
    assert items[0]["url"].startswith("http://www.ncet.edu.cn")
    assert items[1]["host"] == "system.smartedu.cn"


def test_clean_list_dedupes_and_drops_noise():
    cleaned = clean_manual_target_list(SAMPLE)
    assert all("港澳台" not in u and "海外组" not in u for u in cleaned)
    assert "(" not in "".join(cleaned)
    # 样本里两个相同括号 IP 行 → 清理后只剩一个 IP 目标
    assert sum(1 for u in cleaned if "211.153.76.118" in u) == 1
    # 数量应接近资产规模（去噪后仍有几十个）
    assert 70 <= len(cleaned) <= 90


def test_prefer_path_url_when_same_host_twice():
    items = parse_manual_targets([
        "https://jjxm.eduyun.cn/",
        "https://jjxm.eduyun.cn/sys-review/viewGoodCase/viewGoodCase?code=2",
    ])
    assert len(items) == 1
    assert "sys-review" in items[0]["url"]
