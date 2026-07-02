"""离线导入器：遍历纯真库(qqwry.dat) 全部记录，抽取「高校/教育网」段落入 SQLite。

纯真库把归属标到了学校级（如「教育网/南京大学」「浙江大学(玉溪校区)」），
本脚本把这些教育相关记录一次性离线导入，无需联网爬取、无封 IP 风险。

用法：
    ./.venv/bin/python import_qqwry.py            # 导入 edu 相关全部记录
    ./.venv/bin/python import_qqwry.py --all      # 连非 edu 记录也导（一般不需要）
"""
from __future__ import annotations

import argparse
import struct

from qqwry import QQwry

import db as dbmod

QQWRY_FILE = "qqwry.dat"

# 判定「是不是高校/教育网」的关键词（命中即收）
EDU_HINTS = (
    "教育网", "大学", "学院", "学校", "科技网", "研究院", "研究所",
    "职业技术", "高等专科", "师范", "医科", "党校", "CERNET", "campus",
)

# 明显不是学校、但可能含「学院」字样的公司噪音，尽量排除（宽松，宁收勿漏）
NON_SCHOOL_BLOCK = (
    "网络教育学院有限", "教育科技有限公司", "培训学校",
)


def is_edu(area: str, isp: str) -> bool:
    text = f"{area} {isp}"
    if not any(h in text for h in EDU_HINTS):
        return False
    return True


def clean_school(area: str, isp: str) -> str | None:
    """从 (area, isp) 里提炼学校名。纯真 isp 常见形如：
    '教育网/南京大学'、'教育网/教育网骨干节点/华中科技大学'、'清华大学'、'浙江大学(玉溪校区)'
    """
    candidates: list[str] = []
    for seg in isp.split("/"):
        seg = seg.strip()
        if not seg:
            continue
        # 去掉纯"教育网/科技网/骨干节点"这类非学校段
        if seg in ("教育网", "科技网", "教育网骨干节点", "骨干节点", "CERNET"):
            continue
        candidates.append(seg)
    # 优先取含"大学/学院/学校"的候选
    for c in candidates:
        if any(k in c for k in ("大学", "学院", "学校", "师范", "医科", "职业技术", "研究院", "研究所")):
            return c
    # 退而求其次：非教育网的第一个候选
    if candidates:
        return candidates[0]
    return None


def parse_area_province_city(area: str) -> tuple[str | None, str | None]:
    # area 形如 '中国–江苏–南京' 或 '中国–北京–北京–海淀区'
    parts = [p for p in area.replace("—", "–").split("–") if p and p != "中国"]
    province = parts[0] if len(parts) >= 1 else None
    city = parts[1] if len(parts) >= 2 else None
    return province, city


def iter_records(q: QQwry):
    """遍历纯真库所有 index 记录，yield (start_ip_int, end_ip_int, area, isp)。"""
    data = q.data
    begin = q.index_begin
    count = q.index_count
    for i in range(count):
        off = begin + i * 7
        start_ip = struct.unpack("<I", data[off : off + 4])[0]
        # 下一条的起始 IP - 1 即本条结束
        if i + 1 < count:
            noff = begin + (i + 1) * 7
            next_start = struct.unpack("<I", data[noff : noff + 4])[0]
            end_ip = next_start - 1 if next_start > start_ip else start_ip
        else:
            end_ip = 0xFFFFFFFF
        res = q.lookup(dbmod.int_to_ip(start_ip))
        if not res:
            continue
        area, isp = res
        yield start_ip, end_ip, area, isp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="导入全部记录（默认只导 edu 相关）")
    ap.add_argument("--file", default=QQWRY_FILE)
    args = ap.parse_args()

    q = QQwry()
    if not q.load_file(args.file):
        print(f"加载 {args.file} 失败")
        return

    conn = dbmod.connect()
    dbmod.init_db(conn)
    # 离线导入用独立表结构：直接写 ranges，但这里 cidr 存的是任意起止段而非严格 /24
    conn.execute("DELETE FROM ranges WHERE source='qqwry'")
    conn.commit()

    total = q.index_count
    kept = 0
    schools_seen: set[str] = set()
    print(f"纯真库共 {total} 条记录，开始遍历...", flush=True)

    batch = []
    for n, (s, e, area, isp) in enumerate(iter_records(q), 1):
        if not args.all and not is_edu(area, isp):
            continue
        school = clean_school(area, isp)
        province, city = parse_area_province_city(area)
        s_ip, e_ip = dbmod.int_to_ip(s), dbmod.int_to_ip(e)
        cidr = f"{s_ip}-{e_ip}"  # 纯真是任意区间，非 /24；用起止表示
        noise = 1 if dbmod.is_noise_school(school, isp) else 0
        batch.append((s, e, cidr, school, province, city, isp, "qqwry", noise))
        kept += 1
        if school:
            schools_seen.add(school)
        if len(batch) >= 2000:
            conn.executemany(
                """INSERT OR REPLACE INTO ranges
                   (ip_start, ip_end, cidr, school, province, city, isp, source, is_noise, updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,datetime('now'))""",
                batch,
            )
            conn.commit()
            batch = []
        if n % 200000 == 0:
            print(f"  遍历 {n}/{total}，已收教育网记录 {kept}，学校 {len(schools_seen)}", flush=True)

    if batch:
        conn.executemany(
            """INSERT OR REPLACE INTO ranges
               (ip_start, ip_end, cidr, school, province, city, isp, source, is_noise, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,datetime('now'))""",
            batch,
        )
        conn.commit()

    print("=== 导入完成 ===", flush=True)
    print(f"教育网/高校记录: {kept}")
    print(f"去重学校数: {len(schools_seen)}")
    conn.close()


if __name__ == "__main__":
    main()
