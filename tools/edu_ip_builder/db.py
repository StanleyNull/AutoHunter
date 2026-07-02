"""SQLite 库：IP 段 → 高校归属（数据源：纯真离线库 qqwry）。

- ranges 表存任意起止 IP 区间（纯真库是变长区间，非固定 /24），用整数起止建索引反查。
- 反查 O(log n)：命中 ip_start <= n <= ip_end 中范围最小（最精确）的那条。
"""
from __future__ import annotations

import ipaddress
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).with_name("edu_ip.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS ranges (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_start    INTEGER NOT NULL,
    ip_end      INTEGER NOT NULL,
    cidr        TEXT    NOT NULL,      -- 展示用：起止 IP 字符串（纯真为变长区间）
    school      TEXT,                  -- 学校名（已从原始 area/isp 提炼）
    province    TEXT,
    city        TEXT,
    isp         TEXT,                  -- 原始运营商/归属串，保留供核对
    source      TEXT DEFAULT 'qqwry',
    is_noise    INTEGER DEFAULT 0,     -- 1=网吧/宾馆/承建公司等非高校本体记录
    updated_at  TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ranges_start  ON ranges(ip_start);
CREATE INDEX IF NOT EXISTS idx_ranges_end    ON ranges(ip_end);
CREATE INDEX IF NOT EXISTS idx_ranges_school ON ranges(school);
CREATE INDEX IF NOT EXISTS idx_ranges_noise  ON ranges(is_noise);
"""

# 非高校本体的噪音关键词：网吧/宾馆/承建商业公司/培训机构/民宅商铺等
NOISE_KEYWORDS = (
    # 商铺/民用
    "网吧", "网咖", "网苑", "网络会所", "会所", "宾馆", "酒店", "旅馆", "招待所",
    "餐厅", "饭店", "餐馆", "超市", "咖啡", "商铺", "门面", "小卖部", "公寓楼",
    # 商业公司/承建商/机房
    "有限公司", "有限责任公司", "分公司", "科技开发", "信息技术有限",
    "长城宽带", "赛尔网络", "IDC机房", "机房", "数据中心",
    "腾讯", "阿里", "百度", "华为", "字节", "京东",
    "中国移动", "中国电信", "中国联通", "移动教育网", "电信教育网", "联通教育网",
    # 培训机构（非学历高校）
    "电脑学校", "培训学校", "培训中心", "教育培训", "职业培训", "补习",
    "驾校", "驾驶学校", "新华电脑", "北大青鸟",
    # 方位噪音（"XX大学对面/北门"这类蹭名商铺）
    "对面", "门外", "北门", "南门", "东门", "西门", "附近", "旁边", "对过", "隔壁",
)


def is_noise_school(school: str | None, isp: str | None = "") -> bool:
    """判断一条记录是否为「非高校本体」噪音。宁可漏判也别误杀真高校。"""
    if not school:
        return False
    text = f"{school} {isp or ''}"
    return any(k in text for k in NOISE_KEYWORDS)


def connect(db_path: Path | str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def ip_to_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


def int_to_ip(n: int) -> str:
    return str(ipaddress.ip_address(n))


def lookup_ip(conn: sqlite3.Connection, ip: str, include_noise: bool = False) -> sqlite3.Row | None:
    n = ip_to_int(ip)
    noise_clause = "" if include_noise else "AND is_noise = 0 "
    row = conn.execute(
        f"SELECT * FROM ranges WHERE ip_start <= ? AND ip_end >= ? {noise_clause}"
        "ORDER BY (ip_end - ip_start) ASC LIMIT 1",
        (n, n),
    ).fetchone()
    if row is None and not include_noise:
        # 真高校没命中时，回退到含噪音（至少给个归属线索）
        return lookup_ip(conn, ip, include_noise=True)
    return row


def stats(conn: sqlite3.Connection) -> dict:
    ranges_n = conn.execute("SELECT COUNT(*) FROM ranges").fetchone()[0]
    clean = conn.execute("SELECT COUNT(*) FROM ranges WHERE is_noise = 0").fetchone()[0]
    noise = conn.execute("SELECT COUNT(*) FROM ranges WHERE is_noise = 1").fetchone()[0]
    schools = conn.execute(
        "SELECT COUNT(DISTINCT school) FROM ranges "
        "WHERE school IS NOT NULL AND school != '' AND is_noise = 0"
    ).fetchone()[0]
    with_school = conn.execute(
        "SELECT COUNT(*) FROM ranges WHERE school IS NOT NULL AND school != '' AND is_noise = 0"
    ).fetchone()[0]
    return {
        "ranges": ranges_n,
        "ranges_clean": clean,
        "ranges_noise": noise,
        "ranges_with_school": with_school,
        "distinct_schools": schools,
    }
