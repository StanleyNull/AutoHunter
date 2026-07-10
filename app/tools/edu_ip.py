"""教育网 IP → 高校归属查询（离线，纯真库导出的本地 SQLite）。

用于写报告时把目标 IP/域名反查成「所属高校」，供 EduSRC 报告标题/归属单位使用。

- 数据文件：app/data_static/edu_ip.db（随镜像打包，只读）。
- 查询只读、线程安全（check_same_thread=False + 只读连接），失败时静默返回 None，
  绝不因归属查询异常影响主流程。
"""
from __future__ import annotations

import ipaddress
import re
import socket
import sqlite3
import threading
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

_DB_PATH = Path(__file__).resolve().parent.parent / "data_static" / "edu_ip.db"

_conn: sqlite3.Connection | None = None
_conn_lock = threading.Lock()
_read_lock = threading.Lock()  # 共享连接跨线程读时串行化（查询是微秒级，无性能影响）


def _get_conn() -> sqlite3.Connection | None:
    global _conn
    if _conn is not None:
        return _conn
    with _conn_lock:
        if _conn is not None:
            return _conn
        if not _DB_PATH.exists():
            return None
        try:
            c = sqlite3.connect(f"file:{_DB_PATH}?mode=ro", uri=True,
                                check_same_thread=False, timeout=5)
            c.row_factory = sqlite3.Row
            _conn = c
        except Exception:
            return None
    return _conn


def _host_from_target(target: str) -> str | None:
    t = (target or "").strip()
    if not t:
        return None
    if "://" not in t:
        t = "http://" + t
    try:
        host = urlparse(t).hostname
    except Exception:
        host = None
    return host or None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@lru_cache(maxsize=8192)
def _resolve_host(host: str) -> str | None:
    """域名 → IP。带缓存；解析失败/超时返回 None。

    注意：不使用 socket.setdefaulttimeout（那是全局副作用，会污染 httpx 等）。
    这里用 getaddrinfo，本函数应在线程池里调用，超时由调用方 wait 控制上限。
    """
    if _is_ip(host):
        return host
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
        for info in infos:
            return info[4][0]
    except Exception:
        return None
    return None


def _lookup_ip(ip: str) -> sqlite3.Row | None:
    conn = _get_conn()
    if conn is None:
        return None
    try:
        n = int(ipaddress.ip_address(ip))
    except ValueError:
        return None
    try:
        with _read_lock:
            # 优先真高校（非噪音）；命中范围最小者最精确；无则回退含噪音
            row = conn.execute(
                "SELECT school, province, city, isp FROM ranges "
                "WHERE ip_start <= ? AND ip_end >= ? AND is_noise = 0 "
                "ORDER BY (ip_end - ip_start) ASC LIMIT 1",
                (n, n),
            ).fetchone()
            if row is None:
                row = conn.execute(
                    "SELECT school, province, city, isp FROM ranges "
                    "WHERE ip_start <= ? AND ip_end >= ? "
                    "ORDER BY (ip_end - ip_start) ASC LIMIT 1",
                    (n, n),
                ).fetchone()
        return row
    except Exception:
        return None


# 学校名清洗：去掉「教育网/校区/院系/宿舍」等后缀，尽量归到主校名
_SUFFIX_RE = re.compile(
    r"(教育网.*|无线.*|宿舍.*|公寓.*|校区.*|分校.*|学生.*|住宅.*|机房.*|"
    r"实验室.*|中心.*|研究院.*|研究生院.*|附属中学.*|附中.*|\(.*\)|（.*）).*$"
)


def _clean_school_name(name: str | None) -> str | None:
    if not name:
        return None
    s = name.strip()
    # 若含「大学/学院」，截取到第一个「大学」或「学院」结尾，去掉后面的校区/院系
    m = re.search(r"^(.*?(?:大学|学院|学校))", s)
    base = m.group(1) if m else _SUFFIX_RE.sub("", s)
    base = base.strip()
    return base or s


def lookup_school(target: str) -> dict | None:
    """输入 target_url / 域名 / IP，返回 {school, school_full, province, city} 或 None。

    school      = 清洗后的主校名（如「清华大学」），适合做报告标题/归属；
    school_full = 原始细分名（如「清华大学教育网无线校园项目」），保留备查。
    """
    host = _host_from_target(target)
    if not host:
        return None
    ip = _resolve_host(host)
    if not ip:
        return None
    row = _lookup_ip(ip)
    if row is None or not row["school"]:
        return None
    full = row["school"]
    return {
        "school": _clean_school_name(full),
        "school_full": full,
        "province": row["province"],
        "city": row["city"],
        "ip": ip,
    }


def school_name(target: str) -> str | None:
    """便捷：只要主校名，查不到返回 None（同步，可能触发 DNS，勿在事件循环里直接调）。"""
    info = lookup_school(target)
    return info["school"] if info else None


def _lookup_no_dns(target: str) -> dict | None:
    """仅当 target 本身是 IP 时查库；是域名则不解析、直接返回 None（零阻塞）。"""
    host = _host_from_target(target)
    if not host or not _is_ip(host):
        return None
    row = _lookup_ip(host)
    if row is None or not row["school"]:
        return None
    full = row["school"]
    return {
        "school": _clean_school_name(full),
        "school_full": full,
        "province": row["province"],
        "city": row["city"],
        "ip": host,
    }


async def lookup_school_async(target: str, timeout: float = 3.0) -> dict | None:
    """事件循环安全版：
    - target 是 IP：纯查库（微秒级，无网络）。
    - target 是域名：DNS + 查库放线程池执行，最长等待 timeout 秒，超时返回 None。
    任何异常/超时都返回 None，绝不阻塞事件循环、绝不抛给上层。
    """
    import asyncio

    try:
        # 纯 IP 直接同步查库（不涉及 DNS，快且无阻塞风险）
        fast = _lookup_no_dns(target)
        if fast is not None:
            return fast
        host = _host_from_target(target)
        if not host or _is_ip(host):
            # 是 IP 但没命中，或无 host —— 无需再走 DNS
            return None
        loop = asyncio.get_running_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, lookup_school, target), timeout=timeout
        )
    except Exception:
        return None


def school_name_no_dns(target: str) -> str | None:
    """仅 IP 命中返回校名；域名一律返回 None（零阻塞，可安全用于批量/列表）。"""
    info = _lookup_no_dns(target)
    return info["school"] if info else None
