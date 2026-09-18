"""代理池服务：挖洞出口 IP 管理 + 被封后按需轮换。

设计（v2，面向 WAF 封禁对抗）：
- 配置存 SystemSettings.proxy JSON 列（enabled + proxies[]），启动时加载进内存快照。
- acquire(exclude_ids)：round-robin 轮转分配，跳过停用/冷却中/已被该目标用废的。
- report_failure/report_success：连续 3 次连接类失败 → 冷却 60s（WAF 封禁不算代理失败，
  由 executor 的 _used_proxy_ids 记忆层处理，不在这报）。
- 全部不可用（未启用/用尽/全冷却）→ acquire 返回 None = 直连兜底，绝不阻断挖洞。

线程安全：executor 在 worker/killsweep/escalate 多线程里共用，锁保护全部可变状态。
"""
from __future__ import annotations

import itertools
import threading
import time
from typing import Any
from urllib.parse import quote, urlsplit

from app.settings_service import is_masked_secret, mask_secret

PROXY_PROTOCOLS = {"http", "https", "socks5"}
# 连续这么多次连接失败 → 冷却
FAIL_THRESHOLD = 3
# 冷却时长（秒）
COOLDOWN_SECONDS = 60
MAX_PROXIES = 200

_LOCK = threading.Lock()
# 内存快照：{"enabled": bool, "by_id": {id: entry}, "order": [id, ...]}
_state: dict[str, Any] = {"enabled": False, "by_id": {}, "order": []}
# 每代理运行态：失败计数 / 冷却截止时间戳
_health: dict[str, dict[str, float]] = {}
_rr = itertools.count()
_seq = itertools.count(1)


# ── 文本解析（导入用） ──────────────────────────────────────────

def _normalize_protocol(raw: str) -> str:
    p = (raw or "").strip().lower().rstrip(":/")
    if p in ("socks", "socks5h"):
        return "socks5"
    return p if p in PROXY_PROTOCOLS else ""


def parse_proxy_line(line: str) -> dict[str, Any] | None:
    """解析一行代理文本。支持三种格式：

    1. scheme://[user:pass@]host:port   —— http://1.2.3.4:8080 / socks5://u:p@1.2.3.4:1080
    2. protocol|host|port[|user|pass]   —— socks5|1.2.3.4|1080|user|pass
    3. host:port[|user|pass]            —— 1.2.3.4:8080（默认 http）

    密码支持 URL 编码（%40 等），解析时自动解码。返回 dict 或 None（非法行）。
    """
    raw = (line or "").strip()
    if not raw or raw.startswith("#"):
        return None
    protocol = "http"
    host = ""
    port = ""
    username = ""
    password = ""
    try:
        if "://" in raw:
            parts = urlsplit(raw)
            protocol = _normalize_protocol(parts.scheme)
            host = (parts.hostname or "").strip()
            port = str(parts.port or "")
            username = parts.username or ""
            password = parts.password or ""
            if not protocol or not host or not port:
                return None
        else:
            seg = [s.strip() for s in raw.split("|")]
            if len(seg) >= 3 and _normalize_protocol(seg[0]):
                protocol = _normalize_protocol(seg[0])
                host, port = seg[1], seg[2]
                if len(seg) >= 4:
                    username = seg[3]
                if len(seg) >= 5:
                    password = seg[4]
            elif len(seg) >= 1 and ":" in seg[0]:
                host, _, port = seg[0].rpartition(":")
                host = host.strip()
                port = port.strip()
                if len(seg) >= 2:
                    username = seg[1]
                if len(seg) >= 3:
                    password = seg[2]
            else:
                return None
    except ValueError:
        return None
    host = host.strip("[]").strip()
    try:
        port_num = int(port)
    except (TypeError, ValueError):
        return None
    if not (1 <= port_num <= 65535) or not host or " " in host:
        return None
    from urllib.parse import unquote

    return {
        "protocol": protocol,
        "host": host,
        "port": port_num,
        "username": unquote(username),
        "password": unquote(password),
    }


def parse_proxy_text(text: str) -> tuple[list[dict[str, Any]], int]:
    """批量解析导入文本。返回 (解析成功的代理列表, 非法行数)。按 scheme+host+port 去重。"""
    seen: set[tuple[str, str, int]] = set()
    out: list[dict[str, Any]] = []
    invalid = 0
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        parsed = parse_proxy_line(line)
        if parsed is None:
            invalid += 1
            continue
        key = (parsed["protocol"], parsed["host"].lower(), parsed["port"])
        if key in seen:
            invalid += 1
            continue
        seen.add(key)
        out.append(parsed)
    return out, invalid


def proxy_url(item: dict[str, Any]) -> str:
    """拼 httpx 代理 URL。密码特殊字符做 URL 编码。"""
    auth = ""
    user = str(item.get("username") or "")
    pwd = str(item.get("password") or "")
    if user or pwd:
        auth = f"{quote(user, safe='')}:{quote(pwd, safe='')}@"
    return f"{item['protocol']}://{auth}{item['host']}:{item['port']}"


# ── 内部工具 ──────────────────────────────────────────────────

def _clean_entry(item: Any, index: int) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    protocol = _normalize_protocol(str(item.get("protocol") or ""))
    host = str(item.get("host") or "").strip().strip("[]")
    try:
        port = int(item.get("port"))
    except (TypeError, ValueError):
        return None
    if not protocol or not host or not (1 <= port <= 65535) or " " in host:
        return None
    name = str(item.get("name") or "").strip() or f"proxy-{index}"
    pid = str(item.get("id") or "").strip() or f"px-{index}-{int(time.time() * 1000)}"
    return {
        "id": pid[:64],
        "name": name[:80],
        "protocol": protocol,
        "host": host,
        "port": port,
        "username": str(item.get("username") or ""),
        "password": str(item.get("password") or ""),
        "enabled": item.get("enabled") is not False,
    }


def _health_of(pid: str) -> dict[str, float]:
    return _health.setdefault(pid, {"fails": 0.0, "cooldown_until": 0.0})


# ── 加载 / 视图 ───────────────────────────────────────────────

def apply_config(cfg: Any) -> None:
    """用 DB 里 SystemSettings.proxy 的 dict 重建内存快照（服务端启动/保存时调用）。"""
    if not isinstance(cfg, dict):
        cfg = {}
    entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(cfg.get("proxies") or []):
        entry = _clean_entry(raw, index)
        if entry is None or entry["id"] in seen_ids:
            continue
        seen_ids.add(entry["id"])
        entries.append(entry)
    with _LOCK:
        _state["enabled"] = cfg.get("enabled") is True
        _state["by_id"] = {e["id"]: e for e in entries}
        _state["order"] = [e["id"] for e in entries]
        for pid in list(_health):
            if pid not in _state["by_id"]:
                _health.pop(pid, None)


def snapshot_view() -> dict[str, Any]:
    """API 返回视图：密码脱敏，附运行态（冷却/失败计数）。"""
    now = time.time()
    with _LOCK:
        enabled = _state["enabled"]
        entries = [_state["by_id"][pid] for pid in _state["order"] if pid in _state["by_id"]]
    out = []
    for e in entries:
        h = _health.get(e["id"]) or {}
        cooldown_until = float(h.get("cooldown_until") or 0.0)
        user_part = f"{e['username']}@" if e.get("username") else ""
        out.append({
            **{k: v for k, v in e.items() if k != "password"},
            "password": "",
            "password_set": bool(e.get("password")),
            "password_masked": mask_secret(e.get("password") or ""),
            "display": f"{e['protocol']}://{user_part}{e['host']}:{e['port']}",
            "status": "cooldown" if cooldown_until > now else "ok",
            "cooldown_remaining_sec": max(0, int(cooldown_until - now)),
            "consecutive_failures": int(h.get("fails") or 0),
        })
    return {"enabled": enabled, "proxies": out}


def enabled() -> bool:
    with _LOCK:
        return _state["enabled"]


def available_count(exclude_ids: set[str] | None = None) -> int:
    exclude = exclude_ids or set()
    now = time.time()
    with _LOCK:
        if not _state["enabled"]:
            return 0
        return sum(
            1
            for pid in _state["order"]
            if pid not in exclude
            and _state["by_id"][pid]["enabled"]
            and float((_health.get(pid) or {}).get("cooldown_until") or 0.0) <= now
        )


def acquire(exclude_ids: set[str] | None = None) -> dict[str, Any] | None:
    """轮转取下一个可用代理。排除 excluded（该目标已用废的）/停用/冷却中。

    返回 {"id","url","label"} 或 None（无可用 → 调用方直连兜底）。
    """
    exclude = exclude_ids or set()
    now = time.time()
    with _LOCK:
        if not _state["enabled"] or not _state["order"]:
            return None
        n = len(_state["order"])
        start = next(_rr) % n
        for offset in range(n):
            pid = _state["order"][(start + offset) % n]
            if pid in exclude:
                continue
            entry = _state["by_id"].get(pid)
            if not entry or not entry["enabled"]:
                continue
            if float((_health.get(pid) or {}).get("cooldown_until") or 0.0) > now:
                continue
            return {
                "id": pid,
                "url": proxy_url(entry),
                "label": f"{entry['name']}({entry['protocol']}://{entry['host']}:{entry['port']})",
            }
    return None


# ── 健康上报 ──────────────────────────────────────────────────

def report_failure(proxy_id: str) -> bool:
    """连接类失败上报。连续 FAIL_THRESHOLD 次 → 冷却。返回是否进入冷却。"""
    with _LOCK:
        if proxy_id not in _state["by_id"]:
            return False
        h = _health_of(proxy_id)
        h["fails"] = float(h.get("fails") or 0.0) + 1.0
        if h["fails"] >= FAIL_THRESHOLD:
            h["cooldown_until"] = time.time() + COOLDOWN_SECONDS
            h["fails"] = 0.0
            return True
    return False


def report_success(proxy_id: str) -> None:
    with _LOCK:
        h = _health.get(proxy_id)
        if h:
            h["fails"] = 0.0
            h["cooldown_until"] = 0.0


def clear_cooldown(proxy_id: str) -> None:
    """API 测试按钮连通成功后手动解除冷却。"""
    with _LOCK:
        h = _health.get(proxy_id)
        if h:
            h["fails"] = 0.0
            h["cooldown_until"] = 0.0


# ── 配置写路径（由 api/proxy.py 调用，落 DB + 刷新内存） ─────────

def normalize_proxies_payload(items: Any, old_proxies: list[dict] | None = None) -> list[dict[str, Any]]:
    """清洗前端提交的代理列表；密码为脱敏占位时回填旧值（同 LLM key 模式）。"""
    old = {str(o.get("id")): o for o in (old_proxies or []) if isinstance(o, dict)}
    out: list[dict[str, Any]] = []
    for index, item in enumerate(items if isinstance(items, list) else []):
        entry = _clean_entry(item, index)
        if entry is None:
            continue
        pwd = str(item.get("password") or "")
        if (not pwd or is_masked_secret(pwd)) and entry["id"] in old:
            pwd = str(old[entry["id"]].get("password") or "")
        entry["password"] = pwd
        out.append(entry)
    return out[:MAX_PROXIES]


def config_from_view(enabled_flag: Any, proxies: list[dict[str, Any]]) -> dict[str, Any]:
    return {"enabled": bool(enabled_flag), "proxies": proxies}


async def init_proxy_cache() -> None:
    """启动时由 main.py 调用：从 DB 读 proxy 列并重建内存快照。"""
    from app.db.session import SessionLocal
    from app.db.models import SystemSettings

    async with SessionLocal() as session:
        row = await session.get(SystemSettings, "global")
        apply_config(row.proxy if row else {})
