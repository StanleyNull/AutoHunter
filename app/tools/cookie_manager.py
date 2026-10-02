from __future__ import annotations

import json
import re
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse

from app.config import worker_config

_EXPIRED_URL = re.compile(r"(?i)(?:/login|/signin|/cas/login|/sso/|/auth/login)")
_EXPIRED_BODY = re.compile(r"(?i)(请(?:先)?登录|未登录|登录超时|session expired|unauthorized|重新登录)")


def site_key(url_or_host: str) -> str:
    raw = (url_or_host or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        return (urlparse(raw).hostname or "").lower().lstrip(".")
    except Exception:
        return raw.lower()


def looks_expired(result: dict, had_cookies: bool) -> bool:
    if not had_cookies or not isinstance(result, dict) or not result.get("ok"):
        return False
    try:
        status = int(result.get("status_code") or 0)
    except (TypeError, ValueError):
        status = 0
    final = str(result.get("final_url") or result.get("url") or "")
    body = result.get("body") or result.get("response_body") or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "ignore")
    body = str(body)[:8000]
    if status == 401:
        return True
    if status == 403 and _EXPIRED_BODY.search(body):
        return True
    if _EXPIRED_URL.search(final) and (_EXPIRED_BODY.search(body) or status in (302, 303, 307, 308)):
        return True
    # 很多后台登录墙仍返回 200，正文写「请登录」
    if status == 200 and _EXPIRED_BODY.search(body[:2000]):
        return True
    return False


def _cookie_key(entry: dict) -> tuple[str, str, str]:
    return (
        str(entry.get("name") or ""),
        str(entry.get("domain") or ""),
        str(entry.get("path") or "/"),
    )


def _merge_jar(old: list[dict], new: list[dict]) -> list[dict]:
    merged: dict[tuple[str, str, str], dict[str, str]] = {}
    for src in (old, new):
        for raw in src or []:
            if not isinstance(raw, dict) or not raw.get("name"):
                continue
            merged[_cookie_key(raw)] = {
                "name": str(raw.get("name")),
                "value": str(raw.get("value") or "")[:4096],
                "domain": str(raw.get("domain") or ""),
                "path": str(raw.get("path") or "/"),
            }
    return list(merged.values())


class CookieSlot:
    def __init__(self) -> None:
        self.cond = threading.Condition()
        self.cookie_jar: list[dict[str, str]] = []
        self.cookies: dict[str, str] = {}
        self.headers: dict[str, str] = {}
        self.creds: dict[str, str] = {}
        self.status: str = ""
        self.updated_at: float = 0.0
        self.last_relogin: float = 0.0
        self.login_in_flight = False
        self.loaded = False


class CookieManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._slots: dict[str, CookieSlot] = {}

    def _sid(self, task_id: str, host: str) -> str:
        return f"{task_id or '-'}|{site_key(host)}"

    def slot(self, task_id: str, host: str) -> CookieSlot:
        sid = self._sid(task_id, host)
        with self._lock:
            slot = self._slots.get(sid)
            if slot is None:
                slot = CookieSlot()
                self._slots[sid] = slot
        if not slot.loaded:
            self._load(sid, slot)
        return slot

    def _dir(self) -> Path:
        d = Path(worker_config.work_root) / "_cookie_jars"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _path(self, sid: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in sid)[:160]
        return self._dir() / f"{safe}.json"

    def _load(self, sid: str, slot: CookieSlot) -> None:
        with slot.cond:
            if slot.loaded:
                return
            slot.loaded = True
            p = self._path(sid)
            if not p.is_file():
                return
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                return
            if not isinstance(data, dict):
                return
            jar = data.get("cookie_jar")
            cookies = data.get("cookies")
            headers = data.get("headers")
            creds = data.get("creds")
            if isinstance(jar, list):
                slot.cookie_jar = [dict(e) for e in jar if isinstance(e, dict) and e.get("name")]
            if isinstance(cookies, dict):
                slot.cookies = {str(k): str(v)[:4096] for k, v in cookies.items()}
            if isinstance(headers, dict):
                slot.headers = {str(k): str(v)[:4096] for k, v in headers.items()}
            if isinstance(creds, dict):
                slot.creds = {
                    k: str(v) for k, v in creds.items()
                    if k in ("username", "password", "login_url") and v
                }
            slot.status = str(data.get("status") or "")[:40]
            try:
                slot.updated_at = float(data.get("updated_at") or 0)
            except (TypeError, ValueError):
                slot.updated_at = 0.0

    def _save(self, task_id: str, host: str, slot: CookieSlot) -> None:
        sid = self._sid(task_id, host)
        payload = {
            "cookies": dict(slot.cookies),
            "cookie_jar": [dict(e) for e in slot.cookie_jar],
            "headers": dict(slot.headers),
            "creds": dict(slot.creds),
            "status": slot.status,
            "updated_at": slot.updated_at,
        }
        try:
            p = self._path(sid)
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            tmp.replace(p)
        except Exception:
            pass

    def has_session(self, task_id: str, host: str) -> bool:
        slot = self.slot(task_id, host)
        with slot.cond:
            return bool(slot.cookies or slot.headers)

    def remember_creds(
        self,
        task_id: str,
        host: str,
        username: str = "",
        password: str = "",
        login_url: str = "",
    ) -> None:
        if not (username and password):
            return
        slot = self.slot(task_id, host)
        with slot.cond:
            slot.creds = {
                "username": str(username),
                "password": str(password),
                "login_url": str(login_url or ""),
            }
            self._save(task_id, host, slot)

    def remember_from_auth_context(self, task_id: str, host: str, ctx: dict | None) -> None:
        src = dict(ctx or {})
        self.remember_creds(
            task_id, host,
            username=str(src.get("username") or ""),
            password=str(src.get("password") or ""),
            login_url=str(src.get("login_url") or ""),
        )
        cookies = src.get("cookies") if isinstance(src.get("cookies"), dict) else {}
        headers = src.get("headers") if isinstance(src.get("headers"), dict) else {}
        if not (cookies or headers):
            return
        slot = self.slot(task_id, host)
        with slot.cond:
            if cookies:
                slot.cookies.update({str(k): str(v)[:4096] for k, v in cookies.items() if k})
                extra = [
                    {"name": str(k), "value": str(v)[:4096], "domain": site_key(host), "path": "/"}
                    for k, v in cookies.items() if k
                ]
                slot.cookie_jar = _merge_jar(slot.cookie_jar, extra)
            if headers:
                slot.headers.update({str(k): str(v)[:4096] for k, v in headers.items() if k})
            self._save(task_id, host, slot)

    def apply(self, executor: Any, task_id: str, host: str) -> bool:
        slot = self.slot(task_id, host)
        with slot.cond:
            if not (slot.cookie_jar or slot.cookies or slot.headers):
                return False
            jar = [dict(e) for e in slot.cookie_jar]
            cookies = dict(slot.cookies)
            headers = dict(slot.headers)
        restore = getattr(executor, "restore_resume_state", None)
        if callable(restore):
            restore(
                session_cookies=cookies or None,
                session_headers=headers or None,
                session_cookie_jar=jar or None,
            )
            return bool(getattr(executor, "_session_cookies", None) or getattr(executor, "_session_headers", None))
        return False

    def ingest(self, executor: Any, task_id: str, host: str, status: str = "") -> None:
        cookies = dict(getattr(executor, "_session_cookies", None) or {})
        jar = [dict(e) for e in (getattr(executor, "_cookie_jar", None) or [])]
        headers = dict(getattr(executor, "_session_headers", None) or {})
        if not (cookies or jar or headers):
            return
        slot = self.slot(task_id, host)
        with slot.cond:
            if jar:
                slot.cookie_jar = _merge_jar(slot.cookie_jar, jar)
            if cookies:
                slot.cookies.update({str(k): str(v)[:4096] for k, v in cookies.items()})
            if headers:
                slot.headers.update(headers)
            if status:
                slot.status = status[:40]
            slot.updated_at = time.time()
            slot.cond.notify_all()
            self._save(task_id, host, slot)

    @contextmanager
    def login_turn(self, task_id: str, host: str, timeout: float = 90.0) -> Iterator[str]:
        """Return login/reuse/timeout; only the login turn owns the shared flag."""
        slot = self.slot(task_id, host)
        deadline = time.monotonic() + max(1.0, timeout)
        action = "login"
        with slot.cond:
            while slot.login_in_flight:
                remain = deadline - time.monotonic()
                if remain <= 0:
                    break
                slot.cond.wait(timeout=min(2.0, remain))
            if slot.cookies or slot.headers:
                action = "reuse"
            elif slot.login_in_flight:
                action = "timeout"
            else:
                slot.login_in_flight = True
                action = "login"
        try:
            yield action
        finally:
            if action == "login":
                with slot.cond:
                    slot.login_in_flight = False
                    slot.cond.notify_all()


_MANAGER = CookieManager()


def get_manager() -> CookieManager:
    return _MANAGER


class CookieHub:
    def __init__(self, task_id: str, target: str) -> None:
        self.task_id = task_id or ""
        self.target = target or ""
        self.host = site_key(target)
        self.bootstrapping = False
        self._mgr = get_manager()

    def remember_from_auth_context(self, ctx: dict | None) -> None:
        self._mgr.remember_from_auth_context(self.task_id, self.host, ctx)

    def has_session(self) -> bool:
        return self._mgr.has_session(self.task_id, self.host)

    def apply(self, executor: Any) -> bool:
        return self._mgr.apply(executor, self.task_id, self.host)

    def ingest(self, executor: Any, status: str = "") -> None:
        self._mgr.ingest(executor, self.task_id, self.host, status=status)

    def login_turn(self, timeout: float = 90.0):
        return self._mgr.login_turn(self.task_id, self.host, timeout=timeout)

    def creds(self) -> dict[str, str]:
        slot = self._mgr.slot(self.task_id, self.host)
        with slot.cond:
            return dict(slot.creds)

    def can_relogin(self) -> bool:
        slot = self._mgr.slot(self.task_id, self.host)
        with slot.cond:
            creds = slot.creds
            if not (creds.get("username") and creds.get("password")):
                return False
            if time.time() - slot.last_relogin < 60:
                return False
            slot.last_relogin = time.time()
            return True

    def pull(self, executor: Any) -> None:
        if self.bootstrapping:
            return
        self.apply(executor)

    def push(self, executor: Any) -> None:
        if self.bootstrapping:
            return
        self.ingest(executor)

    def maybe_relogin(self, executor: Any, result: dict) -> bool:
        if self.bootstrapping:
            return False
        had = bool(getattr(executor, "_session_cookies", None))
        if not looks_expired(result, had):
            return False
        if not self.can_relogin():
            self.apply(executor)
            return False
        creds = self.creds()
        if not (creds.get("username") and creds.get("password")):
            return False
        from app.agents.auth_bootstrap import login_origin, try_user_login
        self.bootstrapping = True
        try:
            verdict = try_user_login(
                executor,
                login_origin(self.target) or self.target,
                creds["username"],
                creds["password"],
                creds.get("login_url") or "",
            )
        finally:
            self.bootstrapping = False
        if verdict.get("ok"):
            self.ingest(executor, status="login_ok")
            return True
        return False
