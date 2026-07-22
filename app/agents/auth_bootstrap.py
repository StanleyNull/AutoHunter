"""用户提供的登录凭据：解析类型、按目标匹配、启动必试注入/登录。

不提供凭据时整条链路无操作（兼容现状）。事件/状态只暴露 kinds 与字段名，不出明文。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

# ---- 解析 ----

_BEARER_RE = re.compile(r"(?i)\bBearer\s+(\S+)")
_AUTH_HEADER_RE = re.compile(r"(?i)^\s*Authorization\s*:\s*(.+)$", re.M)
_COOKIE_HEADER_RE = re.compile(r"(?i)^\s*Cookie\s*:\s*(.+)$", re.M)
_USER_PASS_LINE = re.compile(
    r"(?i)(?:用户名|账号|帐号|账户|username|user)\s*[:=：]\s*(\S+).{0,40}?"
    r"(?:密码|password|passwd|pwd)\s*[:=：]\s*(\S+)"
)
_SLASH_PAIR = re.compile(r"(?i)^\s*([^\s/]{1,64})\s*/\s*([^\s]{1,128})\s*$")
_KV_COOKIE = re.compile(r"^[A-Za-z0-9_.\-]+=\S+")


def _strip(s: Any) -> str:
    return str(s or "").strip()


def parse_cookie_string(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    text = _strip(raw)
    if not text:
        return out
    text = re.sub(r"(?i)^Cookie\s*:\s*", "", text).strip()
    for part in text.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        k, v = k.strip(), v.strip()
        if k:
            out[k] = v
    return out


def normalize_binding(raw: dict | None) -> dict[str, Any]:
    """把一条用户 binding 规范化，并标出 kinds。"""
    src = dict(raw or {})
    target = _strip(src.get("target")) or "*"
    username = _strip(src.get("username"))
    password = _strip(src.get("password"))
    cookie = _strip(src.get("cookie"))
    authorization = _strip(src.get("authorization") or src.get("Authorization"))
    login_url = _strip(src.get("login_url"))
    note = _strip(src.get("note"))
    blob = _strip(src.get("raw"))

    cookies: dict[str, str] = {}
    headers: dict[str, str] = {}

    if blob:
        m = _AUTH_HEADER_RE.search(blob)
        if m and not authorization:
            authorization = m.group(1).strip()
        m = _COOKIE_HEADER_RE.search(blob)
        if m and not cookie:
            cookie = m.group(1).strip()
        m = _BEARER_RE.search(blob)
        if m and not authorization:
            authorization = f"Bearer {m.group(1)}"
        m = _USER_PASS_LINE.search(blob)
        if m and not (username and password):
            username, password = m.group(1), m.group(2)
        if not (username and password):
            m = _SLASH_PAIR.match(blob.splitlines()[0] if blob else "")
            if m and "/" in blob.splitlines()[0] and "Cookie" not in blob[:40]:
                # 仅当整行像 user/pass 且不像 cookie 串
                line0 = blob.splitlines()[0].strip()
                if "=" not in line0 and _SLASH_PAIR.match(line0):
                    username, password = m.group(1), m.group(2)
        if not cookie and _KV_COOKIE.match(blob.split(";")[0].strip()):
            cookie = blob

    if cookie:
        cookies.update(parse_cookie_string(cookie))
    if authorization:
        if not re.match(r"(?i)^Bearer\s+", authorization) and not re.match(r"(?i)^\w+\s+", authorization):
            authorization = f"Bearer {authorization}"
        headers["Authorization"] = authorization

    kinds: list[str] = []
    if cookies:
        kinds.append("cookie")
    if headers.get("Authorization"):
        kinds.append("bearer")
    if username and password:
        kinds.append("password")

    return {
        "target": target,
        "username": username,
        "password": password,
        "cookie": cookie,
        "authorization": authorization,
        "login_url": login_url,
        "note": note,
        "cookies": cookies,
        "headers": headers,
        "kinds": kinds,
    }


def normalize_bindings(raw_list: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_list, list):
        return []
    out = []
    for item in raw_list:
        if not isinstance(item, dict):
            continue
        nb = normalize_binding(item)
        if nb["kinds"]:
            out.append(nb)
    return out


def has_any_bindings(raw_list: Any) -> bool:
    return bool(normalize_bindings(raw_list))


# ---- 匹配 ----

def _norm_url(u: str) -> str:
    u = _strip(u)
    if not u:
        return ""
    if "://" not in u:
        u = "http://" + u
    p = urlparse(u)
    path = p.path.rstrip("/") or ""
    netloc = (p.netloc or "").lower()
    return f"{p.scheme.lower()}://{netloc}{path}"


def _host_of(u: str) -> str:
    from app.urlnorm import is_bare_ipv6, safe_urlparse
    u = _strip(u)
    if not u:
        return ""
    if "://" not in u and "/" not in u:
        # 裸 IPv6 不能按 ':' 切（会截断成第一段）
        return u.lower() if is_bare_ipv6(u) else u.lower().split(":")[0]
    return (safe_urlparse(u).hostname or "").lower()


def _hostport_of(u: str) -> str:
    from app.urlnorm import is_bare_ipv6, safe_port, safe_urlparse
    u = _strip(u)
    if not u:
        return ""
    if "://" not in u and "/" not in u:
        return u.lower()
    p = safe_urlparse(u)
    host = (p.hostname or "").lower()
    if not host:
        return ""
    disp = f"[{host}]" if is_bare_ipv6(host) else host
    port = safe_port(p)
    if port:
        return f"{disp}:{port}"
    return disp


@dataclass
class MatchResult:
    matched: bool
    matched_by: str = ""
    binding_target: str = ""
    context: dict[str, Any] = field(default_factory=dict)


def match_auth_to_target(
    url: str,
    bindings: list[dict[str, Any]] | Any,
    manual_lines: list[str] | None = None,
) -> MatchResult:
    """按优先级把 bindings 绑到某个目标 URL；可合并多条命中。"""
    norms = normalize_bindings(bindings)
    if not norms:
        return MatchResult(matched=False)

    url_n = _norm_url(url)
    host = _host_of(url)
    hostport = _hostport_of(url)
    lines = [_strip(x) for x in (manual_lines or []) if _strip(x)]

    buckets: dict[str, list[dict]] = {
        "url": [], "line": [], "hostport": [], "host": [], "star": [],
    }
    for b in norms:
        key = _strip(b.get("target")) or "*"
        if key == "*":
            buckets["star"].append(b)
            continue
        if _norm_url(key) and _norm_url(key) == url_n:
            buckets["url"].append(b)
            continue
        if key in lines or _norm_url(key) in {_norm_url(x) for x in lines}:
            # 清单行：仅当该行确实指向当前 url
            for line in lines:
                if key == line or _norm_url(key) == _norm_url(line):
                    if _host_of(line) == host or _norm_url(line) == url_n:
                        buckets["line"].append(b)
                        break
            continue
        if _hostport_of(key) and _hostport_of(key) == hostport:
            buckets["hostport"].append(b)
            continue
        if _host_of(key) and _host_of(key) == host:
            buckets["host"].append(b)

    chosen: list[dict] = []
    matched_by = ""
    binding_target = ""
    for label in ("url", "line", "hostport", "host", "star"):
        if buckets[label]:
            chosen = buckets[label]
            matched_by = label if label != "star" else "default"
            binding_target = chosen[0].get("target") or "*"
            break

    if not chosen:
        return MatchResult(matched=False)

    merged = _merge_contexts(chosen)
    return MatchResult(
        matched=True,
        matched_by=matched_by,
        binding_target=binding_target,
        context=merged,
    )


def _merge_contexts(items: list[dict]) -> dict[str, Any]:
    cookies: dict[str, str] = {}
    headers: dict[str, str] = {}
    kinds: list[str] = []
    username = password = login_url = ""
    for it in items:
        cookies.update(it.get("cookies") or {})
        headers.update(it.get("headers") or {})
        if it.get("username") and it.get("password"):
            username, password = it["username"], it["password"]
        if it.get("login_url"):
            login_url = it["login_url"]
        for k in it.get("kinds") or []:
            if k not in kinds:
                kinds.append(k)
    return {
        "username": username,
        "password": password,
        "cookies": cookies,
        "headers": headers,
        "login_url": login_url,
        "kinds": kinds,
        "cookie_names": sorted(cookies.keys()),
        "header_names": sorted(headers.keys()),
    }


def resolve_auth_context_for_target(
    task_bindings: Any,
    url: str,
    manual_lines: list[str] | None = None,
) -> Optional[dict[str, Any]]:
    """入队时调用：匹配成功才返回 auth_context；未匹配返回 None（不刷 unused 到无关 FOFA 目标）。"""
    if not has_any_bindings(task_bindings):
        return None
    m = match_auth_to_target(url, task_bindings, manual_lines)
    if not m.matched:
        return None
    ctx = dict(m.context)
    ctx["matched"] = True
    ctx["matched_by"] = m.matched_by
    ctx["binding_target"] = m.binding_target
    return ctx


# ---- 启动必试 ----

@dataclass
class AuthAttemptResult:
    used: bool
    matched: bool
    status: str  # injected | login_ok | login_fail | unused
    kinds: list[str] = field(default_factory=list)
    matched_by: str = ""
    binding_target: str = ""
    reason: str = ""
    cookie_names: list[str] = field(default_factory=list)
    header_names: list[str] = field(default_factory=list)

    def as_event(self) -> dict[str, Any]:
        return {
            "used": self.used,
            "matched": self.matched,
            "status": self.status,
            "kinds": list(self.kinds),
            "matched_by": self.matched_by,
            "binding_target": self.binding_target,
            "reason": self.reason[:300],
            "cookie_names": list(self.cookie_names),
            "header_names": list(self.header_names),
        }

    def as_status(self) -> dict[str, Any]:
        return self.as_event()


_LOGIN_PATHS = ("/login", "/user/login", "/admin/login", "/account/login", "/signin")


def bootstrap_auth(executor: Any, auth_context: dict | None, base_url: str) -> AuthAttemptResult:
    """Worker 启动时调用：有 cookie/bearer 则注入；有账密则尝试登录。"""
    ctx = dict(auth_context or {})
    kinds = list(ctx.get("kinds") or [])
    matched = bool(ctx.get("matched", True))  # 旧数据缺省当已匹配
    matched_by = _strip(ctx.get("matched_by"))
    binding_target = _strip(ctx.get("binding_target"))

    if ctx.get("matched") is False or (not kinds and not ctx.get("cookies") and not ctx.get("headers")
                                       and not (ctx.get("username") and ctx.get("password"))):
        return AuthAttemptResult(
            used=False, matched=False, status="unused",
            reason="凭据区未匹配到本目标，未使用",
            matched_by=matched_by, binding_target=binding_target,
        )

    cookies = dict(ctx.get("cookies") or {})
    headers = dict(ctx.get("headers") or {})
    username = _strip(ctx.get("username"))
    password = _strip(ctx.get("password"))
    login_url = _strip(ctx.get("login_url"))

    if not kinds:
        if cookies:
            kinds.append("cookie")
        if headers.get("Authorization"):
            kinds.append("bearer")
        if username and password:
            kinds.append("password")

    if not kinds:
        return AuthAttemptResult(
            used=False, matched=matched, status="unused",
            reason="凭据为空", matched_by=matched_by, binding_target=binding_target,
        )

    # 1) Cookie / Bearer 注入
    if cookies or headers:
        r = executor.session_set(cookies=cookies or None, headers=headers or None)
        if not r.get("ok"):
            return AuthAttemptResult(
                used=True, matched=True, status="login_fail", kinds=kinds,
                matched_by=matched_by, binding_target=binding_target,
                reason=f"session_set 失败: {r.get('error', '')}"[:300],
                cookie_names=sorted(cookies.keys()),
                header_names=sorted(headers.keys()),
            )

    # 2) 仅会话注入、无账密
    if not (username and password):
        return AuthAttemptResult(
            used=True, matched=True, status="injected", kinds=kinds,
            matched_by=matched_by, binding_target=binding_target,
            reason="已注入用户提供的 Cookie/Authorization，后续请求自动携带",
            cookie_names=sorted(cookies.keys()) or list(getattr(executor, "_session_cookies", {}).keys())[:20],
            header_names=sorted(headers.keys()) or list(getattr(executor, "_session_headers", {}).keys())[:20],
        )

    # 3) 账密登录
    login_res = try_user_login(executor, base_url, username, password, login_url)
    status = "login_ok" if login_res.get("ok") else "login_fail"
    return AuthAttemptResult(
        used=True, matched=True, status=status, kinds=kinds,
        matched_by=matched_by, binding_target=binding_target,
        reason=_strip(login_res.get("reason") or login_res.get("error") or "")[:300],
        cookie_names=sorted(getattr(executor, "_session_cookies", {}).keys())[:30],
        header_names=sorted(getattr(executor, "_session_headers", {}).keys())[:20],
    )


def try_user_login(
    executor: Any,
    base_url: str,
    username: str,
    password: str,
    login_url: str = "",
) -> dict[str, Any]:
    """Best-effort 表单登录；成功则会话 jar 已吸收 Set-Cookie。"""
    base = _strip(base_url)
    if not base:
        return {"ok": False, "reason": "无目标 URL"}
    if "://" not in base:
        base = "http://" + base
    origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}"

    candidates: list[str] = []
    if login_url:
        candidates.append(login_url if "://" in login_url else urljoin(origin + "/", login_url.lstrip("/")))
    candidates.append(base)
    for p in _LOGIN_PATHS:
        candidates.append(urljoin(origin + "/", p.lstrip("/")))

    seen = set()
    last_reason = "未找到可用登录表单"
    for page_url in candidates:
        if page_url in seen:
            continue
        seen.add(page_url)
        get_r = executor.http_request(page_url, method="GET", follow_redirects=True, timeout=15)
        if not get_r.get("ok"):
            last_reason = f"打开登录页失败: {get_r.get('error') or get_r.get('status_code')}"
            continue
        body = get_r.get("body") or get_r.get("response_body") or ""
        if isinstance(body, bytes):
            body = body.decode("utf-8", "ignore")
        form = _extract_login_form(body, page_url)
        if not form:
            # JSON 风格：直接 POST 常见字段
            for api_path in ("/api/login", "/api/user/login", "/api/auth/login", "/login"):
                api_url = urljoin(origin + "/", api_path.lstrip("/"))
                if api_url in seen:
                    continue
                seen.add(api_url)
                post = executor.http_request(
                    api_url, method="POST",
                    json_body={"username": username, "password": password,
                               "userName": username, "account": username},
                    follow_redirects=True, timeout=15,
                )
                verdict = _judge_login_success(executor, post, origin)
                if verdict.get("ok"):
                    return verdict
                last_reason = verdict.get("reason") or last_reason
            last_reason = f"页面无登录表单: {page_url}"
            continue

        post_url = form["action"]
        data = dict(form["fields"])
        # 填用户名字段
        user_keys = [k for k in data if re.search(r"(?i)user|account|login|email|name", k)]
        pass_keys = [k for k in data if re.search(r"(?i)pass|pwd", k)]
        if not user_keys:
            user_keys = ["username"]
            data.setdefault("username", "")
        if not pass_keys:
            pass_keys = ["password"]
            data.setdefault("password", "")
        data[user_keys[0]] = username
        data[pass_keys[0]] = password

        body_enc = "&".join(f"{_q(k)}={_q(v)}" for k, v in data.items())
        post = executor.http_request(
            post_url, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=body_enc,
            follow_redirects=True, timeout=20,
        )
        verdict = _judge_login_success(executor, post, origin, form_url=page_url)
        if verdict.get("ok"):
            return verdict
        last_reason = verdict.get("reason") or last_reason

    return {"ok": False, "reason": last_reason}


def _q(s: str) -> str:
    from urllib.parse import quote_plus
    return quote_plus(str(s), safe="")


def _extract_login_form(html: str, page_url: str) -> Optional[dict[str, Any]]:
    if not html:
        return None
    # 找带 password 的 form
    forms = re.findall(r"(?is)<form\b[^>]*>.*?</form>", html)
    for form_html in forms:
        if not re.search(r'(?i)type=["\']?password', form_html):
            continue
        action_m = re.search(r'(?is)<form\b[^>]*\baction=["\']([^"\']*)["\']', form_html)
        action = (action_m.group(1) if action_m else "") or page_url
        action = urljoin(page_url, action)
        fields: dict[str, str] = {}
        for inp in re.finditer(r"(?is)<input\b[^>]*>", form_html):
            tag = inp.group(0)
            name_m = re.search(r'\bname=["\']([^"\']+)["\']', tag, re.I)
            if not name_m:
                continue
            name = name_m.group(1)
            val_m = re.search(r'\bvalue=["\']([^"\']*)["\']', tag, re.I)
            fields[name] = val_m.group(1) if val_m else ""
        return {"action": action, "fields": fields}
    return None


def _judge_login_success(
    executor: Any,
    post_result: dict,
    origin: str,
    form_url: str = "",
) -> dict[str, Any]:
    if not post_result.get("ok"):
        return {"ok": False, "reason": f"登录请求失败: {post_result.get('error') or post_result.get('status_code')}"}
    status = int(post_result.get("status_code") or 0)
    body = post_result.get("body") or post_result.get("response_body") or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "ignore")
    final_url = _strip(post_result.get("final_url") or post_result.get("url") or "")
    body_l = body.lower()

    if re.search(r"(验证码|captcha|太多次|锁定|locked|too many)", body_l):
        return {"ok": False, "reason": "登录失败：可能需要验证码或账号被锁定"}
    if status in (401, 403):
        return {"ok": False, "reason": f"登录失败：HTTP {status}"}
    if re.search(r"(密码错误|用户名或密码|login failed|invalid (user|password)|认证失败)", body_l):
        return {"ok": False, "reason": "登录失败：用户名或密码错误"}

    cookies = getattr(executor, "_session_cookies", {}) or {}
    sessionish = any(re.search(r"(?i)session|token|castgc|jwt|auth", k) for k in cookies)
    left_login = final_url and ("login" not in final_url.lower()) and (not form_url or final_url.rstrip("/") != form_url.rstrip("/"))
    json_ok = bool(re.search(r'"(code|status|success)"\s*:\s*(200|0|true|"ok")', body_l))

    if sessionish or left_login or json_ok or (status in (200, 302) and cookies):
        return {
            "ok": True,
            "reason": f"登录成功（cookies={len(cookies)}, final={final_url[:80] or origin}）",
        }
    return {"ok": False, "reason": "登录后未观察到有效会话 Cookie 或跳转，判定失败"}


def format_auth_status_message(result: AuthAttemptResult | dict) -> str:
    d = result.as_event() if isinstance(result, AuthAttemptResult) else dict(result)
    kinds = ",".join(d.get("kinds") or []) or "-"
    status = d.get("status") or "?"
    bind = d.get("binding_target") or "-"
    reason = d.get("reason") or ""
    if status == "unused":
        return f"凭据未使用：{reason or '未匹配本目标'}"
    if status == "injected":
        names = ",".join(d.get("cookie_names") or d.get("header_names") or []) or kinds
        return f"凭据[{kinds}] → 绑定 {bind} → 已注入 {names}"
    if status == "login_ok":
        return f"凭据[{kinds}] → 绑定 {bind} → 登录成功：{reason}"
    if status == "login_fail":
        return f"凭据[{kinds}] → 绑定 {bind} → 登录失败：{reason}"
    return f"凭据[{kinds}] → {status}：{reason}"


def user_auth_prompt_block(auth_context: dict | None, attempt: dict | None = None) -> str:
    """注入 worker 的用户凭据说明 + 系统尝试结果。"""
    ctx = dict(auth_context or {})
    if not ctx and not attempt:
        return ""
    lines = ["# 用户提供的登录凭据（入场券，登录成功本身不是洞）"]
    kinds = ctx.get("kinds") or []
    if kinds:
        lines.append(f"- 类型：{', '.join(kinds)}")
    if ctx.get("binding_target"):
        lines.append(f"- 绑定：{ctx.get('binding_target')}（匹配方式 {ctx.get('matched_by') or '-'}）")
    if ctx.get("cookie_names"):
        lines.append(f"- Cookie 名：{', '.join(ctx['cookie_names'])}")
    if ctx.get("header_names"):
        lines.append(f"- Header 名：{', '.join(ctx['header_names'])}")
    if ctx.get("username"):
        lines.append(f"- 账号：{ctx['username']} （密码已由系统持有，勿回显）")
    if ctx.get("login_url"):
        lines.append(f"- 登录 URL：{ctx['login_url']}")

    if attempt:
        st = attempt.get("status")
        lines.append(f"- 系统启动尝试：{attempt.get('status')} — {attempt.get('reason') or ''}")
        if st in ("injected", "login_ok"):
            lines.append("纪律：会话已就绪，直接带登录态深挖；禁止重复无效登录；只登录成功不算洞。")
        elif st == "login_fail":
            lines.append("纪律：系统登录未成功，可换登录入口/记录失败后继续测未授权面；勿反复空撞同一接口。")
        elif st == "unused":
            lines.append("纪律：本目标未匹配到凭据，按无登录态挖掘。")
    else:
        lines.append("纪律：必须先使用上述凭据登录或 session_set；登录成功后深挖越权/敏感数据/写操作。")
    return "\n".join(lines) + "\n\n"
