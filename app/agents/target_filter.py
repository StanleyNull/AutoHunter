"""成功路径驱动的资产过滤/优选。

目标：在 worker 前面做一层保守筛选，把明显难出货的展示型资产挡掉；
同时把历史出洞路径/接口特征明显的资产抬到队列前面。

原则：
- 只过滤机械确定的低价值目标；拿不准就放行。
- 手动目标、单站协作、深挖/通杀目标不走这里。
- 高产路径只做加分和解释，不等于漏洞结论。
"""
from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
import os
import re
import time
from urllib.parse import urljoin, urlparse

import httpx


@dataclass(frozen=True)
class FilterDecision:
    skip: bool
    reason: str = ""
    score_bonus: float = 0.0
    bonus_reason: str = ""


@dataclass
class SiteProfile:
    final_url: str = ""
    status: int = 0
    title: str = ""
    server: str = ""
    content_type: str = ""
    body_len: int = 0
    form_count: int = 0
    password_inputs: int = 0
    scripts: list[str] | None = None
    links: list[str] | None = None
    interesting_paths: list[str] | None = None
    api_paths: list[str] | None = None
    success_paths: list[str] | None = None
    frameworks: list[str] | None = None
    errors: list[str] | None = None
    text_sample: str = ""

    def attack_surface_count(self) -> int:
        return (
            self.form_count
            + self.password_inputs
            + len(_active_surface_paths(self.interesting_paths or []))
            + len(_active_surface_paths(self.api_paths or []))
            + len(self.success_paths or [])
        )


@dataclass(frozen=True)
class SuccessSignal:
    name: str
    bonus: float
    patterns: tuple[str, ...]


SUCCESS_SIGNALS: tuple[SuccessSignal, ...] = (
    SuccessSignal("success_path:swagger_openapi", 2.0, (
        "/api/swagger-resources", "/prod-api/swagger-resources", "/v2/api-docs",
        "/v3/api-docs", "/prod-api/v2/api-docs", "/prod-api/v3/api-docs",
        "/api/v2/api-docs", "/api/v3/api-docs", "/swagger-ui", "/knife4j",
    )),
    SuccessSignal("success_path:upload_file", 4.0, (
        "/admin/ajax/upload", "/api/upload", "/api/file/upload", "/api/dev/file/uploadlocalreturnurl",
        "/base/commons/resources/ueditor", "/ueditor/service", "/file_manager_json",
        "/upload_json", "/server/douploadimage", "/zslogin/testlogin",
    )),
    SuccessSignal("success_path:config_secret", 4.0, (
        "/config.js", "/js/config.js", "/appconfig.js",
        "/syscommon/getezconfig", "/rest/sys/parameter/findparameters",
        "/api/rest/sys/parameter/findparameters", "/api/session/properties",
        "/admin/sysplatforminfo/base/info", "/sys/config/oss", "/api/oss/endpoint/sts",
        "/api/init/settings", "/api/frontend/settings", "/api/config/get",
        "/api/system/loginconfig/getloginconfig",
    )),
    SuccessSignal("success_path:ruoyi_init_password", 3.0, (
        "/prod-api/system/config/configkey/sys.user.initpassword",
        "/admin-api/system/config/configkey/sys.user.initpassword",
        "/api/system/config/configkey/sys.user.initpassword",
        "/system/config/configkey/sys.user.initpassword",
        "/tduck-api/system/config/configkey/sys.user.initpassword",
    )),
    SuccessSignal("success_path:auth_token", 3.5, (
        "/api/blade-auth/oauth/token", "/api/auth/oauth/token", "/api/auth/oauth2/token",
        "/api/v3/login/internal", "/api/bigdata/loginbyuserid",
        "/api/uap/unauthorize/login", "/api/user/login", "/clientuser/login/passwordlogin",
        "/serverapi/admin-api/system/auth/login",
    )),
    SuccessSignal("success_path:reset_otp", 3.0, (
        "/api/v1/password/reset_code", "/declaration/register/getcode.do",
        "/login/getlogincode", "/api/sendcode", "/api/user/sendcode", "/api/user/sendsms",
        "/home/sendcode", "/user/ajaxgetforgotpasswordmessagevalidatecode",
        "/api/auth/reset-password", "/api/login/resetting-pwd",
    )),
    SuccessSignal("success_path:user_data", 3.5, (
        "/user/get_user_by_phone", "/api/user/getryxxbysfzh", "/api/user/queryteachersforroleassign",
        "/api/dataall/getdataalllist", "/api/courses/1/members", "/api/isb/lab-report-detail",
        "/api/isb/lab-report-content", "/api/system/user/list", "/prod-api/system/user/list",
        "/admin-api/system/user/list",
    )),
    SuccessSignal("success_path:debug_leak", 3.0, (
        "/.env", "/trace.axd", "/index.php?s=", "/index.php?r=", "/actuator",
        "/actuator/env", "/metrics", "/server-status",
    )),
    SuccessSignal("success_path:webservice_report", 2.5, (
        "/webreport/reportserver", "/webreport", "/ssoservice.asmx",
        "/zas/ajax/invoke", "/synmiddletable/synpersonmiddletable",
    )),
)

_GENERIC_API_RE = re.compile(
    r"/(?:api|prod-api|admin-api|dev-api|rest|service|system|auth|oauth|user|upload|file|download|export|import|swagger|actuator|metrics|webreport|ueditor|kindeditor)/",
    re.I,
)
_FORM_OR_LOGIN_RE = re.compile(r"<form\b|type=[\"']password[\"']|登录|login|sign.?in|forgot|reset|验证码|captcha", re.I)
_SCRIPT_APP_RE = re.compile(r"<script\b|vue|react|webpack|/static/js/|/assets/[^\"']+\.js", re.I)
_LOW_VALUE_TITLE_RE = re.compile(
    r"(官网|首页|新闻网|新闻中心|门户网站|学院概况|学校概况|信息公开|招生网|研究生院|图书馆首页|"
    r"official|homepage|news|portal)",
    re.I,
)
_AUTH_GATEWAY_RE = re.compile(r"(统一身份认证|统一认证|认证平台|CAS|SSO|authserver|idsLogin|登录中心)", re.I)
_OPEN_REDIRECT_ONLY_RE = re.compile(r"/(?:cas|esc-sso)/logout\?service=|open redirect|phish", re.I)
_STATIC_HOST_RE = re.compile(r"^(?:www|news|xcb|www2)\.", re.I)
_BUSINESS_APP_RE = re.compile(
    r"(管理平台|管理系统|后台|控制台|数据库|信息服务|服务管理|移动信息|门户|"
    r"portal|admin|manage|manager|console|dashboard)",
    re.I,
)
_POSITIVE_PRIORITY_LEAD_RE = re.compile(
    r"\+\d+(?:\.\d+)?\s+(?:oss_cloud_storage|admin_backend|top_cold_custom|data_interactive|"
    r"mobile_open_api|face_iot_access|spa_with_api|wechat_platform|enterprise_|api_surface)|"
    r"(?:minio|bucket|oss|后台|管理|上传|导入|导出|开放平台|接口|api)",
    re.I,
)
_MAX_BODY_BYTES = int(os.environ.get("TARGET_FILTER_MAX_BODY_BYTES", "250000"))
_MAX_JS_ASSETS = int(os.environ.get("TARGET_FILTER_MAX_JS_ASSETS", "2"))
_MAX_DISCOVERY_PAGES = int(os.environ.get("TARGET_FILTER_MAX_DISCOVERY_PAGES", "3"))
_MAX_PROBE_PATHS = int(os.environ.get("TARGET_FILTER_MAX_PROBE_PATHS", "6"))
_TARGET_FILTER_TIMEOUT = float(os.environ.get("TARGET_FILTER_TIMEOUT", "2.0"))
_TARGET_FILTER_BUDGET = float(os.environ.get("TARGET_FILTER_BUDGET", "8.0"))
_UA = {"User-Agent": "Mozilla/5.0 (compatible; AutoHunter-TargetFilter)"}
_API_PATH_RE = re.compile(
    r"""(?P<q>["'`])(?P<path>/(?:api|prod-api|admin-api|dev-api|rest|service|system|auth|oauth|user|users|upload|file|download|export|import|swagger|actuator|metrics|webreport|ueditor|kindeditor|blade|sysCommon|clientUser|serverApi)[A-Za-z0-9_./?=&:%-]{0,240})(?P=q)""",
    re.I,
)
_LOOSE_PATH_RE = re.compile(
    r"""(?P<path>/(?:api|prod-api|admin-api|dev-api|v\d+/|rest|service|system|auth|oauth|user|users|upload|file|download|export|import|swagger|actuator|metrics|webreport|ueditor|kindeditor|blade|sysCommon|clientUser|serverApi)[A-Za-z0-9_./?=&:%-]{1,240})""",
    re.I,
)
_INTERESTING_PATH_RE = re.compile(
    r"/(?:login|logon|signin|auth|sso|cas|admin|manager|console|system|user|register|reset|forgot|"
    r"password|captcha|upload|file|swagger|api-docs|knife4j|druid|nacos|actuator|config)(?:/|$|[?._-])",
    re.I,
)
_LOW_VALUE_PATH_RE = re.compile(
    r"/(?:news|article|notice|info|content|page|list|detail|xwzx|tzgg|xxgk|xygk|xyxw|"
    r"images?|css|fonts?|static|assets?)(?:/|$|[?._-])",
    re.I,
)
_STATIC_RESOURCE_RE = re.compile(
    r"(?:^|/)(?:static|assets?|images?|img|css|js|fonts?|system/resource|_css|_web/_search)/|"
    r"\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|map|pdf|docx?|xlsx?|pptx?|zip|rar|7z)(?:$|[?#])",
    re.I,
)
_MEDIA_UPLOAD_ARCHIVE_RE = re.compile(
    r"/(?:uploadfile|uploads?|uploadfiles?)/(?:\d{4}/(?:\d{1,2}(?:/\d{1,2})?|\d{4})|thumb|image|images|pic|pics|photo|photos)(?:/|$)",
    re.I,
)
_BUILD_OR_LOCAL_PATH_RE = re.compile(
    r"^/(?:users/[^/]+|home/[^/]+|private/var|var/folders|tmp|node_modules|webpack|src|dist|build)(?:/|$)",
    re.I,
)
_SEMANTIC_SURFACE_RE = re.compile(
    r"(api|admin|prod|dev|rest|service|system|auth|oauth|user|upload|file|download|export|import|swagger|"
    r"actuator|metrics|webreport|ueditor|kindeditor|blade|syscommon|clientuser|serverapi|login|logon|"
    r"password|captcha|config|reset|sendcode|sms)",
    re.I,
)
_FRAMEWORK_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("vue_spa", ("vue", "__webpack", "/assets/", "/static/js/")),
    ("react_spa", ("react", "reactdom", "__next", "vite")),
    ("ruoyi", ("ruoyi", "若依", "prod-api", "captchaimage")),
    ("jeecg", ("jeecg", "jeecg-boot")),
    ("blade", ("blade-auth", "saber", "bladex")),
    ("swagger", ("swagger-ui", "api-docs", "knife4j")),
    ("thinkphp", ("thinkphp", "index.php?s=")),
)
_PROBE_PATHS = (
    "/api/swagger-resources",
    "/prod-api/swagger-resources",
    "/v2/api-docs",
    "/v3/api-docs",
    "/prod-api/v2/api-docs",
    "/prod-api/v3/api-docs",
    "/config.js",
    "/js/config.js",
    "/appconfig.js",
    "/.env",
    "/actuator",
    "/api/session/properties",
    "/sysCommon/getEzConfig",
    "/prod-api/system/config/configKey/sys.user.initPassword",
    "/admin/ajax/upload",
)


class _SurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []
        self.links: list[str] = []
        self.form_count = 0
        self.password_inputs = 0
        self._in_title = False
        self._title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_d = {k.lower(): v or "" for k, v in attrs}
        tag_l = tag.lower()
        if tag_l == "title":
            self._in_title = True
        elif tag_l == "script" and attrs_d.get("src"):
            self.scripts.append(attrs_d["src"])
        elif tag_l in {"a", "link"}:
            href = attrs_d.get("href")
            if href:
                self.links.append(href)
        elif tag_l == "form":
            self.form_count += 1
            action = attrs_d.get("action")
            if action:
                self.links.append(action)
        elif tag_l == "input" and attrs_d.get("type", "").lower() == "password":
            self.password_inputs += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and data:
            self._title_parts.append(data.strip())

    @property
    def title(self) -> str:
        return " ".join(x for x in self._title_parts if x).strip()[:200]


def analyze_site_surface(
    url: str,
    *,
    host: str = "",
    title_hint: str = "",
    body_hint: str = "",
    timeout: float = _TARGET_FILTER_TIMEOUT,
    max_js: int = _MAX_JS_ASSETS,
    budget: float = _TARGET_FILTER_BUDGET,
) -> SiteProfile:
    """轻量分析一个站点的真实攻击面。

    步骤：
    1. GET 首页，跟随跳转，记录状态/标题/Server/Content-Type。
    2. HTML 解析 form/password/script/link。
    3. 从 HTML 提取 API/上传/配置/认证等路径。
    4. 拉取少量同源 JS，再提取隐藏 API 路径和框架指纹。
    5. 探测少量历史高产端点，只记录 200/401/403 等“存在”信号。
    """
    profile = SiteProfile(
        final_url=url,
        title=title_hint or "",
        scripts=[],
        links=[],
        interesting_paths=[],
        api_paths=[],
        success_paths=[],
        frameworks=[],
        errors=[],
        text_sample=(body_hint or "")[:20_000],
    )
    base = url if "://" in url else f"http://{url}"
    deadline = time.monotonic() + max(1.0, budget)

    def has_budget() -> bool:
        return time.monotonic() < deadline

    def request_timeout() -> float:
        return max(0.25, min(timeout, deadline - time.monotonic()))

    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=True, headers=_UA) as client:
            resp = client.get(base, timeout=request_timeout())
            body = (resp.text or "")[:_MAX_BODY_BYTES]
            profile.final_url = str(resp.url)
            profile.status = resp.status_code
            profile.server = resp.headers.get("server", "")
            profile.content_type = resp.headers.get("content-type", "")
            profile.body_len = len(body)
            profile.text_sample = "\n".join([profile.text_sample, body[:50_000]])

            parser = _SurfaceParser()
            try:
                parser.feed(body)
            except Exception as exc:
                profile.errors.append(f"html_parse:{type(exc).__name__}")
            profile.title = parser.title or profile.title
            profile.form_count = parser.form_count
            profile.password_inputs = parser.password_inputs
            profile.scripts = _same_origin_urls(parser.scripts, profile.final_url, suffixes=(".js", ".mjs"))[:max_js]
            profile.links = _normalize_paths(parser.links, profile.final_url)[:80]
            profile.interesting_paths = _interesting_paths(profile.links)
            profile.api_paths = _extract_paths(body)
            _extend_unique(profile.api_paths, [
                p for p in (profile.links or []) if _GENERIC_API_RE.search(p) or _INTERESTING_PATH_RE.search(p)
            ], limit=160)

            js_texts: list[str] = []
            for script_url in profile.scripts[:max_js]:
                if not has_budget():
                    profile.errors.append("budget:js")
                    break
                try:
                    js_resp = client.get(script_url, timeout=request_timeout())
                    if js_resp.status_code >= 400:
                        continue
                    js_body = (js_resp.text or "")[:_MAX_BODY_BYTES]
                    js_texts.append(js_body)
                    _extend_unique(profile.api_paths, _extract_paths(js_body), limit=180)
                except Exception:
                    continue

            discovery_texts: list[str] = []
            for page_path in _discovery_pages(profile.links or [], profile.final_url, limit=_MAX_DISCOVERY_PAGES):
                if not has_budget():
                    profile.errors.append("budget:discovery")
                    break
                try:
                    page_resp = client.get(
                        urljoin(origin_safe(profile.final_url or base) + "/", page_path.lstrip("/")),
                        timeout=request_timeout(),
                    )
                    if page_resp.status_code >= 500:
                        continue
                    content_type = page_resp.headers.get("content-type", "")
                    if "html" not in content_type.lower() and "text" not in content_type.lower():
                        continue
                    page_body = (page_resp.text or "")[:_MAX_BODY_BYTES]
                    discovery_texts.append(page_body[:60_000])
                    page_parser = _SurfaceParser()
                    try:
                        page_parser.feed(page_body)
                    except Exception:
                        pass
                    profile.form_count += page_parser.form_count
                    profile.password_inputs += page_parser.password_inputs
                    page_links = _normalize_paths(page_parser.links, str(page_resp.url))
                    _extend_unique(profile.links, page_links, limit=120)
                    _extend_unique(profile.interesting_paths, _interesting_paths(page_links), limit=60)
                    _extend_unique(profile.api_paths, _extract_paths(page_body), limit=180)
                    _extend_unique(profile.api_paths, [
                        p for p in page_links if _GENERIC_API_RE.search(p) or _INTERESTING_PATH_RE.search(p)
                    ], limit=180)
                    _extend_unique(profile.scripts, _same_origin_urls(page_parser.scripts, str(page_resp.url), suffixes=(".js", ".mjs")), limit=max_js + 2)
                except Exception:
                    continue

            profile.frameworks = _detect_frameworks("\n".join([body[:60_000], *js_texts, *discovery_texts]))
            profile.success_paths = _matched_success_paths("\n".join([
                body[:60_000], *js_texts, *discovery_texts,
                "\n".join(profile.api_paths), "\n".join(profile.interesting_paths or []),
            ]))

            origin = _origin(profile.final_url or base)
            for probe_path in _PROBE_PATHS[:max(0, _MAX_PROBE_PATHS)]:
                if not has_budget():
                    profile.errors.append("budget:probe")
                    break
                if probe_path in profile.success_paths:
                    continue
                try:
                    probe_resp = client.get(
                        urljoin(origin + "/", probe_path.lstrip("/")),
                        timeout=request_timeout(),
                    )
                    if probe_resp.status_code in (200, 401, 403):
                        text = (probe_resp.text or "")[:5000].lower()
                        if _probe_response_looks_present(probe_path, probe_resp.status_code, text):
                            profile.success_paths.append(probe_path)
                except Exception:
                    continue
    except Exception as exc:
        profile.errors.append(f"fetch:{type(exc).__name__}")
        profile.text_sample = "\n".join([profile.text_sample, title_hint or "", body_hint or ""])

    profile.api_paths = sorted(set(profile.api_paths or []))[:120]
    profile.success_paths = sorted(set(profile.success_paths or []))[:40]
    profile.frameworks = sorted(set(profile.frameworks or []))
    return profile


def evaluate_target(
    *,
    url: str,
    host: str = "",
    title: str = "",
    body: str = "",
    priority_score: float = 0.0,
    priority_reason: str = "",
    source: str = "fofa",
    leaked_creds: list | None = None,
    profile: SiteProfile | None = None,
) -> FilterDecision:
    """评估候选资产是否应跳过/加权。

    `body` 建议传首页/FOFA body snippet；函数内部只取前 20KB，避免大文本开销。
    """
    if source != "fofa" or leaked_creds:
        return FilterDecision(False)

    if profile is None:
        profile = SiteProfile(
            final_url=url,
            status=200 if body else 0,
            title=title,
            body_len=len(body or ""),
            form_count=1 if _FORM_OR_LOGIN_RE.search(body or "") else 0,
            password_inputs=1 if "password" in (body or "").lower() else 0,
            scripts=[],
            links=[],
            interesting_paths=[],
            api_paths=_extract_paths(body or ""),
            success_paths=_matched_success_paths(body or ""),
            frameworks=_detect_frameworks(body or ""),
            errors=[],
            text_sample=(body or "")[:20_000],
        )

    combined = "\n".join([
        url or "", host or "", title or "", profile.title or "",
        priority_reason or "", profile.text_sample[:20_000],
        "\n".join(profile.links or []), "\n".join(profile.interesting_paths or []),
        "\n".join(profile.api_paths or []), "\n".join(profile.success_paths or []),
        "\n".join(profile.frameworks or []),
    ])
    signal_text = "\n".join([
        url or "", host or "", title or "", profile.title or "",
        profile.text_sample[:20_000],
        "\n".join(profile.links or []), "\n".join(profile.interesting_paths or []),
        "\n".join(profile.api_paths or []), "\n".join(profile.success_paths or []),
        "\n".join(profile.frameworks or []),
    ]).lower()
    identity_text = "\n".join([
        title or "", profile.title or "",
        priority_reason or "", profile.text_sample[:20_000],
        "\n".join(profile.frameworks or []),
    ])
    low = combined.lower()
    active_api_paths = _active_surface_paths(profile.api_paths or [])
    active_interesting_paths = _active_surface_paths(profile.interesting_paths or [])
    api_surface = len(active_api_paths)
    surface_text = "\n".join([
        url or "", host or "", title or "", profile.title or "",
        profile.text_sample[:20_000],
        "\n".join(active_interesting_paths),
        "\n".join(active_api_paths),
        "\n".join(profile.success_paths or []),
        "\n".join(profile.frameworks or []),
    ])
    surface_low = surface_text.lower()

    matched: list[str] = []
    bonus = 0.0
    for signal in SUCCESS_SIGNALS:
        if any(pattern in signal_text for pattern in signal.patterns):
            matched.append(signal.name)
            bonus += signal.bonus
            if len(matched) >= 4:
                break
    if matched:
        only_weak_swagger = (
            matched == ["success_path:swagger_openapi"]
            and api_surface < 3
            and "swagger" not in (profile.frameworks or [])
        )
        if not only_weak_swagger:
            return FilterDecision(False, score_bonus=min(10.0, bonus), bonus_reason=" · ".join(matched))

    has_api = bool(active_api_paths)
    has_interesting_path = bool(active_interesting_paths or _INTERESTING_PATH_RE.search(surface_text))
    has_form_or_login = bool(profile.form_count or profile.password_inputs or has_interesting_path or _FORM_OR_LOGIN_RE.search(surface_text))
    # “有 script 标签”不等于有攻击面：jQuery/统计脚本/官网动效不能保护目标。
    # 只有框架型 SPA、构建产物、或 JS 中已抽出 API 时才算值得继续。
    has_script_app = bool(profile.frameworks or _SCRIPT_APP_RE.search(combined))
    has_success_path = bool(profile.success_paths)
    low_score = priority_score <= 0.5
    has_business_identity = bool(_BUSINESS_APP_RE.search(identity_text))
    has_positive_priority_lead = bool(_POSITIVE_PRIORITY_LEAD_RE.search(priority_reason or ""))

    parsed_host = host or urlparse(url if "://" in url else f"http://{url}").netloc
    staticish_homepage = (
        low_score
        and not _has_fetch_error(profile)
        and profile.status > 0
        and profile.status < 400
        and profile.body_len > 0
        and not has_api
        and not has_form_or_login
        and not has_script_app
        and not has_success_path
        and (_LOW_VALUE_TITLE_RE.search(identity_text) or _STATIC_HOST_RE.search(parsed_host or ""))
    )
    if staticish_homepage:
        return FilterDecision(True, "站点画像过滤：官网/新闻/展示型资产，未发现表单、登录、API、JS接口或历史高产路径")

    open_redirect_only = _OPEN_REDIRECT_ONLY_RE.search(combined) and not any(
        marker in surface_low for marker in ("token", "ticket", "session", "oauth", "/api/", "password", "reset")
    )
    if open_redirect_only:
        return FilterDecision(True, "成功路径过滤：纯 CAS/OpenRedirect/钓鱼跳转链路，EduSRC 低收录价值")

    auth_gateway_only = (
        priority_score <= -1
        and not _has_fetch_error(profile)
        and _AUTH_GATEWAY_RE.search(combined)
        and not has_api
        and not has_form_or_login
        and not has_script_app
        and not has_success_path
    )
    if auth_gateway_only:
        return FilterDecision(True, "站点画像过滤：纯统一认证/CAS网关，未发现业务API、表单后续入口或凭证线索")

    auth_gateway_weak = (
        low_score
        and _AUTH_GATEWAY_RE.search(combined)
        and not has_success_path
        and not has_positive_priority_lead
        and not any(marker in surface_low for marker in (
            "reset", "forgot", "captcha", "sendcode", "sms", "oauth/token",
            "/api/", "/prod-api/", "/admin-api/", "password",
        ))
    )
    if auth_gateway_weak:
        return FilterDecision(False, score_bonus=-1.5, bonus_reason="weak_auth_gateway:认证网关未发现重置/验证码/API后续链路，降权排后")

    no_discovered_surface = (
        low_score
        and profile.status > 0
        and profile.status < 400
        and profile.body_len > 0
        and (_LOW_VALUE_TITLE_RE.search(identity_text) or _STATIC_HOST_RE.search(parsed_host or ""))
        and profile.attack_surface_count() == 0
        and not has_script_app
        and not has_success_path
    )
    if no_discovered_surface:
        return FilterDecision(True, "站点画像过滤：首页可访问，但首页/JS/高产端点均未发现表单、登录、API或可验证攻击面")

    weak_or_empty_surface = (
        low_score
        and profile.status > 0
        and profile.status < 500
        and profile.body_len > 0
        and profile.attack_surface_count() == 0
        and not has_success_path
        and not has_script_app
        and not has_business_identity
        and not has_positive_priority_lead
    )
    if weak_or_empty_surface:
        return FilterDecision(False, score_bonus=-2.0, bonus_reason="weak_surface:画像未发现表单/API/高产端点，降权排后")

    low_value_link_farm = (
        low_score
        and profile.status > 0
        and profile.status < 500
        and len(profile.links or []) >= 12
        and not has_api
        and not has_form_or_login
        and not has_success_path
        and not has_script_app
        and _mostly_low_value_links(profile.links or [])
    )
    if low_value_link_farm:
        return FilterDecision(False, score_bonus=-2.0, bonus_reason="weak_link_farm:链接集中在新闻/文章/静态资源，降权排后")

    if low_score and api_surface >= 6 and not has_success_path:
        return FilterDecision(False, score_bonus=1.5, bonus_reason="api_surface:画像发现多个API/后台路径，提前派发")

    # 低分但有 SPA/脚本时放行：JS 里可能藏 API/secret，交给 worker 的 JS 分析工具。
    if priority_score < -3 and not _has_fetch_error(profile) and not has_api and not has_form_or_login and not has_script_app:
        return FilterDecision(True, "站点画像过滤：极低分且无 API/登录/JS 攻击面")

    return FilterDecision(False)


def _origin(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else url.rstrip("/")


def _same_origin_urls(values: list[str], base_url: str, *, suffixes: tuple[str, ...]) -> list[str]:
    origin = _origin(base_url)
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value.startswith(("data:", "blob:", "javascript:")):
            continue
        absolute = urljoin(base_url, value)
        parsed = urlparse(absolute)
        if f"{parsed.scheme}://{parsed.netloc}" != origin:
            continue
        if suffixes and not parsed.path.lower().endswith(suffixes):
            continue
        if absolute not in seen:
            seen.add(absolute)
            out.append(absolute)
    return out


def _normalize_paths(values: list[str], base_url: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value.startswith(("data:", "blob:", "javascript:", "#", "mailto:")):
            continue
        absolute = urljoin(base_url, value)
        parsed = urlparse(absolute)
        path = parsed.path or "/"
        if parsed.query:
            keys = []
            for part in parsed.query.split("&")[:8]:
                key = part.split("=", 1)[0]
                if key:
                    keys.append(key + "=")
            if keys:
                path += "?" + "&".join(keys)
        if path not in seen:
            seen.add(path)
            out.append(path[:260])
    return out


def origin_safe(url: str) -> str:
    return _origin(url)


def _extend_unique(target: list[str] | None, values: list[str], *, limit: int) -> None:
    if target is None:
        return
    seen = set(target)
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        target.append(value[:260])
        if len(target) >= limit:
            return


def _interesting_paths(paths: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if _INTERESTING_PATH_RE.search(path or "") and path not in seen:
            seen.add(path)
            out.append(path[:260])
        if len(out) >= 60:
            break
    return out


def _discovery_pages(paths: list[str], base_url: str, *, limit: int) -> list[str]:
    origin_path = urlparse(base_url if "://" in base_url else f"http://{base_url}").path or "/"
    ranked: list[tuple[int, str]] = []
    seen: set[str] = set()
    for path in paths:
        if not path or path in seen:
            continue
        seen.add(path)
        low = path.lower()
        if not _INTERESTING_PATH_RE.search(path):
            continue
        if low.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".pdf", ".doc", ".docx", ".xls", ".xlsx")):
            continue
        score = 0
        if any(x in low for x in ("login", "signin", "auth", "sso", "cas")):
            score += 6
        if any(x in low for x in ("admin", "manager", "console", "system")):
            score += 5
        if any(x in low for x in ("reset", "forgot", "password", "captcha", "sendcode")):
            score += 4
        if any(x in low for x in ("upload", "file", "config", "swagger", "api-docs", "knife4j")):
            score += 4
        if path == origin_path:
            score -= 3
        if score > 0:
            ranked.append((-score, path))
    ranked.sort()
    return [path for _, path in ranked[:max(0, limit)]]


def _mostly_low_value_links(paths: list[str]) -> bool:
    checked = [p for p in paths if p and p != "/"][:60]
    if len(checked) < 8:
        return False
    low_value = sum(1 for p in checked if _LOW_VALUE_PATH_RE.search(p))
    interesting = sum(1 for p in checked if _INTERESTING_PATH_RE.search(p) or _GENERIC_API_RE.search(p))
    return interesting == 0 and low_value / max(1, len(checked)) >= 0.65


def _active_surface_paths(paths: list[str]) -> list[str]:
    out: list[str] = []
    for path in paths:
        if not path:
            continue
        low = path.lower()
        if _STATIC_RESOURCE_RE.search(low):
            continue
        if _MEDIA_UPLOAD_ARCHIVE_RE.search(low):
            continue
        if _BUILD_OR_LOCAL_PATH_RE.search(low):
            continue
        if low.startswith(("/api.map.", "/v3.22.7/license", "/v3.22.7/")):
            continue
        if _looks_like_encoded_noise_path(path):
            continue
        out.append(path)
    return out


def _looks_like_encoded_noise_path(path: str) -> bool:
    """Filter paths extracted from compressed/base64 blobs, not real routes."""
    value = (path or "").strip()
    if not value or _SEMANTIC_SURFACE_RE.search(value):
        return False
    first = value.split("?", 1)[0].strip("/")
    if not first:
        return False
    segment = first.split("/", 1)[0]
    if len(segment) >= 18 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", segment):
        return True
    if re.fullmatch(r"v\d[A-Za-z0-9+/=_-]{2,}", segment):
        return True
    return False


def _has_fetch_error(profile: SiteProfile) -> bool:
    return any((err or "").startswith("fetch:") for err in (profile.errors or []))


def _extract_paths(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for pattern in (_API_PATH_RE, _LOOSE_PATH_RE):
        for match in pattern.finditer(text or ""):
            path = (match.groupdict().get("path") or "").strip()
            if not path or path in seen:
                continue
            seen.add(path)
            out.append(path[:260])
            if len(out) >= 180:
                return out
    return out


def _detect_frameworks(text: str) -> list[str]:
    low = (text or "").lower()
    out = []
    for name, markers in _FRAMEWORK_MARKERS:
        if any(marker.lower() in low for marker in markers):
            out.append(name)
    return out


def _matched_success_paths(text: str) -> list[str]:
    low = (text or "").lower()
    out: list[str] = []
    seen: set[str] = set()
    for signal in SUCCESS_SIGNALS:
        for pattern in signal.patterns:
            if pattern in low and pattern not in seen:
                seen.add(pattern)
                out.append(pattern)
    return out


def _probe_body_looks_real(path: str, text: str) -> bool:
    if not text:
        return False
    p = path.lower()
    if "api-docs" in p or "swagger" in p:
        return "swagger" in text or "openapi" in text or '"paths"' in text
    if p.endswith(".js"):
        if "<html" in text or "<!doctype" in text:
            return False
        return "api" in text or "config" in text or "baseurl" in text or "cas" in text
    if p == "/.env":
        return "app_key" in text or "db_password" in text or "database" in text
    if "actuator" in p:
        return "_links" in text or "status" in text or "propertysources" in text
    if "config" in p or "properties" in p or "system" in p or "syscommon" in p:
        return "code" in text or "data" in text or "config" in text or "appid" in text
    if "upload" in p:
        return "upload" in text or "file" in text or "success" in text
    return len(text) > 80


def _probe_response_looks_present(path: str, status_code: int, text: str) -> bool:
    """Decide whether a probe response is a real endpoint, not a blanket WAF/404 page."""
    p = path.lower()
    if status_code == 200:
        return _probe_body_looks_real(path, text)
    if status_code not in (401, 403):
        return False
    # Swagger/config probes are frequently blocked by generic 403 pages; require body evidence.
    if "swagger" in p or "api-docs" in p or p.endswith(".js") or "config" in p or p == "/.env":
        return _probe_body_looks_real(path, text)
    if "actuator" in p:
        return "_links" in text or "status" in text or "propertysources" in text or "unauthorized" in text
    if "upload" in p:
        return "upload" in text or "file" in text
    return False
