"""Single-site cooperative route definitions.

FOFA tasks are breadth-first.  A single-site task is different: the same real
host should be attacked by several focused workers, each responsible for a
route and feeding coverage back to the rest of the team.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse


@dataclass(frozen=True)
class SiteRoute:
    source: str
    label: str
    priority: float
    focus: str
    checklist: tuple[str, ...]
    finish_rule: str
    js_first: bool = False
    phase: int = 1


ROUTES: tuple[SiteRoute, ...] = (
    SiteRoute(
        source="site_map",
        label="入口/API 盘点",
        priority=180.0,
        focus="建立全站入口与 API 清单，优先覆盖 robots/sitemap/API 文档/前端路由/隐藏后台/非标路径。",
        checklist=(
            "抓首页、robots.txt、sitemap.xml、常见 API 文档、登录页和跳转链，整理入口地图。",
            "提取 JS/HTML 中的 API base、路由、接口前缀、权限入口和上传/导入/导出路径。",
            "对每组 API 做最小 GET/OPTIONS/HEAD 或安全只读请求，标记公开/需登录/403/404/异常。",
            "用 report_coverage 记录已覆盖的路径簇和剩余最值得分配给其它路线的入口。",
        ),
        finish_rule="没有洞也必须说明 API/入口覆盖面和剩余盲区；发现强线索写 deepen_lead。",
        js_first=True,
        phase=0,
    ),
    SiteRoute(
        source="site_js",
        label="前端 JS/API/密钥",
        priority=170.0,
        focus="围绕前端资源做 JS 审计，挖接口、token、对象存储、隐藏管理路由和未授权 API。",
        checklist=(
            "优先使用 analyze_javascript 抓关联 JS，提取 API、路由、硬编码 key/token、OSS/STS/MinIO 线索。",
            "对提取出的每个高价值 API 做最小实证请求，区分公开接口、未授权、需登录和假阳性。",
            "遇到 token/key 先 decode_transform 看结构，再验证是否可用；不可用不要提交。",
            "用 report_coverage 记录已测试 API 前缀、接口样例和结论。",
        ),
        finish_rule="不能只停在接口清单；每个高价值接口至少做一次实证验证。",
        js_first=True,
        phase=0,
    ),
    SiteRoute(
        source="site_auth",
        label="认证/越权/会话",
        priority=160.0,
        focus="测试登录、SSO/CAS、会话维持、IDOR、水平/垂直越权、默认口令和弱验证码。",
        checklist=(
            "识别登录/认证流程、回调地址、票据、验证码、找回/注册/绑定等账号相关接口。",
            "对用户 ID、订单/文件/消息/部门/班级等对象参数做只读越权验证，必须有 before/after 或差异证据。",
            "如果拿到 session/token，先固定会话再测试受限 API；只登录成功本身不是洞。",
            "用 report_coverage 记录认证接口、对象参数、已尝试的越权维度和结论。",
        ),
        finish_rule="没有真实对象 ID 或状态差异就不交半成品；写清下一轮如何找 ID。",
    ),
    SiteRoute(
        source="site_unauth",
        label="未授权/配置暴露",
        priority=150.0,
        focus="测试 Swagger/Actuator/Nacos/Druid/.git/.env/备份/配置/日志/调试端点等暴露面。",
        checklist=(
            "围绕 API 文档、actuator/env、nacos、druid、.git、.env、备份包、日志路径做小范围验证。",
            "401/403/跳登录只记鉴权存在，不当漏洞；200 也必须拿到配置、凭据、敏感数据或可操作能力。",
            "对配置/凭据必须继续验证可用性，无法验证就不要提交。",
            "用 report_coverage 记录已测试暴露面路径和状态码/证据。",
        ),
        finish_rule="只看到页面/文档不算洞；要落到可用配置、数据或操作能力。",
    ),
    SiteRoute(
        source="site_file",
        label="文件/导入导出",
        priority=140.0,
        focus="测试上传、附件、导入导出、模板下载、任意文件读取/覆盖、路径穿越和解析执行。",
        checklist=(
            "枚举上传/附件/导入/导出/下载/预览/模板接口，先做只读或安全小样本验证。",
            "上传必须证明解析执行、越权读取、敏感覆盖或可控文件落点；txt 可访问不算洞。",
            "下载/预览要验证路径、ID、权限边界，不用破坏性写入。",
            "用 report_coverage 记录文件相关接口、参数和验证结论。",
        ),
        finish_rule="文件类要有真实影响；不能只报能上传普通文件。",
    ),
    SiteRoute(
        source="site_inject",
        label="注入/RCE/模板表达式",
        priority=130.0,
        focus="测试 SQL/NoSQL/命令/模板/表达式/反序列化/RCE 类入口，优先参数明确的 API。",
        checklist=(
            "从 API 清单中挑有参数的查询、搜索、统计、导出、回调接口做 baseline vs payload 差异验证。",
            "优先布尔/时间/错误三类最小 PoC；遇 WAF 用 suggest_waf_bypass 后必须回测。",
            "RCE/命令/模板只做安全无害回显或延时验证，不做破坏性动作。",
            "用 report_coverage 记录已测参数、payload 类型和差异结论。",
        ),
        finish_rule="扫描器输出不等于洞；必须有可复现差异或原始请求响应。",
    ),
    SiteRoute(
        source="site_logic",
        label="业务逻辑/状态流",
        priority=120.0,
        focus="测试注册、审批、支付、报名、验证码、重放、状态流绕过和敏感写操作。",
        checklist=(
            "找状态变化接口：register/save/update/delete/approve/pay/export/import/bind/reset 等。",
            "用安全对象验证重放、越权、缺验证码、顺序绕过、价格/数量/状态篡改等逻辑问题。",
            "写操作必须证明真实状态变化和影响，不对生产数据做破坏性改动。",
            "用 report_coverage 记录已测业务流程、状态接口和结论。",
        ),
        finish_rule="业务逻辑洞必须有前后状态差异；没有就写 no_vuln 或 deepen_lead。",
    ),
)

_ROUTE_BY_SOURCE = {r.source: r for r in ROUTES}
DISCOVERY_ROUTES = tuple(r for r in ROUTES if r.phase == 0)
FOLLOWUP_ROUTES = tuple(r for r in ROUTES if r.phase > 0)
# 开局并发入队的全部固定路线（侦察 + 主题深挖）。单站协作要「快」，
# 5 条主题路线不再苦等侦察跑完，开局即和侦察一起并发抢 worker。
INITIAL_ROUTES = DISCOVERY_ROUTES + FOLLOWUP_ROUTES
FOCUSED_ROUTE = SiteRoute(
    source="site_focus",
    label="定向 API 追打",
    priority=155.0,
    focus="围绕前序 worker 发现的具体 API/路径做逐项验证，不重新泛泛侦察。",
    checklist=(
        "先复现前序记录的基线请求，确认路径/方法/状态码真实存在。",
        "按指令逐项验证未授权、越权、注入、文件、逻辑或配置暴露，不跳到无关路径。",
        "每个参数/对象边界都要有 baseline vs payload/不同对象/不同状态的差异证据。",
        "最后用 report_coverage 写清这个路径簇测过什么、什么有价值、什么打不穿。",
    ),
    finish_rule="只围绕定向入口收敛；打穿就 submit_finding，差一步写 deepen_lead。",
    phase=2,
)


# 开启「跳过入口盘点」时被跳过的侦察路线（只跳 site_map；site_js 前端密钥价值高，保留）。
SKIPPABLE_RECON_SOURCES = ("site_map",)


def skip_recon_enabled(task) -> bool:
    """任务是否开启了「跳过入口盘点侦察」（fofa_config.skip_site_recon）。"""
    cfg = getattr(task, "fofa_config", None) or {}
    return bool(cfg.get("skip_site_recon"))


def initial_routes_for(task) -> tuple[SiteRoute, ...]:
    """按任务配置返回开局入队的路线：开启跳过侦察时剔除 site_map。"""
    if skip_recon_enabled(task):
        return tuple(r for r in INITIAL_ROUTES if r.source not in SKIPPABLE_RECON_SOURCES)
    return INITIAL_ROUTES


def is_site_source(source: str | None) -> bool:
    return (source or "").startswith("site_")


def route_for_source(source: str | None) -> SiteRoute | None:
    source = source or ""
    if re.fullmatch(r"site_f\d{2}", source):
        return FOCUSED_ROUTE
    return _ROUTE_BY_SOURCE.get(source)


def route_reason(route: SiteRoute) -> str:
    return f"[单站协作] {route.label} · {route.focus[:120]}"


# 用户在自由文本里给出的登录凭据/登录态的识别特征。
# 命中任一即认为用户「提供了可登录的凭据」，触发登录后深入引导。
_CRED_SIGNALS: tuple[re.Pattern, ...] = (
    re.compile(r"(?i)(账号|帐号|账户|用户名|登录名|user(?:name)?|account|login)\s*[:：=]\s*\S+"),
    re.compile(r"(?i)(密码|口令|passwd|password|pwd|pass)\s*[:：=]\s*\S+"),
    re.compile(r"(?i)\bcookie\s*[:：]\s*\S+"),
    re.compile(r"(?i)\bauthorization\s*[:：]\s*\S+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{10,}"),
    re.compile(r"(?i)\b(JSESSIONID|PHPSESSID|SESSION|SESSID|sid|token|access_token|CASTGC)\s*=\s*\S+"),
    re.compile(r"(?i)(已有|提供|给你|附上|如下).{0,6}(账号|帐号|账户|登录|凭据|凭证|cookie|token|session)"),
)


def detect_user_credentials(site_info: str) -> bool:
    """判断用户自由文本里是否给出了可登录的账号密码 / 登录态。

    命中即触发 render_context 里的「登录后深入」引导块。宁可宽松命中——
    误判成本只是多一段引导文字，漏判成本是忽略用户凭据不去登录。
    """
    text = (site_info or "").strip()
    if not text:
        return False
    return any(p.search(text) for p in _CRED_SIGNALS)


# 用户给出凭据时的引导块：登录成功后进系统深入，只登录不算漏洞。
_USER_CRED_DIRECTIVE = (
    "# 用户已提供登录凭据 —— 登录并进系统深入\n"
    "上方「用户提供的目标相关信息」里含用户主动给出的账号密码 / Cookie / Token / 登录态，"
    "这是用户授权你使用的入场券，请执行：\n"
    "1. 【先登录】用给出的账号密码走登录接口，或把给出的 Cookie/Authorization 用 session_set 登记；"
    "登记后 http_request 会自动携带登录态，不必每次手动拼 Cookie。\n"
    "2. 【判成败】登录成功的判据：拿到 Set-Cookie/有效 session、能访问到需登录才可见的页面/接口（非跳登录、非 401/403）。"
    "登录本身不是漏洞，不能就此 finish。\n"
    "3. 【进系统深入】带着登录态进入系统内部逐项验证：后台/个人中心/管理菜单，测越权(IDOR/水平垂直)、"
    "他人对象访问、敏感数据读取、上传/导入、敏感写操作、配置暴露、受限 API；实证到够格危害才 submit_finding。\n"
    "4. 【登不进/无货】登录失败就记录现象；登进去但无可深挖危害，用 deepen_lead 写清下一轮拿这登录态该测哪里再 finish。\n"
    "只登录成功 / 只进个人中心 / 只写「可能可以访问 X」都不算漏洞，需要登录态下的实证危害。不要修改任何账号密码。\n"
)


def render_context(
    route: SiteRoute,
    site_info: str = "",
    coverage_block: str = "",
    focus_note: str = "",
    skip_recon: bool = False,
) -> str:
    lines = [
        "# 单站协作分工",
        f"- 当前路线：{route.label}",
        f"- 路线目标：{route.focus}",
        "- 协作规则：只围绕当前站点行动；你负责把本路线测扎实，不要重复其它路线已经覆盖的点。",
        "- 覆盖要求：发现 API/入口后要逐项做最小安全验证；没出洞也要用 report_coverage 记录覆盖面。",
        "- 收敛规则：能打穿就 submit_finding；有明确据点但差一步就写 deepen_lead；无实证不要交半成品。",
    ]
    if route.phase > 0:
        # 主题深挖路线：区别于侦察路线，强调复用侦察成果 + 多轮深挖 + 用 deepen_lead 触发自动接力。
        lines += [
            "- 深挖纪律：你是【深挖路线】不是浅扫。围绕本路线 focus 把每个候选入口都测到有结论——"
            "打穿就 submit_finding；差一步（有据点但缺 ID/凭据/回显）就写 deepen_lead，"
            "系统会自动接力深挖、出洞后还会自动扩大危害；确认无洞也要说清测了哪些入口、为何不通。"
            "不要首页加几个常见路径扫一遍就 finish。",
        ]
        if skip_recon:
            # 用户关闭了「入口盘点(site_map)」侦察：多为已给登录凭据、目标明确的场景，
            # 不再苦等/复用全站入口地图，直接按本路线 focus 快速定位入口开打（省 token）。
            lines += [
                "- 侦察说明：本次已关闭「入口盘点」泛侦察（通常因为你已拿到登录凭据或目标明确）。"
                "site_js 前端资源侦察仍在并发跑、成果会陆续上报；除此之外别再从零泛扒全站，"
                "直接按本路线 focus 定位相关入口（如认证路线直奔登录/越权接口）就开打，边测边深挖。",
            ]
        else:
            lines += [
                "- 复用侦察：site_map/site_js 侦察路线与你并发在跑，成果会陆续上报。"
                "下方【若已有覆盖摘要】就优先在这些已知入口上做本路线的定向验证，别从零重复侦察；"
                "【若暂无覆盖摘要】说明侦察还在跑，你直接按本路线 focus 自己快速摸一遍相关入口就开打，"
                "不要空等侦察——先扒首页/JS 找本路线相关接口（如认证路线找登录/越权接口），边测边深挖。",
            ]
    if site_info.strip():
        lines += ["", "# 用户提供的目标相关信息", site_info.strip()[:2000]]
        if detect_user_credentials(site_info):
            lines += ["", _USER_CRED_DIRECTIVE]
    if coverage_block.strip():
        lines += ["", coverage_block.strip()]
    if focus_note.strip():
        lines += [
            "",
            "# 本轮定向追打指令",
            focus_note.strip()[:1800],
            "不要把这条指令当作已验证结论；必须重新做最小实证请求。",
        ]
    lines += ["", "# 本路线检查清单"]
    lines.extend(f"- {item}" for item in route.checklist)
    lines += ["", f"# 本路线结束标准\n{route.finish_rule}"]
    return "\n".join(lines) + "\n\n"


_HIGH_VALUE_RE = re.compile(
    r"(?i)(api|admin|login|auth|token|session|user|account|member|student|teacher|"
    r"order|file|upload|download|export|import|swagger|api-docs|actuator|nacos|"
    r"druid|env|config|search|query|list|page|save|update|delete|approve|reset|bind|pay)"
)
_STATIC_RE = re.compile(r"(?i)\.(?:css|png|jpe?g|gif|svg|ico|woff2?|map)(?:$|\?)")


def _endpoint_path(item: dict) -> str:
    return str(item.get("path") or item.get("url") or "").strip()


def _endpoint_method(item: dict) -> str:
    return str(item.get("method") or "GET").upper()[:12]


def _normalize_path(path: str, base_url: str) -> str:
    raw = (path or "").strip()
    if not raw:
        return ""
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        return (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    if raw.startswith("//"):
        parsed = urlparse("http:" + raw)
        return parsed.path or "/"
    if raw.startswith("/"):
        return raw
    return urlparse(urljoin(base_url.rstrip("/") + "/", raw)).path or "/" + raw


def _classify_endpoint(path: str, method: str, checks: str = "", result: str = "") -> tuple[str, str]:
    low = " ".join([path, method, checks, result]).lower()
    if any(k in low for k in ("swagger", "api-docs", "actuator", "nacos", "druid", ".env", "config", "heapdump")):
        return "未授权/配置暴露", "验证是否能读到受限配置、凭据、接口文档后的敏感操作能力。"
    if any(k in low for k in ("upload", "download", "file", "attach", "import", "export", "preview", "template")):
        return "文件/导入导出", "验证上传解析、任意文件读、越权下载、导出敏感数据或路径穿越。"
    if any(k in low for k in ("login", "auth", "token", "session", "sso", "cas", "user", "account", "member", "student", "teacher")):
        return "认证/越权", "验证登录态、对象 ID、角色边界、用户资料/学生/教师数据是否可越权读取。"
    if any(k in low for k in ("search", "query", "list", "page", "report", "stat", "sql", "where", "filter")):
        return "注入/查询参数", "做 baseline vs 布尔/错误/延时/排序字段差异验证，禁止拖库。"
    if any(k in low for k in ("save", "update", "delete", "approve", "reset", "bind", "pay", "register", "submit")):
        return "业务逻辑/状态流", "验证缺鉴权、越权写、重放、状态绕过或关键业务参数篡改。"
    return "综合 API 验证", "先判断公开/需登录，再按未授权、越权、参数注入、数据泄露逐项验证。"


# 三阶段元数据：给前端「协作态势」面板渲染阶段流水线用。
PHASES: tuple[dict, ...] = (
    {"phase": 0, "key": "recon", "label": "侦察盘点",
     "desc": "site_map / site_js 摸清全站入口、API 与前端密钥"},
    {"phase": 1, "key": "theme", "label": "主题深挖",
     "desc": "认证越权 / 未授权配置 / 文件 / 注入RCE / 业务逻辑 五路分头深挖"},
    {"phase": 2, "key": "focus", "label": "定向追打",
     "desc": "围绕侦察发现的具体 API 逐项验证打穿"},
)


def _route_meta(source: str) -> SiteRoute | None:
    """把任意 site source（含 site_fXX 追打）映射到路线定义。"""
    return route_for_source(source)


def build_collab_overview(rows: list[dict]) -> dict | None:
    """把该任务的 site 路线聚合成前端可直接渲染的「协作态势」结构。

    rows: 每条是一个 site target 的精简 dict，字段：
        source, status(queued/assigned/scanning/done/skipped/dead),
        verdict, priority_reason, findings(int), deepen_count(int)

    返回三阶段(phase)结构：每阶段含 label/desc + 该阶段路线卡片列表 +
    汇总计数；并推断整体所处阶段 current_phase。非 site 任务传空 rows → None。
    """
    site_rows = [r for r in rows if is_site_source(r.get("source"))]
    if not site_rows:
        return None

    RUNNING = {"assigned", "scanning"}

    def _status_of(r: dict) -> str:
        s = (r.get("status") or "").lower()
        if s in RUNNING:
            return "running"
        if s == "queued":
            return "queued"
        return "done"

    # 定向追打(site_fXX)可能有很多条，聚合成一个"虚拟路线卡"，不逐条铺开。
    phase_buckets: dict[int, list[dict]] = {0: [], 1: [], 2: []}
    focus_agg = {"total": 0, "running": 0, "queued": 0, "done": 0, "findings": 0}

    for r in site_rows:
        src = r.get("source") or ""
        route = _route_meta(src)
        if route is None:
            continue
        st = _status_of(r)
        fcount = int(r.get("findings") or 0)
        if route.phase == 2:  # 追打路线聚合
            focus_agg["total"] += 1
            focus_agg[st] += 1
            focus_agg["findings"] += fcount
            continue
        phase_buckets[route.phase].append({
            "source": src,
            "label": route.label,
            "focus": route.focus,
            "status": st,
            "verdict": r.get("verdict") or "",
            "findings": fcount,
            "deepen_count": int(r.get("deepen_count") or 0),
        })

    # 追打聚合成单张卡塞进 phase 2（有才显示）
    if focus_agg["total"] > 0:
        agg_status = "running" if focus_agg["running"] else ("queued" if focus_agg["queued"] else "done")
        phase_buckets[2].append({
            "source": "site_focus",
            "label": f"定向 API 追打 ×{focus_agg['total']}",
            "focus": FOCUSED_ROUTE.focus,
            "status": agg_status,
            "verdict": "",
            "findings": focus_agg["findings"],
            "deepen_count": 0,
            "is_aggregate": True,
            "aggregate": focus_agg,
        })

    # 每阶段状态：有 running→active；全 done→done；有 queued 但没 running→pending；空→idle
    phases_out = []
    for meta in PHASES:
        cards = phase_buckets[meta["phase"]]
        running = sum(1 for c in cards if c["status"] == "running")
        queued = sum(1 for c in cards if c["status"] == "queued")
        done = sum(1 for c in cards if c["status"] == "done")
        findings = sum(c["findings"] for c in cards)
        if not cards:
            pstate = "idle"
        elif running:
            pstate = "active"
        elif queued:
            pstate = "pending"
        else:
            pstate = "done"
        phases_out.append({
            **meta,
            "state": pstate,
            "routes": cards,
            "counts": {"total": len(cards), "running": running,
                       "queued": queued, "done": done, "findings": findings},
        })

    # 推断整体当前阶段：取最后一个"有活动(active/pending)"的阶段；都 done 则取最高有卡的阶段。
    current = 0
    for p in phases_out:
        if p["state"] in ("active", "pending"):
            current = p["phase"]
    if all(p["state"] in ("idle", "done") for p in phases_out):
        for p in phases_out:
            if p["state"] == "done":
                current = p["phase"]

    total_routes = sum(p["counts"]["total"] for p in phases_out)
    total_findings = sum(p["counts"]["findings"] for p in phases_out)
    total_running = sum(p["counts"]["running"] for p in phases_out)

    return {
        "current_phase": current,
        "phases": phases_out,
        "totals": {"routes": total_routes, "findings": total_findings,
                   "running": total_running},
    }


def followup_specs_from_coverage(
    coverage: list[dict],
    *,
    base_url: str,
    max_specs: int = 8,
) -> list[dict]:
    """从覆盖上报中提炼定向追打任务。

    返回的 spec 不含 DB 细节，只表达“对哪个入口、按什么方向继续打”。
    """
    specs: list[dict] = []
    seen: set[str] = set()
    for record in coverage:
        if not isinstance(record, dict):
            continue
        route = str(record.get("route") or "site")
        remaining = str(record.get("remaining") or "").strip()
        for item in (record.get("endpoints") or [])[:30]:
            if not isinstance(item, dict):
                continue
            raw_path = _endpoint_path(item)
            path = _normalize_path(raw_path, base_url)
            if not path or _STATIC_RE.search(path):
                continue
            status = str(item.get("status") or "")
            checks = str(item.get("checks") or "")
            result = str(item.get("result") or item.get("note") or "")
            method = _endpoint_method(item)
            if not _HIGH_VALUE_RE.search(" ".join([path, checks, result, remaining])):
                continue
            key = f"{method}:{path.split('?')[0]}"
            if key in seen:
                continue
            seen.add(key)
            category, tactic = _classify_endpoint(path, method, checks, result)
            specs.append({
                "method": method,
                "path": path[:220],
                "category": category,
                "source_route": route,
                "priority": FOCUSED_ROUTE.priority + max(0, 20 - len(specs)),
                "reason": (
                    f"[单站协作追打] 来源 {route} 发现 {method} {path[:160]}；"
                    f"方向：{category}。前序状态/结论：{status or '-'} {result[:140]}。"
                    f"任务：{tactic}"
                    + (f" 剩余线索：{remaining[:180]}" if remaining else "")
                )[:300],
            })
            if len(specs) >= max_specs:
                return specs
    return specs
