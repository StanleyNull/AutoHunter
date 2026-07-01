"""目标打法路由：把资产信号映射到更窄的 worker 挖掘路线。

- 不替代 scorer；scorer 决定资产优先级，本模块决定“进去以后先打哪条路”。
- 不生成破坏性 payload；只输出授权测试下的验证重点和快速放弃条件。
- 输出要短，适合注入 worker prompt。

资料基线：OWASP API Top 10 / WSTG（对象级/功能级授权、IDOR），
以及 Swagger/Actuator/Nacos/GraphQL/DevOps/对象存储等组件的公开文档语义。
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from urllib.parse import urlparse


@dataclass(frozen=True)
class RoutePlan:
    route_id: str
    label: str
    confidence: float
    score_bonus: float
    intensity: str
    tags: tuple[str, ...]
    evidence: tuple[str, ...]
    focus: tuple[str, ...]
    avoid: tuple[str, ...]
    finish_hint: str
    alternates: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "route_id": self.route_id,
            "label": self.label,
            "confidence": self.confidence,
            "score_bonus": self.score_bonus,
            "intensity": self.intensity,
            "tags": list(self.tags),
            "evidence": list(self.evidence),
            "focus": list(self.focus),
            "avoid": list(self.avoid),
            "finish_hint": self.finish_hint,
            "alternates": list(self.alternates),
        }


@dataclass(frozen=True)
class _RouteDef:
    route_id: str
    label: str
    tag_weights: dict[str, float]
    focus: tuple[str, ...]
    avoid: tuple[str, ...]
    finish_hint: str
    base: float = 0.0
    bonus_cap: float = 4.0
    intensity: str = "normal"
    min_score: float = 1.0


_API_PATH_RE = re.compile(
    r"""(?ix)
    ["'\s(]
    (
      /(?:
        api|rest|service|openapi|graphql|graphiql|v[12]|admin-api|system|
        actuator|nacos|druid|swagger-ui|v2/api-docs|v3/api-docs|
        upload|file|import|export|download|register|login|
        jenkins|gitlab|harbor|grafana|minio|s3|oss|\.git|\.env
      )
      [\w./?=&:%@+-]*
    )
    """
)

# 路线集合：定向深挖 + 几类通用攻击面 + 兜底/快速收敛。
_ROUTES: tuple[_RouteDef, ...] = (
    _RouteDef(
        "directed_deepen",
        "审核/worker 指令定向深挖",
        {"deepen": 12, "worker_lead": 3, "review_deepen": 3},
        (
            "先执行 deepen 指向的单一路径，不重新做泛侦察",
            "围绕原 finding 的接口/参数补齐 before-after 或越权/敏感数据证据",
            "若该链路被证明不通，finish(no_vuln) 并写清失败点",
        ),
        ("不要把原半成品重复提交", "不要扩散到无关系统"),
        "定向验证完仍无实证危害就结束，保留下一步线索。",
        base=2,
        bonus_cap=6,
        intensity="deep",
    ),
    _RouteDef(
        "api_authorization",
        "API 文档/接口授权边界(Swagger/OpenAPI/GraphQL)",
        {"swagger": 5, "openapi": 5, "graphql": 5, "doc_api": 3, "api_paths_many": 2, "admin_api": 2},
        (
            "优先读取接口文档/paths/parameters 或 GraphQL schema，挑列表/详情/导出/管理接口",
            "围绕对象级授权(BOLA/IDOR)：替换 id、userId、tenantId、deptId、ids 等参数",
            "围绕功能级授权(BFLA)：未登录或低权限访问管理/导出/配置接口",
            "提交前必须证明接口本应受限，且拿到够格数据或真实写操作变化",
        ),
        ("不要只把 swagger/doc.html 暴露当漏洞", "不要遍历全 API，只测高价值端点"),
        "文档可访问但所有高价值接口 401/403/公开展示时，快速结束。",
        base=1,
        bonus_cap=4,
        intensity="deep",
    ),
    _RouteDef(
        "component_exposure",
        "中间件/配置组件暴露面(Actuator/Nacos/Druid)",
        {"actuator": 6, "nacos": 6, "druid": 4, "spring": 2, "env": 2, "heapdump": 3, "config_service": 2},
        (
            "先确认组件是否需鉴权；开放则只读验证 env/configprops/heapdump/配置/服务列表",
            "核心证据是可读到数据库/中间件凭证、token/secret 或能导致下一跳的配置",
            "只有 health/info/metrics 等普通状态时不按漏洞提交",
        ),
        ("不要把 health UP 当洞", "不要调用 shutdown 或破坏性管理端点"),
        "只剩普通状态且无凭证/敏感配置时结束。",
        base=1,
        bonus_cap=5,
        intensity="deep",
    ),
    _RouteDef(
        "devops_control_plane",
        "DevOps/运维控制面暴露面",
        {"jenkins": 6, "gitlab": 6, "harbor": 5, "grafana": 4, "kubernetes": 6, "apisix": 4, "kong": 4, "devops": 3, "anonymous": 2, "token": 2},
        (
            "先判断是否匿名可读或弱鉴权暴露，只读项目/仓库/构建/镜像/仪表盘/集群资源",
            "核心证据是可用 token/secret、CI 变量、私有仓库/镜像、K8s secret、数据源凭证",
            "有 token/session 时验证最小只读受限资源；不要触发构建/部署/删除",
        ),
        ("不要触发 job/build/deploy", "不要删除镜像/仓库/Pod/配置", "不要把登录页或版本号单独提交"),
        "只能看到公开登录页/版本页，或匿名只读无敏感资源时结束。",
        base=1,
        bonus_cap=5,
        intensity="deep",
    ),
    _RouteDef(
        "secret_storage_exposure",
        "源码/配置/密钥/对象存储泄露链",
        {"git_exposed": 7, "env_file": 6, "secret": 4, "backup": 3, "config_file": 3, "minio": 5, "s3": 4, "oss": 4, "bucket": 3, "sts": 3, "cloud_storage": 2},
        (
            "先只读确认 .git/.env/备份/对象存储 endpoint/key 是否真实可取，不做大规模拉取",
            "提取 DB/API/JWT/对象存储/第三方 key 后，必须验证最小只读受限资源或调用成功",
            "对象存储重点验证越权读私有对象、STS 凭证访问范围、跨 bucket/租户访问",
        ),
        ("不要把路径存在或无效 key 单独提交", "不要全量下载/覆盖/删除对象"),
        "拿不到可用凭证，或只含公开前端/静态资源时结束。",
        base=1,
        bonus_cap=5,
        intensity="deep",
    ),
    _RouteDef(
        "spa_js_api",
        "SPA 前端 JS/API/密钥路线",
        {"spa": 4, "js": 3, "api_paths_many": 3, "secret": 4, "token": 2},
        (
            "先用 analyze_javascript 提取接口、路由、鉴权、签名、secret/token 线索",
            "按接口价值排序验证：用户信息、导出、文件、管理、支付/审批、配置",
            "发现 secret/key 后必须证明它能调通受限接口或产生真实影响",
        ),
        ("不要只提交 JS 硬编码", "不要把公开前端接口当未授权"),
        "JS 只有静态资源/公开接口，且 secret 无法利用时结束。",
        base=0.5,
        bonus_cap=4,
        intensity="normal",
    ),
    _RouteDef(
        "upload_business_idor",
        "上传/导出/业务状态机/IDOR",
        {"upload": 4, "import": 3, "export": 4, "download": 3, "file": 2, "business": 3, "payment": 3, "approval": 2, "order": 2, "register": 2, "api_paths_many": 1},
        (
            "找真实对象 ID/业务上下文，测越权读写：id、ids、userId、deptId、tenantId、status、amount",
            "上传做最小可逆验证（安全文本/图片），再看扩展名、MIME、路径回显、访问控制",
            "业务操作做 before-after，必须证明状态确实变化或越权读到他人资源",
        ),
        ("不要用不存在的 ID 证明写操作", "不要做破坏性覆盖/删除", "不要只看 success=true"),
        "找不到真实对象/无法安全证明影响时结束。",
        base=0.5,
        bonus_cap=4,
        intensity="deep",
    ),
    _RouteDef(
        "auth_gateway_post_login",
        "SSO/CAS/统一认证后置深挖",
        {"auth_gateway": 5, "sso": 5, "cas": 5, "leaked_creds": 3},
        (
            "统一认证本身通常难出；若有凭证，登录只作为进入具体业务系统的第 0 步",
            "从跳转应用、ticket/service、个人中心链接找到具体业务系统，再测受限资源",
            "必须实证登录后读到够格数据、越权操作或具体业务系统内的独立漏洞",
        ),
        ("不要把登录成功/session 本身提交", "不要空泛写可能访问其它系统"),
        "只有认证中心且无具体业务实害时结束或交 deepen_lead。",
        base=-0.5,
        bonus_cap=2,
        intensity="quick",
    ),
    _RouteDef(
        "generic_admin_api",
        "通用后台/API 快速验证",
        {"admin": 3, "login": 2, "api_paths_few": 1, "nonstandard_port": 1},
        (
            "优先登录/API/上传/导出/配置/用户列表，不做泛目录",
            "3-5 个动作内找不到可交互点或高价值接口就快速收敛",
            "有 API 后转入 IDOR/BFLA/文件/业务状态机验证",
        ),
        ("不要泛扫空转", "不要提交后台登录页存在"),
        "无登录、无 API、无表单、无上传下载时结束。",
        base=0,
        bonus_cap=2,
        intensity="normal",
        min_score=0.5,
    ),
    _RouteDef(
        "static_low_value",
        "低价值静态/门户快速收敛",
        {"static": 5, "portal": 4, "news": 4, "marketing": 3, "public_display": 2},
        (
            "只确认是否存在登录/API/表单/上传/JS 接口；没有就立刻结束",
            "若发现 JS API 或后台入口，切换到 SPA/API/后台路线",
        ),
        ("不要在新闻/官网/静态页上路径穷举", "不要把公开内容当泄露"),
        "无交互点时 3-5 个动作内 finish(no_vuln)。",
        base=-1,
        bonus_cap=-2,
        intensity="quick",
        min_score=2,
    ),
)


def _norm(text: str) -> str:
    return (text or "").lower()


def _path(url: str) -> str:
    try:
        return urlparse(url or "").path or ""
    except Exception:
        return ""


def _port(url: str) -> int:
    try:
        p = urlparse(url or "")
        if p.port:
            return p.port
        return 443 if p.scheme == "https" else 80
    except Exception:
        return 80


def _add_signal(signals: dict[str, list[str]], tag: str, evidence: str) -> None:
    if not evidence:
        evidence = tag
    bucket = signals.setdefault(tag, [])
    if evidence not in bucket and len(bucket) < 4:
        bucket.append(evidence[:160])


def _extract_paths(text: str) -> list[str]:
    paths: list[str] = []
    for m in _API_PATH_RE.finditer(f" {text or ''} "):
        path = m.group(1).strip().rstrip(".,;)")
        if path and path not in paths:
            paths.append(path[:180])
        if len(paths) >= 30:
            break
    return paths


# tag -> 命中判定关键词（覆盖各路线所需信号）
_SIGNAL_CHECKS = [
    ("swagger", ("swagger-ui", "/swagger", "swagger ui")),
    ("openapi", ("openapi", "/v3/api-docs", "/v2/api-docs")),
    ("graphql", ("/graphql", "graphiql", "__schema", "graphql playground")),
    ("doc_api", ("api-docs", "接口文档", "knife4j", "doc.html")),
    ("actuator", ("/actuator", "spring boot actuator")),
    ("spring", ("spring", "springboot", "spring boot")),
    ("env", ("/actuator/env", "propertysources", "systemproperties")),
    ("heapdump", ("heapdump", "/actuator/heapdump")),
    ("nacos", ("nacos", "/nacos", "console-ui")),
    ("config_service", ("配置中心", "configurations", "/v1/cs/configs", "service list", "服务列表")),
    ("druid", ("druid stat", "/druid", "druid-version")),
    ("jenkins", ("jenkins", "/jenkins", "x-jenkins")),
    ("gitlab", ("gitlab", "gitlab-ci", "/users/sign_in")),
    ("harbor", ("harbor", "harbor registry", "/harbor")),
    ("grafana", ("grafana", "grafana_session", "/grafana")),
    ("kubernetes", ("kubernetes dashboard", "k8s", "kubeconfig", "/api/v1/namespaces")),
    ("apisix", ("apisix", "apache apisix", "/apisix/admin")),
    ("kong", ("kong", "kong admin")),
    ("devops", ("devops", "ci/cd", "持续集成", "镜像仓库", "制品库", "nexus", "sonarqube")),
    ("anonymous", ("anonymous", "匿名", "未登录访问")),
    ("spa", ("vue", "react", "angular", "__webpack", "webpack", "single-spa")),
    ("js", (".js", "<script", "javascript")),
    ("secret", ("secret", "appsecret", "accesskey", "privatekey", "clientsecret")),
    ("token", ("token", "jwt", "authorization")),
    ("minio", ("x-minio", "minio console", "/minio/")),
    ("s3", ("s3", "amazons3", "x-amz-")),
    ("oss", ("oss", "aliyun", "x-oss-")),
    ("bucket", ("bucket", "对象存储")),
    ("sts", ("sts", "securitytoken", "assume-role")),
    ("cloud_storage", ("云存储", "对象存储", "x-oss-", "x-amz-")),
    ("git_exposed", ("/.git/config", "[core]", "repositoryformatversion")),
    ("env_file", ("/.env", "app_key", "db_password", "db_database", "spring.datasource.password")),
    ("backup", (".bak", ".zip", ".tar.gz", "backup", "备份")),
    ("config_file", ("application.yml", "application.properties", "config.json", "settings.py")),
    ("register", ("register", "注册", "/register")),
    ("login", ("login", "登录", "signin", "password")),
    ("upload", ("upload", "上传")),
    ("import", ("import", "导入")),
    ("export", ("export", "导出")),
    ("download", ("download", "下载")),
    ("file", ("file", "附件", "文件")),
    ("business", ("审批", "报名", "预约", "成绩", "工单", "流程", "业务")),
    ("payment", ("支付", "缴费", "订单", "退款", "发票")),
    ("approval", ("审批", "审核", "流程")),
    ("order", ("订单", "预约", "报名")),
    ("auth_gateway", ("统一身份认证", "统一认证", "认证平台", "登录中心", "authserver")),
    ("sso", ("sso", "single sign-on", "单点登录")),
    ("cas", ("cas", "castgc")),
    ("static", ("static", "assets", "cdn", "纯前端", "静态")),
    ("portal", ("官网", "门户", "首页")),
    ("news", ("新闻网", "新闻", "公告")),
    ("marketing", ("宣传", "简介", "概况", "联系我们")),
    ("public_display", ("展示", "可视化大屏", "数据大屏")),
]

# path 片段 -> 追加信号（对路径命中做补充标注）
_PATH_TAGS = [
    ("swagger", "doc_api"), ("api-docs", "doc_api"), ("doc.html", "doc_api"),
    ("actuator", "actuator"), ("graphql", "graphql"), ("nacos", "nacos"),
    ("admin-api", "admin_api"), ("/admin/", "admin"),
    ("upload", "upload"), ("export", "export"), ("import", "import"), ("register", "register"),
    (".git", "git_exposed"), (".env", "env_file"), ("minio", "minio"),
]


def extract_route_signals(
    *,
    url: str,
    title: str = "",
    server: str = "",
    body: str = "",
    priority_reason: str = "",
    src_type: str = "edusrc",
    source: str = "",
    deepen_context: dict | None = None,
    leaked_creds: list[dict] | None = None,
) -> dict[str, list[str]]:
    """抽取路由信号，返回 tag -> evidence[]。"""
    signals: dict[str, list[str]] = {}
    path = _path(url)
    port = _port(url)
    combined = "\n".join([url, title, server, body[:12000], priority_reason, source])
    low = _norm(combined)

    if deepen_context:
        _add_signal(signals, "deepen", str(deepen_context.get("directive") or deepen_context)[:160])
        src = str(deepen_context.get("source") or "")
        if src == "worker_lead":
            _add_signal(signals, "worker_lead", src)
        if "review" in src or "ai" in src:
            _add_signal(signals, "review_deepen", src)
    if source == "killsweep":
        _add_signal(signals, "deepen", "通杀验证目标")
    if leaked_creds:
        _add_signal(signals, "leaked_creds", f"leaked_creds×{len(leaked_creds)}")

    for tag, needles in _SIGNAL_CHECKS:
        for needle in needles:
            if needle.lower() in low:
                _add_signal(signals, tag, needle)
                break

    paths = _extract_paths(combined)
    if len(paths) >= 3:
        _add_signal(signals, "api_paths_many", f"api_paths×{len(paths)}")
    elif paths:
        _add_signal(signals, "api_paths_few", paths[0])
    for p in paths[:12]:
        plow = p.lower()
        for frag, tag in _PATH_TAGS:
            if frag in plow:
                _add_signal(signals, tag, p)
        if any(x in plow for x in ("jenkins", "gitlab", "harbor", "grafana", "apisix", "kong")):
            _add_signal(signals, "devops", p)
        if "/s3" in plow or "/oss" in plow:
            _add_signal(signals, "cloud_storage", p)

    if port not in (80, 443):
        _add_signal(signals, "nonstandard_port", f":{port}")
    if path and any(x in path.lower() for x in ("admin", "console", "manager")):
        _add_signal(signals, "admin", path)
    if "enterprise" in (src_type or "").lower():
        _add_signal(signals, "enterprise", "src_type=enterprise")
    return signals


def route_target(
    *,
    url: str,
    title: str = "",
    server: str = "",
    body: str = "",
    priority_reason: str = "",
    src_type: str = "edusrc",
    source: str = "",
    deepen_context: dict | None = None,
    leaked_creds: list[dict] | None = None,
) -> RoutePlan:
    signals = extract_route_signals(
        url=url,
        title=title,
        server=server,
        body=body,
        priority_reason=priority_reason,
        src_type=src_type,
        source=source,
        deepen_context=deepen_context,
        leaked_creds=leaked_creds,
    )
    scored: list[tuple[float, _RouteDef, list[str], list[str]]] = []
    for route in _ROUTES:
        score = route.base
        tags: list[str] = []
        evidence: list[str] = []
        for tag, weight in route.tag_weights.items():
            if tag in signals:
                score += weight
                tags.append(tag)
                evidence.extend(signals[tag][:2])
        if not tags:
            continue
        if score >= route.min_score:
            scored.append((score, route, tags, evidence))

    if not scored:
        fallback = next(r for r in _ROUTES if r.route_id == "generic_admin_api")
        return _build_plan(0.0, fallback, [], ["普通资产"], [])

    scored.sort(key=lambda x: x[0], reverse=True)
    # 低价值静态只在没有更强攻击面时胜出，避免“官网里有一个 /api”被静态路线盖掉。
    if scored[0][1].route_id == "static_low_value" and len(scored) > 1 and scored[1][0] >= scored[0][0] - 1:
        scored = [scored[1], scored[0], *scored[2:]]
    top_score, route, tags, evidence = scored[0]
    alternates = [r.label for _, r, _, _ in scored[1:4] if r.route_id != route.route_id]
    return _build_plan(top_score, route, tags, evidence, alternates)


def _build_plan(score: float, route: _RouteDef, tags: list[str], evidence: list[str], alternates: list[str]) -> RoutePlan:
    confidence = min(0.98, max(0.35, score / 12.0))
    if route.bonus_cap < 0:
        score_bonus = route.bonus_cap
    else:
        score_bonus = min(route.bonus_cap, max(0.0, score / 3.0))
    clean_evidence: list[str] = []
    for item in evidence:
        s = str(item or "").strip()
        if s and s not in clean_evidence:
            clean_evidence.append(s)
    return RoutePlan(
        route_id=route.route_id,
        label=route.label,
        confidence=round(confidence, 2),
        score_bonus=round(score_bonus, 1),
        intensity=route.intensity,
        tags=tuple(dict.fromkeys(tags)),
        evidence=tuple(clean_evidence[:8]),
        focus=route.focus,
        avoid=route.avoid,
        finish_hint=route.finish_hint,
        alternates=tuple(alternates),
    )


def render_playbook_block(plan: RoutePlan) -> str:
    """渲染给 worker 的短上下文块。"""
    lines = [
        "# 打法路由（系统根据目标指纹自动生成，优先执行）",
        f"- 路线：{plan.label}（confidence={plan.confidence:.2f}, intensity={plan.intensity}）",
    ]
    if plan.tags:
        lines.append(f"- 命中信号：{', '.join(plan.tags[:8])}")
    if plan.evidence:
        lines.append("- 证据片段：" + "；".join(plan.evidence[:5]))
    lines.append("- 先做：")
    for item in plan.focus[:4]:
        lines.append(f"  - {item}")
    if plan.avoid:
        lines.append("- 避免：")
        for item in plan.avoid[:3]:
            lines.append(f"  - {item}")
    lines.append(f"- 快速收敛：{plan.finish_hint}")
    if plan.alternates:
        lines.append(f"- 若首选路线无攻击面，再切：{' / '.join(plan.alternates[:3])}")
    return "\n".join(lines) + "\n\n"


def append_route_reason(reason: str, plan: RoutePlan) -> str:
    """把路由结果压缩进 priority_reason，供排序和看板解释。"""
    base = reason or "普通资产"
    tag = f"route:{plan.route_id}/{plan.label}/+{plan.score_bonus:g}"
    if tag in base:
        return base
    if len(base) > 420:
        base = base[:420].rstrip() + "..."
    return f"{base} · {tag}"
