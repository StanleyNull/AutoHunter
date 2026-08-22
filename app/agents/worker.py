"""Worker Agent：1:1 绑定一个目标，LLM + 工具真实挖洞。

流程（对应设计文档 §5.5）：
  只给一个裸 target → LLM 完全自主侦察+挖掘（function calling 循环）
  → 发现漏洞调 submit_finding → 挖完调 finish → 产出 WorkerResult。
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from pydantic import ValidationError

from app.agents.history import compact_messages
from app.agents.prompts import is_enterprise_src, normalize_worker_prompt_version, worker_system_prompt
from app.agents.backdoor_proof import weak_backdoor_block_reason
from app.agents.edu_scope import edu_bombing_block_reason
from app.agents.write_proof import HARMLESS_PROTOCOL, weak_write_block_reason
from app.agents import auth_bootstrap
from app.config import worker_config
from app import dedup
from app.llm.client import LLMClient, LLMError, llm_error_event_fields
from app.schemas import Finding, Verdict, WorkerResult
from app.tools.executor import ToolExecutor
from app.urlnorm import ensure_scheme, is_unusable_host, safe_urlparse
from app.tools.schemas import (
    JS_ANALYZER_TOOL_SCHEMAS,
    SESSION_TOOL_SCHEMAS,
    TOOL_SCHEMAS,
)


_BROAD_NMAP_RE = re.compile(r"\bnmap\b[\s\S]*(?:-p\s*(?:-|1-10000|1-65535|0-65535)|--top-ports\s+\d{3,})", re.IGNORECASE)
_SLEEP_RE = re.compile(r"\bsleep\s+(\d+)", re.IGNORECASE)
_FOR_LIST_RE = re.compile(r"\bfor\s+\w+\s+in\s+([^;\n]+);", re.IGNORECASE)
_JS_INTENT_RE = re.compile(
    r"(?i)(?:审计|分析|提取|查看|深入|打|挖).{0,24}(?:js|javascript|前端|script|接口|密钥|secret|token)"
    r"|(?:^|[\s/\"'=])[\w./-]+\.js(?:[?#\"'\s>)]|$)|<script\b|id=[\"'](?:app|root)[\"']"
)
_WORKER_STATIC_PREFIX = (
    "下一条是目标/情报。只打当前目标；确认无攻击面才快速 finish。工具按信号开放，JS 线索再用 analyze_javascript。"
)

# 强制前置侦察：通用高危入口探测路径（技术路径，不绑定具体商业产品）。
# 仅用于确定性测绘，把常见后台/API/运维面先探出来给模型，弱模型也不会漏入口。
_RECON_PROBE_PATHS = (
    "/admin", "/admin/", "/login", "/login/", "/api", "/api/", "/api/v1", "/api/v2",
    "/swagger-ui.html", "/swagger", "/swagger/index.html", "/api-docs", "/v2/api-docs", "/doc.html",
    "/actuator", "/actuator/", "/druid", "/druid/", "/console", "/console/",
    "/phpmyadmin", "/phpMyAdmin", "/manager/html", "/manager",
    "/graphql", "/graphiql", "/.env", "/.git/config", "/debug", "/status", "/health",
    "/metrics", "/info", "/jenkins", "/solr", "/_profiler", "/upload", "/uploads", "/files",
)
# 技术栈指纹规则：仅识别通用框架/中间件，辅助模型优先打法（非商业产品示例）。
_RECON_FINGERPRINT_RULES = (
    ("Spring Boot", ("spring boot", "springboot", "whitelabel error page")),
    ("Actuator", ("/actuator", "management.endpoint")),
    ("Druid", ("druid", "德鲁伊")),
    ("Nacos", ("nacos",)),
    ("ThinkPHP", ("thinkphp",)),
    ("Laravel", ("laravel", "x-laravel")),
    ("WordPress", ("wordpress", "wp-content", "wp-includes")),
    ("Jenkins", ("jenkins", "x-jenkins")),
    ("phpMyAdmin", ("phpmyadmin",)),
    ("Apache Solr", ("solr",)),
    ("Tomcat", ("apache-coyote", "tomcat")),
    ("Nginx", ("nginx",)),
    ("IIS", ("microsoft-iis",)),
    ("Apache", ("apache",)),
    ("JBoss", ("jboss",)),
    ("WebLogic", ("weblogic",)),
    ("Vue", ("__nuxt", "_vue", "vue.")),
    ("React", ("reactjs", "react.")),
    ("Angular", ("angular", "ng-")),
)

# LLM 调用失败时，worker 内软重试次数（清粘性后换端点/同端点再试），耗尽才整轮收尾回队。
_WORKER_LLM_SOFT_RETRIES = int(os.environ.get("WORKER_LLM_SOFT_RETRIES", "3"))
_WORKER_LLM_SOFT_RETRY_KINDS = {
    "rate_limit", "timeout", "network", "upstream", "provider_cooldown",
    "blocked", "unknown", "quota",
}


class Worker:
    def __init__(
        self,
        target: str,
        llm: Optional[LLMClient] = None,
        on_event: Optional[Callable[[str, dict], None]] = None,
        deepen_context: Optional[dict] = None,
        target_meta: Optional[dict] = None,
        duplicate_history: Optional[list[dict]] = None,
        cancel_event: Optional[threading.Event] = None,
        src_type: str = "edusrc",
        fofa_key: str = "",
        fofa_base_url: str = "",
        engine: str = "fofa",
        prompt_version: str | None = None,
        src_rules: str = "",
        pop_directive: Optional[Callable[[], Optional[str]]] = None,
    ):
        self.target = target
        self.llm = llm or LLMClient()
        self.cancel_event = cancel_event or threading.Event()
        self.src_type = src_type
        self._enterprise = is_enterprise_src(src_type)
        self.src_rules = src_rules or ""
        self.prompt_version = normalize_worker_prompt_version(prompt_version or worker_config.prompt_version)
        self.executor = ToolExecutor(
            target, cancel_event=self.cancel_event,
            enterprise=self._enterprise, fofa_key=fofa_key, fofa_base_url=fofa_base_url,
            engine=engine,
        )
        self.findings: list[Finding] = []
        self.on_event = on_event or (lambda kind, data: None)
        self._finished: Optional[dict] = None
        # 审核打回的定向深挖任务：{directive, vuln_type, original_title, original_summary}
        self.deepen_context = deepen_context or None
        # 人工 mid-run 指令：编排层按轮次弹出一条，注入下一轮 user 消息。
        self.pop_directive = pop_directive
        # 资产情报：候选归属学校/org/title，供 worker 核实并写进报告 owner
        self.target_meta = target_meta or {}
        # 同一 target 历史已提交漏洞摘要，用于 worker 提交前查重（superseded 不传入）
        self.duplicate_history = duplicate_history or []
        # JS 审计工具 schema 体积较大，默认只在目标/情报/响应出现 JS 信号后开放。
        self._js_tool_enabled = self._initial_js_tool_enabled()
        self._js_signal_seen = self._js_tool_enabled
        self._tool_counts: dict[str, int] = {}
        self._last_js_analysis_round = 0
        self._post_js_validation_count = 0
        # worker 主动上报的可复用情报（纯内存收集，由编排层 async 统一落全局情报库）
        self._reported_intel: list[dict] = []
        # 单站协作覆盖记录（API/入口/测试项摘要），由编排层写入事件流供后续 worker 复用。
        self._reported_coverage: list[dict] = []

    def _emit(self, kind: str, **data: Any) -> None:
        self.on_event(kind, data)

    def _initial_js_tool_enabled(self) -> bool:
        if worker_config.js_tool_always_on:
            return True
        meta = self.target_meta or {}
        if (meta.get("site_collab_route") or {}).get("js_first"):
            return True
        text = "\n".join([
            self.target,
            str(meta.get("title") or ""),
            str(meta.get("priority_reason") or ""),
            str((meta.get("playbook_route") or {}).get("route_id") or ""),
            " ".join((meta.get("playbook_route") or {}).get("tags") or []),
            str(meta.get("playbook_block") or ""),
            json.dumps(self.deepen_context or {}, ensure_ascii=False),
        ])
        low = text.lower()
        if _JS_INTENT_RE.search(text):
            return True
        return any(marker in low for marker in (
            "spa", "webpack", "vue", "react", "angular", "frontend", "front-end",
            "javascript", "script", "api_exposed", "secret", "前端",
        ))

    # ---- 强制前置侦察：LLM 自主挖洞前确定性完成入口测绘 ----
    def _safe_recon_req(self, executor, url: str, follow_redirects: bool = False) -> dict:
        """包裹 executor.http_request，任何异常都返回空 dict，避免侦察拖垮主流程。"""
        try:
            return executor.http_request(url=url, method="GET", follow_redirects=follow_redirects) or {}
        except Exception:
            return {}

    def _looks_blocked(self, resp: dict) -> bool:
        """轻量判断响应是否像被 WAF/风控拦截页（不依赖具体厂商指纹，仅看状态码反射与通用拦截词）。"""
        if not isinstance(resp, dict):
            return False
        code = resp.get("status_code")
        if code in (406, 429, 503):
            return True
        body = str((resp.get("body") or "")).lower()
        if not body:
            return False
        return any(
            kw in body
            for kw in (
                "access denied", "forbidden", "blocked", "your request has been blocked",
                "security violation", "请求被拦截", "已被拦截", "访问被拒绝", "防火墙", "captcha",
                "verify you are human", "just a moment", "拦截", "阻断", "攻击特征", "危险请求",
            )
        )

    def _recon_title(self, resp: dict) -> str:
        body = (resp or {}).get("body") or ""
        if not body:
            return ""
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        return (m.group(1).strip()[:120] if m else "")

    def _recon_header(self, resp: dict, key: str) -> str:
        hdrs = (resp or {}).get("response_headers") or {}
        if not isinstance(hdrs, dict):
            return ""
        for k, v in hdrs.items():
            if k.lower() == key.lower():
                return str(v)[:80]
        return ""

    def _recon_js_signal(self, resp: dict) -> bool:
        if not isinstance(resp, dict):
            return False
        text = str((resp.get("body") or ""))
        if ".js" in text or _JS_INTENT_RE.search(text):
            return True
        return bool(_JS_INTENT_RE.search(str(resp.get("url") or "")))

    def _recon_fingerprint(self, resp: dict) -> list:
        if not isinstance(resp, dict):
            return []
        hdrs = (resp or {}).get("response_headers") or {}
        header_blob = " ".join(f"{k}:{v}" for k, v in hdrs.items() if isinstance(hdrs, dict))
        blob = (header_blob + " " + str((resp.get("body") or ""))).lower()
        found = []
        for name, keys in _RECON_FINGERPRINT_RULES:
            if any(k.lower() in blob for k in keys):
                found.append(name)
        return found[:12]

    @staticmethod
    def _dedupe_script_srcs(srcs: list, base: str) -> list:
        """把首页 <script src> 归一化为可独立分析的绝对 URL，去重并排除无关资源。

        仅保留同源或绝对路径的脚本（跨域 CDN 分析价值低且易超时），避免重复发包。
        """
        out: list[str] = []
        seen: set[str] = set()
        for s in srcs or []:
            s = (s or "").strip()
            if not s or s.startswith(("data:", "blob:", "javascript:", "//")):
                continue
            if s.startswith("/"):
                s = base + s
            elif not s.startswith("http"):
                continue
            key = s.rstrip("/")
            if key in seen:
                continue
            seen.add(key)
            out.append(s)
        return out

    # 轻量参数级探测：对常见漏洞承载参数名做只读 GET，按响应特征提示对应漏洞类。
    # 不发包到不存在的参数（默认首页即带参请求），只标记「该参数在目标上有响应差异」给模型。
    _RECON_PARAM_PROBES = (
        ("id", "IDOR/越权/SQLi：对象/记录主键常被直接引用"),
        ("file", "任意文件读取/LFI：file 参数常接路径"),
        ("path", "任意文件读取/LFI/路径遍历"),
        ("url", "SSRF：url 参数常外发或内网请求"),
        ("redirect", "开放重定向/SSRF：redirect 参数常做跳转"),
        ("token", "令牌泄露/越权：token 参数常携凭证"),
        ("page", "分页越权/敏感信息泄露：page 参数常暴露列表"),
        ("filename", "任意文件读取/LFI"),
        ("download", "任意文件下载/越权下载"),
        ("q", "SQLi/命令注入：搜索参数常进查询"),
        ("keyword", "SQLi/命令注入：搜索参数常进查询"),
        ("cmd", "命令注入：cmd 参数常直接执行"),
        ("host", "SSRF/主机头注入：host 参数常做内网寻址"),
    )

    # 参数级漏洞字典探测：仅对「已被 _param_probe_block 确认在目标上有响应」的参数，
    # 再发一组**只读 GET**特征 payload，按响应特征标记确定性漏洞线索（仅供模型深挖，不误报为已确认洞）。
    # 每条规则：(payload, 漏洞类, 命中特征正则列表)；命中特征全部小写匹配响应正文。
    # 设计为「绝不写/不改服务端状态」的探针——SQLi 仅触发报错回显、SSTI 仅触发表达式求值回显、遍历仅读系统文件特征。
    _RECON_PARAM_PAYLOADS = (
        ("'\"`", "SQLi", ("sql syntax", "mysql", "sqlite", "ora-", "pg_query", "syntax error", "unclosed quotation", "you have an error")),
        ("{{7*7}}", "SSTI/server-side 模板注入", ("49", "jinja", "freemarker", "velocity")),
        ("../../../../../../etc/passwd", "路径遍历/LFI", ("root:x:", "bin/bash", "daemon:x:")),
        ("{{7*'7'}}", "SSTI/server-side 模板注入", ("7777777", "49")),
        ("<svg/onload=alert(1)>", "反射型 XSS（参数回显）", ("<svg/onload=alert(1)>", "alert(1)")),
        ("$ENV{'PATH'}", "命令/模板注入", ("/usr/bin", "/bin:", "path'")),
    )

    # 匿名响应体敏感数据泄露特征：仅用于「匿名可达端点」的确定性只读扫描，
    # 把模糊的「匿名可达」标记升级为具体的「疑似泄露了什么」。每条：(标签, 正则, 去敏样例)。
    # 正则全部小写匹配响应正文（预转为小写）；命中即产出确定性线索交由模型复现，不直接判定为漏洞。
    # 设计为只读特征扫描——不发任何写请求、不枚举、不爆破，仅读匿名 GET 的返回正文一次。
    _RECON_LEAK_SIGS = (
        ("邮箱", r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", "user@example.com"),
        ("手机号", r"1[3-9]\d{9}", "138****0000"),
        ("身份证号", r"\b\d{17}[\dxX]\b", "11010119900101123X"),
        ("JSON 接口裸数据", r"\"(id|user(id)?|phone|email|token|password|mobile|realname|address)\"\s*:", "{\"id\":1,\"phone\":…"),
        ("JWT/令牌", r"eyj[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+", "eyJhbGciOi…"),
        ("API Key/私钥", r"(api[_-]?key|secret|private[_-]?key|access[_-]?token)[\"'\s:=]+[a-z0-9/+]{16,}", "api_key=\"…\""),
        ("SQL/堆栈报错", r"(sql syntax|traceback \(most recent call|stack trace|java\.lang\.(nullpointer|runtime)|unhandled exception)", "SQL syntax error"),
        ("XML/SOAP 裸响应", r"<\?xml|<\w+:\w+(\s|>)", "<?xml version…"),
    )

    # 业务流节点识别：按 URL 路径关键字把已发现端点聚类到业务阶段，并给出该阶段的典型逻辑缺陷打法。
    # 元素：(关键字元组, 阶段名, 建议攻击面, 业务指纹key)。命中任一关键字即归入该阶段；顺序即优先级（先精确后泛化）。
    # 业务指纹key 用于在攻击链模板匹配时构造 biz:<key> 软指纹，让「业务流识别」闭环到「打法推荐」。
    # 目的：把「散落的接口」连成「业务流地图」，让模型定向打业务逻辑缺陷（订单 IDOR/支付篡改/越权操作用户等），
    # 而非把每个接口当孤立端点。纯静态路径分析，不发包、确定性、零误报风险。
    _BUSINESS_FLOW_NODES = (
        (("register", "signup", "sign-up", "regist"), "账号注册/开通",
         "注册逻辑绕过（重复注册/验证码绕过/邀请码爆破）、默认角色权限过高", "register"),
        (("login", "logon", "signin", "auth", "oauth", "sso", "cas"), "身份认证/登录",
         "登录态窃取（JWT/会话）、认证绕过（空密码/参数篡改）、SSO/CAS 越权、弱口令", "auth"),
        (("logout", "exit", "signout"), "会话注销", "注销后令牌未失效（复用令牌）、CSRF 注销", "session"),
        (("password", "reset", "forget", "forgot", "pwd"), "密码重置/找回",
         "重置令牌可预测/不过期、重置响应枚举（用户是否存在）、密码找回逻辑绕过", "reset"),
        (("order", "orders", "trade", "bill", "invoice"), "订单/交易",
         "订单 IDOR（遍历他人订单）、订单状态篡改、越权查看/操作他人订单", "order"),
        (("pay", "payment", "checkout", "alipay", "wechat", "wxpay", "charge"), "支付/收银",
         "支付金额/数量篡改（负值/0 元/小数溢出）、支付方式绕过、回调伪造", "payment"),
        (("refund", "return", "cancel"), "退款/退货",
         "退款金额篡改、退款逻辑绕过（重复退款/未发货退款）、越权退款他人订单", "refund"),
        (("cart", "basket", "shopcar"), "购物车", "购物车越权操作、优惠券/折扣叠加绕过", "cart"),
        (("user", "users", "member", "profile", "account", "mine", "center"), "用户中心/个人资料",
         "水平越权（改他人 user_id）、个人资料 XSS、绑定信息篡改", "user_center"),
        (("address", "consignee", "receiver"), "收货地址", "地址 ID IDOR（篡改/查看他人地址）", "address"),
        (("coupon", "discount", "promo", "voucher"), "优惠券/营销", "优惠券爆破/叠加、活动逻辑绕过", "coupon"),
        (("admin", "manage", "backend", "console", "dashboard", "sys"), "后台/管理面",
         "垂直越权（普通用户访问管理接口）、后台未授权、管理功能滥用", "admin"),
        (("api", "v1", "v2", "graphql", "openapi"), "API/开放接口",
         "API 越权/未授权、GraphQL introspection、批量查询越权", "api"),
        (("upload", "file", "attachment", "avatar"), "文件上传", "上传 webshell/恶意文件、路径遍历、存储型 XSS", "upload"),
        (("search", "query", "list", "querylist"), "查询/检索", "SQLi/命令注入、越权查询他人数据、敏感信息泄露", "search"),
    )

    def _business_flow_block(self, base: str, apis: list[str], hit_paths: list[tuple[str, int]],
                             meta_exposed: list) -> str:
        """业务流状态机映射：把已发现端点按业务阶段聚类，给模型一张「业务流地图」。

        纯静态路径关键字匹配，不发包、确定性。命中端点归入对应业务阶段并标注典型逻辑缺陷打法，
        帮助模型从「孤立接口」升级到「业务流程攻击」（IDOR/支付篡改/越权操作等）。
        无任何端点命中业务关键字时返回空字符串（不刷屏）。
        """
        # 汇总所有候选端点：探测命中 + JS 接口 + 选靶暴露端点
        candidates: list[str] = []
        for p, _ in hit_paths:
            candidates.append(base + p)
        candidates.extend(apis)
        for e in meta_exposed[:20]:
            ep = re.split(r"[（(]", str(e), maxsplit=1)[0].strip()
            if ep and ep.startswith(("http://", "https://", "/")):
                candidates.append(ep if ep.startswith("http") else base + ep)

        if not candidates:
            return ""

        # 聚类：每个阶段收集命中的端点（去重）
        buckets: dict[str, list[str]] = {}
        for url in candidates:
            low = url.lower()
            for keys, stage, advice, _biz in self._BUSINESS_FLOW_NODES:
                if any(k in low for k in keys):
                    buckets.setdefault(stage, []).append(url)
                    break  # 每个端点只归入最优先匹配的阶段

        if not buckets:
            return ""

        lines = ["## 业务流状态机映射（系统据端点路径推断，供定向打业务逻辑缺陷）"]
        for keys, stage, advice, _biz in self._BUSINESS_FLOW_NODES:
            eps = buckets.get(stage)
            if not eps:
                continue
            seen = list(dict.fromkeys(eps))[:8]  # 去重并限 8 条避免刷屏
            lines.append(f"### {stage}（命中 {len(eps)} 个端点）")
            for u in seen:
                lines.append(f"- {u}")
            lines.append(f"  建议打法：{advice}")
        lines.append(
            "提示：把以上端点视为「业务流程」而非孤立接口——优先测水平/垂直越权（换他人 ID/角色）、"
            "状态与金额篡改、关键步骤跳过；同阶段端点间常存在依赖（下单→支付→退款），可串起来打。"
        )
        return "\n".join(lines)

    def _detect_business_stages(self, base: str, apis: list[str], hit_paths: list[tuple[str, int]],
                                meta_exposed: list) -> list[str]:
        """从已发现端点识别业务阶段，返回 biz_key 列表（按命中端点数降序）。

        用于把「业务流识别」闭环到「攻击链模板匹配」——worker 在 recon 后已掌握业务上下文，
        此时按 biz:<key> 软指纹重新匹配模板，优先复用与业务强相关的成功打法（订单 IDOR/支付篡改等）。
        纯静态路径分析、不发包、确定性；无任何命中返回空列表。
        """
        candidates: list[str] = []
        for p, _ in hit_paths:
            candidates.append(base + p)
        candidates.extend(apis)
        for e in meta_exposed[:20]:
            ep = re.split(r"[（(]", str(e), maxsplit=1)[0].strip()
            if ep and ep.startswith(("http://", "https://", "/")):
                candidates.append(ep if ep.startswith("http") else base + ep)

        # 统计每个 biz_key 命中的端点数（按最优先匹配阶段计）
        counts: dict[str, int] = {}
        for url in candidates:
            low = url.lower()
            for keys, _stage, _advice, biz in self._BUSINESS_FLOW_NODES:
                if any(k in low for k in keys):
                    counts[biz] = counts.get(biz, 0) + 1
                    break
        # 按命中数降序返回 biz_key；无命中返回空
        return [k for k, _ in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)]

    def _param_dict_leads(self, executor, base: str, confirmed_params: list[str]) -> list[dict]:
        """参数级漏洞字典探测的结构化版：对已在目标上确认有响应的参数发只读特征 payload 直通，
        返回确定性命中线索（param/url/vuln_cls/signature），供模型首轮直接拿到「已确认可疑参数清单」，
        省去重新发包验证。仅当参数名命中 `_RECON_PARAM_PROBES` 才探测，避免浪费发包；
        **不**直接判定为漏洞（仅特征探针）。全程静默降级返回空列表。
        """
        if executor is None or not hasattr(executor, "http_request") or not confirmed_params:
            return []
        known = {p for p, _ in self._RECON_PARAM_PROBES}
        out: list[dict] = []
        for param in confirmed_params:
            if param not in known:
                continue
            for payload, vuln_cls, signatures in self._RECON_PARAM_PAYLOADS:
                probe_url = f"{base}/?{param}={payload}"
                try:
                    r = self._safe_recon_req(executor, probe_url)
                    code = r.get("status_code")
                    if code is None or code >= 500:
                        # 5xx 直接跳过：可能是常规报错页，不在这里解读（交给模型按上下文判断）。
                        continue
                    body = str(r.get("body") or "").lower()
                    if not body:
                        continue
                    hit = next((sig for sig in signatures if sig in body), None)
                    if hit:
                        out.append({
                            "param": param,
                            "url": probe_url,
                            "vuln_cls": vuln_cls,
                            "signature": hit,
                        })
                except Exception:
                    continue
        return out

    @staticmethod
    def _lead_to_text(lead: dict) -> str:
        shown = lead["url"].split("=", 1)[-1]
        shown = shown if len(shown) <= 20 else shown[:20] + "..."
        return (
            f"- 参数 `{lead['param']}` 命中 payload \"{shown}\" 触发响应特征「{lead['signature']}」"
            f"—— 疑似 {lead['vuln_cls']}，优先用定向 payload 深挖（当前仅特征探针，未确认可利用）。"
        )

    def _param_dict_probe_block(self, executor, base: str, confirmed_params: list[str]) -> list[str]:
        """参数级漏洞字典探测（文本版，供 recon 报告）：基于结构化 leads 渲染可读线索行。

        仅当参数名命中 `_RECON_PARAM_PROBES`（即 confirmed_params 来源于 _param_probe_block 的命中）
        才探测，避免对静态参数浪费发包。返回「疑似命中」线索，供模型优先深挖，**不**直接判定为漏洞。
        """
        leads = self._param_dict_leads(executor, base, confirmed_params)
        out: list[str] = []
        for lead in leads:
            shown = lead["url"].split("=", 1)[-1]
            shown = shown if len(shown) <= 20 else shown[:20] + "..."
            out.append(
                f"- 参数 `{lead['param']}` 命中 payload \"{shown}\" 触发响应特征「{lead['signature']}」"
                f"—— 疑似 {lead['vuln_cls']}，优先用定向 payload 深挖（当前仅特征探针，未确认可利用）。"
            )
        return out

    def _param_probe_block(self, executor, base: str) -> list[str]:
        """轻量参数级探测：对常见漏洞承载参数做只读 GET，按响应差异给出漏洞类提示。

        不依赖任何先验知识，仅标记「该参数在目标上有非 404/非 5xx 响应」供模型优先试探。
        全程静默降级：executor 不支持 http_request / 任何异常都返回空列表。
        """
        if executor is None or not hasattr(executor, "http_request"):
            return []
        out: list[str] = []
        seen_params: set[str] = set()
        for param, hint in self._RECON_PARAM_PROBES:
            if param in seen_params:
                continue
            seen_params.add(param)
            probe_url = f"{base}/?{param}=autohunter_probe"
            try:
                r = self._safe_recon_req(executor, probe_url)
                code = r.get("status_code")
                if code in (200, 201, 301, 302, 307, 308, 400, 403, 406, 422, 500):
                    body = str(r.get("body") or "")
                    # 仅过滤完全空响应的 200（真空响应无信息量）；带任何正文即视为参数被服务器接收。
                    if code == 200 and len(body) == 0:
                        continue
                    out.append(f"- `{param}=` 返回 HTTP {code} —— 疑似被解析，优先试探：{hint}")
            except Exception:
                continue
        return out

    def _auth_diff_probe(self, executor, url: str) -> dict:
        """对单个端点做「匿名 vs 登录态」双态请求，对比鉴权差异。

        返回结构化结果：
          - reachable_anon / reachable_auth：两端点是否被允许访问（2xx/3xx 视为可达）
          - unauth_code / authed_code：两端点的状态码
          - gap：差异结论（anon_open=匿名即暴露；auth_only=仅登录可见；both_blocked=两端都拦；both_open=都通）
          - error：探测异常原因（非空表示降级）

        实现：先保存当前会话态 → 清除会话发匿名请求 → 恢复原会话发登录态请求。
        任何一步失败都记 error 并返回空结论，绝不拖垮主侦察。
        """
        base_error = ""
        saved_cookies = dict(getattr(executor, "_session_cookies", {}) or {})
        saved_headers = dict(getattr(executor, "_session_headers", {}) or {})
        # 匿名态：清掉会话，发一次请求
        try:
            executor.session_set(clear=True)
        except Exception:
            base_error = "session_clear_fail"
        unauth = self._safe_recon_req(executor, url)
        unauth_code = unauth.get("status_code")
        # 恢复登录态：把之前保存的会话重新设回去
        try:
            executor.session_set(cookies=saved_cookies or None, headers=saved_headers or None)
        except Exception:
            base_error = base_error or "session_restore_fail"
        authed = self._safe_recon_req(executor, url)
        authed_code = authed.get("status_code")

        def _open(c):
            return isinstance(c, int) and c in (200, 201, 202, 203, 204, 206, 301, 302, 303, 307, 308)

        reachable_anon = _open(unauth_code)
        reachable_auth = _open(authed_code)
        if reachable_anon and not reachable_auth:
            gap = "anon_open"
        elif not reachable_anon and reachable_auth:
            gap = "auth_only"
        elif not reachable_anon and not reachable_auth:
            gap = "both_blocked"
        else:
            gap = "both_open"
        return {
            "url": url,
            "unauth_code": unauth_code,
            "authed_code": authed_code,
            "unauth_resp": unauth,
            "authed_resp": authed,
            "reachable_anon": reachable_anon,
            "reachable_auth": reachable_auth,
            "gap": gap,
            "error": base_error,
        }

    def _anon_leak_scan(self, executor, urls: list[str]) -> list[dict]:
        """匿名响应体敏感数据泄露扫描：对「匿名可达端点」逐一发一次匿名 GET，读正文扫描泄露特征。

        把 step5 得到的模糊标记「该端点匿名可达」升级为具体线索「匿名响应疑似泄露了 X 类数据」。
        纯只读：不发写请求、不枚举、不爆破，仅对已知匿名可达端点各读一次正文；任何异常静默降级空列表。
        返回结构化线索（url/label/sample），供 run() 在 recon 之后按独立块后置注入首轮（避开 _intel_block 时序），
        模型据此直接复现并判断是否真泄露——不直接判定为漏洞。
        """
        if executor is None or not hasattr(executor, "http_request") or not urls:
            return []
        # 匿名态扫描：先清会话确保以未登录身份读取正文，避免把登录态才能看到的数据误判为泄露。
        try:
            executor.session_set(clear=True)
        except Exception:
            pass
        out: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for u in urls[:8]:  # 限 8 个，避免对大量匿名端点刷屏/超时
            try:
                r = self._safe_recon_req(executor, u)
                body = str(r.get("body") or "")
                if not body:
                    continue
                low = body.lower()
                for label, pat, sample in self._RECON_LEAK_SIGS:
                    if (u, label) in seen:
                        continue
                    m = re.search(pat, low, re.I)
                    if m:
                        seen.add((u, label))
                        out.append({"url": u, "label": label, "sample": sample})
            except Exception:
                continue
        return out

    def _collect_waf_profile(self, blocked_responses: list[dict]) -> dict:
        """从侦察阶段已收集的「被拦响应」中聚类 WAF/风控指纹。

        零额外发包：只消费 step3（路径探测）与 step5（鉴权差异）已经发出的请求响应。
        复用 app.tools.waf_advisor._detect_waf 做厂商指纹识别；按指纹归类并保留证据，
        返回结构化画像写独立字段 waf_profile，由 run() 在 recon 之后后置注入首轮。
        任何异常静默降级为空画像。
        """
        if not blocked_responses:
            return {}
        try:
            from app.tools.waf_advisor import _detect_waf

            by_type: dict[str, dict] = {}
            for r in blocked_responses:
                if not isinstance(r, dict):
                    continue
                status = r.get("status_code")
                headers = (r.get("response_headers") or {})
                body = str(r.get("body") or "")
                sig, evidence = _detect_waf(status, headers, body)
                name = sig.name
                if name == "none":
                    continue
                entry = by_type.setdefault(
                    name,
                    {"waf_type": name, "evidence": set(), "blocked_statuses": set(), "samples": 0},
                )
                entry["evidence"].add(evidence)
                if isinstance(status, int):
                    entry["blocked_statuses"].add(status)
                entry["samples"] += 1
            if not by_type:
                return {}
            # 取命中样本最多的前 2 个指纹（多于 2 个厂商同框罕见，避免刷屏）。
            ranked = sorted(by_type.values(), key=lambda e: e["samples"], reverse=True)[:2]
            for e in ranked:
                e["evidence"] = sorted(e["evidence"])
                e["blocked_statuses"] = sorted(e["blocked_statuses"])
            return {
                "detected": True,
                "profiles": ranked,
                "guidance": (
                    "侦察已识别前述防护。首轮探测请优先带 X-Forwarded-For/X-Real-IP(127.0.0.1) "
                    "与常见浏览器 UA 变形；命中拦截时再用 suggest_waf_bypass 取候选变形做 baseline vs "
                    "variant 实测，切勿为绕 WAF 泛试 payload。"
                ),
            }
        except Exception:
            return {}

    def _waf_profile_block(self) -> str:
        """渲染「WAF/风控指纹画像」块（读 target_meta[\"waf_profile\"]，空字段返回空）。"""
        profile = (getattr(self, "target_meta", None) or {}).get("waf_profile") or {}
        if not profile.get("detected"):
            return ""
        profiles = profile.get("profiles") or []
        if not profiles:
            return ""
        lines = ["## WAF/风控指纹画像（侦察已实测，首轮即带变形策略）", ""]
        for p in profiles:
            wt = p.get("waf_type", "unknown")
            codes = "/".join(str(c) for c in (p.get("blocked_statuses") or []))
            ev = "；".join(p.get("evidence") or [])
            lines.append(f"- ⚠ 疑似 **{wt}** 防护（拦截码 {codes or '?'}）：{ev}")
        lines.append(
            "提示：" + profile.get("guidance", "命中拦截时用 suggest_waf_bypass 取候选变形实测。")
        )
        return "\n".join(lines) + "\n\n"

    def _passive_intel_block(self, executor, base: str) -> str:
        """被动情报补充攻击面（仅配置了测绘 key 时确定性前置一次）。

        对当前目标域/同组织资产做一次只读测绘，把同 IP/同域暴露的其它
        主机、端口、服务标题补充进攻击面，让 worker 有机会打到隐藏后台、
        旁路服务或非标准端口。无任何 key / 查询失败 / 超时都静默降级为空串。

        这是纯被动只读查询，不对目标产生任何请求；验证仍需 http_request 实证。
        """
        fofa_key = (getattr(executor, "fofa_key", None) or "").strip()
        if not fofa_key:
            return ""
        parsed = safe_urlparse(base)
        host = (parsed.hostname or "").strip()
        if not host:
            return ""
        if is_unusable_host(host):
            return ""
        # 裸 IP 用 ip= 查邻居段；域名用 domain= 覆盖同组织全量资产。
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            query = f'ip="{host}"'
        else:
            # 取主域（最后两段），避免子域过窄导致漏资产。
            parts = host.split(".")
            domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
            query = f'domain="{domain}"'
        try:
            res = executor.fofa_lookup(query=query, size=20)
        except Exception:
            return ""
        if not isinstance(res, dict) or not res.get("ok"):
            return ""
        sample = res.get("sample") or []
        if not sample:
            return ""
        out = [
            "## 被动情报补充攻击面（测绘只读，确认后仍需 http_request 实证）",
            f"- 查询：{query}（命中规模约 {res.get('size', '?')}）",
        ]
        shown = 0
        seen_pairs: set[tuple[str, str]] = set()
        for r in sample:
            if not isinstance(r, dict):
                continue
            h = (r.get("host") or "").strip()
            p = str(r.get("port") or "").strip()
            if not h:
                continue
            pair = (h, p)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            title = (r.get("title") or "").strip()
            org = (r.get("org") or "").strip()
            line = f"- {h}:{p}" if p else f"- {h}"
            if title:
                line += f"  标题：{title}"
            if org and org != (r.get("domain") or ""):
                line += f"  归属：{org}"
            out.append(line)
            shown += 1
            if shown >= 20:
                break
        if shown == 0:
            return ""
        out.append(
            "提示：以上为同域/同组织的其它暴露面，可能藏隐藏后台、旁路接口或非标准端口服务；"
            "优先用 http_request 验证其中与本目标相关的资产。"
        )
        return "\n".join(out) + "\n"

    def _run_mandatory_recon(self) -> str:
        """LLM 自主挖洞前做确定性入口测绘，保证任何模型都先拿到入口地图。

        仅对首次挖洞（非回炉）执行；全程确定性调用工具，不消耗 LLM 轮次。
        任何异常都静默降级为空字符串（不影响主挖洞流程）。executor 不具备
        http_request 能力（如单测桩）时直接返回空，避免无意义调用。
        """
        executor = getattr(self, "executor", None)
        if executor is None or not hasattr(executor, "http_request"):
            return ""
        base = ensure_scheme(self.target).rstrip("/")
        self._emit("worker_recon_start", target=base)
        try:
            lines = [
                "# 强制前置侦察报告（系统已完成，请直接基于此挖，不要重复下列基础探测）",
                "",
            ]
            # 跨 step 累积的全部已发现端点（sitemap/探测命中/JS 接口），供业务流映射块聚类分析。
            apis_all: list[str] = []

            # 1. 首页/根：标题、指纹、是否含 JS
            home = self._safe_recon_req(executor, base, follow_redirects=True)
            title = self._recon_title(home)
            server = self._recon_header(home, "server")
            x_powered = self._recon_header(home, "x-powered-by")
            fp = self._recon_fingerprint(home)
            js_signal = self._recon_js_signal(home)
            lines.append(f"## 首页（{base}）")
            if home.get("ok"):
                lines.append(
                    f"- 状态码：{home.get('status_code')}；"
                    f"最终地址：{home.get('final_url') or home.get('url')}"
                )
                if title:
                    lines.append(f"- 标题：{title}")
                if server:
                    lines.append(f"- Server：{server}")
                if x_powered:
                    lines.append(f"- X-Powered-By：{x_powered}")
            else:
                lines.append("- 首页不可达（连接失败/超时），目标可能离线或网络受限。")
            if fp:
                lines.append(f"- 指纹命中：{', '.join(fp)}")
            lines.append("")

            # 选靶阶段已主动探出的高价值端点：直接采用，不再重复发包。
            meta_exposed = (getattr(self, "target_meta", None) or {}).get("exposed_endpoints") or []
            already_probed: set[str] = set()
            if meta_exposed:
                lines.append("## 选靶阶段已发现入口（系统已探测，直接复用，无需重探）")
                for e in meta_exposed[:20]:
                    path = re.split(r"[（(]", str(e), maxsplit=1)[0].strip()
                    auth = "（需鉴权）" if "需鉴权" in str(e) else ""
                    lines.append(f"- {path}{auth}")
                    if path:
                        already_probed.add(path.rstrip("/"))
                lines.append("")

            # 2. robots.txt / sitemap.xml：常暴露后台/隐藏路径
            lines.append("## 暴露的入口清单")
            for p in ("/robots.txt", "/sitemap.xml"):
                r = self._safe_recon_req(executor, base + p)
                code = r.get("status_code")
                if r.get("ok") and code == 200:
                    body = (r.get("body") or "")
                    if p.endswith("sitemap.xml"):
                        # sitemap 用 <loc> 列出真实页面/接口，解析入面（上限 40，避免巨型站点刷屏）
                        locs = re.findall(r"<loc>(.*?)</loc>", body, re.I | re.S)
                        locs = [u.strip() for u in locs if u.strip()][:40]
                        if locs:
                            # 同源路径并入已探集合，避免 step3 重复发包；疑似接口/后台的 loc 单列给模型。
                            api_like: list[str] = []
                            for u in locs:
                                pu = safe_urlparse(u)
                                if pu.hostname and pu.hostname == (safe_urlparse(base).hostname):
                                    path = (pu.path or "").rstrip("/")
                                    if path:
                                        already_probed.add(path)
                                if re.search(r"(/api/|/admin|/rest|/service|/v[12]/|/actuator|/swagger|\.json|\.api)", u, re.I):
                                    api_like.append(u)
                            lines.append(f"- sitemap.xml 暴露页面/接口 {len(locs)} 个（取前 40，同源路径已并入侦察面）：")
                            for u in locs:
                                lines.append(f"  - {u}")
                            if api_like:
                                lines.append(f"- 其中疑似后台/API 接口 {len(api_like)} 个（优先深挖）：")
                                for u in api_like[:15]:
                                    lines.append(f"  - {u}")
                        else:
                            # 兼容 robots 风格的 Allow/Disallow（部分站点把路径放 sitemap 同址）
                            exposed = [
                                ln.split(maxsplit=1)[1].strip()
                                for ln in body.splitlines()
                                if ln.strip().lower().startswith(("allow:", "disallow:"))
                                and len(ln.split(maxsplit=1)) > 1
                            ]
                            if exposed:
                                lines.append(f"- {p} 暴露路径：{', '.join(exposed[:30])}")
                            else:
                                lines.append(f"- {p} 存在（{len(body)} 字节），无 <loc> 路径条目。")
                    else:
                        exposed = [
                            ln.split(maxsplit=1)[1].strip()
                            for ln in body.splitlines()
                            if ln.strip().lower().startswith(("allow:", "disallow:"))
                            and len(ln.split(maxsplit=1)) > 1
                        ]
                        if exposed:
                            lines.append(f"- {p} 暴露路径：{', '.join(exposed[:30])}")
                        else:
                            lines.append(f"- {p} 存在（{len(body)} 字节），无明显路径条目。")
                elif code not in (None,):
                    lines.append(f"- {p}：HTTP {code}（无暴露入口）")
            lines.append("")

            # 3. 后台/API/运维常见路径探测（只记录有响应的，排除纯 404）
            # 选靶阶段已探明的端点不再重复发包，只补探尚未覆盖的路径。
            lines.append("## 后台/API/运维路径探测（状态码）")
            hit_paths = []
            # 拦截响应汇总：把命中拦截特征（403/406/429/拦截页 body）的原始响应收集起来，
            # 供 step5.6 做 WAF/风控指纹聚类（零额外发包，纯被动复用侦察已有响应）。
            blocked_responses: list[dict] = []
            for p in _RECON_PROBE_PATHS:
                if p.rstrip("/") in already_probed:
                    continue
                r = self._safe_recon_req(executor, base + p)
                if not r.get("ok"):
                    continue
                code = r.get("status_code")
                if code in (200, 201, 301, 302, 307, 308, 401, 403, 405, 500):
                    hit_paths.append((p, code))
                    if code in (401, 403):
                        lines.append(f"- {p}：{code}（需鉴权，可能是后台/管理面）")
                    elif code in (301, 302, 307, 308):
                        lines.append(f"- {p}：{code}（跳转→{r.get('final_url') or ''}）")
                    else:
                        lines.append(f"- {p}：{code}")
                    if str(code) in ("401", "403", "406", "429") or self._looks_blocked(r):
                        blocked_responses.append(r)
            if not hit_paths:
                lines.append("- 上述常见路径均未暴露（全 404/不可达）。")
            lines.append("")

            # 3.5 轻量参数级探测：常见漏洞承载参数名只读 GET，按响应差异提示漏洞类。
            #     把命中参数端点也并入鉴权差异候选（参数端点是 IDOR/未授权/SSRF 的主战场）。
            param_hits = self._param_probe_block(executor, base)
            if param_hits:
                lines.append("## 参数级探测（常见漏洞承载参数，疑似被解析）")
                for h in param_hits[:14]:
                    lines.append(h)
                lines.append(
                    "提示：以上参数在目标上返回非 404/5xx，可能真正参与逻辑；"
                    "优先按提示类目试探越权/未授权/注入/SSRF，不要把参数当静态文本。"
                )
                lines.append("")

                # 3.6 参数级漏洞字典探测：仅对上述已确认有响应的参数发只读特征 payload 直通，
                # 把确定性漏洞线索（SQLi 报错/SSTI 求值/遍历回显/XSS 回显）直接喂给模型深挖。
                confirmed_params = []
                for h in param_hits[:14]:
                    m = re.match(r"- `([^`]+)=`", h)
                    if m:
                        confirmed_params.append(m.group(1))
                # 结构化 leads（param/url/vuln_cls/signature）用于首轮后置注入，让模型不必重新 parse 文本。
                dict_leads = self._param_dict_leads(executor, base, confirmed_params)
                dict_hits = [self._lead_to_text(l) for l in dict_leads]
                if dict_hits:
                    lines.append("## 参数级漏洞字典探测（只读特征 payload 直通）")
                    for d in dict_hits[:14]:
                        lines.append(d)
                    lines.append(
                        "提示：以上为「特征探针」命中，仅说明该参数对特定 payload 产生了可疑回显；"
                        "需用定向 payload 复现并确认可利用性，切勿直接判定为已利用漏洞。"
                    )
                    lines.append("")
                if dict_leads:
                    # 写回 target_meta，run() 在 recon 之后按独立块后置注入首轮（避开 _intel_block 时序）。
                    self.target_meta["confirmed_probe_leads"] = dict_leads

            # 鉴权差异候选：侦察阶段会话已带登录态，因此探测返回 200/开放码的入口
            # （含选靶阶段已暴露的端点 + 命中参数端点）本身并不能说明是否受鉴权保护——必须做
            # 「匿名 vs 登录态」双态对比才能区分「匿名即可达（未授权）」与「仅登录可见（越权战场）」。
            # 统一收集后见 step 5。
            auth_diff_candidates: list[str] = []
            for p, code in hit_paths:
                if code in (200, 201, 301, 302, 307, 308, 500):
                    auth_diff_candidates.append(base + p)
            for e in meta_exposed[:20]:
                # 暴露端点文本可能带中文/英文括号标注（如「（暴露）」「（需鉴权）」），统一去掉括号后缀。
                ep = re.split(r"[（(]", str(e), maxsplit=1)[0].strip()
                if ep and ep.startswith(("http://", "https://", "/")):
                    auth_diff_candidates.append(ep if ep.startswith("http") else base + ep)
            for h in param_hits[:14]:
                # 从 "- `id=` 返回 HTTP 200 —— ..." 提取参数名构造探测端点候选。
                m = re.match(r"- `([^`]+)=`", h)
                if m:
                    auth_diff_candidates.append(f"{base}/?{m.group(1)}=autohunter_probe")

            # 4. JS 接口提取（首页含 JS 信号时确定性做，把接口地图直接给模型）
            if js_signal:
                try:
                    seen_eps: set[str] = set()
                    chains_all: list = []

                    def _collect(js: dict | None) -> None:
                        if not isinstance(js, dict):
                            return
                        for a in (js.get("api_endpoints") or js.get("endpoints") or []):
                            ep = a if isinstance(a, str) else (a.get("url") or a.get("path") or "")
                            if ep and ep not in seen_eps:
                                seen_eps.add(ep)
                                apis_all.append(ep)
                        for ch in (js.get("chains") or []):
                            chains_all.append(ch)

                    # 4a. 首页本身（内联脚本 + 主 bundle），加深深度覆盖 SPA chunk
                    home_js = executor.analyze_javascript(url=base, max_depth=3, max_assets=120)
                    _collect(home_js)
                    # 4b. 首页显式 <script src> 逐文件分析，把全量接口地图直接给模型
                    #     （SPA 的真实 API 面常藏在独立 chunk 里，单分析首页会漏）
                    home_body = (home.get("body") or "") if isinstance(home, dict) else ""
                    # 兼容带引号与裸属性两种写法：src="a.js" / src='a.js' / src=a.js
                    script_srcs = re.findall(
                        r"<script[^>]+src=(?:[\"']([^\"']+)[\"']|([^\s>\"']+))",
                        home_body, re.I,
                    )
                    script_srcs = [a or b for a, b in script_srcs]
                    script_srcs = self._dedupe_script_srcs(script_srcs, base)[:12]
                    for s in script_srcs:
                        try:
                            _collect(executor.analyze_javascript(url=s, max_depth=3, max_assets=120))
                        except Exception:
                            continue

                    if apis_all:
                        # 接口地图直接给模型上限放宽到 80，覆盖大型 SPA 的真实 API 面（原 40 易漏）。
                        lines.append("## 前端 JS 暴露的接口线索")
                        for ep in apis_all[:80]:
                            lines.append(f"- {ep}")
                        lines.append("")
                    if chains_all:
                        lines.append(f"- JS 高价值链路 {len(chains_all)} 条（详见工作目录 JS 分析报告）。")
                        lines.append("")
                except Exception:
                    pass

            # 5. 鉴权差异对比：对候选端点做「匿名 vs 登录态」双态请求，把鉴权缺口直接喂给模型。
            #    这是坐实 IDOR/未授权/垂直越权的最短路——避免模型在 LLM 轮次里反复手动清 cookie 对比。
            #    仅当至少有 1 个候选端点且 executor 支持会话态时执行；任何异常静默跳过。
            # anon_open 在 step5 块内填充，step5.5 扫描依赖它；提前声明为空，避免 step5 不执行时未绑定。
            anon_open: list[str] = []
            if auth_diff_candidates and hasattr(executor, "session_set"):
                try:
                    diff_lines = ["## 鉴权差异对比（匿名 vs 登录态，系统已实测）"]
                    auth_only: list[str] = []
                    for u in auth_diff_candidates[:12]:
                        d = self._auth_diff_probe(executor, u)
                        if d.get("error"):
                            continue
                        if d["gap"] == "anon_open":
                            anon_open.append(u)
                            diff_lines.append(
                                f"- ⚠ {u}：匿名即返回 {d['unauth_code']}（登录态 {d['authed_code']}）——"
                                f"疑似未授权可直接拿数据，优先深挖是否含受限/敏感资源"
                            )
                        elif d["gap"] == "auth_only":
                            auth_only.append(u)
                            diff_lines.append(
                                f"- {u}：匿名 {d['unauth_code']} → 登录态 {d['authed_code']}——"
                                f"确实受鉴权保护，可尝试越权/鉴权绕过打法"
                            )
                        elif d["gap"] == "both_blocked":
                            diff_lines.append(f"- {u}：匿名 {d['unauth_code']} / 登录态 {d['authed_code']}——两端都拦，暂不可达")
                            # 两端都拦：把两端响应都纳入 WAF/风控指纹聚类（step5.6 复用，零额外发包）。
                            for _resp in (d.get("unauth_resp"), d.get("authed_resp")):
                                if isinstance(_resp, dict) and (str(_resp.get("status_code")) in ("401", "403", "406", "429") or self._looks_blocked(_resp)):
                                    blocked_responses.append(_resp)
                        else:  # both_open
                            diff_lines.append(f"- {u}：匿名 {d['unauth_code']} / 登录态 {d['authed_code']}——两端都通，需看响应数据是否随身份变化")
                    if anon_open or auth_only:
                        diff_lines.append(
                            "提示：匿名可达端点先按「公开接口识别」排除本就公开的展示类接口；"
                            "确实受保护却匿名可达 = 未授权访问；仅登录可见端点 = 优先测水平/垂直越权与鉴权绕过。"
                        )
                        lines.append("\n".join(diff_lines))
                        lines.append("")
                    # 两端都拦 / 两端都通 没有额外结论价值，避免刷屏，不单独出块。
                except Exception:
                    pass

            # 5.5 匿名响应体敏感数据泄露扫描：对 step5 已确认「匿名可达」的端点逐一发一次匿名 GET，
            # 把模糊的「匿名可达」标记升级为具体线索「匿名响应疑似泄露 X 类数据」（邮箱/手机号/身份证/
            # JSON 裸数据/JWT/报错/XML 等）。纯只读、不枚举、不爆破；结果写入独立字段 anon_leak_leads，
            # 由 run() 在 recon 之后后置注入首轮（避开 _intel_block 时序窗口）。任何异常静默跳过。
            if anon_open:
                try:
                    leak_leads = self._anon_leak_scan(executor, anon_open)
                    if leak_leads:
                        self.target_meta["anon_leak_leads"] = leak_leads
                except Exception:
                    pass

            # 5.6 WAF/风控指纹画像：对侦察阶段已收集的「被拦响应」（step3 路径探测 + step5 鉴权差异两端）
            # 做厂商指纹聚类，写独立字段 waf_profile，由 run() 在 recon 之后后置注入首轮——
            # 让模型第一发请求就知道前面架着什么防护、该带什么变形，而不是撞墙后才补救。
            # 纯被动复用既有响应，零额外发包。
            if blocked_responses:
                try:
                    waf_profile = self._collect_waf_profile(blocked_responses)
                    if waf_profile.get("detected"):
                        self.target_meta["waf_profile"] = waf_profile
                except Exception:
                    pass

            # 6. 被动情报补充攻击面（仅配置测绘 key 时确定性前置一次，无 key/失败静默跳过）
            try:
                intel_block = self._passive_intel_block(executor, base)
                if intel_block:
                    lines.append(intel_block)
            except Exception:
                pass

            # 7. 业务流状态机映射：把已发现端点（探测命中 + JS 接口 + 选靶暴露）按业务阶段聚类，
            #    给模型一张「业务流程地图」，定向打 IDOR/支付篡改/越权操作等逻辑缺陷。纯静态分析不发包。
            biz_keys: list[str] = []
            try:
                flow_block = self._business_flow_block(base, apis_all, hit_paths, meta_exposed)
                if flow_block:
                    lines.append(flow_block)
                    lines.append("")
                # 业务流识别闭环到攻击链模板：把 biz_key 写回 target_meta，并本地按 biz 软指纹
                # 匹配业务针对性打法。写入独立字段 business_attack_chain（而非混入编排层注入的
                # attack_chain_hints）——因为 _intel_block 在 recon 之前已组装，混入口会被时序吃掉、
                # 首轮 LLM 拿不到业务打法；改为 run() 在 recon 注入后单独追加业务打法块（见 _business_chain_block）。
                biz_keys = self._detect_business_stages(base, apis_all, hit_paths, meta_exposed)
                if biz_keys:
                    self.target_meta["business_stages"] = biz_keys
                    try:
                        from app.agents.attack_chain_templates import match_for
                        biz_hints = match_for([], business_stages=biz_keys)
                        if biz_hints:
                            self.target_meta["business_attack_chain"] = biz_hints
                    except Exception:
                        pass
            except Exception:
                pass

            lines.append(
                "以上为系统强制完成的入口测绘。请优先覆盖已暴露的高价值接口/后台，"
                "再按方法论深挖；不要重复探测上面已列出的不可达/404 路径。"
            )
            report = "\n".join(lines)
            self._emit("worker_recon_done", target=base, hits=len(hit_paths), fingerprint=",".join(fp))
            return report
        except Exception as e:  # 侦察失败绝不影响主挖洞
            self._emit("worker_recon_error", target=base, error=str(e)[:200])
            return ""

    def _intel_block(self) -> str:
        m = self.target_meta or {}
        school = (m.get("school") or "").strip()
        org = (m.get("org") or "").strip()
        title = (m.get("title") or "").strip()
        source = (m.get("source") or "").strip()
        site = self._site_collab_block()
        priority_reason = (m.get("priority_reason") or "").strip()
        playbook = self._playbook_block()
        # 即使没有资产情报，只要有泄露凭证/情报库命中也要带出去（企业目标常无 school/org/title）。
        if not (school or org or title or source):
            return site + playbook + self._user_auth_block() + self._creds_block() + self._intel_lib_block()
        owner_label = "候选归属单位/系统" if is_enterprise_src(self.src_type) else "候选归属学校"
        prefix = [b.rstrip() for b in (site, playbook) if b.strip()]
        lines = prefix + ["# 资产情报（搜集阶段提供，需你核实）"]
        if school:
            lines.append(f"- {owner_label}：{school}")
        if org:
            lines.append(f"- 单位(org)：{org}")
        if title:
            lines.append(f"- 站点标题：{title}")
        if source == "killsweep":
            lines.append("- 来源：通杀验证目标（已由通杀 Hunter 找到同款系统并验证过 1 个点）")
            if priority_reason:
                lines.append(f"- 通杀上下文：{priority_reason}")
            lines.append("注意：你只负责把当前站点的实际漏洞证据打出来，不要围绕该产品继续做通杀扩散判断。")
        lines.append("提交漏洞时，请核实归属（域名/备案/证书CN/页脚版权/FOFA org/登录页品牌）后把最终归属写进 submit_finding 的 owner 字段。")
        return ("\n".join(lines) + "\n\n" + self._user_auth_block() + self._creds_block()
                + self._intel_lib_block() + self._attack_chain_block())

    def _user_auth_block(self) -> str:
        """用户在凭据区提供的 Cookie/账密（系统已尝试后的回执）。"""
        ctx = (self.target_meta or {}).get("user_auth") or (self.target_meta or {}).get("auth_context")
        attempt = (self.target_meta or {}).get("auth_attempt")
        if not ctx and not attempt:
            return ""
        return auth_bootstrap.user_auth_prompt_block(ctx, attempt)

    def _bootstrap_user_auth(self) -> None:
        """启动时确定性使用用户凭据：注入 Cookie/Bearer 或尝试账密登录，并 emit 反馈。"""
        ctx = (self.target_meta or {}).get("user_auth") or (self.target_meta or {}).get("auth_context")
        if not ctx:
            return
        result = auth_bootstrap.bootstrap_auth(self.executor, ctx, self.target)
        payload = result.as_event()
        self.target_meta["auth_attempt"] = payload
        self._emit(
            "auth_status",
            message=auth_bootstrap.format_auth_status_message(result),
            **payload,
        )

    def _playbook_block(self) -> str:
        """目标打法路由：编排层生成的短路线块。"""
        return (self.target_meta or {}).get("playbook_block") or ""

    def _site_collab_block(self) -> str:
        """单站协作路线块：当前 worker 的分工和已有覆盖摘要。"""
        return (self.target_meta or {}).get("site_collab_block") or ""

    def _intel_lib_block(self) -> str:
        """全局情报库命中（编排层触发式检索后注入的现成文本块）。"""
        return (self.target_meta or {}).get("intel_block") or ""

    def _attack_chain_block(self) -> str:
        """命中攻击链模板库的历史成功打法：按指纹复用相似系统有效利用链。

        回炉（deepen）任务已有明确方向，跳过；任何异常静默返回空。
        """
        if self.deepen_context:
            return ""
        hints = (self.target_meta or {}).get("attack_chain_hints") or []
        if not hints:
            return ""
        lines = ["# 同类系统历史成功打法（按指纹匹配，优先复用，但仍需逐目标实弹验证）"]
        for h in hints[:3]:
            chain = (h.get("attack_chain") or "").strip()
            vt = h.get("vuln_type") or ""
            if chain:
                lines.append(f"- [{vt}] {chain}")
        lines.append(
            "注意：这些是相似系统上已被采纳的有效打法，可作为优先尝试方向；"
            "但每个目标需独立取证，禁止直接套用未经验证的结论。"
        )
        return "\n".join(lines) + "\n\n"

    def _business_chain_block(self) -> str:
        """业务流识别闭环产出的业务针对性打法：recon 阶段按端点识别业务阶段（订单/支付/用户中心等），
        本地匹配对应通用打法，在 recon 注入后单独追加到首轮上下文（避开 _intel_block 的时序窗口）。

        与 _attack_chain_block 分离：前者是系统指纹命中（编排层注入、首轮前已就绪），本块是侦察期
        动态识别的业务上下文命中（recon 后才算得出来），必须后置注入才进得了首轮 LLM。
        """
        hints = (self.target_meta or {}).get("business_attack_chain") or []
        if not hints:
            return ""
        stages = (self.target_meta or {}).get("business_stages") or []
        lines = ["# 业务流针对性打法（侦察期识别到目标属典型业务系统，优先复用）"]
        if stages:
            lines.append(f"- 识别到的业务阶段：{', '.join(stages)}")
        for h in hints[:3]:
            chain = (h.get("attack_chain") or "").strip()
            vt = h.get("vuln_type") or ""
            if chain:
                lines.append(f"- [{vt}] {chain}")
        lines.append(
            "注意：业务系统最易出逻辑缺陷（订单/支付/用户越权、金额篡改、状态跳过）。"
            "把端点当「业务流程」打，优先测水平/垂直越权与状态金额篡改，而非孤立接口。"
        )
        return "\n".join(lines) + "\n\n"

    def _probe_leads_block(self) -> str:
        """确定性漏洞线索块：侦察期参数字典探测已确认的「可疑参数」结构化清单，在 recon 之后
        后置注入首轮上下文（与 _business_chain_block 同理由——避开 _intel_block 时序窗口）。

        让模型首轮直接拿到「哪些参数对哪些 payload 产生了可疑回显」，省去重新发包验证、直接做
        定向复现与可利用性确认；仍明确标注「仅特征探针、未确认可利用」，避免误报。
        """
        leads = (self.target_meta or {}).get("confirmed_probe_leads") or []
        if not leads:
            return ""
        lines = ["# 确定性漏洞线索（侦察期参数字典探测已确认可疑参数，首轮直接复用）"]
        for l in leads[:10]:
            lines.append(
                f"- `{l.get('param')}` → 疑似 {l.get('vuln_cls')}（特征「{l.get('signature')}」，"
                f"探针 {l.get('url')}）"
            )
        lines.append(
            "纪律：这些是只读特征探针命中，已确认「该参数对该类 payload 有可疑回显」；"
            "请用定向 payload 复现并确认可利用性后再提交，切勿直接判定为已利用漏洞。"
        )
        return "\n".join(lines) + "\n\n"

    def _anon_leak_block(self) -> str:
        """匿名敏感数据泄露线索块：侦察期对「匿名可达端点」读正文扫描出的疑似泄露线索，
        在 recon 之后后置注入首轮上下文（同 _business_chain_block / _probe_leads_block 的时序理由）。

        把 step5 的模糊标记「该端点匿名可达」升级为具体「匿名响应疑似泄露了 X 类数据」，让模型
        首轮直接拿到待复现线索；仍明确标注「仅特征扫描、需复现确认」，避免把正常接口误报为泄露。
        """
        leads = (self.target_meta or {}).get("anon_leak_leads") or []
        if not leads:
            return ""
        lines = ["# 匿名敏感数据泄露线索（侦察期对匿名可达端点读正文扫描，首轮直接复用）"]
        for l in leads[:10]:
            lines.append(
                f"- {l.get('url')} 匿名响应疑似含「{l.get('label')}」（特征样例：{l.get('sample')}）——"
                f"优先复现是否真泄露受限/敏感数据"
            )
        lines.append(
            "纪律：这些是只读特征扫描命中，仅说明匿名响应正文出现了某类敏感数据的特征；"
            "需剔除本就公开的展示类接口后，用定向请求复现并确认确实泄露了他人/受限数据再提交。"
        )
        return "\n".join(lines) + "\n\n"

    def _creds_block(self) -> str:
        """泄露凭证情报：搜集阶段查到的该域已泄露账号密码（已过滤打分）。"""
        creds = (self.target_meta or {}).get("leaked_creds") or []
        if not creds:
            return ""
        lines = [
            "# 泄露凭证情报（搜集阶段已过滤打分）",
            "以下账密按可用概率排序；它们只是深挖入场券，不是漏洞本身。",
        ]
        for c in creds[:12]:
            u = (c.get("username") or "")[:40]
            p = (c.get("password") or "")[:40]
            h = (c.get("host") or "")[:40]
            lines.append(f"- {u} : {p}  （泄露于 {h}）")
        lines.append("纪律：登录成功/CASTGC/session/个人中心本身不算洞；必须继续实证死规矩敏感数据、越权、敏感写操作、注入/上传 getshell 或具体业务系统危害。没实锤就写 deepen_lead；试 2-3 个高价值凭证失败就换攻击面；严禁改密。")
        return "\n".join(lines) + "\n\n"

    def _duplicate_block(self) -> str:
        if not self.duplicate_history:
            return ""
        lines = ["# 统一查重上下文（跨任务同 host / 通杀明细，勿重复提交）"]
        lines.append(f"后端完整查重池含 {len(self.duplicate_history)} 条；这里只列摘要。提交前必须调用 check_duplicate_finding。")
        lines.append("duplicate=true 才禁止提交同系统同洞；其它 endpoint/类型/证据链可继续。")
        for item in self.duplicate_history[:6]:
            reason = (item.get("dedup_reason") or "")[:80]
            lines.append(
                f"- 来源={item.get('source','history')}；[{item.get('vuln_type','')}] {item.get('title','')} "
                f"@ {item.get('target_url','')}（状态：{item.get('status','')}；原因：{reason or '已存在'}）"
            )
        if len(self.duplicate_history) > 6:
            lines.append(f"- 其余 {len(self.duplicate_history) - 6} 条仅在后台查重池中。")
        return "\n".join(lines) + "\n\n"

    def run(self) -> WorkerResult:
        # 用户凭据：在任何 LLM 轮次前强制尝试，结果写进 target_meta 供 prompt 与看板。
        try:
            self._bootstrap_user_auth()
        except Exception as e:
            self._emit("auth_status", used=True, matched=True, status="login_fail",
                       kinds=[], reason=f"凭据启动异常: {type(e).__name__}: {e}"[:300],
                       message=f"凭据启动异常: {e}")

        # 上一轮 LLM 中断留下的进度：笔记 + 会话态先恢复，再开挖
        self._restore_interrupt_progress()

        if self.deepen_context:
            user_content = self._intel_block() + self._duplicate_block() + self._deepen_brief()
            self._emit("worker_start", target=self.target, mode="deepen", prompt_version=self.prompt_version)
        else:
            user_content = (
                self._intel_block()
                + self._duplicate_block()
                + f"目标：{self.target}\n\n"
                + "只挖此目标；自主侦察取证，结束调用 finish。"
            )
            self._emit("worker_start", target=self.target, prompt_version=self.prompt_version)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": worker_system_prompt(self.src_type, self.prompt_version, src_rules=self.src_rules)},
            {"role": "user", "content": _WORKER_STATIC_PREFIX},
            {"role": "user", "content": user_content},
        ]

        # 强制前置侦察：LLM 自主挖洞前先做确定性入口测绘，弱模型也不会漏入口。
        # 回炉（deepen）任务已有明确方向，跳过以减少重复；任何异常静默降级。
        if worker_config.mandatory_recon and not self.deepen_context:
            try:
                recon_report = self._run_mandatory_recon()
            except Exception:
                recon_report = ""
            if recon_report:
                messages.append({"role": "user", "content": recon_report})
                self._emit("worker_recon_injected", target=self.target)
                # 业务流识别闭环产出的业务针对性打法：recon 之后才算得出来，必须在这里后置注入，
                # 否则首轮 LLM 拿不到（_intel_block 在 recon 之前已组装）。
                biz_chain = self._business_chain_block()
                if biz_chain:
                    messages.append({"role": "user", "content": biz_chain})
                    self._emit("worker_biz_chain_injected", target=self.target)
                # 确定性漏洞线索（参数字典探测已确认可疑参数）：同理后置注入首轮，让模型直接复用、
                # 不必重新发包验证，直接做定向复现与可利用性确认。
                probe_leads = self._probe_leads_block()
                if probe_leads:
                    messages.append({"role": "user", "content": probe_leads})
                    self._emit("worker_probe_leads_injected", target=self.target)
                # 匿名敏感数据泄露线索（step5 已确认匿名可达端点读正文扫描）：同理后置注入首轮，
                # 把模糊的「匿名可达」升级为具体的「疑似泄露 X 类数据」，模型首轮直接拿到待复现线索。
                anon_leak = self._anon_leak_block()
                if anon_leak:
                    messages.append({"role": "user", "content": anon_leak})
                    self._emit("worker_anon_leak_injected", target=self.target)

                # WAF/风控指纹画像（step3+step5 被动复用被拦响应聚类）：后置注入首轮，
                # 让模型第一发请求就知道前面架着什么防护、该带什么变形，而不是撞墙后才补救。
                waf_profile = self._waf_profile_block()
                if waf_profile:
                    messages.append({"role": "user", "content": waf_profile})
                    self._emit("worker_waf_profile_injected", target=self.target)

        rounds = 0
        no_tool_rounds = 0
        # auto 兼容模式下，检测到「哑模型」(全程零工具)时只自愈切一次提示词模拟，避免反复切
        tool_compat_selfheal_tried = False
        consecutive_failures = 0
        consecutive_blocked = 0
        consecutive_arg_errors = 0
        consecutive_network_failures = 0
        consecutive_llm_failures = 0
        # 按 src_type 取预算：企业模式给更大深挖空间（110/60），edu 走量沿用 90/45。
        max_rounds, soft_rounds = self._route_rounds(*worker_config.rounds_for(self.src_type))
        while rounds < max_rounds:
            if self.cancel_event.is_set():
                return self._cancelled_result(rounds)
            # 人工实时指令：在开新一轮 LLM 前注入，优先于自主打法。
            # 用 getattr：部分单测用 Worker.__new__ 绕过 __init__。
            directive = ""
            pop_directive = getattr(self, "pop_directive", None)
            if pop_directive:
                try:
                    directive = (pop_directive() or "").strip()
                except Exception:
                    directive = ""
            if directive:
                messages.append({
                    "role": "user",
                    "content": (
                        "# 人工实时指令（优先执行）\n"
                        f"{directive}\n\n"
                        "请按上述指令调整本轮打法，继续调用工具验证或 finish。"
                    ),
                })
                self._emit("worker_directive", round=rounds + 1, text=directive[:500])
            rounds += 1
            try:
                self._emit("llm_round_start", round=rounds)
                tools = list(TOOL_SCHEMAS)
                # 会话保持工具全模式开放：拿到泄露/用户凭证登录后固化登录态再深挖。
                tools += SESSION_TOOL_SCHEMAS
                if self._js_tool_enabled:
                    tools += JS_ANALYZER_TOOL_SCHEMAS
                send_messages = compact_messages(messages, rounds)
                # 每轮注入当前状态块（会话态 + 工作笔记）——临时消息，不存入 messages 历史，
                # 避免累积膨胀；每轮新鲜生成，始终反映最新的 cookie/token/notes。
                # 这是连续性的核心：即使旧历史被压缩成摘要，worker 仍能看到自己当前
                # 持有哪些登录态、记录了哪些关键进度，不会跨轮"失忆"重复扫。
                send_messages.append({"role": "user", "content": self.executor.session_status_block()})
                msg = self.llm.chat(send_messages, tools=tools, tool_choice="auto")
                consecutive_llm_failures = 0
            except Exception as e:
                fields = llm_error_event_fields(e)
                self._emit("llm_error", **fields)
                failure_kind = e.kind if isinstance(e, LLMError) else ""
                retry_after = e.retry_after if isinstance(e, LLMError) else 0
                if self._should_soft_retry_llm(e) and consecutive_llm_failures < _WORKER_LLM_SOFT_RETRIES:
                    consecutive_llm_failures += 1
                    clearer = getattr(self.llm, "clear_sticky_provider", None)
                    if callable(clearer):
                        clearer()
                    wait_s = min(2 ** (consecutive_llm_failures - 1), 8)
                    if retry_after:
                        wait_s = max(wait_s, min(int(retry_after), 30))
                    self._emit(
                        "llm_soft_retry",
                        round=rounds,
                        attempt=consecutive_llm_failures,
                        max_attempts=_WORKER_LLM_SOFT_RETRIES,
                        failure_kind=failure_kind or "unknown",
                        wait_seconds=wait_s,
                        error=str(e)[:240],
                        error_copy=fields.get("error_copy") or str(e),
                        detail=fields.get("detail") or "",
                        diagnostic=fields.get("diagnostic") or "",
                    )
                    # 不消耗轮次预算：基础设施抖动不应吃掉挖掘配额
                    rounds = max(0, rounds - 1)
                    if self.cancel_event.wait(wait_s):
                        return self._cancelled_result(rounds)
                    continue
                err_text = str(e)
                if not err_text.startswith("LLM"):
                    err_text = f"LLM 调用失败：{err_text}"
                return self._llm_interrupt_result(
                    rounds=rounds,
                    error=err_text,
                    failure_kind=failure_kind,
                    retry_after=retry_after,
                )
            if self.cancel_event.is_set():
                return self._cancelled_result(rounds)

            # 模型可能只回文本（思考），也可能带 tool_calls
            tool_calls = getattr(msg, "tool_calls", None)
            assistant_msg: dict[str, Any] = {"role": "assistant", "content": msg.content or ""}
            if tool_calls:
                assistant_msg["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                    }
                    for tc in tool_calls
                ]
            messages.append(assistant_msg)

            # 是否在本轮要插入 JS 工具提示。注意：若本轮带 tool_calls，这条 user 提示必须
            # 延迟到所有 tool 响应 append 之后再插入，否则会破坏 assistant(tool_calls) → tool
            # 的连续性，触发 400。
            js_hint_pending = False
            if msg.content:
                self._emit("worker_thought", round=rounds, text=msg.content[:500])
                if self._maybe_enable_js_tool(msg.content, "模型明确提出 JS/前端分析意图"):
                    js_hint_pending = True
            js_hint_msg = {
                "role": "user",
                "content": "JS 工具已开放：analyze_javascript 只给线索，必须再用 http_request/run_shell 实证。",
            }
            if js_hint_pending and not tool_calls:
                messages.append(js_hint_msg)
                js_hint_pending = False

            if not tool_calls:
                no_tool_rounds += 1
                # auto 自愈：全程一个工具都没调过 + 是 auto 兼容模式 → 疑似「接受 tools 但不真正
                # 调工具」的哑模型。提前(第3轮)让 LLM 客户端把当前端点切成提示词模拟再给它机会，
                # 而不是空转到第6轮才放弃、还要用户手动设 AUTOHUNTER_TOOL_COMPAT=prompt。
                # getattr 防御：单测里 self.llm 可能是 mock，没有该方法。
                if (not tool_compat_selfheal_tried
                        and no_tool_rounds >= 3
                        and sum(self._tool_counts.values()) == 0):
                    switch = getattr(self.llm, "force_prompt_tools_current", None)
                    if callable(switch) and switch():
                        tool_compat_selfheal_tried = True
                        no_tool_rounds = 0
                        self._emit("tool_compat_switch", round=rounds,
                                   detail="模型全程零工具，自动切提示词模拟工具调用重试")
                        messages.append({"role": "user", "content": "（已切换为提示词模拟工具调用）请按工具协议继续调用工具，或 finish。"})
                        continue
                if no_tool_rounds >= 6:
                    # 两种情况分开说清楚，别再堆黑话：
                    # ① 全程一个工具都没调过 → 是所选模型本身不会 function calling（哑模型）。
                    #    注意：真·报错「不支持 tools」的已被 LLM 层自动切提示词模拟兜底，走不到这里；
                    #    能走到这里说明模型没报错、返回正常，只是从不发起工具调用。
                    # ② 之前调过工具、但最近连续 6 轮又不调也不 finish → 模型在原地绕圈，空转收尾。
                    if sum(self._tool_counts.values()) == 0:
                        if tool_compat_selfheal_tried:
                            reason_msg = (
                                "没挖成：当前模型不会调用工具，已自动尝试提示词模拟仍无效。"
                                "请更换支持工具调用的模型(DeepSeek/GPT/Claude/通义/Kimi 等)。"
                            )
                        else:
                            reason_msg = (
                                "没挖成：当前模型不会调用工具(function calling)，连续 6 轮只回文字、不调工具，没法挖。"
                                "不是目标站问题，也不是报错，是模型能力不够。"
                                "解决：换个支持工具调用的模型(DeepSeek/GPT/Claude/通义/Kimi 等)，"
                                "或在服务端设 AUTOHUNTER_TOOL_COMPAT=prompt 强制模拟。设置页「测试连接」可检测。"
                            )
                    else:
                        reason_msg = (
                            "自动收尾：模型连续 6 轮既不调工具也不结束(finish)，在原地绕圈，已收尾。"
                            "可重试或换更强的模型。"
                        )
                    self._auto_finish(reason_msg, "model_behavior")
                    break
                # 没有工具调用也没结束，提醒模型继续或收尾
                messages.append({"role": "user", "content": "继续调用工具验证，或 finish。"})
                continue
            no_tool_rounds = 0

            # 逐个执行工具调用。
            # 关键：OpenAI 协议要求 assistant.tool_calls 里【每一个】tool_call_id 都必须有
            # 对应的 tool 响应消息，否则下一轮请求会 400（insufficient tool messages）。
            # 因此用 answered 跟踪已响应的 id，无论循环怎么提前退出（收敛 break / 取消），
            # 循环结束后都补齐所有未响应的 tool_call，保证 messages 历史始终合法。
            answered: set[str] = set()
            cancelled_mid = False
            blocked_nudge_pending = False
            for tc in tool_calls:
                if self.cancel_event.is_set():
                    cancelled_mid = True
                    break
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError as e:
                    args = {}
                    result = self._tool_arg_error(
                        name, "valid JSON arguments",
                        f"工具参数不是合法 JSON：{e}。请修正后只做一个高价值验证请求；无明确验证动作就 finish(no_vuln)。",
                    )
                    self._emit("tool_arg_error", round=rounds, tool=name, error=str(e))
                else:
                    try:
                        result = self._dispatch(name, args, rounds)
                    except Exception as e:
                        result = {
                            "ok": False,
                            "error": f"工具执行异常: {type(e).__name__}: {e}",
                            "guidance": "不要重复触发同一异常。请换成最小可验证请求；若无明确路径就 finish(no_vuln)。",
                        }
                        self._emit("tool_exception", round=rounds, tool=name, error=str(e))
                # 工具失败时注入针对性恢复提示，帮模型在同流里快速纠偏而非从头推理。
                hint = self._recovery_hint(name, result)
                if hint:
                    result.setdefault("guidance", hint)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result, ensure_ascii=False),
                    "_round": rounds,
                    "_tool": name,
                })
                answered.add(tc.id)

                outcome = self._tool_outcome(result)
                if outcome == "ok":
                    consecutive_failures = 0
                    consecutive_blocked = 0
                    consecutive_arg_errors = 0
                    consecutive_network_failures = 0
                    continue

                consecutive_failures += 1
                consecutive_blocked = consecutive_blocked + 1 if outcome == "blocked" else 0
                consecutive_arg_errors = consecutive_arg_errors + 1 if outcome == "arg_error" else 0
                consecutive_network_failures = consecutive_network_failures + 1 if outcome in ("network", "timeout") else 0

                if consecutive_blocked >= 2:
                    # 被策略拦截的是“方向错”，不是目标无漏洞。以前这里直接 auto_finish，
                    # 会造成目标在 1-2 秒内被判 no_vuln/dead。现在只纠偏，不把目标判死。
                    blocked_nudge_pending = True
                    consecutive_failures = 0
                    consecutive_blocked = 0
                    continue
                if consecutive_arg_errors >= 3:
                    self._auto_finish(
                        "连续 3 次工具参数错误，模型未修正，本轮未得到可靠结论。",
                        "tool_argument",
                    )
                    break
                if consecutive_network_failures >= 3:
                    self._auto_finish("连续 3 次网络/超时失败，目标当前不可稳定验证，系统自动收敛。")
                    break
                if consecutive_failures >= 8:
                    self._auto_finish("连续 8 次工具失败且无新证据，系统自动收敛。")
                    break

            # 补齐所有未响应的 tool_call，保证消息历史合法（防 400）。
            for tc in tool_calls:
                if tc.id not in answered:
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps(
                            {"ok": False, "error": "该工具调用未执行（本轮已收敛或被取消）。"},
                            ensure_ascii=False,
                        ),
                    })

            if cancelled_mid:
                return self._cancelled_result(rounds)

            # tool 响应已全部 append，此时再补上延迟的 JS 工具提示，保证顺序合法。
            if js_hint_pending:
                messages.append(js_hint_msg)

            if self._finished is not None:
                break

            if blocked_nudge_pending:
                messages.append({
                    "role": "user",
                    "content": (
                        "低价值动作已拦截。改做 JS/API/登录/上传/导出/Swagger/actuator 等明确入口的最小实证；别泛扫或打姊妹域。"
                    ),
                })

            # 早收敛提醒：尽早打断低价值空转，但只提醒，不硬杀复杂目标。
            if not self.findings and rounds in (12, 20, 30):
                messages.append({
                    "role": "user",
                    "content": (
                        f"收敛检查：{rounds} 轮无实锤。若仍是枚举/网络/公开数据，打最后一个明确验证或 finish(no_vuln)。"
                    ),
                })

            # 软引导：超过软阈值后，每轮催 worker 收尾，避免低价值空转（不硬杀）
            if rounds >= soft_rounds:
                remaining = max_rounds - rounds
                if remaining <= 5:
                    nudge = (
                        f"仅剩 {remaining} 轮：有洞 submit_finding 后 finish；无实锤立即 finish(no_vuln)。"
                    )
                else:
                    nudge = (
                        f"已 {rounds} 轮：聚焦实锤；别再穷举。无明确突破就 finish(no_vuln)。"
                    )
                messages.append({"role": "user", "content": nudge})

        verdict = Verdict(self._finished["verdict"]) if self._finished else Verdict.error
        if self.findings and verdict == Verdict.no_vuln:
            verdict = Verdict.found  # 有漏洞却说 no_vuln，以实际为准
        return WorkerResult(
            target=self.target,
            verdict=verdict,
            findings=self.findings,
            summary=(self._finished or {}).get("summary", ""),
            rounds=rounds,
            error=(self._finished or {}).get("error") or (
                None if self._finished else f"达到最大轮数 {max_rounds} 未主动结束"
            ),
            failure_kind=(self._finished or {}).get("failure_kind", ""),
            deepen_lead=(self._finished or {}).get("deepen_lead", ""),
            reported_intel=self._reported_intel,
            reported_coverage=self._reported_coverage,
        )

    def _route_rounds(self, max_rounds: int, soft_rounds: int) -> tuple[int, int]:
        """按打法路线微调软收敛节奏。

        据点（回炉）目标：已得入口/凭证，给足预算把多步利用链打穿，不被收敛提前截断。
        deep 路线（Actuator/Nacos/API docs/低代码等）更容易需要多步链路，延后软催收；
        static_low_value 才收紧硬上限，避免门户/官网长时间空转。
        """
        if self.deepen_context:
            # 回炉据点：复杂多步链常需远超首挖的轮次才能打穿，放宽硬/软上限。
            max_rounds = max(max_rounds, 180 if self._enterprise else 150)
            soft_rounds = max(soft_rounds, 120 if self._enterprise else 100)
        route = (self.target_meta or {}).get("playbook_route") or {}
        route_id = str(route.get("route_id") or "")
        intensity = str(route.get("intensity") or "")
        if intensity == "deep":
            soft_rounds = max(soft_rounds, min(max_rounds, 36 if not self._enterprise else 48))
        elif route_id == "static_low_value":
            soft_rounds = min(soft_rounds, 12)
            max_rounds = min(max_rounds, 30)
        elif intensity == "quick":
            soft_rounds = min(soft_rounds, 18)
        return max(1, max_rounds), max(1, min(soft_rounds, max_rounds))

    def _cancelled_result(self, rounds: int) -> WorkerResult:
        self._emit("worker_cancelled", target=self.target, round=rounds)
        return WorkerResult(
            target=self.target,
            verdict=Verdict.error,
            findings=self.findings,
            summary="任务已被 pause/stop 控制面取消，结果由 orchestrator 丢弃。",
            rounds=rounds,
            error="worker cancelled by task control",
            resume_context=self._build_resume_context(rounds),
        )

    @staticmethod
    def _should_soft_retry_llm(exc: BaseException) -> bool:
        """限流/超时/网络/冷却/策略拦截等：同轮内再试（池模式会换端点）。"""
        if isinstance(exc, LLMError):
            return exc.kind in _WORKER_LLM_SOFT_RETRY_KINDS or not exc.kind
        # 非 LLMError 的瞬时异常也给一次机会
        text = str(exc).lower()
        return any(k in text for k in ("timeout", "timed out", "connection", "network", "429", "rate"))

    def _build_resume_context(self, rounds: int) -> dict:
        snap = self.executor.export_resume_state()
        notes = (snap.get("worker_notes") or "").strip()
        cookies = snap.get("session_cookies") or {}
        headers = snap.get("session_headers") or {}
        has_progress = bool(notes or cookies or headers or self.findings or rounds >= 2)
        if not has_progress:
            return {}
        directive_bits = [
            "上一轮因 LLM 调用中断，请从已有进度继续，不要从头泛扫。",
        ]
        if notes:
            directive_bits.append(f"工作笔记：\n{notes[:1500]}")
        if cookies or headers:
            directive_bits.append(
                f"已恢复会话态（cookie {sorted(cookies.keys())}，鉴权头 {sorted(headers.keys())}），"
                "优先用现有登录态继续深挖。"
            )
        if self.findings:
            directive_bits.append(
                f"本轮已提交 {len(self.findings)} 个漏洞，继续挖其它入口或 finish。"
            )
        return {
            "directive": "\n".join(directive_bits)[:2000],
            "worker_notes": notes[:4000],
            "session_cookies": cookies,
            "session_headers": headers,
            "rounds_done": rounds,
            "source": "llm_interrupt",
            "original_summary": notes[:1000],
        }

    def _restore_interrupt_progress(self) -> None:
        ctx = self.deepen_context or {}
        if ctx.get("source") != "llm_interrupt" and not (
            ctx.get("worker_notes") or ctx.get("session_cookies") or ctx.get("session_headers")
        ):
            return
        notes = str(ctx.get("worker_notes") or "")
        cookies = ctx.get("session_cookies") if isinstance(ctx.get("session_cookies"), dict) else {}
        headers = ctx.get("session_headers") if isinstance(ctx.get("session_headers"), dict) else {}
        self.executor.restore_resume_state(
            worker_notes=notes,
            session_cookies=cookies,
            session_headers=headers,
        )
        self._emit(
            "worker_resume",
            notes_len=len(notes),
            cookies=sorted(cookies.keys())[:20],
            headers=sorted(headers.keys())[:20],
            rounds_done=int(ctx.get("rounds_done") or 0),
        )

    def _llm_interrupt_result(
        self,
        *,
        rounds: int,
        error: str,
        failure_kind: str,
        retry_after: int,
    ) -> WorkerResult:
        resume = self._build_resume_context(rounds)
        self._emit(
            "llm_interrupt",
            round=rounds,
            failure_kind=failure_kind or "unknown",
            has_resume=bool(resume),
            findings=len(self.findings),
            error=error[:240],
        )
        return WorkerResult(
            target=self.target,
            verdict=Verdict.error,
            findings=self.findings,
            summary="LLM 调用失败，已保存进度供回队续挖。" if resume else "",
            rounds=rounds,
            error=error,
            failure_kind=failure_kind,
            retry_after_seconds=int(retry_after or 0),
            resume_context=resume,
        )

    def _deepen_brief(self) -> str:
        ctx = self.deepen_context or {}
        directive = ctx.get("directive", "").strip()
        original = ctx.get("original_title", "") or ctx.get("vuln_type", "")
        summary = (ctx.get("original_summary", "") or "").strip()
        if ctx.get("source") == "llm_interrupt":
            parts = [
                f"目标：{self.target}",
                "",
                "⚡ 这是一次【断点续挖】：上一轮 LLM 中断，会话态与工作笔记已恢复。",
            ]
            if summary:
                parts.append(f"已有进度摘要：{summary[:800]}")
            parts += [
                "",
                f"👉 继续任务：{directive or '从已有笔记与登录态接着打，不要重新泛扫。'}",
                "",
                "要求：直接接上进度验证/深挖；打穿就 submit_finding；确认无增量就 finish。",
            ]
            return "\n".join(parts)
        parts = [
            f"目标：{self.target}",
            "",
            "⚡ 这是一次【定向深挖任务】，不是普通自由挖掘。",
            f"上一轮在此目标发现了线索：{original}",
        ]
        if summary:
            parts.append(f"原始线索摘要：{summary[:800]}")
        parts += [
            "",
            "审核判定：线索真实有价值，但利用链没打穿，所以打回让你专门攻这一个点。",
            f"👉 你这一轮的唯一任务：{directive}",
            "",
            "要求：",
            "1. 直奔主题，优先把上面这条利用链打穿，不要重新从头泛泛侦察。",
            "2. 打穿了（取到真实数据/造成实锤危害）就用 submit_finding 提交完整利用链 + 原始请求响应证据。",
            "3. 反复尝试确实打不穿、证明只是理论可能，就 finish(verdict=no_vuln) 并说明卡在哪，绝不交半成品。",
        ]
        return "\n".join(parts)

    def _dispatch(self, name: str, args: dict, rnd: int) -> dict:
        if name == "http_request":
            self._mark_tool_used(name, rnd)
            url = (args.get("url") or "").strip()
            if not url:
                return self._tool_arg_error(
                    "http_request", "url",
                    "必须传完整 URL。不要因为工具参数缺失中断任务；修正参数后只做一次高价值请求，"
                    "若没有明确攻击面就 finish(verdict=no_vuln)。",
                )
            self._emit("tool_http", round=rnd, url=url, method=args.get("method", "GET"))
            self._maybe_enable_js_tool(url, "worker 主动请求 JS 资源")
            result = self.executor.http_request(
                url=url,
                method=args.get("method", "GET"),
                headers=args.get("headers"),
                data=args.get("data"),
                json_body=args.get("json_body"),
                follow_redirects=args.get("follow_redirects", False),
                confirm_destructive=args.get("confirm_destructive", False),
                confirm_reason=args.get("confirm_reason") or "",
            )
            if not self._js_tool_enabled and isinstance(result, dict):
                headers = result.get("response_headers") if isinstance(result.get("response_headers"), dict) else {}
                probe_text = "\n".join([
                    url,
                    str(result.get("url") or ""),
                    str(headers.get("content-type") or headers.get("Content-Type") or ""),
                    str(result.get("body") or "")[:1400],
                ])
                if self._maybe_enable_js_tool(probe_text, "HTTP 响应出现 JS/SPA/前端接口信号"):
                    result["guidance"] = (
                        (result.get("guidance") or "")
                        + " 检测到 JS/SPA/前端接口信号；下一轮可使用 analyze_javascript 提取接口和密钥线索。"
                    ).strip()
            return result

        if name == "analyze_javascript":
            self._mark_tool_used(name, rnd)
            if not self._js_tool_enabled:
                return {
                    "ok": False,
                    "blocked": True,
                    "error": "JS 分析工具尚未开放：只有明确进入 JS/前端接口/密钥审计方向后才能调用。",
                    "guidance": "如果你确实要审计 JS，请先说明具体 JS 方向和原因；否则继续常规攻击面验证。",
                }
            url = (args.get("url") or "").strip()
            text = args.get("text") or ""
            self._emit("tool_js_analyze", round=rnd, url=url[:200], has_text=bool(text))
            return self.executor.analyze_javascript(
                url=url,
                text=text,
                max_depth=args.get("max_depth", 2),
                max_assets=args.get("max_assets", 80),
            )

        if name == "run_shell":
            self._mark_tool_used(name, rnd)
            command = (args.get("command") or args.get("cmd") or args.get("shell") or "").strip()
            if not command:
                return self._tool_arg_error(
                    "run_shell", "command",
                    "必须传要执行的命令字符串。不要重复空调用；若已经没有明确验证动作就 finish(verdict=no_vuln)。",
                )
            low_value = self._low_value_shell_reason(command, rnd)
            if low_value:
                self._emit("tool_shell_blocked", round=rnd, command=command[:200], reason=low_value)
                return {
                    "ok": False,
                    "blocked": True,
                    "error": low_value,
                    "guidance": (
                        "该动作会高概率造成低价值空转。请改为一个具体、可证明危害的最小验证请求；"
                        "如果没有这样的请求，立即调用 finish(verdict=no_vuln)。"
                    ),
                }
            self._emit("tool_shell", round=rnd, command=command[:200])
            return self.executor.run_shell(
                command,
                timeout=args.get("timeout"),
                confirm_destructive=args.get("confirm_destructive", False),
                confirm_reason=args.get("confirm_reason") or "",
            )

        if name == "decode_transform":
            self._mark_tool_used(name, rnd)
            value = args.get("value") or ""
            self._emit("tool_decode", round=rnd, mode=args.get("mode", "auto"), value_len=len(str(value)))
            return self.executor.decode_transform(value=value, mode=args.get("mode", "auto"))

        if name == "suggest_waf_bypass":
            self._mark_tool_used(name, rnd)
            payload = args.get("payload") or ""
            if not payload:
                return self._tool_arg_error(
                    "suggest_waf_bypass", "payload",
                    "必须传被 WAF 拦截的最小 payload 或可控参数值；不要空调用。",
                )
            self._emit("tool_waf_advice", round=rnd, context=args.get("context", "generic"), payload_len=len(str(payload)))
            return self.executor.suggest_waf_bypass(
                payload=payload,
                status_code=args.get("status_code"),
                response_headers=args.get("response_headers"),
                response_body=args.get("response_body", ""),
                context=args.get("context", "generic"),
            )

        if name == "fofa_lookup":
            self._mark_tool_used(name, rnd)
            query = (args.get("query") or "").strip()
            if not query:
                return self._tool_arg_error(
                    "fofa_lookup", "query",
                    '必须传 FOFA 语法（如 ip="1.2.3.4"）；无明确测绘需求就别空调用。',
                )
            self._emit("tool_fofa_lookup", round=rnd, query=query[:120])
            return self.executor.fofa_lookup(query=query, size=args.get("size", 10))

        if name == "session_set":
            self._mark_tool_used(name, rnd)
            self._emit("tool_session_set", round=rnd,
                       has_cookies=bool(args.get("cookies")), has_headers=bool(args.get("headers")))
            return self.executor.session_set(
                cookies=args.get("cookies"),
                headers=args.get("headers"),
                clear=bool(args.get("clear", False)),
            )

        if name == "update_notes":
            self._mark_tool_used(name, rnd)
            return self.executor.update_notes(notes=args.get("notes", ""))

        if name == "report_intel":
            self._mark_tool_used(name, rnd)
            return self._report_intel(args)

        if name == "report_coverage":
            self._mark_tool_used(name, rnd)
            return self._report_coverage(args)

        if name == "submit_finding":
            self._mark_tool_used(name, rnd)
            return self._submit_finding(args)

        if name == "check_duplicate_finding":
            self._mark_tool_used(name, rnd)
            return self._check_duplicate(args)

        if name == "finish":
            premature = self._premature_finish_reason(args, rnd)
            if premature:
                self._emit("finish_blocked", round=rnd, reason=premature[:300])
                return {
                    "ok": False,
                    "kind": "premature_finish",
                    "error": premature,
                    "guidance": (
                        "继续补齐入口覆盖：读完 JS/API 线索，挑高价值接口做最小实证；"
                        "只有真不可达/纯静态/无交互，或线索已验证打不穿，才 finish(no_vuln)。"
                    ),
                }
            self._finished = {
                "verdict": args.get("verdict", "no_vuln"),
                "summary": args.get("summary", ""),
                "deepen_lead": (args.get("deepen_lead") or "").strip(),
            }
            self._report_provider_success()
            self._emit("worker_finish", verdict=self._finished["verdict"],
                       summary=self._finished["summary"][:300],
                       deepen_lead=self._finished["deepen_lead"][:300])
            return {"ok": True, "message": "已记录结束。"}

        return {"ok": False, "error": f"未知工具: {name}"}

    def _mark_tool_used(self, name: str, rnd: int) -> None:
        self._tool_counts[name] = self._tool_counts.get(name, 0) + 1
        if name == "analyze_javascript":
            self._last_js_analysis_round = rnd
            self._post_js_validation_count = 0
        elif name in {"http_request", "run_shell"} and self._last_js_analysis_round:
            self._post_js_validation_count += 1

    def _premature_finish_reason(self, args: dict, rnd: int) -> str:
        if (args.get("verdict") or "no_vuln") != "no_vuln" or self.findings:
            return ""
        if self.deepen_context:
            return ""
        if self._js_signal_seen and not self._tool_counts.get("analyze_javascript"):
            return (
                f"过早结束：已出现 JS/API/前端接口信号，但第 {rnd} 轮仍未调用 analyze_javascript。"
                "先抓取/审计关联 JS，提取接口、路由、secret/token/sign，再决定是否无洞。"
            )
        if self._last_js_analysis_round and self._post_js_validation_count == 0:
            return (
                "过早结束：已经分析 JS，但还没有对 JS 提取出的高价值接口/链路做 http_request/run_shell 实证。"
                "至少挑登录/找回/导出/用户/管理/上传/配置等高价值端点验证一次。"
            )
        tool_actions = sum(self._tool_counts.values())
        if (rnd < 12 or tool_actions < 8) and not self._quick_no_vuln_allowed(args):
            return (
                f"过早结束：仅 {rnd} 轮、{tool_actions} 次工具动作，不足以确认有攻击面的站点无洞。"
                "除非已明确证明目标不可达，或纯静态且无登录/表单/API/JS/可控参数，否则继续覆盖首页、登录/API/JS/高价值端点。"
            )
        return ""

    @staticmethod
    def _quick_no_vuln_allowed(args: dict) -> bool:
        text = "\n".join([
            str(args.get("summary") or ""),
            str(args.get("deepen_lead") or ""),
        ]).lower()
        unreachable = (
            "不可达", "连不上", "连接失败", "拒连", "超时", "timeout",
            "connection refused", "could not resolve", "dns", "下线",
        )
        static_or_empty = (
            "纯静态", "静态页", "空壳", "无交互", "无攻击面",
        )
        no_surface = (
            "无登录", "无表单", "无api", "无 api", "无js", "无 js",
            "无可控参数", "没有登录", "没有表单", "没有api", "没有 api",
        )
        return any(x in text for x in unreachable) or (
            any(x in text for x in static_or_empty) and any(x in text for x in no_surface)
        )

    def _maybe_enable_js_tool(self, text: str, reason: str) -> bool:
        if self._js_tool_enabled:
            return False
        if not _JS_INTENT_RE.search(text or ""):
            return False
        self._js_tool_enabled = True
        self._js_signal_seen = True
        self._emit("js_analyzer_enabled", reason=reason)
        return True

    @staticmethod
    def _tool_arg_error(tool: str, missing: str, guidance: str) -> dict:
        return {
            "ok": False,
            "kind": "arg_error",
            "error": f"{tool} 工具参数缺失：{missing}",
            "guidance": guidance,
        }

    def _recovery_hint(self, tool: str, result: dict) -> str:
        """工具失败时返回针对性恢复提示，帮模型在同流里快速纠偏而非从头推理。

        只在 result 不含 guidance 时才会被采用（调用方用 setdefault）。
        针对 http_request 的各类状态码、run_shell 的各类失败、以及通用错误分别给提示。
        """
        if result.get("ok") is True or result.get("guidance"):
            return ""
        if tool == "http_request":
            sc = result.get("status_code")
            err = str(result.get("error", ""))
            if sc == 401:
                return "401 未授权：需要登录态。若已 session_set 过，可能 session 过期了——重新登录或换凭证；若本就是测未授权，401 说明接口有鉴权，换个不需要登录的入口或测越权。"
            if sc == 403:
                return "403 禁止：常见原因——路径不对(试目录爆破/换路径)、需要特定角色/IP、WAF 拦截(看响应体有无 WAF 特征，用 suggest_waf_bypass)、或缺少 CSRF token。换路径或换攻击面，别死磕同一个 403。"
            if sc == 404:
                return "404 不存在：路径不对。从 JS/首页/接口文档里重新找正确路径，或试常见变体(/api/v1/、/api/v2/、大小写、尾斜杠)。"
            if sc in (500, 502, 503):
                return f"{sc} 服务端错误：可能是 payload 触发了异常(注入/RCE 线索)或服务临时不可用。保留这个请求作为证据，换参数复现确认；若多次稳定 500 可作为注入/异常漏洞线索。"
            if sc == 302:
                loc = (result.get("response_headers", {}) or {}).get("Location", "")
                return f"302 跳转到 {loc[:120]}：若是跳登录页说明需要登录态；若是跳 ticket/SSO 链，设 follow_redirects=true 跟完整个登录链。"
            if "timed out" in err.lower() or "timeout" in err.lower():
                return "请求超时：目标可能慢或不可达。换更小范围的请求、加大 timeout、或确认目标是否在线；连续超时就 finish。"
            if "connection" in err.lower() or "refused" in err.lower() or "unreachable" in err.lower():
                return "连接失败：目标可能下线/防火墙拦截/端口未开放。确认目标可达性(换个端口/协议)；不可达就 finish(no_vuln)。"
        if tool == "run_shell":
            rc = result.get("return_code")
            if rc and rc != 0:
                return f"命令退出码 {rc}：检查命令语法/参数/路径是否正确。换最小命令验证环境，别重复跑同一条失败的命令。"
            if result.get("timed_out"):
                return "命令超时：可能命令本身耗时(如 nmap 全端口)或挂起。换更小范围或加 timeout 参数；别重复跑超时命令。"
            if result.get("blocked"):
                return ""  # blocked 已有自己的 guidance
        if "参数" in str(result.get("error", "")) or "JSON" in str(result.get("error", "")):
            return "参数格式错误：检查工具参数是否合法 JSON、必填字段是否齐全。对照工具 schema 修正后重试一次。"
        return ""

    def _auto_finish(self, reason: str, failure_kind: str = "") -> None:
        if failure_kind:
            self._finished = {
                "verdict": "error",
                "summary": reason,
                "error": reason,
                "failure_kind": failure_kind,
            }
            self._report_provider_failure(reason, failure_kind)
            self._emit(
                "worker_auto_finish",
                verdict="error",
                failure_kind=failure_kind,
                summary=reason[:300],
                error=reason[:500],
                error_copy=reason,
            )
            return
        verdict = "found" if self.findings else "no_vuln"
        self._finished = {"verdict": verdict, "summary": reason}
        self._emit("worker_auto_finish", verdict=verdict, summary=reason[:300])

    def _report_provider_failure(self, reason: str, failure_kind: str) -> None:
        if failure_kind not in {"model_behavior", "tool_argument"}:
            return
        reporter = getattr(self.llm, "report_current_provider_failure", None)
        if not reporter:
            return
        try:
            reporter(reason, kind=failure_kind)
        except Exception as exc:
            self._emit("provider_degrade_error", error=str(exc), failure_kind=failure_kind)

    def _report_provider_success(self) -> None:
        reporter = getattr(self.llm, "report_current_provider_success", None)
        if not reporter:
            return
        try:
            reporter()
        except Exception as exc:
            self._emit("provider_health_error", error=str(exc))

    @staticmethod
    def _tool_outcome(result: dict) -> str:
        if result.get("ok") is True:
            return "ok"
        if result.get("kind") == "needs_more_evidence":
            return "ok"
        if result.get("blocked"):
            return "blocked"
        if result.get("kind") == "arg_error" or "工具参数缺失" in str(result.get("error", "")):
            return "arg_error"
        if result.get("timed_out"):
            return "timeout"
        if result.get("cancelled"):
            return "timeout"
        text = (str(result.get("error", "")) + "\n" + str(result.get("output", ""))).lower()
        if any(marker in text for marker in ("timed out", "timeout", "超时")):
            return "timeout"
        if any(marker in text for marker in (
            "connection refused", "connection reset", "connection timed out",
            "network is unreachable", "no route to host", "name or service not known",
            "temporary failure", "http 请求异常",
        )):
            return "network"
        return "error"

    def _low_value_shell_reason(self, command: str, rnd: int) -> str:
        cmd = command.strip()
        lower = cmd.lower()
        target_host = urlparse(self.target if "://" in self.target else f"http://{self.target}").netloc.lower()

        sleep_values = [int(m.group(1)) for m in _SLEEP_RE.finditer(lower)]
        if sleep_values and max(sleep_values) >= 30:
            return "禁止长 sleep/等待式探测：这会占住 worker 且不产生漏洞证据。"

        if _BROAD_NMAP_RE.search(lower):
            return "禁止宽端口 nmap 扫描：请只验证当前 Web 服务相关端口或直接收尾。"

        if "nuclei" in lower and " -t " not in lower and " -tags " not in lower and " -id " not in lower:
            return "禁止无模板/无 tag 的 nuclei 泛扫：先用接口/JS/逻辑分析形成假设，再用具体模板或最小请求验证。"

        if "sqlmap" in lower and not any(marker in lower for marker in ("?", "--data", " -r ", "--cookie", "--headers")):
            return "禁止无具体参数/请求包的 sqlmap 泛扫：必须先定位可控参数或原始请求，再做针对性注入验证。"

        if re.search(r"\b(ffuf|gobuster|dirsearch|feroxbuster)\b", lower):
            if not any(marker in lower for marker in ("api", "swagger", "actuator", "druid", "nacos", "upload", "login")):
                return "禁止泛目录爆破：优先测试已发现的接口、登录/改密/上传/越权逻辑；目录扫描只能针对高价值路径簇。"

        if "socket.socket" in lower and rnd >= 6:
            return "禁止在中后期用 raw socket 死磕协议异常：网络/协议不可达应收敛为 no_vuln。"

        if "/dev/tcp/" in lower and "for port in" in lower and rnd >= 8:
            return "禁止中后期用 /dev/tcp 循环探端口：这属于低价值端口枚举，应聚焦当前 Web 入口。"

        if "curl" in lower and "for " in lower:
            match = _FOR_LIST_RE.search(cmd)
            if match:
                items = [x for x in re.split(r"\s+", match.group(1).strip()) if x]
                if len(items) > 10 and rnd >= 8:
                    return "禁止中后期大列表路径/子域枚举：请聚焦已确认入口，或无洞收尾。"

        url_hosts = re.findall(r"https?://([^/\\s\"']+)", lower)
        if rnd >= 6 and target_host and any(h.endswith(".edu.cn") and h != target_host for h in url_hosts):
            return "禁止中后期偏离当前目标请求姊妹域：本 worker 只负责当前 target。"

        sibling_markers = (".edu.cn", "for sub in", "for host in")
        if rnd >= 10 and any(marker in lower for marker in sibling_markers) and "curl" in lower and "for " in lower:
            return "禁止偏离当前目标批量探测姊妹域：本 worker 只负责当前目标。"

        return ""

    def _candidate_pool(self) -> list[dict]:
        pool = list(self.duplicate_history)
        for f in self.findings:
            pool.append(f.model_dump(mode="json"))
        return pool

    def _dup_matches(self, candidate: dict) -> tuple[bool, list[dict]]:
        return dedup.is_duplicate(candidate, self._candidate_pool(), target_ref=self.target)

    def _check_duplicate(self, args: dict) -> dict:
        duplicate, matches = self._dup_matches(args)
        self._emit("duplicate_checked", duplicate=duplicate, matches=len(matches),
                   title=(args.get("title") or "")[:120])
        return {
            "ok": True,
            "duplicate": duplicate,
            "matches": matches,
            "guidance": (
                "这是重复/已驳回/通杀库已覆盖的漏洞，不要 submit_finding；继续挖其它入口或 finish。"
                if duplicate else
                "未发现明显重复；若已取得真实证据，可继续 submit_finding。"
            ),
        }

    def _report_intel(self, args: dict) -> dict:
        """worker 主动上报可复用情报（纯内存收集，编排层 async 统一落全局情报库）。

        kind: cred / endpoint / profile（fingerprint 由系统自动识别，不让 worker 报）
        - cred:     {username, password}  —— 仅上报【验证过能登录】的凭证
        - endpoint: {path, vuln_type}     —— 验证有效的未授权/敏感端点
        - profile:  {key, value}          —— 技术栈/WAF/突破口等画像
        纯本地、无网络、无 DB、不阻塞。最多收集 20 条防滥用。
        """
        kind = (args.get("kind") or "").strip().lower()
        if kind not in ("cred", "endpoint", "profile"):
            return {"ok": False, "error": "kind 必须是 cred/endpoint/profile 之一。"}
        payload = args.get("payload")
        if not isinstance(payload, dict) or not payload:
            return {"ok": False, "error": "payload 必须是非空对象，按 kind 提供对应字段。"}
        if len(self._reported_intel) >= 20:
            return {"ok": True, "message": "本轮情报已上报足够，无需再报。"}
        def _safe_text(value: Any, limit: int) -> str:
            if isinstance(value, (dict, list)):
                try:
                    text = json.dumps(value, ensure_ascii=False)
                except Exception:
                    text = str(value)
            else:
                text = str(value or "")
            return text[:limit]

        item = {
            "kind": kind,
            "payload": {str(k)[:50]: _safe_text(v, 300) for k, v in payload.items() if v not in (None, "")},
            "summary": _safe_text(args.get("summary"), 300),
            "confidence": "verified" if args.get("verified") else "likely",
        }
        if not item["payload"]:
            return {"ok": False, "error": "payload 内容为空。"}
        self._reported_intel.append(item)
        self._emit("intel_reported", intel_kind=kind)
        return {"ok": True, "message": "情报已记录，将沉淀到全局情报库供后续 worker 复用。继续挖洞或 finish。"}

    def _report_coverage(self, args: dict) -> dict:
        """单站协作覆盖记录：记录已验证 API/入口，供后续 worker 复用。"""
        if len(self._reported_coverage) >= 12:
            return {"ok": True, "message": "本轮覆盖记录已足够，收尾时汇总即可。"}

        def _safe_text(value: Any, limit: int) -> str:
            if isinstance(value, (dict, list)):
                try:
                    text = json.dumps(value, ensure_ascii=False)
                except Exception:
                    text = str(value)
            else:
                text = str(value or "")
            return text[:limit]

        route = (args.get("route") or "").strip()
        if not route:
            route = str((self.target_meta.get("site_collab_route") or {}).get("source") or "")
        summary = _safe_text(args.get("summary"), 400).strip()
        if not summary:
            return {"ok": False, "error": "summary 不能为空：请概括已覆盖的 API/入口和结论。"}
        endpoints_in = args.get("endpoints") or []
        endpoints: list[dict] = []
        if isinstance(endpoints_in, list):
            for item in endpoints_in[:20]:
                if not isinstance(item, dict):
                    continue
                endpoints.append({
                    "method": _safe_text(item.get("method") or "GET", 12).upper(),
                    "path": _safe_text(item.get("path") or item.get("url"), 220),
                    "status": _safe_text(item.get("status"), 40),
                    "checks": _safe_text(item.get("checks"), 120),
                    "result": _safe_text(item.get("result") or item.get("note"), 180),
                })
        record = {
            "route": route or "site",
            "summary": summary,
            "endpoints": endpoints,
            "remaining": _safe_text(args.get("remaining"), 400),
        }
        self._reported_coverage.append(record)
        self._emit("coverage_reported", route=record["route"], summary=summary[:180], endpoints=len(endpoints))
        return {"ok": True, "message": "覆盖记录已记下，后续同站 worker 会看到摘要。继续补盲区或 finish。"}

    def _submit_finding(self, args: dict) -> dict:
        """Pydantic 兜底校验（双保险），失败返回错误让模型修正。"""
        try:
            finding = Finding(**args)
        except ValidationError as e:
            self._emit("finding_invalid", errors=str(e))
            return {"ok": False, "error": f"Finding 校验失败，请修正后重新提交: {e}"}

        if not self._enterprise:
            bomb_block = edu_bombing_block_reason(finding)
            if bomb_block:
                self._emit("finding_out_of_scope", title=finding.title, reason=bomb_block[:200])
                return {
                    "ok": False,
                    "kind": "out_of_scope",
                    "submitted": False,
                    "error": bomb_block,
                }

        backdoor_block = weak_backdoor_block_reason(finding)
        if backdoor_block:
            self._emit("finding_out_of_scope", title=finding.title, reason=backdoor_block[:200])
            return {
                "ok": False,
                "kind": "out_of_scope",
                "submitted": False,
                "error": backdoor_block,
            }

        evidence_block = self._weak_write_evidence_reason(finding)
        if evidence_block:
            self._emit("finding_needs_more_evidence", title=finding.title, reason=evidence_block[:200])
            return {
                "ok": False,
                "kind": "needs_more_evidence",
                "submitted": False,
                "error": evidence_block,
                "guidance": (
                    "不要把这条半成品提交给 reviewer。" + HARMLESS_PROTOCOL
                ),
            }

        duplicate, matches = self._dup_matches(finding.model_dump(mode="json"))
        if duplicate:
            self._emit("finding_duplicate", title=finding.title, matches=len(matches))
            return {
                "ok": False,
                "duplicate": True,
                "matches": matches,
                "error": "该漏洞命中统一查重库（历史提交/已驳回/通杀明细），已拦截。不要再次提交同一漏洞，继续挖其它点或 finish。",
            }

        self.findings.append(finding)
        # 侦察期已独立确认「该端点匿名可达且响应疑似泄露敏感数据」（anon_leak_leads 命中）的，
        # 在 finding 上打 recon_anon_leak 标记——这是侦察侧强信号，审核降过杀时应优先救援，
        # 避免把「侦察已实锤匿名可读数据」的线索误判为垃圾。仅做前缀匹配，避免 URL 带 query 时漏标。
        anon_leak_leads = (self.target_meta or {}).get("anon_leak_leads") or []
        if anon_leak_leads:
            target_low = (finding.target_url or "").lower()
            for lead in anon_leak_leads:
                lu = (lead.get("url") or "").lower()
                if lu and target_low.startswith(lu.rstrip("/")):
                    finding.self_check.recon_anon_leak = True
                    break
        # 侦察期已实锤目标前方存在 WAF/风控（waf_profile.detected）时，打 recon_waf_present 标记——
        # 该 finding 的「证据残缺」很可能源于被 WAF 拦截而非本身无价值，审核降过杀时应优先 rescue
        # 派 worker 带 XFF/UA 变形补证，而不是被当成「没证据」直接归档。与目标端点是否命中泄露无关，
        # 这是「本次目标整体有 WAF」的全局信号，对所有可疑 finding 都值得放宽门槛。
        waf_profile = (self.target_meta or {}).get("waf_profile") or {}
        if waf_profile.get("detected"):
            finding.self_check.recon_waf_present = True
        # 携带完整 finding 供 orchestrator 实时落库（进程被打断时不丢洞）。
        self._emit(
            "finding_submitted",
            title=finding.title,
            severity=finding.severity_claimed.value,
            vuln_type=finding.vuln_type,
            finding=finding.model_dump(mode="json"),
        )
        return {"ok": True, "message": f"已收录漏洞「{finding.title}」（{finding.severity_claimed.value}）。可继续挖其它漏洞或调用 finish。"}

    def _weak_write_evidence_reason(self, finding: Finding) -> str:
        """拦截 EduSRC 最常见半成品：写接口返回成功但影响 0 行。

        无害证法（哨兵闭环 / 鉴权对照 / 幂等回写 / 旁路回读）放行；
        只拦「成功文案 + 零影响」且没有任何无害证据的半成品。
        """
        if self._enterprise:
            return ""
        return weak_write_block_reason(finding)
