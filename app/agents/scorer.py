"""目标优先级评分。

理念：
- 评分只决定【先打谁】，绝不代表放弃——低分目标仍入队，只是排后面。
- 业务价值主要看 title/业务文本；负向只降权、不禁止。
- 可选主动探测高价值暴露端点（swagger/actuator/druid/nacos/.git/.env 等）加权。

入口：score_target(url, title, server, body, probe_endpoints, timeout, src_type) -> (score, reason)。
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

# ------------------------------------------------------------------------------
# 关键词权重表（正向加权 / 负向降权；通用、可自行增删）
# ------------------------------------------------------------------------------
_POSITIVE = [
    {"name": "admin_backend", "weight": 3, "keywords": ["管理后台", "后台管理", "管理系统", "管理中心", "控制台", "console", "manager"]},
    {"name": "data_interactive", "weight": 3, "keywords": ["支付", "缴费", "考试", "成绩", "充值", "转账", "订单", "申报", "报名", "审批"]},
    {"name": "wechat_platform", "weight": 2, "keywords": ["微信管理", "企业微信", "公众号", "小程序管理"]},
    {"name": "api_gateway", "weight": 2, "keywords": ["开放平台", "应用管理", "api网关"], "server_match": ["APISIX", "Kong"]},
    {"name": "spa_with_api", "weight": 2, "keywords": ["vue", "react", "nuxt", "angular", "/api/", "swagger"]},
    {"name": "cloud_storage", "weight": 2, "keywords": ["x-oss-", "oss-cn-", ".aliyuncs.com", "sts", "minio", "bucket"]},
    {"name": "nonstandard_port", "weight": 1, "port_not_in": [80, 443]},
    {"name": "edu_industry", "weight": 1, "keywords": ["大学", "学院", "学校", "职业技术", "教育局", "教育厅", "科学院", "研究所"]},
]

_NEGATIVE = [
    {"name": "auth_gateway", "weight": -4, "keywords": ["统一身份认证", "统一认证", "认证平台", "CAS", "SSO", "authserver", "登录中心"]},
    {"name": "pure_frontend", "weight": -4, "keywords": ["官网", "新闻网", "门户", "首页", "宣传", "概况", "简介"]},
    {"name": "sensitive_gov", "weight": -3, "keywords": ["党员", "党建", "党委", "纪检", "组织部", "统战", "信访"]},
    {"name": "data_display", "weight": -2, "keywords": ["数据平台", "数据中心", "大数据", "统计平台", "数据可视化大屏"]},
    {"name": "public_generic_service", "weight": -3, "keywords": ["grafana", "kibana", "redis", "zabbix", "prometheus", "jenkins", "phpmyadmin"]},
    {"name": "known_opensource", "weight": -1, "keywords": ["wordpress", "wp-content", "discuz", "dedecms", "phpcms"]},
]

_ENTERPRISE_POSITIVE = [
    {"name": "enterprise_admin", "weight": 4, "keywords": ["管理后台", "后台管理", "控制台", "admin", "console", "manager", "portal"]},
    {"name": "enterprise_core_business", "weight": 4, "keywords": ["CRM", "ERP", "OA", "工单", "客服", "会员", "订单", "支付", "发票", "合同", "审批", "采购"]},
    {"name": "enterprise_data_platform", "weight": 3, "keywords": ["BI", "报表", "数据平台", "经营分析", "大屏", "指标"]},
    {"name": "enterprise_devops", "weight": 4, "keywords": ["jenkins", "gitlab", "harbor", "sonarqube", "nexus", "grafana", "kibana", "nacos", "druid", "actuator", "swagger"]},
    {"name": "enterprise_api_gateway", "weight": 3, "keywords": ["api", "openapi", "gateway", "apisix", "kong", "开放平台", "接口平台"]},
    {"name": "enterprise_upload_export", "weight": 2, "keywords": ["upload", "import", "export", "file", "附件", "上传", "导入", "导出"]},
    {"name": "nonstandard_port", "weight": 1, "port_not_in": [80, 443]},
]

_ENTERPRISE_NEGATIVE = [
    {"name": "pure_marketing_site", "weight": -3, "keywords": ["官网", "新闻", "品牌介绍", "企业文化", "招聘", "联系我们"]},
    {"name": "static_assets", "weight": -3, "keywords": ["cdn", "static", "assets", "image", "font", "jsdelivr"]},
    {"name": "public_generic_service", "weight": -1, "keywords": ["redis", "zabbix", "phpmyadmin", "elasticsearch head"]},
    {"name": "known_opensource", "weight": -1, "keywords": ["wordpress", "wp-content", "discuz", "dedecms", "phpcms"]},
]

_BANDS = {"high": 5, "medium": 1}

# 主动探测的高价值暴露端点（通用、公开已知路径 + 少量特征串过滤 SPA 全 200 误报）
_HIGH_VALUE_ENDPOINTS = [
    ("/actuator", ["_links", "/actuator/"]),
    ("/actuator/env", ["activeProfiles", "propertySources", "systemProperties"]),
    ("/swagger-ui.html", ["swagger", "Swagger UI"]),
    ("/v2/api-docs", ['"swagger"', '"paths"', "openapi"]),
    ("/v3/api-docs", ["openapi", '"paths"']),
    ("/druid/index.html", ["Druid Stat", "druid-version"]),
    ("/nacos/", ["Nacos", "console-ui", "nacos"]),
    ("/.git/config", ["[core]", "repositoryformatversion"]),
    ("/.env", ["APP_KEY", "DB_PASSWORD", "DB_DATABASE", "APP_ENV"]),
    ("/server-status", ["Apache Server Status", "Server uptime"]),
]
_AUTH_MEANS_EXISTS = {"/actuator", "/nacos/", "/druid/index.html"}

_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}


def _match_rule(rule: dict, combined_text: str, server: str, port: int) -> bool:
    if "keywords" in rule:
        low = combined_text.lower()
        if any(kw.lower() in low for kw in rule["keywords"]):
            return True
    if "server_match" in rule and server:
        if any(pat.lower() in server.lower() for pat in rule["server_match"]):
            return True
    if "port_not_in" in rule and port not in rule["port_not_in"]:
        return True
    return False


def _probe_endpoints(base_url: str, timeout: float) -> list[str]:
    """探测高价值端点，返回命中列表（带特征串过滤 SPA 全 200 误报）。"""
    p = urlparse(base_url)
    root = f"{p.scheme}://{p.netloc}"
    found: list[str] = []
    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=True, headers=_UA) as c:
            for path, sigs in _HIGH_VALUE_ENDPOINTS:
                try:
                    r = c.get(root + path)
                    if r.status_code == 200:
                        body = r.text[:8000].lower()
                        if any(s.lower() in body for s in sigs):
                            found.append(path)
                    elif r.status_code in (401, 403) and path in _AUTH_MEANS_EXISTS:
                        found.append(f"{path}(需鉴权)")
                except Exception:
                    continue
    except Exception:
        pass
    return found


def _port_from_url(url: str) -> int:
    try:
        p = urlparse(url)
        if p.port:
            return p.port
        return 443 if p.scheme == "https" else 80
    except Exception:
        return 80


def score_target(url: str, title: str = "", server: str = "",
                 body: str = "", probe_endpoints: bool = True,
                 timeout: float = 6.0, src_type: str = "edusrc") -> tuple[float, str]:
    """对单个目标打分。返回 (score, reason)。score 越高越优先。HIGH>=5, MEDIUM>=1, LOW<1。"""
    score = 0
    reasons: list[str] = []
    port = _port_from_url(url)
    combined_text = f"{title} {url} {(body or '')[:3000]}"

    enterprise = (src_type or "").lower() == "enterprise"
    positive_rules = _ENTERPRISE_POSITIVE if enterprise else _POSITIVE
    negative_rules = _ENTERPRISE_NEGATIVE if enterprise else _NEGATIVE

    for rule in positive_rules:
        if _match_rule(rule, combined_text, server, port) and rule["weight"] != 0:
            score += rule["weight"]
            reasons.append(f"+{rule['weight']} {rule['name']}")
    for rule in negative_rules:
        if _match_rule(rule, combined_text, server, port):
            score += rule["weight"]
            reasons.append(f"{rule['weight']} {rule['name']}")

    # 高价值暴露端点（主动探测）
    exposed = _probe_endpoints(url, timeout) if probe_endpoints else []
    if exposed:
        confirmed = [e for e in exposed if "(需鉴权)" not in e]
        auth_required = [e for e in exposed if "(需鉴权)" in e]
        if confirmed:
            score += 4
            reasons.append(f"+4 暴露端点:{','.join(e.split('(')[0] for e in confirmed[:3])}")
        if auth_required:
            score += 1
            reasons.append(f"+1 鉴权端点:{','.join(e.split('(')[0] for e in auth_required[:3])}")

    # 登录入口
    if body and re.search(r'<input[^>]*type=["\']password["\']', body, re.I):
        score += 2
        reasons.append("+2 login_form")
    elif body and re.search(r'(登录|login|sign.?in)', body[:3000], re.I):
        score += 1
        reasons.append("+1 login_hint")

    # API 暴露
    api_paths = re.findall(r'["\']/(?:api|rest|service|v[12]|admin-api|system)/[^"\']+["\']', body or "", re.I)
    if len(api_paths) >= 3:
        score += 2
        reasons.append(f"+2 api×{len(api_paths)}")
    elif api_paths:
        score += 1
        reasons.append(f"+1 api×{len(api_paths)}")

    # SPA 前后端分离
    if body and re.search(r"vue(\.min)?\.js|react(\.min)?\.js|__vue__|reactDOM", body[:6000], re.I):
        score += 1
        reasons.append("+1 spa")

    if score >= _BANDS["high"]:
        prio = "HIGH"
    elif score >= _BANDS["medium"]:
        prio = "MEDIUM"
    else:
        prio = "LOW"

    if not reasons:
        reasons.append("普通资产")
    return float(score), f"[{prio}] " + " · ".join(reasons[:6])
