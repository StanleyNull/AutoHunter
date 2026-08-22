"""攻击链模板库：把已采纳的成功打法沉淀为可复用模板，按目标指纹自动匹配注入 worker。

与全局情报库（intel）的区别：intel 沉淀凭证/端点/指纹，本模块沉淀「打法」
（针对某类系统的有效利用链条），让相似目标上的 worker 直接复用，系统越挖越聪明。
存储为 JSON 文件（位于 worker_config.work_root），避免改动 DB schema 与迁移。
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Optional

from app.agents.intel import detect_fingerprints

_LOCK = threading.Lock()
_STORE_PATH_CACHE: Optional[str] = None
_MAX_TEMPLATES = 200


def _store_path() -> str:
    global _STORE_PATH_CACHE
    if _STORE_PATH_CACHE is None:
        from app.config import worker_config
        root = (worker_config.work_root or "/tmp/autohunter/work").rstrip("/")
        os.makedirs(root, exist_ok=True)
        _STORE_PATH_CACHE = os.path.join(root, "attack_chain_templates.json")
    return _STORE_PATH_CACHE


def load_templates() -> dict:
    try:
        with open(_store_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def save_templates(data: dict) -> None:
    path = _store_path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)  # 原子替换，防并发写坏


def _normalize_chain(text: str) -> str:
    return " ".join((text or "").split()).strip()[:600]


def record_success(fingerprints: list[str], vuln_type: str, attack_chain: str, owner: str = "") -> bool:
    """沉淀一条成功打法。fingerprints 为空时退化为以 vuln_type 作为软指纹。

    返回是否成功（异常一律降级 False，绝不抛异常影响审核落库）。
    """
    chain = _normalize_chain(attack_chain)
    vuln_type = (vuln_type or "").strip().lower()
    if not chain or not vuln_type:
        return False
    fps = [f for f in (fingerprints or []) if f]
    if not fps:
        fps = [f"type:{vuln_type}"]
    sig = f"{vuln_type}|{chain}"
    with _LOCK:
        data = load_templates()
        templates = data.setdefault("templates", [])
        for t in templates:
            if t.get("sig") == sig:
                t["hits"] = (t.get("hits") or 0) + 1
                t["last_seen"] = int(time.time())
                save_templates(data)
                return True
        templates.append({
            "id": f"{int(time.time())}-{len(templates)}",
            "sig": sig,
            "fingerprints": fps,
            "vuln_type": vuln_type,
            "attack_chain": chain,
            "owner": (owner or "")[:120],
            "hits": 1,
            "created_at": int(time.time()),
            "last_seen": int(time.time()),
        })
        # 控制规模：保留最多 _MAX_TEMPLATES 条，按命中次数降序裁剪长尾。
        if len(templates) > _MAX_TEMPLATES:
            templates.sort(key=lambda t: (t.get("hits") or 0, t.get("last_seen") or 0), reverse=True)
            data["templates"] = templates[:_MAX_TEMPLATES]
        save_templates(data)
        return True


_SEEDED = False  # 进程内只自动播种一次，避免每次 match_for 重复读盘


def match_for(fingerprints: list[str], limit: int = 3, business_stages: Optional[list[str]] = None) -> list[dict]:
    """按目标指纹返回匹配的成功打法（按命中次数排序），供 worker 复用。

    首次调用时懒注入冷启动种子（幂等：不覆盖已有模板），保证新仓库开箱即有通用打法。
    business_stages：worker 在 recon 后识别出的业务阶段 biz_key 列表，转换为 biz:<key> 软指纹
    并入匹配集，让「业务流识别」闭环到「打法推荐」（订单/支付/用户中心等针对性打法优先命中）。
    """
    global _SEEDED
    if not _SEEDED:
        try:
            seed_default_chains()
        except Exception:
            pass
        _SEEDED = True
    fps = set(f for f in (fingerprints or []) if f)
    if business_stages:
        fps |= {f"biz:{k}" for k in business_stages if k}
    if not fps:
        return []
    data = load_templates()
    templates = data.get("templates") or []
    matched = [t for t in templates if set(t.get("fingerprints") or []) & fps]
    matched.sort(key=lambda t: (t.get("hits") or 0), reverse=True)
    return matched[:limit]


def record_accepted_finding(finding) -> bool:
    """从 Finding（ORM 或 schema）提取指纹与打法并沉淀。供审核 accepted 落库点调用。"""
    try:
        target_url = getattr(finding, "target_url", "") or ""
        title = getattr(finding, "title", "") or ""
        owner = getattr(finding, "owner", "") or ""
        vuln_type = getattr(finding, "vuln_type", "") or ""
        steps = getattr(finding, "steps", None) or []
        if isinstance(steps, list):
            chain = "\n".join(str(s) for s in steps if s)
        else:
            chain = str(steps or "")
        if not chain:
            chain = getattr(finding, "description", "") or ""
        fps = detect_fingerprints(target_url, title, owner)
        return record_success(fps, vuln_type, chain, owner)
    except Exception:
        return False


# ---- 冷启动种子：开箱即用的通用打法库 ----
# 设计原则：
# - 覆盖高频系统指纹 + 通用漏洞类型，让新建仓库第一票目标就有可复用打法。
# - 每条种子带具体系统指纹标识（如 framework_ruoyi）与 type:<vuln_type> 软指纹兜底，
#   既能被具体系统命中，也能在无指纹时按漏洞类型软匹配。
# - 全部为「通用打法描述」，不针对任一具体目标，符合合规要求（无具体品牌硬编码示例）。
_SEED_CHAINS: list[dict] = [
    # 国产后台框架：若依 / Ruoyi
    {
        "fingerprints": ["framework_ruoyi", "type:unauthorized_access"],
        "vuln_type": "unauthorized_access",
        "attack_chain": (
            "若依(RuoYi)类后台通用排查："
            "① 直接访问 /system/role/list、/system/menu/list、/system/dept/list 等接口，"
            "未配置匿名拦截时会匿名返回 JSON 用户/角色/部门数据（未授权访问）；"
            "② 检查 /captchaImage 是否泄露 uuid 与验证码，结合 /login 弱口令爆破；"
            "③ 若开启 Swagger(/swagger-ui.html) 且未鉴权，优先打后台写操作类接口；"
            "④ 关注 /common/download 任意文件读取与 /tool/gen 代码生成器后台。"
        ),
    },
    # ThinkPHP
    {
        "fingerprints": ["framework_thinkphp", "type:rce"],
        "vuln_type": "rce",
        "attack_chain": (
            "ThinkPHP 通用排查："
            "① 先看 X-Powered-By / 报错页确认版本；"
            "② 老版本检查 s=/模块/控制器/方法 路由兼容模式与 ?s= 数组注入；"
            "③ 5.x 关注 method 覆盖(__method=__construct)导致的 RCE；"
            "④ 检查 /runtime/ 日志与缓存文件是否可未授权读取（泄露配置/会话）；"
            "⑤ 搜索页面里泄露的 app_debug 报错栈，确认是否有 phpinfo 暴露。"
        ),
    },
    # Spring Boot / actuator
    {
        "fingerprints": ["framework_springboot", "type:info_leak"],
        "vuln_type": "info_leak",
        "attack_chain": (
            "Spring Boot 通用排查："
            "① 直接访问 /actuator/env、/actuator/configprops、/actuator/heapdump，"
            "未鉴权时泄露数据库/中间件账密与内部域名；"
            "② /actuator/metrics、/actuator/loggers 可探测与改日志级别；"
            "③ 若暴露 /actuator/refresh 或 /actuator/gateway/routes（Spring Cloud Gateway），"
            "警惕 SpEL/RCE 类利用；"
            "④ 检查 /error 白标页与 1.x 默认错误端点是否回显堆栈；"
            "⑤ 配合 Swagger(/v2/api-docs) 直接枚举全部业务接口。"
        ),
    },
    # Jeecg-Boot
    {
        "fingerprints": ["framework_jeecg", "type:unauthorized_access"],
        "vuln_type": "unauthorized_access",
        "attack_chain": (
            "Jeecg-Boot 通用排查："
            "① 检查 /jeecg-boot/sys/* 与 /sys/ 系列接口是否匿名可达；"
            "② 老版本关注 /jeecg-boot/sys/common/upload 任意文件上传与 /sys/user/queryUser 数据泄露；"
            "③ 留意 online 表单(/online/*) 与报表接口的低权限越权读；"
            "④ 结合 Swagger 文档枚举后台写接口。"
        ),
    },
    # 致远 OA / 泛微 OA
    {
        "fingerprints": ["oa_seeyon", "type:rce"],
        "vuln_type": "rce",
        "attack_chain": (
            "致远 OA(Seeyon)通用排查："
            "① 老版本检查 /seeyon/htmlofficeservlets、/seeyon/autologin 等历史文件操作/越权端点；"
            "② 关注 /seeyon/createpdf、/seeyon/report 等模板注入类入口；"
            "③ 检查 /seeyon/login/ 是否有默认口令与验证码可绕过；"
            "④ 留意 body 中暴露的 A8 版本号，对应已知补丁前的服务端模板/反序列化利用面。"
        ),
    },
    {
        "fingerprints": ["oa_weaver", "type:info_leak"],
        "vuln_type": "info_leak",
        "attack_chain": (
            "泛微 OA(Weaver/Ecology)通用排查："
            "① 检查 /weaver/ 下历史接口与 /OAapp*/ 移动端接口是否未鉴权；"
            "② 关注 ecology 版本号暴露，确认补丁前的 WorkflowCenterTreeData 等越权数据接口；"
            "③ 留意 /verifyquicklogin 等快速登录跳转是否可绕过二次校验；"
            "④ 搜索页面泄露的 sysadmin 默认口令线索。"
        ),
    },
    # 通达 OA
    {
        "fingerprints": ["oa_tongda", "type:unauthorized_access"],
        "vuln_type": "unauthorized_access",
        "attack_chain": (
            "通达 OA 通用排查："
            "① 检查 /ispirit/ 与 /general/ 系列接口是否匿名可达（历史未授权文件/接口）；"
            "② 关注 /ispirit/interface/gateway.php 等网关类入口的任意文件包含/上传利用面；"
            "③ 留意 /general/login 默认口令与 /general/index 越权跳转；"
            "④ 检查 /inc/ 与 /attach/ 目录是否可直接读取附件与配置。"
        ),
    },
    # Nacos
    {
        "fingerprints": ["mw_nacos", "type:unauthorized_access"],
        "vuln_type": "unauthorized_access",
        "attack_chain": (
            "Nacos 通用排查："
            "① 直接访问 /nacos/v1/auth/ 系列与 /nacos/v1/cs/configs，未开启鉴权时匿名读取全部配置（含数据库/Redis 账密）；"
            "② 检查 /nacos/v1/ns/ 服务注册发现接口是否可匿名写；"
            "③ 若开启鉴权但版本偏低，关注默认 token(secret.key) 可绕过登录；"
            "④ /nacos/#/ 控制台登录页尝试默认口令 nacos/nacos。"
        ),
    },
    # Druid 监控
    {
        "fingerprints": ["mw_druid", "type:info_leak"],
        "vuln_type": "info_leak",
        "attack_chain": (
            "Druid 监控通用排查："
            "① 直接访问 /druid/index.html 与 /druid/websession.html，未鉴权时泄露 Session 与 SQL 执行记录；"
            "② /druid/sql.html 可看到历史 SQL（可能含参数与表结构）；"
            "③ 从 websession 取 JSESSIONID 复用他人登录态；"
            "④ 若 sessionStat 暴露登录账号，结合系统后台直接越权。"
        ),
    },
    # Swagger / OpenAPI
    {
        "fingerprints": ["api_swagger", "type:unauthorized_access"],
        "vuln_type": "unauthorized_access",
        "attack_chain": (
            "Swagger / OpenAPI 通用排查："
            "① 访问 /swagger-ui.html、/v2/api-docs、/v3/api-docs 直接拿到全量接口契约；"
            "② 逐一尝试无需 token 的 GET 数据接口（未授权读）；"
            "③ 用 Try-It-Out 或脚本批量打写接口，关注是否仅靠前端隐藏权限；"
            "④ 若文档含内网地址/密钥字段，回收为信息泄露证据。"
        ),
    },
    # PhpMyAdmin
    {
        "fingerprints": ["db_phpmyadmin", "type:unauthorized_access"],
        "vuln_type": "unauthorized_access",
        "attack_chain": (
            "PhpMyAdmin 通用排查："
            "① 访问 /phpmyadmin/ 尝试弱口令与空口令，关注 /index.php 是否可绕过；"
            "② 若已登录或存在 CSRF 零 token 漏洞，直接用 SQL 执行拿 Webshell（SELECT INTO OUTFILE 写 Web 目录）；"
            "③ 检查 /setup/ 是否残留可写配置；"
            "④ 留意 cookie 中配置的明文数据库账密。"
        ),
    },
    # 邮件系统（Coremail / Exchange）
    {
        "fingerprints": ["mail_coremail", "mail_exchange", "type:unauthorized_access"],
        "vuln_type": "unauthorized_access",
        "attack_chain": (
            "邮件系统通用排查："
            "① 检查 /coremail/ 或 /owa/ 登录页默认口令、历史越权接口（如通讯录/附件匿名读）；"
            "② Exchange 关注 /ecp/、/Microsoft-Server-ActiveSync 与历史反序列化利用面；"
            "③ 留意 autodiscover 配置泄露内网域名与账号格式；"
            "④ 用已知弱口令批量爆破时注意账号锁定策略。"
        ),
    },
    # 统一身份认证 / CAS
    {
        "fingerprints": ["sso_cas", "type:auth_bypass"],
        "vuln_type": "auth_bypass",
        "attack_chain": (
            "SSO / CAS 通用排查："
            "① 抓登录跳转的 service 参数与 ticket，验证是否可构造 service=攻击站点完成中继；"
            "② 检查 /cas/login 是否接受未校验的 redirect 与潜伏的默认账号；"
            "③ 关注 logout/validate 接口越权与 ticket 复用；"
            "④ 用本平台「鉴权差异对比」结论定位哪些后台接口其实匿名可达（CAS 仅前端隐藏）。"
        ),
    },
    # 教务 / 校园业务系统
    {
        "fingerprints": ["edu_jwgl", "edu_zhengfang", "type:idor"],
        "vuln_type": "idor",
        "attack_chain": (
            "教务/校园系统通用排查："
            "① 抓带学号/工号/ID 的 GET 参数，改为他人编号验证水平越权(IDOR)读成绩/课表/档案；"
            "② 关注 /jwglxt/ 与 /xscj/ 等接口是否仅靠前端隐藏权限；"
            "③ 找回密码/验证码接口是否可被枚举或绕过；"
            "④ 统一身份认证登录后，尝试用同一 Cookie 直接打后台数据接口（缺失二次鉴权）。"
        ),
    },
    # 通用：未授权后台（软指纹兜底，所有目标都尝试）
    {
        "fingerprints": ["type:unauthorized_access"],
        "vuln_type": "unauthorized_access",
        "attack_chain": (
            "通用未授权后台排查："
            "① 对侦察阶段暴露的所有 /admin、/manage、/console、/api/internal、/api/back 类端点做「匿名 vs 登录态」双态请求（参考本平台鉴权差异块）；"
            "② 匿名即 200 的直接读取；匿名 401 但登录态 200 的，优先打 IDOR/越权（换他人账号遍历 ID）；"
            "③ 后台登录页试默认口令与验证码可绕过性；"
            "④ 留意接口仅前端隐藏权限、后端未校验的情况。"
        ),
    },
    # 通用：Swagger 之外的接口未授权（软指纹兜底）
    {
        "fingerprints": ["type:info_leak"],
        "vuln_type": "info_leak",
        "attack_chain": (
            "通用信息泄露排查："
            "① 读 /.git/config、/robots.txt、/sitemap.xml 找隐藏路径与内网域名；"
            "② 读 /actuator、/status、/health、/metrics 等运维端点；"
            "③ 检查报错页/调试模式是否回显堆栈与绝对路径；"
            "④ 看 JS 资源里是否硬编码密钥、内网地址与接口前缀。"
        ),
    },
    # 业务流：订单/交易系统（biz:order 软指纹，由 worker recon 业务流识别触发）
    {
        "fingerprints": ["biz:order", "biz:trade", "type:idor"],
        "vuln_type": "idor",
        "attack_chain": (
            "订单/交易系统通用排查（业务流识别命中）："
            "① 抓带 order_id/orderNo/trade_id 的接口，改为他人编号验证水平越权(IDOR)读/改订单；"
            "② 订单状态接口(order/status、order/cancel)尝试越权取消/修改他人订单；"
            "③ 订单详情接口是否泄露收货人/手机号/地址等敏感字段；"
            "④ 结合本平台「业务流状态机映射」把下单→支付→退款串起来打依赖流程。"
        ),
    },
    # 业务流：支付/收银系统（biz:payment 软指纹）
    {
        "fingerprints": ["biz:payment", "biz:pay", "type:logic_flaw"],
        "vuln_type": "logic_flaw",
        "attack_chain": (
            "支付/收银系统通用排查（业务流识别命中）："
            "① 下单时篡改 amount/price/quantity（负值、0 元、小数溢出、数量改大价改小）看服务端是否重算；"
            "② 支付回调/notify 接口尝试伪造 success 标记或重复回调（需结合业务验证幂等）；"
            "③ 优惠券/折扣参数叠加绕过；"
            "④ 支付接口仅前端校验金额时，直接构造低价请求打后端未校验漏洞。"
        ),
    },
    # 业务流：用户中心/个人资料（biz:user_center 软指纹）
    {
        "fingerprints": ["biz:user_center", "biz:profile", "type:idor"],
        "vuln_type": "idor",
        "attack_chain": (
            "用户中心/个人资料系统通用排查（业务流识别命中）："
            "① 带 user_id/uid/member_id 的接口改为他人编号，验证水平越权读/改个人资料、绑定手机、余额；"
            "② 头像/附件上传接口打存储型 XSS 与路径遍历；"
            "③ 个人资料修改接口是否缺失二次鉴权（改绑定邮箱/手机即账户接管）；"
            "④ 关注 /api/user/info、/member/center 类接口是否仅靠前端隐藏权限。"
        ),
    },
    # 业务流：身份认证/登录（biz:auth 软指纹）
    {
        "fingerprints": ["biz:auth", "biz:login", "type:auth_bypass"],
        "vuln_type": "auth_bypass",
        "attack_chain": (
            "身份认证/登录系统通用排查（业务流识别命中）："
            "① 登录接口试默认口令、弱口令与验证码可绕过（不刷新/可重用/前端校验）；"
            "② JWT 改 alg=none 或改 payload 角色字段尝试越权；"
            "③ 登录态窃取：从 Druid/Swagger/报错页回收可用 Session/JWT 复用；"
            "④ 结合本平台「鉴权差异对比」结论定位匿名即可达的认证相关接口（后端未校验）。"
        ),
    },
]


def seed_default_chains(force: bool = False) -> int:
    """注入冷启动通用打法种子。幂等：已存在同 sig 的模板跳过（不覆盖用户沉淀）。

    返回本次实际新增的条数。force=True 时仍只跳过「种子自身」重复，不覆盖用户数据。
    """
    with _LOCK:
        data = load_templates()
        templates = data.setdefault("templates", [])
        existing_sigs = {t.get("sig") for t in templates}
        added = 0
        now = int(time.time())
        for s in _SEED_CHAINS:
            vuln_type = (s["vuln_type"] or "").strip().lower()
            chain = _normalize_chain(s["attack_chain"])
            if not vuln_type or not chain:
                continue
            sig = f"{vuln_type}|{chain}"
            if sig in existing_sigs:
                continue  # 幂等：已存在（无论来源）不重复插入、不覆盖
            fps = [f for f in (s.get("fingerprints") or []) if f]
            if not fps:
                fps = [f"type:{vuln_type}"]
            templates.append({
                "id": f"seed-{now}-{added}",
                "sig": sig,
                "fingerprints": fps,
                "vuln_type": vuln_type,
                "attack_chain": chain,
                "owner": "seed",
                "hits": 0,
                "created_at": now,
                "last_seen": now,
            })
            existing_sigs.add(sig)
            added += 1
        if added:
            save_templates(data)
        return added
