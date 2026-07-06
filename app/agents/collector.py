"""Collector（搜集 Agent）：智能搜集目标 → 机械预筛 → edu 判定 → 入队 queued。

对应设计文档 §7.5。流程：
1. 查询生成：用户给 FOFA 语法则直用；给自然语言意图则 LLM 翻译成语法并逐轮演化。
2. 执行：调 FOFA 翻页拉取候选。
3. 机械预筛：过滤 CDN/死链/纯前端静态站。
4. edu 判定：LLM 综合 host+org+title 判断归属（拿不准的资产）。
5. 去重(host级) → 写库 queued。

任何 LLM/FOFA 失败都降级（退回机械模式或跳过本轮），绝不阻断 orchestrator 主循环。
"""
from __future__ import annotations

import asyncio
import os
import re
import time
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_runtime import COLLECTOR_IO_EXECUTOR
from app.agents import collector_llm, playbook_router, prefilter, scorer, site_collab, target_filter
from app.agents import target_cluster
from app.agents.prompts import is_enterprise_src
from app.db.models import Target, Task
from app.engines import get_engine, EngineResult, QuakeRateLimitError
from app.tools.leakcreds import query_leaked_creds
from app.llm.client import LLMClient, LLMError
from app.settings_service import llm_client_for_task_optional, resolve_engine_config, resolve_skip_score_threshold

_EDUSRC_ORG_FILTER = 'org="China Education and Research Network Center"'
_PREFILTER_CONCURRENCY = int(os.environ.get("COLLECTOR_PREFILTER_CONCURRENCY", "12"))
_SCORE_CONCURRENCY = int(os.environ.get("COLLECTOR_SCORE_CONCURRENCY", "8"))
_TARGET_FILTER_CONCURRENCY = int(os.environ.get("TARGET_FILTER_CONCURRENCY", "6"))
_TARGET_FILTER_HARD_TIMEOUT = float(os.environ.get("TARGET_FILTER_HARD_TIMEOUT", "10.0"))
# 泄露凭证查询走外部 logs API，并发要小、节奏要慢，避免把对方打挂或被限流。
_LEAK_CONCURRENCY = int(os.environ.get("LEAK_QUERY_CONCURRENCY", "2"))
_LEAK_QUERY_DELAY = float(os.environ.get("LEAK_QUERY_DELAY", "0.6"))
ProgressCallback = Callable[[str, str, dict], Awaitable[None]]
ProgressReporter = Callable[..., Awaitable[None]]


def normalize_host(url_or_host: str) -> str:
    """归一化为 host（去协议、去末尾/、小写）。"""
    s = url_or_host.strip()
    if "://" not in s:
        s = "http://" + s
    parsed = urlparse(s)
    host = (parsed.hostname or "").lower()
    if parsed.port and parsed.port not in (80, 443):
        host = f"{host}:{parsed.port}"
    return host


def _is_edusrc_intent_task(task: Task, raw: str, is_intent: bool) -> bool:
    if not is_intent:
        return False
    src_type = (task.src_type or "").lower()
    raw_lower = (raw or "").lower()
    return (
        "edusrc" in src_type
        or "edu src" in raw_lower
        or "edusrc" in raw_lower
        or "教育src" in raw_lower
        or "教育行业" in raw_lower
    )


def _with_edusrc_org_filter(query: str) -> str:
    q = (query or "").strip()
    if not q or _EDUSRC_ORG_FILTER.lower() in q.lower():
        return q
    return f"({q}) && {_EDUSRC_ORG_FILTER}"


def _extract_enterprise_domains(raw: str) -> list[str]:
    """从用户的企业资产范围（如 `*.21cn.com *.189.cn ，资产范围就这些`）里提取根域名。
    支持通配符、逗号/空格/中文逗号分隔、零散域名。返回去重后的根域名列表。"""
    import re
    if not raw:
        return []
    # 抓出所有形如 (*.)example.com / sub.example.com.cn 的域名 token
    tokens = re.findall(r"[*]?\.?[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)+", raw.lower())
    domains: list[str] = []
    seen: set[str] = set()
    for t in tokens:
        t = t.lstrip("*.").strip(".")
        if not t or "." not in t:
            continue
        # 用 target_cluster 的 root_domain 归一到根域（含 .com.cn 等二级后缀处理）
        root = target_cluster.root_domain(t)
        if root and root not in seen:
            seen.add(root)
            domains.append(root)
    return domains


def _with_enterprise_scope_filter(query: str, domains: list[str]) -> str:
    """企业模式范围硬约束：把 LLM 生成的整条语法用用户指定的域名范围 `&&` 包裹，
    彻底杜绝 `||` 运算符优先级导致的范围逃逸（否则 (domain=a)&&(body=x) || (body=y)
    会被 FOFA 解析成后半段脱离域名约束、命中全网无关资产）。"""
    q = (query or "").strip()
    if not q or not domains:
        return q
    scope = " || ".join(f'domain="{d}"' for d in domains)
    scope = f"({scope})"
    # 已经包含完整范围约束则不重复包裹
    if scope.lower() in q.lower():
        return q
    return f"{scope} && ({q})"


def _extract_scope_anchors(raw: str) -> dict[str, list[str]]:
    """从用户原始 FOFA 语法里提取「资产归属锚点」：具体域名 + cert.subject.org。

    专治单目标任务(如 `ecut.edu.cn && cert.subject.org="东华理工大学"`)被 LLM
    逐轮演化时把这些锚点丢掉、换成宽泛的 `body="东华理工大学"`，导致范围从一所
    学校扩散到全国教育网（body 里凡是提到这几个字的友链/新闻/名录站全被圈进来）。

    返回 {"domains": [...根域...], "cert_orgs": ['东华理工大学', ...]}。
    只提取「精确锚点」——纯 org=/body= 这类宽泛条件不算锚点，不参与硬约束。
    """
    import re
    raw = (raw or "").strip()
    if not raw:
        return {"domains": [], "cert_orgs": []}

    cert_orgs: list[str] = []
    seen_org: set[str] = set()
    for m in re.finditer(r'cert\.subject\.org\s*=\s*"([^"]+)"', raw, re.I):
        v = m.group(1).strip()
        if v and v not in seen_org:
            seen_org.add(v)
            cert_orgs.append(v)

    # 提取具体域名锚点：优先 domain="x"/host="x"，其次裸写的域名 token。
    # 排除 FOFA 通用 org 值（China Education... 不是资产锚点，是全网范围）。
    domains: list[str] = []
    seen_dom: set[str] = set()

    def _add_domain(token: str) -> None:
        t = token.strip().strip('"').lstrip("*.").strip(".").lower()
        if not t or "." not in t:
            return
        root = target_cluster.root_domain(t)
        if root and root not in seen_dom:
            seen_dom.add(root)
            domains.append(root)

    for m in re.finditer(r'(?:domain|host)\s*=\s*"([^"]+)"', raw, re.I):
        _add_domain(m.group(1))
    # 裸写域名（未包在字段里）：如 `ecut.edu.cn && cert...`
    stripped = re.sub(r'(?:domain|host|org|cert\.[a-z.]+|title|body|icon_hash|ip|port|protocol)\s*=\s*"[^"]*"', " ", raw, flags=re.I)
    for tok in re.findall(r"[*]?\.?[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)+", stripped.lower()):
        _add_domain(tok)

    return {"domains": domains, "cert_orgs": cert_orgs}


def _with_scope_anchors(query: str, anchors: dict[str, list[str]]) -> str:
    """把用户原始锚点(域名/cert.subject.org)作为外层 && 硬约束包裹整条语法，
    杜绝 LLM 演化出的 `||` 分支脱离归属逃逸到别的学校/全网。

    多个域名之间用 `||`，多个 cert_org 之间用 `||`，域名组与 cert 组之间也用
    `||`（任一命中即算属于该目标——单站可能只有域名匹配，或只有证书匹配）。
    """
    q = (query or "").strip()
    domains = anchors.get("domains") or []
    cert_orgs = anchors.get("cert_orgs") or []
    if not q or (not domains and not cert_orgs):
        return q
    parts: list[str] = []
    parts += [f'domain="{d}"' for d in domains]
    parts += [f'cert.subject.org="{o}"' for o in cert_orgs]
    scope = f"({' || '.join(parts)})"
    if scope.lower() in q.lower():
        return q
    return f"{scope} && ({q})"


def _ensure_url(host: str) -> str:
    return host if host.startswith("http") else f"http://{host}"


async def _existing_hosts(session: AsyncSession, task_id: str) -> set[str]:
    rows = await session.execute(select(Target.host).where(Target.task_id == task_id))
    return {r[0] for r in rows.all()}


async def _existing_cluster_state(session: AsyncSession, task_id: str) -> dict[str, dict]:
    rows = (await session.execute(
        select(Target).where(
            Target.task_id == task_id,
            Target.status.in_(["queued", "assigned", "scanning", "dead", "skipped"]),
        )
    )).scalars().all()
    state: dict[str, dict] = {}
    for t in rows:
        key = target_cluster.target_cluster_key(t.host or t.url, t.title, t.org)
        if not key:
            continue
        item = state.setdefault(key, {"deadish": 0, "pending": 0, "sample": ""})
        if t.status in ("queued", "assigned", "scanning"):
            item["pending"] += 1
        if _is_cluster_deadish(t):
            item["deadish"] += 1
            item["sample"] = item.get("sample") or (t.host or t.url)
    return state


def _is_cluster_deadish(t: Target) -> bool:
    reason = (t.dead_reason or t.last_error or "").lower()
    if t.status == "skipped" and t.verdict == "skip_cluster_cooldown":
        return True
    if t.status != "dead":
        return False
    if t.verdict in ("no_vuln", "timeout"):
        return True
    return any(marker in reason for marker in ("无可利用", "无果", "自动收敛", "打不穿", "timeout", "超时"))


def _llm_for_task(task: Task) -> LLMClient | None:
    return llm_client_for_task_optional(task)


async def _resolve_query(task: Task, llm: LLMClient | None) -> tuple[str, str]:
    """确定本轮 FOFA 语法。
    - intent_mode='syntax'：用户给的就是 FOFA 语法，直用。
    - intent_mode='intent' 或自然语言：LLM 翻译成语法并逐轮演化。
    返回 (query, reason)。
    """
    cfg = dict(task.fofa_config or {})
    history: list[str] = list(cfg.get("history", []))
    raw = (task.fofa_query or "").strip()
    intent_mode = cfg.get("intent_mode") or resolve_engine_config(task).get("intent_mode", "")
    # 'syntax' / 'intent'，未设则启发式判断

    # 启发式：含 FOFA 字段符号视为语法，否则视为自然语言意图
    looks_like_syntax = any(tok in raw for tok in ("=", "&&", "||", "domain", "title=", "body=", "org="))
    is_intent = intent_mode == "intent" or (intent_mode != "syntax" and raw and not looks_like_syntax)
    force_edusrc_org = _is_edusrc_intent_task(task, raw, is_intent)

    # 企业模式范围硬约束：用户已明确指定资产范围（如 *.21cn.com 这些），
    # 提取根域名作为外层 && 约束，强制包裹后续一切语法，杜绝 LLM 生成的
    # `||` 分支脱离域名约束逃逸到全网（实测会圈进俄罗斯/西班牙等无关资产）。
    enterprise_domains: list[str] = []
    if is_enterprise_src(task.src_type):
        enterprise_domains = _extract_enterprise_domains(raw)

    # 单目标资产锚点硬约束（非企业模式）：用户原始语法里若带具体域名 /
    # cert.subject.org，就把它作为外层 && 强制包住每一轮演化后的语法，
    # 防止 LLM 把归属锚点替换成宽泛 body= 后范围扩散到别的学校。
    scope_anchors: dict[str, list[str]] = {"domains": [], "cert_orgs": []}
    if not enterprise_domains and looks_like_syntax:
        scope_anchors = _extract_scope_anchors(raw)

    def _apply_scope(q: str) -> str:
        if enterprise_domains:
            return _with_enterprise_scope_filter(q, enterprise_domains)
        if scope_anchors.get("domains") or scope_anchors.get("cert_orgs"):
            return _with_scope_anchors(q, scope_anchors)
        if force_edusrc_org:
            return _with_edusrc_org_filter(q)
        return q

    # 用户直接给语法、且没历史 → 第一轮直用原语法（企业模式仍强制套范围约束）
    if raw and looks_like_syntax and not history:
        return _apply_scope(raw), "用户指定语法"

    # 需要 LLM 生成（自然语言意图 / 语法已用过要演化 / 完全没给）
    if llm is not None:
        intent_text = raw if is_intent else (raw and f"在此基础上换角度扩展：{raw}" or "")
        try:
            loop = asyncio.get_running_loop()
            gen = await loop.run_in_executor(
                COLLECTOR_IO_EXECUTOR,
                lambda: collector_llm.generate_query(
                    llm, intent_text, list(task.vuln_types or []), history, task.src_type
                ),
            )
            if gen and gen["query"] and gen["query"] not in history:
                return _apply_scope(gen["query"]), gen.get("reason", "LLM 生成")
        except LLMError as e:
            if e.kind == "quota":
                raise
            cfg["last_llm_error"] = str(e)[:300]
            task.fofa_config = cfg
        except Exception as e:
            cfg["last_llm_error"] = str(e)[:300]
            task.fofa_config = cfg

    # 降级：有原语法就继续用原语法翻页，否则空（企业模式仍强制套范围约束）
    if raw and looks_like_syntax:
        return _apply_scope(raw), "降级沿用原语法"
    return "", ""


async def refill(session: AsyncSession, task: Task, low_watermark: int = 5,
                 batch_pages: int = 1,
                 progress_cb: ProgressCallback | None = None) -> int:
    """补充目标。返回新入队数量。队列够则不补。"""
    queued = (await session.execute(
        select(func.count()).select_from(Target).where(
            Target.task_id == task.id, Target.status == "queued")
    )).scalar() or 0
    if queued >= low_watermark:
        return 0

    async def progress(phase: str, text: str, **payload) -> None:
        cfg = dict(task.fofa_config or {})
        cfg.update(
            collector_phase=phase,
            collector_phase_text=text,
            collector_phase_payload=payload,
        )
        task.fofa_config = cfg
        if progress_cb:
            await progress_cb(phase, text, payload)

    seen = await _existing_hosts(session, task.id)
    cluster_state = await _existing_cluster_state(session, task.id)
    added = 0

    # 单站协作：同一个真实 host 按路线拆成多个 worker，不走 FOFA 翻页。
    if task.target_source == "site":
        added += await _site_collect(session, task)
        await session.commit()
        return added

    # 1) 手动清单（一次性消费，不预筛——用户明确指定的直接挖）
    if task.target_source in ("manual", "both") and task.manual_targets:
        for raw in task.manual_targets:
            host = normalize_host(raw)
            if not host or host in seen:
                continue
            seen.add(host)
            session.add(Target(task_id=task.id, url=_ensure_url(host), host=host,
                               source="manual", status="queued"))
            added += 1
        task.manual_targets = []  # 消费掉，避免重复

    # 2) FOFA 智能搜集
    if task.target_source in ("fofa", "both"):
        added += await _fofa_collect(session, task, seen, cluster_state, progress)

    await session.commit()
    return added


async def _site_collect(session: AsyncSession, task: Task) -> int:
    """把用户给的单站目标拆成多条协作路线入队。

    不消费 manual_targets，便于任务详情/编辑保留用户原始目标；靠 DB 的
    (task_id, host, source) 唯一索引和应用层 existing_sources 防重复。
    """
    raw_targets = [str(t).strip() for t in (task.manual_targets or []) if str(t).strip()]
    if not raw_targets:
        return 0
    added = 0
    for raw in raw_targets:
        host = normalize_host(raw)
        if not host:
            continue
        url = _ensure_url(raw)
        existing = (await session.execute(
            select(Target.source).where(Target.task_id == task.id, Target.host == host)
        )).all()
        existing_sources = {r[0] for r in existing}
        # 开局就把侦察(phase0)+5 条主题深挖(phase1)路线一次性全部并发入队。
        # 之前只入队侦察路线、等它跑完才补派主题路线，导致「能快速出洞的
        # 认证越权路线」被侦察串行硬拖到几十分钟。改回并发：侦察 worker 产出的
        # coverage 仍会通过 _build_coverage_context 喂给后启动的主题 worker，
        # 成果照样复用、又不牺牲开局速度。priority 高的侦察路线天然先抢并发。
        for route in site_collab.INITIAL_ROUTES:
            if route.source in existing_sources:
                continue
            session.add(Target(
                task_id=task.id,
                url=url,
                host=host,
                source=route.source,
                status="queued",
                priority_score=route.priority,
                priority_reason=site_collab.route_reason(route),
            ))
            added += 1
    return added


async def _fofa_collect(
    session: AsyncSession,
    task: Task,
    seen: set[str],
    cluster_state: dict[str, dict],
    progress: ProgressReporter | None = None,
) -> int:
    async def report(phase: str, text: str, **payload) -> None:
        if progress:
            await progress(phase, text, **payload)

    cfg = dict(task.fofa_config or {})
    defaults = resolve_engine_config(task)
    engine_name = defaults["engine"]
    engine = get_engine(engine_name)
    if engine is None:
        return 0

    key = defaults["key"]
    if not key:
        return 0
    max_pages = int(defaults["max_pages"])
    size = int(defaults["page_size"])
    base_url = defaults.get("base_url") or engine.get_default_base_url()

    llm = _llm_for_task(task)
    history: list[str] = list(cfg.get("history", []))
    cur_query = cfg.get("current_query", "")
    cursor = int(cfg.get("cursor", 0))

    # 当前语法翻完了（或还没语法）→ 换/生成新语法
    if not cur_query or cursor >= max_pages:
        new_q, reason = await _resolve_query(task, llm)
        if not new_q:
            return 0
        cur_query = new_q
        cursor = 0
        if new_q not in history:
            history.append(new_q)

    next_cursor = cursor + 1

    # 频率限制冷却检查：如果还在冷却期内，直接跳过本轮
    rate_limit_until = float(cfg.get("rate_limit_until", 0))
    if rate_limit_until > time.monotonic():
        remain = rate_limit_until - time.monotonic()
        cfg["collector_phase"] = "fofa_error"
        await report(
            "fofa_error",
            f"{engine.display_name} 频率限制冷却中（还剩 {remain:.0f} 秒），跳过本轮",
            fofa_error="rate_limit_cooldown", cursor=cursor, cooldown_remaining=remain,
        )
        task.fofa_config = {**cfg}
        return 0

    try:
        res = await engine.search(key, cur_query, page=next_cursor, page_size=size,
                                  base_url=base_url)
    except QuakeRateLimitError as e:
        # Quake 专用限流异常
        err = f"{e}"[:300]
        rl_count = int(cfg.get("rate_limit_count", 0)) + 1
        # 不 sleep：设足够长的冷却期（60s→120s→240s→480s），让调度器跳过
        backoff = min(60 * (2 ** (rl_count - 1)), 600)
        cfg["rate_limit_count"] = rl_count
        cfg["rate_limit_until"] = time.monotonic() + backoff
        cfg["last_fofa_error"] = err
        cfg["collector_phase"] = "fofa_error"
        cfg["fofa_auth_fail_count"] = 0
        await report(
            "fofa_error",
            f"{engine.display_name} 频率限制（第 {rl_count} 次），冷却 {backoff} 秒",
            fofa_error=err, cursor=cursor, retry_after=backoff, rate_limit_count=rl_count,
        )
        task.fofa_config = {**cfg}
        return 0
    except (ValueError, Exception) as e:
        err = f"{e}"[:300]
        err_lower = str(e).lower()
        # 通用频率限制检测（不限引擎，匹配常见限流关键词）
        _is_rate_limit = any(m in err_lower for m in (
            "rate limit", "too many", "过于频繁", "请求太频繁", "q3005", "429", "retry after",
        ))
        if _is_rate_limit:
            rl_count = int(cfg.get("rate_limit_count", 0)) + 1
            # 不 sleep，设冷却期让调度器跳过
            backoff = min(60 * (2 ** (rl_count - 1)), 600)
            cfg["rate_limit_count"] = rl_count
            cfg["rate_limit_until"] = time.monotonic() + backoff
            cfg["last_fofa_error"] = err
            cfg["collector_phase"] = "fofa_error"
            cfg["fofa_auth_fail_count"] = 0
            await report(
                "fofa_error",
                f"{engine.display_name} 频率限制（第 {rl_count} 次），冷却 {backoff} 秒",
                fofa_error=err, cursor=cursor, retry_after=backoff, rate_limit_count=rl_count,
            )
            task.fofa_config = {**cfg}
            return 0
        cfg["last_fofa_error"] = err
        cfg["collector_phase"] = "fofa_error"
        # 账号级致命错误标记（各引擎用不同的错误判断逻辑）
        is_account_err = any(m in err_lower for m in (
            "key", "token", "无效", "过期", "余额", "quota", "permission",
            "unauthorized", "forbidden", "account", "401", "403",
        ))
        if is_account_err:
            cfg["fofa_auth_fail_count"] = int(cfg.get("fofa_auth_fail_count", 0)) + 1
            await report(
                "fofa_error",
                f"{engine.display_name} 账号无效（第 {cfg['fofa_auth_fail_count']} 次）：{err}",
                fofa_error=err, cursor=cursor, fofa_auth_fail=cfg["fofa_auth_fail_count"],
            )
        else:
            cfg["fofa_auth_fail_count"] = 0
            await report(
                "fofa_error",
                f"{engine.display_name} 检索失败，已跳过本轮（游标停留第 {cursor} 页，下轮重试）：{err}",
                fofa_error=err, cursor=cursor,
            )
        task.fofa_config = {**cfg}
        return 0
    cursor = next_cursor
    cfg["fofa_auth_fail_count"] = 0
    cfg["rate_limit_count"] = 0  # 成功请求重置限流计数
    cfg.pop("rate_limit_until", None)
    cfg.pop("last_fofa_error", None)

    # host 归属兜底过滤：即使 FOFA 语法因运算符优先级或 LLM 演化丢锚点而放宽范围，
    # 也在入库前按用户指定的根域名白名单二次过滤，丢弃一切范围外的无关资产。
    # - 企业模式：用户指定的资产域名范围。
    # - 单目标模式：用户原始语法里的具体域名锚点（如 ecut.edu.cn）。
    #   注意：仅当原始语法带域名锚点时才启用；只有 cert.subject.org 无域名锚点时
    #   不做客户端根域过滤（证书归属无法在本地判定，靠语法层的 && 硬约束兜底）。
    scope_domains: set[str] = set()
    if is_enterprise_src(task.src_type):
        scope_domains = set(_extract_enterprise_domains((task.fofa_query or "")))
    else:
        anchor_domains = _extract_scope_anchors((task.fofa_query or "")).get("domains") or []
        scope_domains = set(anchor_domains)

    fields = res.fields
    candidates: list[dict] = []
    dropped_oos = 0
    for row in res.results:
        rec = dict(zip(fields, row)) if isinstance(row, list) else row
        host = normalize_host(rec.get("host") or rec.get("domain") or rec.get("ip") or "")
        if not host or host in seen:
            continue
        if scope_domains and target_cluster.root_domain(host) not in scope_domains:
            dropped_oos += 1
            continue  # 范围外资产，丢弃（不入库、不占去重位）
        seen.add(host)
        candidates.append({
            "host": host,
            "url": _ensure_url(rec.get("host") or host),
            "ip": rec.get("ip", ""), "org": rec.get("org", ""), "title": rec.get("title", ""),
        })

    # 本轮 FOFA 没返回任何「新」资产（要么本页全是已入库去重、要么范围外被丢、
    # 要么该目标资产已被搜完）。此时后面预筛/评分/过滤器都是对空列表空转，
    # 会刷一串「候选0→存活0→过滤器0/0」的无意义日志。直接静默收敛：
    # 只在偶尔（每若干轮）报一次状态，避免看板被 0/0 刷屏。
    if not candidates:
        cfg["current_query"] = cur_query
        cfg["cursor"] = cursor
        cfg["history"] = history
        cfg["collector_phase"] = "exhausted"
        empty_streak = int(cfg.get("empty_streak", 0)) + 1
        cfg["empty_streak"] = empty_streak
        task.fofa_config = {**cfg}
        # 每 5 轮空转才报一次，且措辞明确指出「资产可能已搜完」，而非误导性的 0/0。
        if empty_streak == 1 or empty_streak % 5 == 0:
            hint = "本轮无新增资产" + (f"（范围外丢弃 {dropped_oos} 个）" if dropped_oos else "")
            hint += f"；当前语法第 {cursor} 页已无新目标，连续空轮 {empty_streak} 次，可能该目标资产已基本搜完"
            await report("exhausted", hint, candidates=0, empty_streak=empty_streak, dropped_out_of_scope=dropped_oos)
        return 0
    cfg.pop("empty_streak", None)

    # 机械预筛（并发探活，过滤 CDN/死链/纯前端）
    await report("prefilter", f"正在探活预筛 {len(candidates)} 个候选目标", candidates=len(candidates))
    survivors = await _prefilter(candidates)
    await report(
        "scoring",
        f"预筛后存活 {len(survivors)} 个，正在评分与归属标注",
        candidates=len(candidates),
        survivors=len(survivors),
    )

    # 模式化资产归属标注 + 优先级评分（决定 worker 先打谁，不过滤）
    await _annotate_assets(survivors, llm, task.src_type)
    await _score_targets(survivors, task.src_type)
    await report(
        "target_filter",
        f"正在跑目标过滤器 {len(survivors)} 个存活目标",
        survivors=len(survivors),
    )
    await _analyze_target_filters(survivors)
    filter_evaluated = sum(1 for c in survivors if c.get("_site_profile") is not None)
    await report(
        "enrich",
        f"过滤器完成 {filter_evaluated}/{len(survivors)}，正在补充泄露凭据",
        survivors=len(survivors),
        filter_evaluated=filter_evaluated,
    )

    # 顺带查泄露凭证：按根域去重批量查（同根域多 host 共享一次查询），
    # 过滤打分后挂到 survivor 上，入库时一起写入，供 worker 当额外攻击面。
    await _enrich_leaked_creds(survivors)

    added = 0
    skipped_low = 0
    skipped_cluster = 0
    skipped_filter = 0
    # 企业 SRC 默认禁用同款簇限流：目标集中在指定资产，不存在「同款刷屏」问题，
    # 沿用 EduSRC 的按 root 域名聚类限流会把大量该打的企业资产误 skip。
    cluster_limit_on = target_cluster.cluster_limit_enabled(task.src_type)
    for c in survivors:
        score = c.get("priority_score", 0.0)
        reason = c.get("priority_reason", "")
        filter_decision = target_filter.evaluate_target(
            url=c.get("url", ""),
            host=c.get("host", ""),
            title=c.get("title", ""),
            body=(c.get("_probe") or {}).get("body_snippet", ""),
            priority_score=score,
            priority_reason=reason,
            source="fofa",
            leaked_creds=c.get("leaked_creds") or [],
            profile=c.get("_site_profile"),
        )
        if filter_decision.score_bonus:
            score += filter_decision.score_bonus
            sign = "+" if filter_decision.score_bonus > 0 else ""
            reason = f"{reason} · {sign}{filter_decision.score_bonus:g} {filter_decision.bonus_reason}"
            c["priority_score"], c["priority_reason"] = score, reason
        cluster_key = target_cluster.target_cluster_key(c["host"], c.get("title", ""), c.get("org", ""))
        cluster_item = cluster_state.setdefault(cluster_key, {"deadish": 0, "pending": 0, "sample": ""}) if cluster_key else None
        if cluster_limit_on and cluster_item and target_cluster.should_cooldown_cluster(cluster_item):
            session.add(Target(
                task_id=task.id, url=c["url"], host=c["host"],
                ip=c["ip"], org=c["org"], title=c["title"],
                source="fofa", status="skipped", is_edu=c.get("is_edu"),
                school=c.get("school", ""),
                priority_score=score, priority_reason=reason,
                verdict="skip_cluster_cooldown",
                dead_reason=target_cluster.cooldown_reason(cluster_item, cluster_item.get("sample", "")),
            ))
            skipped_cluster += 1
            continue
        if cluster_limit_on and cluster_item and cluster_item.get("pending", 0) >= target_cluster.CLUSTER_PENDING_LIMIT:
            session.add(Target(
                task_id=task.id, url=c["url"], host=c["host"],
                ip=c["ip"], org=c["org"], title=c["title"],
                source="fofa", status="skipped", is_edu=c.get("is_edu"),
                school=c.get("school", ""),
                priority_score=score, priority_reason=reason,
                verdict="skip_cluster_pending",
                dead_reason=target_cluster.pending_limit_reason(cluster_item),
            ))
            skipped_cluster += 1
            continue
        if filter_decision.skip:
            session.add(Target(
                task_id=task.id, url=c["url"], host=c["host"],
                ip=c["ip"], org=c["org"], title=c["title"],
                source="fofa", status="skipped", is_edu=c.get("is_edu"),
                school=c.get("school", ""),
                priority_score=score, priority_reason=reason,
                verdict="skip_target_filter",
                dead_reason=filter_decision.reason[:300],
            ))
            skipped_filter += 1
            continue
        # 低于阈值：直接 skipped（不派 worker），仍入库以占住去重位（不会被重复搜集）
        skip_thr = resolve_skip_score_threshold()
        if score < skip_thr:
            session.add(Target(
                task_id=task.id, url=c["url"], host=c["host"],
                ip=c["ip"], org=c["org"], title=c["title"],
                source="fofa", status="skipped", is_edu=c.get("is_edu"),
                school=c.get("school", ""),
                priority_score=score, priority_reason=reason,
                verdict="skip_low_score",
                dead_reason=f"评分 {score:.0f} < {skip_thr:.0f}，垃圾资产不打",
            ))
            skipped_low += 1
            continue
        session.add(Target(
            task_id=task.id, url=c["url"], host=c["host"],
            ip=c["ip"], org=c["org"], title=c["title"],
            source="fofa", status="queued", is_edu=c.get("is_edu"),
            school=c.get("school", ""),
            priority_score=score, priority_reason=reason,
            leaked_creds=c.get("leaked_creds") or None,
        ))
        if cluster_item:
            cluster_item["pending"] += 1
        added += 1

    cfg.update(current_query=cur_query, cursor=cursor, history=history,
               last_skipped_low=skipped_low, last_skipped_cluster=skipped_cluster,
               last_skipped_filter=skipped_filter,
               last_dropped_out_of_scope=dropped_oos,
               last_target_filter_total=len(survivors),
               last_target_filter_evaluated=filter_evaluated,
               collector_phase="dispatch",
               collector_phase_text=f"目标过滤完成：入队 {added} 个，过滤 {skipped_filter} 个，低分跳过 {skipped_low} 个")
    task.fofa_config = cfg
    return added


async def _prefilter(candidates: list[dict]) -> list[dict]:
    """并发机械预筛，返回存活、值得挖的资产（带首页探测信息供评分复用）。"""
    if not candidates:
        return []
    sem = asyncio.Semaphore(max(1, _PREFILTER_CONCURRENCY))

    async def one(c: dict):
        async with sem:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                COLLECTOR_IO_EXECUTOR,
                lambda: prefilter.should_skip_ex(c["host"], c["url"]),
            )

    results = await asyncio.gather(*[one(c) for c in candidates])
    out = []
    for c, (skip, _reason, info) in zip(candidates, results):
        if not skip:
            c["_probe"] = info  # 缓存首页探测，避免评分时重复抓
            out.append(c)
    return out


async def _score_targets(survivors: list[dict], src_type: str = "edusrc") -> None:
    """目标优先级打分（复用预筛的首页探测 + 探高价值端点）。
    评分只决定先打谁，不过滤——低分仍入队，排后面。"""
    sem = asyncio.Semaphore(max(1, _SCORE_CONCURRENCY))

    async def one(c: dict):
        async with sem:
            info = c.get("_probe") or {}
            title = c.get("title") or info.get("title", "")
            try:
                loop = asyncio.get_running_loop()
                sc, reason = await loop.run_in_executor(
                    COLLECTOR_IO_EXECUTOR,
                    lambda: scorer.score_target(
                        c["url"], title,
                        info.get("server", ""), info.get("body_snippet", ""), True,
                        6.0, src_type,
                    ),
                )
                plan = playbook_router.route_target(
                    url=c["url"],
                    title=title,
                    server=info.get("server", ""),
                    body=info.get("body_snippet", ""),
                    priority_reason=reason,
                    src_type=src_type,
                    source=c.get("source", ""),
                )
                sc += plan.score_bonus
                reason = playbook_router.append_route_reason(reason, plan)
            except Exception:
                sc, reason = 0.0, "评分异常"
            c["priority_score"], c["priority_reason"] = sc, reason

    await asyncio.gather(*[one(c) for c in survivors])


async def _analyze_target_filters(survivors: list[dict]) -> None:
    """构建轻量站点画像，供 target_filter 基于真实攻击面过滤/加权。

    这一步只对已经通过机械预筛且完成评分的 survivor 执行；失败时保守放行，
    不阻断入队。
    """
    if not survivors:
        return
    sem = asyncio.Semaphore(max(1, _TARGET_FILTER_CONCURRENCY))

    async def one(c: dict) -> None:
        async with sem:
            info = c.get("_probe") or {}
            try:
                loop = asyncio.get_running_loop()
                future = loop.run_in_executor(
                    COLLECTOR_IO_EXECUTOR,
                    lambda: target_filter.analyze_site_surface(
                        c["url"],
                        host=c.get("host", ""),
                        title_hint=c.get("title") or info.get("title", ""),
                        body_hint=info.get("body_snippet", ""),
                    ),
                )
                profile = await asyncio.wait_for(future, timeout=max(1.0, _TARGET_FILTER_HARD_TIMEOUT))
                c["_site_profile"] = profile
            except asyncio.TimeoutError:
                c["_site_profile"] = None
            except Exception:
                c["_site_profile"] = None

    await asyncio.gather(*(one(c) for c in survivors))


async def _enrich_leaked_creds(survivors: list[dict]) -> None:
    """按根域去重批量查泄露凭证，过滤打分后挂到 survivor['leaked_creds']。

    设计：
    - 按 root_domain 聚合，同根域只查一次（省调用、ES 也按域返回）。
    - 同步 httpx 调用放进 COLLECTOR_IO_EXECUTOR，不阻塞事件循环。
    - 全程失败降级（leakcreds 内部已兜底），绝不阻断搜集入库。
    - 只挂正分精选凭证；查不到就不挂（worker 端按是否有凭证决定提示）。
    """
    if not survivors:
        return
    # 按根域聚合 host
    roots: dict[str, list[dict]] = {}
    for c in survivors:
        root = target_cluster.root_domain(c.get("host") or c.get("url") or "")
        if not root or "." not in root:
            continue
        # IP 目标不查凭证（ES 按域名索引，IP 查不到有效凭证，纯属浪费调用）。
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", root):
            continue
        roots.setdefault(root, []).append(c)
    if not roots:
        return

    # 外部 logs API：低并发 + 请求间小延迟，温柔点别打挂对方。
    sem = asyncio.Semaphore(max(1, _LEAK_CONCURRENCY))

    async def one(root: str, members: list[dict]):
        async with sem:
            try:
                loop = asyncio.get_running_loop()
                res = await loop.run_in_executor(
                    COLLECTOR_IO_EXECUTOR,
                    lambda: query_leaked_creds(root),
                )
            except Exception:
                return
            finally:
                # 持锁期间限速：让同一并发槽的下一次查询至少间隔 _LEAK_QUERY_DELAY 秒。
                if _LEAK_QUERY_DELAY > 0:
                    await asyncio.sleep(_LEAK_QUERY_DELAY)
            creds = (res or {}).get("creds") or []
            if not creds:
                return
            # 同根域所有 host 共享这批凭证（worker 会自行核对 host 归属）。
            for c in members:
                c["leaked_creds"] = creds

    await asyncio.gather(*[one(r, m) for r, m in roots.items()])


async def _annotate_assets(assets: list[dict], llm: LLMClient | None, src_type: str) -> None:
    if is_enterprise_src(src_type):
        _annotate_enterprise(assets)
        return
    await _annotate_edu(assets, llm)


def _annotate_enterprise(assets: list[dict]) -> None:
    """企业模式不做 EduSRC 范围判定，只给 worker 一个单位/系统候选归属。"""
    for a in assets:
        a["is_edu"] = False
        a["school"] = (a.get("org") or a.get("title") or "").strip()[:200]


async def _annotate_edu(assets: list[dict], llm: LLMClient | None) -> None:
    """给资产标 is_edu + 候选归属学校 school。规则能判的直接标，剩下的交 LLM 批量判。"""
    pending = []
    for a in assets:
        r = _is_edu(a["host"], a.get("org", ""))
        if r is True:
            a["is_edu"] = True
            a.setdefault("school", a.get("org", ""))  # 规则判 edu 时先用 org 作候选，worker 再核实
        elif r is None:
            pending.append(a)
    if pending and llm is not None:
        try:
            loop = asyncio.get_running_loop()
            verdicts = await loop.run_in_executor(
                COLLECTOR_IO_EXECUTOR,
                lambda: collector_llm.judge_edu_batch(llm, pending),
            )
            for i, a in enumerate(pending):
                v = verdicts.get(i)
                if isinstance(v, dict):
                    a["is_edu"] = v.get("is_edu")
                    if v.get("school"):
                        a["school"] = v["school"]
                else:
                    a["is_edu"] = None
        except LLMError as e:
            if e.kind == "quota":
                raise
        except Exception:
            pass


def _is_edu(host: str, org: str) -> bool | None:
    h = host.lower()
    if ".edu.cn" in h or ".edu." in h or h.endswith(".edu"):
        return True
    if any(k in (org or "") for k in ("大学", "学院", "教育", "学校", "Education", "University", "College")):
        return True
    return None  # 不确定，交后续判断
