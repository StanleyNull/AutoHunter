"""Orchestrator：24x7 不停歇主循环，调度 worker/reviewer，崩溃恢复。

对应设计文档 §8 + §8.5。
- 单进程 asyncio；worker/reviewer 因 LLM+工具同步阻塞，用线程池跑。
- 状态全持久化到 SQLite；进程重启从 DB 重建。
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import subprocess
import threading
import traceback
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlparse, urlunparse

from sqlalchemy import select
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app import dedup
from app.agents import collector
from app.agents import intel as intel_lib
from app.agents import playbook_router
from app.agents import prefilter
from app.agents import site_collab
from app.agents import target_cluster
from app.agents.deepen import DEEPEN_CAP  # 单 target 深挖上限（人工+AI 合计，防死循环）
from app.agents.prompts import is_enterprise_src, should_escalate
from app.agents.reviewer import Reviewer
from app.agents.worker import Worker
from app.agent_runtime import (
    AGENT_EXECUTOR, COLLECTOR_IO_EXECUTOR, WORKER_MAX_CONCURRENCY,
    agent_semaphore, shutdown_agent_executor,
)
from app.db.models import CST, Finding, Killsweep, Review, Target, Task, TaskEvent
from app.db.session import SessionLocal
from app.events import bus
from app.llm.client import LLMClient
from app.settings_service import (
    llm_client_for_task,
    resolve_fofa_base_url,
    resolve_fofa_key,
    resolve_proxy_config,
    resolve_worker_prompt_version,
)
from app.schemas import Finding as FindingSchema
from app.schemas import Verdict

logger = logging.getLogger("autohunter.orchestrator")


def _now_iso() -> str:
    """当前时刻的 CST ISO 字符串（带 +08:00 偏移），供实时事件统一携带时区。"""
    return datetime.now(CST).isoformat()


# 等级排序：用于「扩大危害」显著性判定（升级是否真的更严重）。
_SEVERITY_RANK = {"低危": 1, "中危": 2, "高危": 3, "严重": 4}
# 升级后类型命中这些关键词，即使等级没跳变也算「定性质变」（顶格危害）。
_ESCALATE_TOPTIER_KEYWORDS = (
    "接管", "密码重置", "改密", "rce", "命令执行", "getshell", "get shell",
    "提权", "权限提升", "任意文件写", "任意文件上传", "任意用户", "全部",
)
# 影响面数量级阈值：impact_count 达到此值也算「影响面质变」。
_ESCALATE_IMPACT_THRESHOLD = int(os.environ.get("ESCALATE_IMPACT_THRESHOLD", "100"))


def _escalation_is_significant(orig_severity: str, res: dict) -> bool:
    """判定扩大危害结果是否『显著』——不显著则丢弃，不产出新 finding。

    满足任一即算显著：
      1. 等级实际跳变（新等级 > 原等级）；
      2. 定性质变（升级后类型/标题命中顶格危害关键词，如 接管/RCE）；
      3. 影响面数量级（impact_count ≥ 阈值）。
    """
    if not res or not res.get("escalated"):
        return False
    new_sev = res.get("severity") or ""
    if _SEVERITY_RANK.get(new_sev, 0) > _SEVERITY_RANK.get(orig_severity, 0):
        return True
    blob = f"{res.get('vuln_type','')} {res.get('title','')}".lower()
    if any(k in blob for k in _ESCALATE_TOPTIER_KEYWORDS):
        return True
    if int(res.get("impact_count", 0) or 0) >= _ESCALATE_IMPACT_THRESHOLD:
        return True
    return False


LOOP_INTERVAL = 3.0
LOW_WATERMARK = 5
MAX_RETRY = 1  # 单 target 最多再挖 1 次
# 单 target 超时兜底。
# WORKER_WALL_TIMEOUT 保持向后兼容：现在作为「无活动空闲超时」默认值。
# 活跃 worker 可继续运行到 WORKER_MAX_WALL_TIMEOUT，避免深挖正在推进时被 30min 一刀切。
WORKER_WALL_TIMEOUT = float(os.environ.get("WORKER_WALL_TIMEOUT", "1800"))
WORKER_IDLE_TIMEOUT = float(os.environ.get("WORKER_IDLE_TIMEOUT", str(WORKER_WALL_TIMEOUT)))
WORKER_MAX_WALL_TIMEOUT = float(os.environ.get("WORKER_MAX_WALL_TIMEOUT", str(max(WORKER_WALL_TIMEOUT * 4, WORKER_WALL_TIMEOUT))))
WORKER_WAIT_POLL_INTERVAL = float(os.environ.get("WORKER_WAIT_POLL_INTERVAL", "10"))
REVIEW_WALL_TIMEOUT = float(os.environ.get("REVIEW_WALL_TIMEOUT", "600"))
KILLSWEEP_WALL_TIMEOUT = float(os.environ.get("KILLSWEEP_WALL_TIMEOUT", "3600"))
# 扩大危害深挖刻意克制：轮数少、墙钟短，打不动就撤。
ESCALATE_WALL_TIMEOUT = float(os.environ.get("ESCALATE_WALL_TIMEOUT", "900"))
WORKER_CLEANUP_TIMEOUT = float(os.environ.get("WORKER_CLEANUP_TIMEOUT", "15"))
REVIEW_RETRY_BACKOFF = float(os.environ.get("REVIEW_RETRY_BACKOFF", "300"))
TARGET_HEARTBEAT_INTERVAL = float(os.environ.get("TARGET_HEARTBEAT_INTERVAL", "30"))
KILLSWEEP_DEDUP_SCAN_LIMIT = int(os.environ.get("KILLSWEEP_DEDUP_SCAN_LIMIT", "200"))
# 同一目标因临时 LLM 错误回队的最大次数（内存级，不耗 retry_count）。
# 超过则置 dead 收敛，避免模型持续抽风时目标无限回队空转。
MAX_TRANSIENT_LLM_REQUEUE = int(os.environ.get("MAX_TRANSIENT_LLM_REQUEUE", "5"))
# FOFA 账号无效（key 失效/过期/无 F 点/权限）连续次数达到此阈值 → 自动暂停任务，
# 避免持续空转刷无效请求。0 表示禁用该保护。
FOFA_AUTH_FAIL_PAUSE_THRESHOLD = int(os.environ.get("FOFA_AUTH_FAIL_PAUSE_THRESHOLD", "3"))
# 「无活跃协程的幽灵目标」回收短宽限（秒）。
# 这类目标在 DB 里是 scanning/assigned，但 _active_workers 里没有对应协程——
# 说明协程已不存在（进程重启残留 / 协程异常死亡 / 控制面清理后状态没归位）。
# 既然没有协程在跑，就不需要等 WORKER_WALL_TIMEOUT(30min) 那么久（那是给"协程
# 还在跑、只是心跳暂时停滞"留的，而那种情况已被 in _active_workers 拦截）。
# 这里只留一个覆盖「spawn→首次心跳」窗口 + 一轮慢操作余量的短宽限，幽灵目标
# 一旦超过就立即回队，杜绝"挤牙膏式 reclaim 刷屏一小时、目标长期虚占 scanning"。
STALE_NO_WORKER_GRACE = float(os.environ.get("STALE_NO_WORKER_GRACE", "150"))
# 派发前探活：queued 目标真正交给 worker 前再复查一次，避免 worker 时间浪费在死链上。
QUEUE_LIVENESS_TIMEOUT = float(os.environ.get("QUEUE_LIVENESS_TIMEOUT", "6"))
QUEUE_LIVENESS_CONCURRENCY = int(os.environ.get("QUEUE_LIVENESS_CONCURRENCY", "8"))
QUEUE_LIVENESS_CACHE_TTL = float(os.environ.get("QUEUE_LIVENESS_CACHE_TTL", "300"))
QUEUE_LOW_SUCCESS_SKIP = os.environ.get("QUEUE_LOW_SUCCESS_SKIP", "1").lower() not in {"0", "false", "no"}
QUEUE_LOW_SUCCESS_SCORE_THRESHOLD = float(os.environ.get("QUEUE_LOW_SUCCESS_SCORE_THRESHOLD", "-3.5"))
QUEUE_TRANSIENT_PREFILTER_COOLDOWN = float(os.environ.get("QUEUE_TRANSIENT_PREFILTER_COOLDOWN", "900"))
QUEUE_DISPATCH_CANDIDATE_LIMIT = max(30, int(os.environ.get("QUEUE_DISPATCH_CANDIDATE_LIMIT", "120")))
QUEUE_LIVENESS_BATCH_SIZE = max(1, int(os.environ.get("QUEUE_LIVENESS_BATCH_SIZE", "24")))

_LOW_SUCCESS_SCORE_MARKERS = (
    "pure_frontend", "pure_marketing_site", "static_assets", "data_display_platform",
    "public_generic_service", "纯前端", "静态", "官网", "门户", "营销展示",
)
_TRANSIENT_UNREACHABLE_REASONS = ("服务异常",)
_NO_VULN_RETRY_PRIORITY_MARKERS = (
    "killchain:",
    "暴露端点:",
)
_USABLE_LEAKED_CRED_STATUS = {
    "usable", "valid", "verified", "login_success", "success", "authenticated", "ok"
}
_WORKER_DEEPEN_NEGATIVE_MARKERS = (
    "无。", "无攻击面", "无有效攻击面", "无入口", "无有效入口", "无可深入", "无可利用",
    "凭证均无效", "泄露凭证均无效", "所有凭证", "均失败", "登录失败", "默认密码登录失败",
    "需要有效凭证", "需有效凭证", "需先获取", "后续若获得", "若未来获得", "未来获得",
    "社会工程", "联系厂家", "无法继续", "无法突破", "打不穿", "已证明不通", "已失效",
    "均需认证", "均需鉴权", "需认证", "需鉴权", "无下游", "无其他攻击面",
)
_WORKER_DEEPEN_ACTIONABLE_MARKERS = (
    "拿到", "已拿到", "登录成功", "可用凭据", "可用凭证", "有效凭据", "有效凭证",
    "token", "jwt", "session", "cookie", "secret", "ak/sk", "accesskey", "签名",
    "未授权", "越权", "idor", "接口", "api", "参数", "对象 id", "对象ID", "user_id",
    "tenant", "导出", "上传", "下载", "写操作", "重置", "验证码", "绕过",
)
_WORKER_DEEPEN_ACTION_MARKERS = (
    "调用", "调 ", "访问", "验证", "证明", "上传", "执行", "解析", "读取", "导出",
    "枚举", "伪造", "重放", "替换", "越权读取", "越权修改",
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _worker_timeout_reason(started_at: float, last_activity_at: float, now: float) -> str:
    """返回 worker 应被回收的原因；空字符串表示继续等。

    - idle：长时间没有任何 worker 事件，通常是 LLM/工具卡死；
    - max_wall：即使一直活跃也不能无限占用线程池。
    """
    if WORKER_MAX_WALL_TIMEOUT > 0 and now - started_at >= WORKER_MAX_WALL_TIMEOUT:
        return f"worker 达到最大墙钟上限(>{int(WORKER_MAX_WALL_TIMEOUT)}s)，强制回收"
    if WORKER_IDLE_TIMEOUT > 0 and now - last_activity_at >= WORKER_IDLE_TIMEOUT:
        return f"worker 空闲超时(>{int(WORKER_IDLE_TIMEOUT)}s 无新动作)，强制回收"
    return ""


def _has_usable_leaked_cred(creds: list | None) -> bool:
    """是否存在已验证可用的泄露凭据。

    搜集阶段的 leaked_creds 只是按质量打分筛选，不能代表真的可登录。
    no_vuln 后只有显式带成功/可用标记的凭据才值得自动回队深挖。
    """
    for cred in creds or []:
        if not isinstance(cred, dict):
            continue
        if any(cred.get(k) is True for k in (
            "usable", "valid", "verified", "login_success", "authenticated"
        )):
            return True
        status = str(cred.get("status") or cred.get("result") or cred.get("login_status") or "").strip().lower()
        if status in _USABLE_LEAKED_CRED_STATUS:
            return True
    return False


def _is_actionable_worker_deepen_lead(lead: str) -> bool:
    """worker finish(no_vuln) 时给出的 deepen_lead 是否真值得自动回火。

    deepen_lead 是模型自由文本，实际运行里会出现“无”“未来有凭证再测”这类空线索。
    这类不应再派 worker；只有已经拿到某个据点，且下一步能落到具体接口/参数/凭据/状态
    验证时，才值得自动深挖。
    """
    text = (lead or "").strip()
    if len(text) < 8:
        return False
    compact = text.lower()
    if any(marker.lower() in compact for marker in _WORKER_DEEPEN_NEGATIVE_MARKERS):
        return False
    has_actionable_marker = any(marker.lower() in compact for marker in _WORKER_DEEPEN_ACTIONABLE_MARKERS)
    has_concrete_endpoint = "/" in text or "?" in text or "=" in text
    has_concrete_action = any(marker.lower() in compact for marker in _WORKER_DEEPEN_ACTION_MARKERS)
    return has_actionable_marker and (has_concrete_endpoint or has_concrete_action)


def _consume_task_exception(task: asyncio.Future) -> None:
    """读取后台 future 异常，避免未观测异常和引用链长期滞留。"""
    try:
        task.exception()
    except (asyncio.CancelledError, Exception):
        pass


def _log_bg_task_exc(task: asyncio.Future, label: str) -> None:
    """后台 fire-and-forget 任务的异常回调：记录留痕而非静默吞掉。
    专治「实时落库/推送悄悄失败 → 真洞丢失且无从追查」。"""
    try:
        exc = task.exception()
    except asyncio.CancelledError:
        return
    except Exception:
        return
    if exc is not None:
        logger.error("background task %s failed: %r", label, exc,
                     exc_info=(type(exc), exc, exc.__traceback__))


def _with_scheme(url_or_host: str) -> str:
    s = (url_or_host or "").strip()
    if not s:
        return ""
    return s if "://" in s else f"http://{s}"


def _swap_url_scheme(url: str) -> str:
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.netloc:
            return ""
        alt = "https" if p.scheme == "http" else "http"
        return urlunparse((alt, p.netloc, p.path or "/", "", p.query, ""))
    except Exception:
        return ""


def _probe_urls(url: str, host: str) -> list[str]:
    """生成派发前探活 URL：优先原 URL，再试同 host 的另一种 http/https。"""
    primary = _with_scheme(url or host)
    urls: list[str] = []
    for candidate in (primary, _swap_url_scheme(primary), _with_scheme(host)):
        if candidate and candidate not in urls:
            urls.append(candidate)
    return urls


def _probe_via_ssh_proxy(url: str, proxy_config, timeout: float) -> dict:
    """通过 SSH 代理探活，防止 WAF 封本地 IP 导致误判不可达。

    本机 IP 被目标 WAF 封禁时，本地 HTTP 请求会被丢包/重置/超时，
    导致 _probe_target_liveness 误判目标不可达。此时通过 SSH 代理
    发一个干净的 curl 请求交叉验证：代理能通说明目标本身存活，
    本地不通是 IP 层面的问题。
    """
    servers = proxy_config.server_list
    if not servers:
        return {"alive": False, "reason": "无可用代理服务器"}

    srv = servers[0]
    key_path = proxy_config.ssh_key_path
    # 解析 user@host:port
    if ":" in srv.split("@")[-1]:
        user_host, port = srv.rsplit(":", 1)
    else:
        user_host, port = srv, "22"

    curl_cmd = (
        f"curl -s -o /dev/null -w '%{{http_code}}' -m {int(timeout)} -k '{url}'"
    )
    ssh_cmd = [
        "ssh", "-i", key_path,
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-p", port, user_host,
        curl_cmd,
    ]

    try:
        result = subprocess.run(
            ssh_cmd, capture_output=True, text=True,
            timeout=timeout + 10,  # SSH 连接开销
        )
        status_code = (result.stdout or "").strip().strip("'")
        if status_code.isdigit():
            code = int(status_code)
            if 0 < code < 500:
                return {"alive": True, "url": url, "status": code, "skip": False}
            if code >= 500:
                return {
                    "alive": True, "url": url, "status": code,
                    "skip": True, "reason": f"服务异常({code})",
                }
        # curl 无输出 = 连接失败
        err = (result.stderr or "")[:200]
        return {"alive": False, "reason": f"代理探活失败：{err}"}
    except subprocess.TimeoutExpired:
        return {"alive": False, "reason": "代理探活超时"}
    except Exception as exc:
        return {"alive": False, "reason": f"代理探活异常：{str(exc)[:180]}"}


def _probe_target_liveness(url: str, host: str, timeout: float, proxy_config=None) -> dict:
    """同步派发前预筛，给 run_in_executor 调用。

    - 任意可访问 HTTP 响应都算 alive；
    - prefilter 判定的 CDN/静态/5xx 等返回 skip=True，不交给 worker 消耗 token；
    - http/https 都不通才 alive=False；
    - 本地探活失败时，若配置了 SSH 代理，通过代理交叉验证防止 WAF 封 IP 误判。
    """
    urls = _probe_urls(url, host)
    skipped: list[dict] = []
    for probe_url in urls:
        skip, reason, info = prefilter.should_skip_ex(host, probe_url)
        if not skip:
            return {
                "alive": True,
                "url": probe_url,
                "status": info.get("status", 0),
                "skip": False,
            }
        skipped.append({"reason": reason, "url": probe_url, "status": info.get("status", 0)})

    for item in skipped:
        reason = item.get("reason") or ""
        if reason and reason != "死链/连接超时/无响应":
            return {
                "alive": True,
                "url": item.get("url") or (urls[0] if urls else url or host),
                "status": item.get("status", 0),
                "skip": True,
                "reason": reason,
            }

    # 所有本地探活 URL 都失败了，尝试通过 SSH 代理交叉验证
    if proxy_config and proxy_config.available:
        probe_url = urls[0] if urls else (url or host)
        proxy_result = _probe_via_ssh_proxy(probe_url, proxy_config, timeout)
        if proxy_result.get("alive"):
            proxy_result["via_proxy"] = True
            return proxy_result

    return {
        "alive": False,
        "url": urls[0] if urls else (url or host),
        "status": 0,
        "skip": False,
        "reason": "派发前探活失败：死链/连接超时/无响应",
    }


def _llm_for_task(task: Task) -> LLMClient:
    return llm_client_for_task(task)


class TaskRunner:
    """单个任务的不停歇循环。"""

    def __init__(self, task_id: str):
        self.task_id = task_id
        self._stop = asyncio.Event()
        self._active_workers: dict[str, asyncio.Task] = {}
        self._worker_cancel_events: dict[str, threading.Event] = {}
        self._cancelled_targets: set[str] = set()
        self._review_inflight: set[str] = set()
        self._review_tasks: dict[str, asyncio.Task] = {}
        self._review_backoff: dict[str, float] = {}
        self._killsweep_inflight: set[str] = set()  # 正在做通杀分析的 finding_id
        self._killsweep_tasks: dict[str, asyncio.Task] = {}
        self._killsweep_cancel_events: dict[str, threading.Event] = {}
        self._escalation_inflight: set[str] = set()  # 正在做扩大危害深挖的 finding_id
        self._escalation_tasks: dict[str, asyncio.Task] = {}
        self._escalation_cancel_events: dict[str, threading.Event] = {}
        # 实时看板：每个在跑 worker 的活态 {target_id: {host, url, round, action, started_at, findings}}
        self._live: dict[str, dict] = {}
        self._worker_last_activity: dict[str, float] = {}
        # 临时 LLM 错误回队计数（内存级，不耗 retry_count）：防止模型持续抽风时目标无限回队。
        self._transient_llm_requeue: dict[str, int] = {}
        # 企业模式缓存：企业目标多为用户指定的具体资产，不做同款簇冷却/限流
        # （否则 pre-paycenter/test-gateway 等不同子系统会因"同簇打不穿3个"被误跳）。
        # 在 _tick 拿到 task 时刷新。
        self._is_enterprise: bool = False
        # 派发前探活缓存：刚确认存活的 queued 目标短时间内不重复发包。
        self._queue_liveness_ok_until: dict[str, float] = {}
        # 5xx 等临时预筛失败不进终态 skipped，只做短冷却，稍后再探。
        self._queue_prefilter_retry_after: dict[str, float] = {}

    def live_workers(self) -> list[dict]:
        return list(self._live.values())

    def diagnostic_snapshot(self) -> dict:
        return {
            "task_id": self.task_id,
            "stopped": self._stop.is_set(),
            "active_workers": len(self._active_workers),
            "worker_cancel_events": len(self._worker_cancel_events),
            "review_inflight": len(self._review_inflight),
            "review_tasks": len(self._review_tasks),
            "killsweep_inflight": len(self._killsweep_inflight),
            "killsweep_tasks": len(self._killsweep_tasks),
            "escalation_inflight": len(self._escalation_inflight),
            "escalation_tasks": len(self._escalation_tasks),
            "live_workers": [
                {
                    "target_id": item.get("target_id"),
                    "host": item.get("host"),
                    "url": item.get("url"),
                    "round": item.get("round"),
                    "action": item.get("action"),
                    "mode": item.get("mode"),
                    "started_at": item.get("started_at"),
                    "last_activity_at": item.get("last_activity_at"),
                    "findings": item.get("findings"),
                }
                for item in list(self._live.values())[:10]
            ],
        }

    async def _log(self, session: AsyncSession, agent: str, kind: str, message: str, level: str = "info", **payload):
        session.add(TaskEvent(task_id=self.task_id, agent=agent, kind=kind, level=level,
                              message=message, payload=payload))
        await session.commit()
        # ts 统一用带 UTC 标识的 ISO 字符串（…+00:00），前端 new Date 才能正确转本地时区。
        await bus.publish(self.task_id, {"agent": agent, "kind": kind, "level": level,
                                         "message": message, "ts": _now_iso(), **payload})

    async def recover(self, session: AsyncSession) -> None:
        """重启恢复：assigned/scanning → queued；不动已有 Finding/Review。"""
        rows = (await session.execute(
            select(Target).where(
                Target.task_id == self.task_id, Target.status.in_(["assigned", "scanning"])
            )
        )).scalars().all()
        recovered = 0
        killed = 0
        for tgt in rows:
            if self._queue_or_dead_after_attempt(tgt, "进程重启恢复：运行中目标回队重试"):
                recovered += 1
            else:
                killed += 1
        await session.commit()
        await self._log(
            session, "orchestrator", "recover",
            f"重启恢复：{recovered} 个进行中目标回退队列，{killed} 个超过重试上限转入硬骨头库",
            recovered=recovered, killed=killed,
        )

        # 重测状态恢复：worker 可能已死，重置 testing → idle
        task = await session.get(Task, self.task_id)
        if task and task.retest_state:
            state = task.retest_state
            if state.get("current_step") == "testing":
                state["current_step"] = "idle"
                state["current_id"] = None
                await self._log(
                    session, "orchestrator", "retest_recover",
                    "重测状态恢复：worker 已死，重置为 idle 等待重新取目标",
                    level="info",
                )
            await session.commit()

    async def run_forever(self) -> None:
        async with SessionLocal() as session:
            await self.recover(session)
        while not self._stop.is_set():
            try:
                await self._tick()
            except Exception as exc:
                tb = traceback.format_exc()
                # 完整 traceback 只进后端日志（服务端可查），不写事件流，避免把 SQL
                # 参数里的 leaked_creds 明文暴露到前端看板。
                logger.warning("TaskRunner[%s] tick error:\n%s", self.task_id, tb)
                summary = self._summarize_exc(exc)
                async with SessionLocal() as s:
                    if self._is_quota_error(tb):
                        await self._stop_task_for_quota(s, tb)
                        await self._log(s, "orchestrator", "quota_stop",
                                        "LLM/API 额度不足，任务已自动停止", level="error")
                    else:
                        # 只记可读的异常摘要（类名+消息），不糊整条 SQL/参数。
                        await self._log(s, "orchestrator", "error",
                                        f"主循环异常: {summary}", level="error")
            await asyncio.sleep(LOOP_INTERVAL)

    async def _tick(self) -> None:
        async with SessionLocal() as session:
            task = await session.get(Task, self.task_id)
            if not task:
                return
            if task.status == "stopped":
                # 停止：清除重测状态（完全重置）
                if task.retest_state:
                    task.retest_state = None
                    await session.commit()
                return
            if task.status == "paused":
                # 暂停：保留 retest_state，恢复后从断点继续休眠/重测
                # 仅重置 testing → idle（worker 已被 pause 取消，恢复后重新取目标）
                if task.retest_state and task.retest_state.get("current_step") == "testing":
                    task.retest_state["current_step"] = "idle"
                    task.retest_state["current_id"] = None
                    await self._retest_save(session, task)
                    await self._log(
                        session, "orchestrator", "retest_paused",
                        "任务暂停，重测进度已保留（恢复后从断点继续）",
                        level="info",
                    )
                return
            self._is_enterprise = is_enterprise_src(task.src_type)

            # 1. 队列水位低 → 补目标
            async def collector_progress(phase: str, text: str, payload: dict) -> None:
                await self._log(
                    session,
                    "collector",
                    "collector_phase",
                    text,
                    phase=phase,
                    **payload,
                )

            added = await collector.refill(session, task, LOW_WATERMARK, progress_cb=collector_progress)

            # FOFA 账号连续无效达阈值 → 自动暂停任务，不再空转刷无效请求。
            fofa_fail = int((task.fofa_config or {}).get("fofa_auth_fail_count", 0))
            if FOFA_AUTH_FAIL_PAUSE_THRESHOLD and fofa_fail >= FOFA_AUTH_FAIL_PAUSE_THRESHOLD:
                last_err = (task.fofa_config or {}).get("last_fofa_error", "")
                reason = f"FOFA 账号连续 {fofa_fail} 次无效，已自动暂停任务，请检查/更换 FOFA key 后重新启动"
                task.status = "paused"
                await session.commit()
                await self._log(session, "orchestrator", "auto_paused", f"{reason}（最后错误：{last_err}）",
                                fofa_auth_fail=fofa_fail, fofa_error=last_err)
                await self.pause(reason)
                return

            # FOFA 每日额度耗尽，连续 12 次（约 12 小时）未恢复 → 自动暂停任务。
            # 适合挂机过夜：额度恢复则自动继续搜集；12 小时都没恢复才停。
            if (task.fofa_config or {}).get("daily_limit_exhausted"):
                dl_count = int((task.fofa_config or {}).get("daily_limit_count", 0))
                last_err = (task.fofa_config or {}).get("last_fofa_error", "")
                reason = f"FOFA 每日额度耗尽，连续 {dl_count} 次（约 {dl_count} 小时）未恢复，已自动暂停任务"
                task.status = "paused"
                await session.commit()
                await self._log(session, "orchestrator", "auto_paused", f"{reason}（最后错误：{last_err}）",
                                daily_limit_count=dl_count, fofa_error=last_err)
                await self.pause(reason)
                return

            if added:
                fc = task.fofa_config or {}
                cur_q = fc.get("current_query", "")
                skipped_low = fc.get("last_skipped_low", 0)
                skipped_cluster = fc.get("last_skipped_cluster", 0)
                skipped_filter = fc.get("last_skipped_filter", 0)
                msg = f"新增 {added} 个目标入队" + (f"（语法: {cur_q}）" if cur_q else "")
                if skipped_low:
                    msg += f"；{skipped_low} 个低分垃圾资产已跳过"
                if skipped_cluster:
                    msg += f"；{skipped_cluster} 个同款冷却/限流资产已跳过"
                if skipped_filter:
                    msg += f"；{skipped_filter} 个低出货概率资产已过滤"
                await self._log(session, "collector", "refill", msg, added=added,
                                query=cur_q, skipped_low=skipped_low,
                                skipped_cluster=skipped_cluster, skipped_filter=skipped_filter)

            # 2. 派发前先回收：清理已完成 task + 抢救心跳超时的僵尸目标
            self._reap_workers()
            await self._reclaim_stale(session)
            # task.concurrency 是用户在 UI 配的期望并发；worker 实际并发还受全局信号量
            # WORKER_MAX_CONCURRENCY 封顶。这里按两者取小来决定本轮 spawn 多少，避免多起
            # 的协程只是白白阻塞在 worker_sem.acquire()（表现为"配了 N 并发但没那么多在跑"）。
            effective_cap = min(task.concurrency, WORKER_MAX_CONCURRENCY)
            free = effective_cap - len(self._active_workers)
            for _ in range(max(0, free)):
                target = await self._pop_queued(session)
                if not target:
                    break
                self._spawn_worker(task, target)

            # 3. 派发审核（pending_review → reviewed）
            await self._dispatch_reviews(session, task)

            # 4. idle 标记
            queued = await self._count(session, "queued")
            # 除了 queued 和内存里的活跃 worker，还要看 DB 里有没有 assigned/scanning 的
            # 在途目标：幽灵 scanning(协程已死但状态没回收)期间不能误判 idle，否则前端显示
            # 空闲、实际还有目标虚挂，直到 reclaim(最多 ~150s)才回收——保持 running 更真实。
            inflight = await self._count_inflight(session)
            busy = bool(self._active_workers) or inflight > 0

            # 5. 失败目标自动重测：首轮目标全部完成且无活跃 worker 时，启动重测生命周期
            if queued == 0 and not busy:
                retest_active = await self._retest_tick(session, task)
                if retest_active:
                    queued = 1  # 保持 running，不进 idle

            if queued == 0 and not busy and task.status == "running":
                if task.status != "idle":
                    task.status = "idle"
                    await session.commit()
            elif task.status == "idle" and (queued or busy):
                task.status = "running"
                await session.commit()

    async def _count(self, session: AsyncSession, status: str) -> int:
        from sqlalchemy import func
        return (await session.execute(
            select(func.count()).select_from(Target).where(
                Target.task_id == self.task_id, Target.status == status)
        )).scalar() or 0

    async def _count_inflight(self, session: AsyncSession) -> int:
        """在途目标数：assigned(已 pop 待起协程) + scanning(挖掘中/幽灵未回收)。
        用于 idle 判定，避免有目标虚挂时把任务误标为空闲。"""
        from sqlalchemy import func
        return (await session.execute(
            select(func.count()).select_from(Target).where(
                Target.task_id == self.task_id,
                Target.status.in_(("assigned", "scanning")))
        )).scalar() or 0

    # ===== 失败目标自动重测生命周期 =====
    # 匹配失败 dead_reason 的关键词（与 reset-failed API 保持一致）
    _RETEST_DEAD_PATTERNS = ("探活失败", "死链", "连接超时", "系统自动收敛", "连续")
    # 有代理模式递增休眠时长（小时）
    _RETEST_SLEEP_HOURS = [4, 8, 24]

    @staticmethod
    async def _retest_save(session: AsyncSession, task: Task) -> None:
        """标记 retest_state 为脏并提交。SQLAlchemy 不自动检测 JSON 字段的原地修改。"""
        flag_modified(task, "retest_state")
        await session.commit()

    async def _retest_tick(self, session: AsyncSession, task: Task) -> int:
        """重测生命周期入口。返回 >0 表示重测进行中（不进 idle），0 表示无需重测。"""
        state = task.retest_state

        # 无状态 → 尝试启动
        if not state:
            return await self._retest_start(session, task)

        phase = state.get("phase", "")

        # 已完成 → 清理
        if phase == "done":
            task.retest_state = None
            await self._retest_save(session, task)
            return 0

        # 休眠中 → 检查唤醒 + 30 分钟日志
        if phase in ("phase3_sleep", "noproxy_sleep"):
            return await self._retest_sleep(session, task, state)

        # 活跃阶段 → 执行一步
        if phase in ("phase1", "phase2", "noproxy_round"):
            return await self._retest_step(session, task, state)

        return 0

    async def _retest_start(self, session: AsyncSession, task: Task) -> int:
        """收集失败目标，初始化重测状态。"""
        from sqlalchemy import func

        # 查询匹配失败模式的 dead 目标
        dead_targets = (await session.execute(
            select(Target).where(
                Target.task_id == self.task_id,
                Target.status == "dead",
            )
        )).scalars().all()

        eligible = []
        for tgt in dead_targets:
            reason = (tgt.dead_reason or "")
            if not any(p in reason for p in self._RETEST_DEAD_PATTERNS):
                continue
            if (tgt.deepen_count or 0) >= DEEPEN_CAP:
                continue
            eligible.append(tgt.id)

        if not eligible:
            return 0

        proxy_available = resolve_proxy_config().available
        mode = "proxy" if proxy_available else "noproxy"
        phase = "phase1" if proxy_available else "noproxy_round"

        task.retest_state = {
            "mode": mode,
            "phase": phase,
            "remaining_ids": eligible,
            "total": len(eligible),
            "unreachable_ids": [],  # noproxy 模式专用
            "current_id": None,
            "current_step": "idle",
            "sleep_until": None,
            "sleep_round": 0,
            "last_log_at": None,
        }
        await self._log(
            session, "orchestrator", "retest_start",
            f"开始重测 {len(eligible)} 个失败目标（{'有' if proxy_available else '无'}代理模式）",
            level="info", phase=phase, target_count=len(eligible),
        )
        await self._retest_save(session, task)
        return 1

    async def _retest_step(self, session: AsyncSession, task: Task, state: dict) -> int:
        """串行探活+测试的单步执行。每次 tick 调用一次。"""
        step = state.get("current_step", "idle")
        current_id = state.get("current_id")

        # --- idle: 取下一个目标 ---
        if step == "idle":
            if not state.get("remaining_ids"):
                # 本阶段全部处理完 → 阶段转换
                return await self._retest_phase_transition(session, task, state)

            current_id = state["remaining_ids"][0]
            state["current_id"] = current_id
            phase = state.get("phase")

            # Phase 2: 直接派 worker（ip_banned 目标已确认需要代理测试）
            if phase == "phase2":
                tgt = await session.get(Target, current_id)
                if not tgt or tgt.status != "ip_banned":
                    state["remaining_ids"].remove(current_id)
                    state["current_id"] = None
                    await self._retest_save(session, task)
                    return 1
                tgt.status = "queued"
                tgt.verdict = ""
                tgt.retry_count = 0
                tgt.deepen_context = {
                    "directive": "IP 封禁复测：你的 IP 被目标 WAF 封禁，必须全程通过 SSH 代理发送请求。",
                    "ip_ban_retest": True,
                    "source": "ip_ban_retest",
                }
                tgt.last_error = "IP 封禁复测：切换代理模式"
                tgt.dead_reason = ""
                await self._retest_save(session, task)
                self._spawn_worker(task, tgt)
                state["current_step"] = "testing"
                await self._retest_save(session, task)
                return 1

            # Phase 1 / noproxy_round: 需要探活
            # 暂停恢复后，目标可能已被正常调度处理（状态不再是 dead），跳过
            tgt = await session.get(Target, current_id)
            if not tgt or tgt.status != "dead":
                state["remaining_ids"].remove(current_id)
                state["current_id"] = None
                await self._retest_save(session, task)
                return 1
            state["current_step"] = "probing"
            await self._retest_save(session, task)
            return 1

        # --- probing: 探活 ---
        if step == "probing":
            tgt = await session.get(Target, current_id) if current_id else None
            if not tgt:
                if current_id and current_id in state.get("remaining_ids", []):
                    state["remaining_ids"].remove(current_id)
                state["current_id"] = None
                state["current_step"] = "idle"
                await self._retest_save(session, task)
                return 1

            loop = asyncio.get_running_loop()
            proxy_cfg = resolve_proxy_config()
            phase = state.get("phase")

            # 本机探活
            probe_result = await loop.run_in_executor(
                COLLECTOR_IO_EXECUTOR,
                lambda: self._retest_probe_local(tgt.url, tgt.host),
            )

            if probe_result.get("alive"):
                # 本机可达 → 入队测试
                tgt.status = "queued"
                tgt.verdict = ""
                tgt.assigned_worker = ""
                tgt.heartbeat_at = None
                tgt.dead_reason = ""
                tgt.last_error = ""
                tgt.retry_count = 0
                tgt.ip_ban_confirmed = False
                tgt.deepen_context = None
                tgt.priority_score = (tgt.priority_score or 0) + 50.0
                tgt.priority_reason = "[重测] 探活成功，重新入队测试"
                await self._retest_save(session, task)
                self._spawn_worker(task, tgt)
                state["current_step"] = "testing"
                await self._retest_save(session, task)
                return 1

            # 本机不可达
            if phase == "noproxy_round":
                # 无代理模式：保留到 unreachable_ids，下轮再试
                state.setdefault("unreachable_ids", []).append(current_id)
                state["remaining_ids"].remove(current_id)
                state["current_id"] = None
                state["current_step"] = "idle"
                await self._retest_save(session, task)
                return 1

            # 有代理模式：依次尝试探活服务器 → 测试服务器
            ssh_key_path = proxy_cfg.ssh_key_path
            probe_urls = _probe_urls(tgt.url, tgt.host)
            probe_url = probe_urls[0] if probe_urls else (tgt.url or tgt.host)

            # 先探活服务器，再测试服务器
            all_servers = list(proxy_cfg.probe_server_list) + list(proxy_cfg.server_list)
            server_reachable = False
            for srv in all_servers:
                srv_result = await loop.run_in_executor(
                    COLLECTOR_IO_EXECUTOR,
                    lambda s=srv: self._retest_probe_via_server(probe_url, s, ssh_key_path),
                )
                if srv_result.get("alive"):
                    server_reachable = True
                    break

            if server_reachable:
                # 服务器可达 → 标记 ip_banned
                tgt.status = "ip_banned"
                tgt.ip_ban_confirmed = True
                tgt.assigned_worker = ""
                tgt.heartbeat_at = None
                tgt.dead_reason = ""
                tgt.last_error = "重测探活：本机不可达但服务器可达，标记 IP 封禁"
                await self._log(
                    session, "orchestrator", "retest_ip_banned",
                    f"重测探活：{tgt.host} 本机不可达但服务器可达，标记 IP 封禁",
                    level="warn", target_id=current_id,
                )
            else:
                # 全部不可达 → 标记 dead
                tgt.status = "dead"
                tgt.assigned_worker = ""
                tgt.heartbeat_at = None
                tgt.dead_reason = "本机和所有服务器均探活失败，确定服务不可达"
                await self._log(
                    session, "orchestrator", "retest_dead",
                    f"重测探活：{tgt.host} 本机和所有服务器均不可达，标记 dead",
                    level="warn", target_id=current_id,
                )

            if current_id in state.get("remaining_ids", []):
                state["remaining_ids"].remove(current_id)
            state["current_id"] = None
            state["current_step"] = "idle"
            await self._retest_save(session, task)
            return 1

        # --- testing: 等待 worker 完成 ---
        if step == "testing":
            if current_id and current_id in self._active_workers:
                return 1  # worker 仍在运行，等下次 tick
            # worker 已完成
            state["current_step"] = "idle"
            state["current_id"] = None
            # 从 remaining 移除（已处理完）
            if current_id and current_id in state.get("remaining_ids", []):
                state["remaining_ids"].remove(current_id)
            await self._retest_save(session, task)
            return 1

        return 1

    async def _retest_phase_transition(self, session: AsyncSession, task: Task, state: dict) -> int:
        """本阶段全部目标处理完后的阶段转换。"""
        mode = state.get("mode")
        phase = state.get("phase")

        if mode == "noproxy":
            # 无代理模式：检查不可达目标
            unreachable = state.get("unreachable_ids", [])
            if not unreachable:
                # 全部测完，无残留
                state["phase"] = "done"
                await self._log(session, "orchestrator", "retest_done",
                                "无代理重测完成，所有失败目标已处理",
                                level="info")
                await self._retest_save(session, task)
                return 1

            # 有不可达目标 → 检查轮次
            sleep_round = state.get("sleep_round", 0)
            if sleep_round >= 2:
                # 已完成 3 轮（round 0, 1, 2）→ 标记 dead
                for tid in unreachable:
                    tgt = await session.get(Target, tid)
                    if tgt:
                        tgt.status = "dead"
                        tgt.assigned_worker = ""
                        tgt.heartbeat_at = None
                        tgt.dead_reason = "重测3轮仍不可达，确定服务不可达"
                state["phase"] = "done"
                await self._log(session, "orchestrator", "retest_done",
                                f"无代理重测3轮结束，{len(unreachable)} 个目标标记 dead",
                                level="warn", dead_count=len(unreachable))
                await self._retest_save(session, task)
                return 1

            # 进入休眠
            wake_at = datetime.now(CST) + timedelta(hours=4)
            state["phase"] = "noproxy_sleep"
            state["sleep_until"] = wake_at.isoformat()
            state["last_log_at"] = None
            await self._log(session, "orchestrator", "retest_sleep",
                            f"第{sleep_round + 1}轮重测完成，{len(unreachable)} 个不可达目标，"
                            f"休眠4h，预计第{sleep_round + 2}轮将在 {self._retest_fmt(wake_at)} 开始",
                            level="info", sleep_until=state["sleep_until"])
            await self._retest_save(session, task)
            return 1

        # 有代理模式
        if phase == "phase1":
            # Phase 1 完成 → 查询所有 ip_banned 目标（包括 Phase 1 中新产生的）
            banned = (await session.execute(
                select(Target).where(
                    Target.task_id == self.task_id,
                    Target.status == "ip_banned",
                )
            )).scalars().all()

            if banned:
                state["phase"] = "phase2"
                state["remaining_ids"] = [t.id for t in banned]
                state["current_id"] = None
                state["current_step"] = "idle"
                await self._log(session, "orchestrator", "retest_phase2",
                                f"Phase 1 完成，{len(banned)} 个 IP 封禁目标进入 Phase 2 服务器测试",
                                level="info")
                await self._retest_save(session, task)
                return 1
            else:
                state["phase"] = "done"
                await self._log(session, "orchestrator", "retest_done",
                                "有代理重测完成，无 IP 封禁目标",
                                level="info")
                await self._retest_save(session, task)
                return 1

        if phase == "phase2":
            # Phase 2 完成 → 查询仍为 ip_banned 的目标
            still_banned = (await session.execute(
                select(Target).where(
                    Target.task_id == self.task_id,
                    Target.status == "ip_banned",
                )
            )).scalars().all()

            if not still_banned:
                state["phase"] = "done"
                await self._log(session, "orchestrator", "retest_done",
                                "有代理重测完成，所有 IP 封禁目标已测完",
                                level="info")
                await self._retest_save(session, task)
                return 1

            # 有残留 ip_banned → 用探活服务器交叉验证
            proxy_cfg = resolve_proxy_config()
            probe_servers = proxy_cfg.probe_server_list or proxy_cfg.server_list
            ssh_key_path = proxy_cfg.ssh_key_path

            if probe_servers:
                loop = asyncio.get_running_loop()
                first_tgt = still_banned[0]
                probe_urls = _probe_urls(first_tgt.url, first_tgt.host)
                probe_url = probe_urls[0] if probe_urls else (first_tgt.url or first_tgt.host)

                probe_reachable = False
                for srv in probe_servers:
                    srv_result = await loop.run_in_executor(
                        COLLECTOR_IO_EXECUTOR,
                        lambda s=srv: self._retest_probe_via_server(probe_url, s, ssh_key_path),
                    )
                    if srv_result.get("alive"):
                        probe_reachable = True
                        break

                if not probe_reachable:
                    # 探活服务器也不可达 → 全部标记 dead
                    for tgt in still_banned:
                        tgt.status = "dead"
                        tgt.assigned_worker = ""
                        tgt.heartbeat_at = None
                        tgt.dead_reason = "本机和所有服务器均探活失败，确定服务不可达"
                    state["phase"] = "done"
                    await self._log(session, "orchestrator", "retest_done",
                                    f"Phase 2 后探活服务器也不可达，{len(still_banned)} 个目标标记 dead",
                                    level="warn", dead_count=len(still_banned))
                    await self._retest_save(session, task)
                    return 1

            # 探活服务器可达 → 进入 Phase 3 休眠
            sleep_round = state.get("sleep_round", 0)
            if sleep_round >= len(self._RETEST_SLEEP_HOURS):
                # 已超过最大休眠轮次 → 标记 dead
                for tgt in still_banned:
                    tgt.status = "dead"
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.dead_reason = "重测休眠耗尽（4h→8h→24h），确定服务不可达"
                state["phase"] = "done"
                await self._log(session, "orchestrator", "retest_done",
                                f"休眠轮次耗尽，{len(still_banned)} 个目标标记 dead",
                                level="warn", dead_count=len(still_banned))
                await self._retest_save(session, task)
                return 1

            sleep_hours = self._RETEST_SLEEP_HOURS[sleep_round]
            wake_at = datetime.now(CST) + timedelta(hours=sleep_hours)
            state["phase"] = "phase3_sleep"
            state["sleep_until"] = wake_at.isoformat()
            state["last_log_at"] = None
            state["remaining_ids"] = [t.id for t in still_banned]
            await self._log(session, "orchestrator", "retest_sleep",
                            f"Phase 2 后 {len(still_banned)} 个目标仍 IP 封禁，"
                            f"进入休眠 {sleep_hours}h，预计 {self._retest_fmt(wake_at)} 重新探活",
                            level="info", sleep_until=state["sleep_until"])
            await self._retest_save(session, task)
            return 1

        state["phase"] = "done"
        await self._retest_save(session, task)
        return 1

    async def _retest_sleep(self, session: AsyncSession, task: Task, state: dict) -> int:
        """休眠检查 + 30 分钟周期日志。"""
        sleep_until_str = state.get("sleep_until")
        if not sleep_until_str:
            state["phase"] = "done"
            await self._retest_save(session, task)
            return 1

        sleep_until = datetime.fromisoformat(sleep_until_str)
        now = datetime.now(CST)

        if now < sleep_until:
            # 还在休眠 → 检查 30 分钟日志
            last_log = state.get("last_log_at")
            if last_log:
                last_log_dt = datetime.fromisoformat(last_log)
            else:
                last_log_dt = None

            if not last_log_dt or (now - last_log_dt).total_seconds() >= 1800:
                mode = state.get("mode")
                sleep_round = state.get("sleep_round", 0)
                if mode == "noproxy":
                    msg = (f"第{sleep_round + 1}轮重测休眠中，"
                           f"预计第{sleep_round + 2}轮将在 {self._retest_fmt(sleep_until)} 开始")
                else:
                    msg = (f"IP封禁队列休眠中，预计启动时间 {self._retest_fmt(sleep_until)}")
                await self._log(session, "orchestrator", "retest_sleep_log", msg, level="info")
                state["last_log_at"] = now.isoformat()
                await self._retest_save(session, task)
            return 1

        # 休眠时间到 → 唤醒
        mode = state.get("mode")
        sleep_round = state.get("sleep_round", 0)

        if mode == "noproxy":
            # 无代理模式唤醒 → 重新一轮
            unreachable = state.get("unreachable_ids", [])
            state["phase"] = "noproxy_round"
            state["remaining_ids"] = list(unreachable)
            state["unreachable_ids"] = []
            state["current_id"] = None
            state["current_step"] = "idle"
            state["sleep_round"] = sleep_round + 1
            state["sleep_until"] = None
            await self._log(session, "orchestrator", "retest_wake",
                            f"休眠结束，开始第{sleep_round + 2}轮重测，{len(state['remaining_ids'])} 个目标",
                            level="info")
            await self._retest_save(session, task)
            return 1

        # 有代理模式唤醒 → 从 Phase 1 重新开始
        remaining = state.get("remaining_ids", [])
        state["phase"] = "phase1"
        state["current_id"] = None
        state["current_step"] = "idle"
        state["sleep_round"] = sleep_round + 1
        state["sleep_until"] = None
        await self._log(session, "orchestrator", "retest_wake",
                        f"休眠结束，重新开始 Phase 1 探活，{len(remaining)} 个目标",
                        level="info")
        await self._retest_save(session, task)
        return 1

    @staticmethod
    def _retest_probe_local(url: str, host: str, timeout: float = 6.0) -> dict:
        """本机 HTTP 探活（不经过代理）。"""
        urls = _probe_urls(url, host)
        for probe_url in urls:
            skip, reason, info = prefilter.should_skip_ex(host, probe_url)
            if not skip:
                return {"alive": True, "url": probe_url, "status": info.get("status", 0)}
            # 非死链的 skip（CDN/5xx/静态）说明目标存活
            if reason and reason != "死链/连接超时/无响应":
                return {"alive": True, "url": probe_url, "status": info.get("status", 0)}
        return {"alive": False, "url": urls[0] if urls else (url or host)}

    @staticmethod
    def _retest_probe_via_server(url: str, server: str, ssh_key_path: str, timeout: float = 8.0) -> dict:
        """通过指定 SSH 服务器探活。"""
        if ":" in server.split("@")[-1]:
            user_host, port = server.rsplit(":", 1)
        else:
            user_host, port = server, "22"

        curl_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' -m {int(timeout)} -k '{url}'"
        ssh_cmd = [
            "ssh", "-i", ssh_key_path,
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            "-p", port, user_host,
            curl_cmd,
        ]
        try:
            result = subprocess.run(
                ssh_cmd, capture_output=True, text=True,
                timeout=timeout + 10,
            )
            status_code = (result.stdout or "").strip().strip("'")
            if status_code.isdigit():
                code = int(status_code)
                if 0 < code < 500:
                    return {"alive": True, "url": url, "status": code}
            return {"alive": False}
        except Exception:
            return {"alive": False}

    @staticmethod
    def _retest_fmt(dt: datetime) -> str:
        """格式化时间为 'M月d日 HH:MM'。"""
        return f"{dt.month}月{dt.day}日 {dt:%H:%M}"

    async def _pop_queued(self, session: AsyncSession) -> Target | None:
        # 按 EduSRC 优先级评分降序派发：高价值目标先挖。
        # 多取一批是为了遇到同款系统正在跑/已冷却时，能跳到其它 cluster。
        loop = asyncio.get_running_loop()
        now = loop.time()
        if self._queue_prefilter_retry_after:
            self._queue_prefilter_retry_after = {
                tid: until for tid, until in self._queue_prefilter_retry_after.items() if until > now
            }
        candidates = (await session.execute(
            select(Target).where(Target.task_id == self.task_id, Target.status == "queued")
            .order_by(Target.priority_score.desc(), Target.created_at).limit(QUEUE_DISPATCH_CANDIDATE_LIMIT)
        )).scalars().all()
        if not candidates:
            return None

        all_targets = (await session.execute(
            select(Target).where(
                Target.task_id == self.task_id,
                Target.status.in_(["queued", "assigned", "scanning", "dead", "skipped"]),
            )
        )).scalars().all()
        cluster_state = self._cluster_state(all_targets)
        active_clusters = {
            target_cluster.target_cluster_key(t.host or t.url, t.title, t.org)
            for t in all_targets
            if t.status in ("assigned", "scanning")
        }
        active_clusters.discard("")

        skipped_cooldown = 0
        eligible: list[Target] = []
        for target in candidates:
            if self._queue_prefilter_retry_after.get(target.id, 0) > now:
                continue
            key = target_cluster.target_cluster_key(target.host or target.url, target.title, target.org)
            # 企业模式：目标多为用户指定的具体资产（pre-paycenter/test-gateway 等不同子系统），
            # 不做同款簇冷却/并发限流，每个指定资产都要挖——否则会被"同簇打不穿3个"误跳。
            # 定向深挖目标同样不受同簇冷却影响（人工/审核明确要求继续打穿的例外）。
            # 手动清单（source=manual）是用户明确点名要打的，逐个挖，绝不因同款簇冷却跳过
            # （与低成功率预筛的 manual 豁免保持一致，见 _low_success_skip_reason）。
            if (not self._is_enterprise and not target.deepen_context
                    and target.source != "manual"
                    and not site_collab.is_site_source(target.source) and key):
                state = cluster_state.get(key, {})
                if target_cluster.should_cooldown_cluster(state):
                    target.status = "skipped"
                    target.verdict = "skip_cluster_cooldown"
                    target.dead_reason = target_cluster.cooldown_reason(state, state.get("sample", ""))
                    target.last_error = ""
                    skipped_cooldown += 1
                    continue
                if key in active_clusters:
                    continue

            eligible.append(target)

        if not eligible:
            if skipped_cooldown:
                await session.commit()
                await self._log(
                    session, "orchestrator", "cluster_cooldown_skip",
                    f"派发前跳过 {skipped_cooldown} 个同款冷却目标",
                    level="info", skipped=skipped_cooldown,
                )
            return None

        removed_unreachable = 0
        skipped_low_success = 0
        deferred_transient = 0
        selected: tuple[Target, dict] | None = None
        # 小批探活：不必每次把最多 120 个候选全探完才派发一个 worker。
        # 高分优先的小批里一旦找到可打目标就立刻返回，剩余候选留给下一轮，
        # 避免一堆慢/死站把空闲 worker 卡在调度阶段。
        for i in range(0, len(eligible), QUEUE_LIVENESS_BATCH_SIZE):
            batch = eligible[i:i + QUEUE_LIVENESS_BATCH_SIZE]
            liveness = await self._probe_queued_liveness(batch)
            for target in batch:
                probe = liveness.get(target.id) or {"alive": False}
                if not probe.get("alive"):
                    self._queue_prefilter_retry_after.pop(target.id, None)
                    target.status = "dead"
                    target.verdict = "unreachable"
                    target.assigned_worker = ""
                    target.heartbeat_at = None
                    target.last_error = ""
                    target.dead_reason = (probe.get("reason") or "派发前探活失败：目标访问不了")[:300]
                    removed_unreachable += 1
                    continue

                skip_reason = self._low_success_skip_reason(target, probe)
                if skip_reason:
                    if self._is_transient_prefilter_reason(skip_reason):
                        self._queue_prefilter_retry_after[target.id] = now + QUEUE_TRANSIENT_PREFILTER_COOLDOWN
                        target.status = "queued"
                        target.verdict = ""
                        target.assigned_worker = ""
                        target.heartbeat_at = None
                        target.last_error = skip_reason[:500]
                        target.dead_reason = ""
                        deferred_transient += 1
                        continue
                    self._queue_prefilter_retry_after.pop(target.id, None)
                    target.status = "skipped"
                    target.verdict = "skip_low_success"
                    target.assigned_worker = ""
                    target.heartbeat_at = None
                    target.last_error = ""
                    target.dead_reason = skip_reason[:300]
                    skipped_low_success += 1
                    continue

                if probe.get("alive"):
                    selected = (target, probe)
                    break
            if selected:
                break

        if selected:
            target, probe = selected
            self._queue_prefilter_retry_after.pop(target.id, None)
            target.status = "assigned"
            target.assigned_worker = f"w-{target.id[:8]}"
            target.heartbeat_at = _now()
            target.dead_reason = ""
            target.last_error = ""
            alive_url = probe.get("url") or ""
            if alive_url and alive_url != target.url:
                target.url = alive_url
            # 本地探活失败但代理探活成功 → 本机 IP 疑似被封，标记代理模式
            if probe.get("via_proxy"):
                target.ip_ban_confirmed = True
                target.deepen_context = {
                    "directive": "本地 IP 疑似被 WAF 封禁（派发前探活本地不通、代理可达），全程通过 SSH 代理发送请求。",
                    "ip_ban_retest": True,
                    "source": "ip_ban_retest",
                }
            await session.commit()
            if probe.get("via_proxy"):
                await self._log(
                    session, "orchestrator", "target_revived_via_proxy",
                    f"目标本地探活失败但代理可达，疑似 IP 被封，已标记代理模式派发",
                    level="warn", target_id=target.id, host=target.host,
                )
            if removed_unreachable:
                await self._log(
                    session, "orchestrator", "target_unreachable",
                    f"派发前剔除 {removed_unreachable} 个访问不了的目标",
                    level="warn", removed=removed_unreachable,
                )
            if skipped_low_success:
                await self._log(
                    session, "orchestrator", "target_prefilter_skip",
                    f"派发前跳过 {skipped_low_success} 个低成功率目标",
                    level="warn", skipped=skipped_low_success,
                )
            if deferred_transient:
                await self._log(
                    session, "orchestrator", "target_prefilter_defer",
                    f"派发前暂缓 {deferred_transient} 个临时异常目标，稍后重试",
                    level="info", deferred=deferred_transient,
                    cooldown_seconds=QUEUE_TRANSIENT_PREFILTER_COOLDOWN,
                )
            return target

        if skipped_cooldown:
            await session.commit()
            await self._log(
                session, "orchestrator", "cluster_cooldown_skip",
                f"派发前跳过 {skipped_cooldown} 个同款冷却目标",
                level="info", skipped=skipped_cooldown,
            )
        if removed_unreachable:
            await session.commit()
            await self._log(
                session, "orchestrator", "target_unreachable",
                f"派发前剔除 {removed_unreachable} 个访问不了的目标",
                level="warn", removed=removed_unreachable,
            )
        if skipped_low_success:
            await session.commit()
            await self._log(
                session, "orchestrator", "target_prefilter_skip",
                f"派发前跳过 {skipped_low_success} 个低成功率目标",
                level="warn", skipped=skipped_low_success,
            )
        if deferred_transient:
            await session.commit()
            await self._log(
                session, "orchestrator", "target_prefilter_defer",
                f"派发前暂缓 {deferred_transient} 个临时异常目标，稍后重试",
                level="info", deferred=deferred_transient,
                cooldown_seconds=QUEUE_TRANSIENT_PREFILTER_COOLDOWN,
            )
        return None

    async def _probe_queued_liveness(self, targets: list[Target]) -> dict[str, dict]:
        if not targets:
            return {}
        loop = asyncio.get_running_loop()
        now = loop.time()
        results: dict[str, dict] = {}
        pending: list[tuple[str, str, str]] = []
        for target in targets:
            if self._queue_liveness_ok_until.get(target.id, 0) > now:
                results[target.id] = {"alive": True, "url": target.url, "status": 0, "cached": True}
            else:
                pending.append((target.id, target.url, target.host))

        if pending:
            from app.settings_service import resolve_proxy_config
            proxy_config = resolve_proxy_config()
            sem = asyncio.Semaphore(max(1, QUEUE_LIVENESS_CONCURRENCY))

            async def one(target_id: str, url: str, host: str) -> tuple[str, dict]:
                async with sem:
                    try:
                        res = await loop.run_in_executor(
                            COLLECTOR_IO_EXECUTOR,
                            lambda: _probe_target_liveness(
                                url, host, QUEUE_LIVENESS_TIMEOUT,
                                proxy_config=proxy_config,
                            ),
                        )
                    except Exception as exc:
                        res = {
                            "alive": False,
                            "url": url or host,
                            "status": 0,
                            "reason": f"派发前探活异常：{str(exc)[:180]}",
                        }
                    return target_id, res

            for target_id, res in await asyncio.gather(*(one(*item) for item in pending)):
                # 代理探活恢复的目标不缓存：缓存路径不含 via_proxy 标记，
                # 重入队列时需重新探活以正确触发代理模式。
                if res.get("alive") and not res.get("skip") and not res.get("via_proxy"):
                    self._queue_liveness_ok_until[target_id] = now + QUEUE_LIVENESS_CACHE_TTL
                else:
                    self._queue_liveness_ok_until.pop(target_id, None)
                results[target_id] = res

        if len(self._queue_liveness_ok_until) > 1000:
            self._queue_liveness_ok_until = {
                tid: until for tid, until in self._queue_liveness_ok_until.items() if until > now
            }
        return results

    @staticmethod
    def _low_success_skip_reason(target: Target, probe: dict) -> str:
        if not QUEUE_LOW_SUCCESS_SKIP:
            return ""
        # 定向深挖和通杀验证目标是明确有线索的例外，不因低分/静态特征提前拦。
        if target.deepen_context or target.source in ("killsweep", "manual") or site_collab.is_site_source(target.source):
            return ""
        if target.leaked_creds:
            return ""

        reason = str(probe.get("reason") or "")
        if probe.get("skip") and reason:
            if any(marker in reason for marker in _TRANSIENT_UNREACHABLE_REASONS):
                return f"{reason}，本轮不交给 worker，避免消耗 token"
            return f"{reason}，低成功率目标不交给 worker"

        score_reason = (target.priority_reason or "").lower()
        if target.priority_score <= QUEUE_LOW_SUCCESS_SCORE_THRESHOLD and any(
            marker in score_reason for marker in _LOW_SUCCESS_SCORE_MARKERS
        ):
            return (
                f"评分 {target.priority_score:.0f} <= {QUEUE_LOW_SUCCESS_SCORE_THRESHOLD:.1f}，"
                f"命中低成功率特征：{(target.priority_reason or '')[:180]}"
            )
        return ""

    @staticmethod
    def _no_vuln_retry_reason(target: Target) -> str:
        """普通 no_vuln 是否值得再挖一轮。

        默认不重试，避免泛目标在「确认没洞」后继续消耗 LLM；只有已确认的高价值入口
        或已验证可用凭据这类实证线索，才允许用 MAX_RETRY 再换角度打一轮。
        """
        if _has_usable_leaked_cred(target.leaked_creds):
            return "存在已验证可用泄露凭据，值得换角度深挖一次"
        # 单站协作的主题/追打路线（认证越权/未授权/文件/注入/逻辑/定向追打）带着明确 focus
        # 来深挖，打不穿时值得换角度再来一轮；discovery 侦察路线(phase==0)不在此列。
        route = site_collab.route_for_source(target.source or "")
        if route is not None and route.phase != 0:
            return f"单站协作深挖路线（{route.label}），换角度再打一轮"
        score_reason = target.priority_reason or ""
        for marker in _NO_VULN_RETRY_PRIORITY_MARKERS:
            if marker in score_reason:
                return f"命中高价值实证入口({marker.rstrip(':')})，值得换角度验证一次"
        return ""

    @staticmethod
    def _is_transient_prefilter_reason(reason: str) -> bool:
        return any(marker in (reason or "") for marker in _TRANSIENT_UNREACHABLE_REASONS)

    @staticmethod
    def _cluster_state(targets: list[Target]) -> dict[str, dict]:
        state: dict[str, dict] = {}
        for t in targets:
            key = target_cluster.target_cluster_key(t.host or t.url, t.title, t.org)
            if not key:
                continue
            item = state.setdefault(key, {"deadish": 0, "pending": 0, "sample": ""})
            if t.status in ("queued", "assigned", "scanning"):
                item["pending"] += 1
            if TaskRunner._is_cluster_deadish(t):
                item["deadish"] += 1
                item["sample"] = item.get("sample") or (t.host or t.url)
        return state

    @staticmethod
    def _is_cluster_deadish(t: Target) -> bool:
        reason = (t.dead_reason or t.last_error or "").lower()
        if t.status == "skipped" and t.verdict == "skip_cluster_cooldown":
            return True
        if t.status != "dead":
            return False
        if t.verdict in ("no_vuln", "timeout"):
            return True
        return any(marker in reason for marker in ("无可利用", "无果", "自动收敛", "打不穿", "timeout", "超时"))

    def _spawn_worker(self, task: Task, target: Target) -> None:
        cancel_event = threading.Event()
        self._cancelled_targets.discard(target.id)
        prev = self._active_workers.get(target.id)
        if prev is not None and not prev.done():
            # 关键诊断：同一 target 已有未结束的协程，却又被派发 → 双协程！
            logger.error("[double_spawn] target=%s 已有未结束协程仍被重复派发！", target.id[:8])
        self._worker_cancel_events[target.id] = cancel_event
        t = asyncio.create_task(self._run_worker(task.id, target.id, target.url, cancel_event))
        self._active_workers[target.id] = t

    def _reap_workers(self) -> None:
        done = [tid for tid, t in self._active_workers.items() if t.done()]
        for tid in done:
            task = self._active_workers.pop(tid, None)
            if task:
                # 关键：worker 协程若异常死亡，绝不静默吞掉——记后端日志留痕，
                # 否则又会出现「worker 挖到一半莫名其妙消失」且无从追查。
                try:
                    exc = task.exception()
                except asyncio.CancelledError:
                    exc = None
                except Exception:
                    exc = None
                if exc is not None:
                    logger.error(
                        "TaskRunner[%s] worker coroutine died target=%s: %r",
                        self.task_id, tid[:8], exc,
                        exc_info=(type(exc), exc, exc.__traceback__),
                    )
            self._worker_cancel_events.pop(tid, None)

    async def _reclaim_stale(self, session: AsyncSession) -> None:
        """抢救僵尸目标：处于 assigned/scanning 但已无活跃 worker 协程跟踪的，及时回队。

        关键修复：`assigned`/`scanning` 是在 _spawn_worker 同步设置并同步登记到
        _active_workers 的，所以「状态在挖、却不在 _active_workers」只可能是：
        worker 协程异常死亡、进程重启残留、或控制面清理后状态没归位。这类目标的
        worker 早已不存在，必须尽快回收——绝不能等满 WORKER_WALL_TIMEOUT(默认30min)，
        否则它们会长期虚占「扫描中」、堵住吞吐（历史现象：扫描中虚高 20~30）。

        - 无活跃协程：只给一个短宽限期(STALE_NO_WORKER_GRACE)，过了立即回队；
        - 有活跃协程：不动，由协程自身 idle/max-wall 超时策略管理。
        """
        from datetime import timedelta
        # 关键修正：先用 `in _active_workers` 排除所有「协程还在跑」的目标——
        # 那种"协程在跑、心跳暂时停滞"的情况由协程自身的 idle/max-wall 策略兜底，
        # 不归这里管。因此能走到回收判定的，全是「DB=scanning/assigned 但内存里
        # 没有协程」的幽灵目标（进程重启残留 / 协程异常死亡 / 状态没归位）。
        # 既然没有协程在跑，就没有"打断正在挖的 worker"风险，只需一个覆盖
        # 「spawn→首次心跳」窗口的短宽限即可立即回收，避免幽灵目标长期虚占
        # scanning、reclaim 挤牙膏刷屏（本次事故根因：23 个幽灵 scanning）。
        ghost_cutoff = _now() - timedelta(seconds=STALE_NO_WORKER_GRACE)
        rows = (await session.execute(
            select(Target).where(
                Target.task_id == self.task_id,
                Target.status.in_(["assigned", "scanning"]),
            )
        )).scalars().all()
        reclaimed = 0
        for tgt in rows:
            if tgt.id in self._active_workers:
                continue  # 仍有活跃协程在跑，不动（协程自带墙钟超时）
            hb = tgt.heartbeat_at
            if hb is not None and hb.tzinfo is None:
                hb = hb.replace(tzinfo=timezone.utc)
            # 无协程跟踪 + （从未写心跳 或 心跳停滞超短宽限）→ 幽灵目标，立即回收。
            if hb is None or hb < ghost_cutoff:
                hb_age = "None" if hb is None else f"{int((_now() - hb).total_seconds())}s"
                # 诊断：记录被回收目标的现场，便于判断是真幽灵还是误判活跃 worker。
                logger.warning(
                    "[reclaim] target=%s host=%s hb_age=%s in_active=%s active_total=%d",
                    tgt.id[:8], (tgt.url or "")[:40], hb_age,
                    tgt.id in self._active_workers, len(self._active_workers),
                )
                if self._queue_or_dead_after_attempt(tgt, "僵尸目标回收：worker 协程已不存在"):
                    reclaimed += 1
        if reclaimed:
            await session.commit()
            await self._log(session, "orchestrator", "reclaim",
                            f"抢救 {reclaimed} 个僵尸目标回退队列", level="warn", reclaimed=reclaimed)

    async def pause(self, reason: str = "任务暂停") -> None:
        """暂停调度并收回正在跑的 worker。已进入同步调用的线程会收到取消标记，结果不再落库。"""
        await self._cancel_active_workers(f"{reason}：运行中 worker 已取消并回队")

    async def stop(self, reason: str = "任务停止") -> None:
        """停止 runner，并取消 worker/reviewer/killsweep 的后续落库。"""
        self._stop.set()
        await self._cancel_active_workers(f"{reason}：运行中 worker 已取消并回队")
        self._cancel_review_tasks(reason)
        self._cancel_killsweep_tasks(reason)
        self._cancel_escalation_tasks(reason)

    async def _cancel_active_workers(self, reason: str) -> None:
        target_ids = list(self._active_workers.keys())
        if not target_ids:
            return
        for tid in target_ids:
            self._cancelled_targets.add(tid)
            if ev := self._worker_cancel_events.get(tid):
                ev.set()
            if task := self._active_workers.get(tid):
                task.cancel()
            self._live.pop(tid, None)

        async with SessionLocal() as session:
            rows = (await session.execute(
                select(Target).where(Target.task_id == self.task_id, Target.id.in_(target_ids))
            )).scalars().all()
            for tgt in rows:
                if tgt.status in ("assigned", "scanning"):
                    tgt.status = "queued"
                    tgt.verdict = ""
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.last_error = reason[:500]
                    tgt.dead_reason = ""
            await session.commit()
            await self._log(
                session, "orchestrator", "workers_cancelled",
                f"{reason}，已收回 {len(rows)} 个目标",
                level="warn", count=len(rows),
            )

        self._active_workers.clear()
        for tid in target_ids:
            self._worker_cancel_events.pop(tid, None)

    def _cancel_review_tasks(self, reason: str) -> None:
        for finding_id, task in list(self._review_tasks.items()):
            task.cancel()
            self._review_backoff[finding_id] = asyncio.get_running_loop().time() + REVIEW_RETRY_BACKOFF
        self._review_tasks.clear()
        self._review_inflight.clear()

    def _cancel_killsweep_tasks(self, reason: str) -> None:
        for ev in self._killsweep_cancel_events.values():
            ev.set()
        for task in list(self._killsweep_tasks.values()):
            task.cancel()
        self._killsweep_tasks.clear()
        self._killsweep_inflight.clear()
        self._killsweep_cancel_events.clear()

    def _cancel_escalation_tasks(self, reason: str) -> None:
        for ev in self._escalation_cancel_events.values():
            ev.set()
        for task in list(self._escalation_tasks.values()):
            task.cancel()
        self._escalation_tasks.clear()
        self._escalation_inflight.clear()
        self._escalation_cancel_events.clear()

    def _queue_or_dead_after_attempt(self, tgt: Target, reason: str) -> bool:
        """失败/恢复后的统一回队策略。返回 True=回队，False=终态 dead。

        这类回队代表一次 worker 尝试已经失效，应消耗 retry；否则重启/僵尸回收会绕过 MAX_RETRY。
        """
        tgt.assigned_worker = ""
        tgt.heartbeat_at = None
        tgt.last_error = reason[:500]
        tgt.dead_reason = ""
        if tgt.retry_count < MAX_RETRY:
            tgt.retry_count += 1
            tgt.status = "queued"
            tgt.verdict = ""
            return True
        tgt.status = "dead"
        tgt.verdict = "error"
        tgt.dead_reason = f"{reason}，且已达重试上限"
        return False

    @staticmethod
    def _history_item(f: Finding, r: Review | None, host_key: str = "") -> dict:
        source = "finding:pending_review"
        reason = "同 host 历史已提交但尚未审核，避免跨任务重复提交同一线索"
        if r:
            if r.user_status == "rejected":
                source = "review:user_rejected"
                reason = f"人工已驳回：{(r.user_notes or r.reviewer_notes or '')[:260]}"
            elif r.user_status == "passed":
                source = "review:user_passed"
                reason = "人工已通过，已进入待提交/已提交池"
            elif r.verdict == "ignored":
                source = "review:ai_ignored"
                reason = "AI 审核已忽略：" + "；".join((r.ignore_reasons or [])[:3])
            elif r.verdict == "accepted":
                source = "review:ai_accepted"
                reason = "AI 已采纳，正在等待或已经经过人工复审"
            elif r.verdict == "deepen":
                source = "review:deepen"
                reason = f"已被打回深挖：{(r.deepen_directive or '')[:260]}"
        return {
            "id": f.id,
            "dedup_key": f.dedup_key,
            "source": source,
            "policy": "block",
            "vuln_type": f.vuln_type,
            "title": f.title,
            "target_url": f.target_url,
            "host": host_key,
            "description": (f.description or "")[:300],
            "status": f.status,
            "dedup_reason": reason,
        }

    async def _find_existing_duplicate(self, session: AsyncSession, target_ref: str, f: dict) -> dict | None:
        """落库前权威查重：全局 exact key + 同 host 软匹配。"""
        key = dedup.dedup_key(target_ref, f)
        exact = (await session.execute(
            select(Finding, Review)
            .outerjoin(Review, Review.finding_id == Finding.id)
            .where(Finding.dedup_key == key, Finding.status != "superseded")
            .limit(1)
        )).first()
        if exact:
            old_f, old_r = exact
            return self._history_item(old_f, old_r, dedup.normalize_host(old_f.target_url or target_ref))

        host_key = dedup.normalize_host(f.get("target_url") or target_ref)
        if not host_key:
            return None
        rows = (await session.execute(
            select(Finding, Review, Target)
            .outerjoin(Review, Review.finding_id == Finding.id)
            .join(Target, Target.id == Finding.target_id)
            .where(Target.host == host_key, Finding.status != "superseded")
            .order_by(Finding.created_at.desc())
            .limit(100)
        )).all()
        history = [self._history_item(old_f, old_r, old_t.host or host_key) for old_f, old_r, old_t in rows]
        duplicate, matches = dedup.is_duplicate(f, history, target_ref=target_ref)
        if duplicate and matches:
            return matches[0]

        # 同一产品/同款系统可能同时存在域名站、IP站、反代别名；host 不同但产品前缀或
        # 路径 + 漏洞类型一致时，也应拦截重复产出。
        # 漏洞类型走归一化比较，但 DB 预筛用「别名集合 IN」走索引，避免全表扫：
        # 既缩小扫描范围又不漏掉库里以别名写法存储的旧记录。最终判重以 Python 侧归一化为准。
        vuln_type = dedup.normalize_vuln_type(f.get("vuln_type", ""))
        if not vuln_type:
            return None
        product = dedup.title_product_key(f.get("title", ""))
        alias_set = dedup.vuln_type_alias_set(f.get("vuln_type", ""))
        rows = (await session.execute(
            select(Finding, Review, Target)
            .outerjoin(Review, Review.finding_id == Finding.id)
            .join(Target, Target.id == Finding.target_id)
            .where(
                Finding.status != "superseded",
                Finding.vuln_type.in_(alias_set),
            )
            .order_by(Finding.created_at.desc())
            .limit(400)
        )).all()
        cross_history = [
            self._history_item(old_f, old_r, old_t.host or host_key)
            for old_f, old_r, old_t in rows
            if dedup.normalize_vuln_type(old_f.vuln_type) == vuln_type
            and (
                (product and dedup.title_product_key(old_f.title) == product)
                or not product  # 无产品名时交给 dedup 的跨 host 同路径兜底判定
            )
        ]
        duplicate, matches = dedup.is_duplicate(f, cross_history, target_ref=target_ref)
        return matches[0] if duplicate and matches else None

    async def _build_duplicate_history(self, session: AsyncSession, task_id: str, tgt: Target) -> list[dict]:
        """统一构建 worker 查重上下文。

        查重来源分层：
        - finding/review：跨任务同 host 历史漏洞，不管 AI 通过、人工通过、人工驳回、AI 忽略，都给 worker 看；
        - killsweep affected_table：通杀 Hunter 列出的学校/通杀洞明细，命中同 host 时也作为查重事实；
        - superseded：深挖让位的旧线索不放进强查重，避免挡住新一轮打穿后的提交。
        """
        history: list[dict] = []
        host_key = dedup.normalize_host(tgt.url or tgt.host)
        rows = (await session.execute(
            select(Finding, Review)
            .outerjoin(Review, Review.finding_id == Finding.id)
            .join(Target, Target.id == Finding.target_id)
            .where(
                Target.host == host_key,
                Finding.status != "superseded",
            )
            .order_by(Finding.created_at.desc())
            .limit(40)
        )).all()

        for f, r in rows:
            history.append(self._history_item(f, r, host_key))

        # 补充跨 host 历史：同款系统常同时存在域名/IP/反代别名，单 host 查重会漏掉
        # 「中医疫病古籍整理数据库」这类同产品重复洞，以及无产品名但同路径的别名站重复洞。
        # 用同 host 已有 finding 的归一化类型集合，DB 侧 IN 预筛走索引，避免全表扫。
        product = dedup.title_product_key(tgt.title or "")
        type_aliases: set[str] = set()
        for item in history:
            type_aliases |= dedup.vuln_type_alias_set(item.get("vuln_type", ""))
        if product or type_aliases:
            stmt = (
                select(Finding, Review, Target)
                .outerjoin(Review, Review.finding_id == Finding.id)
                .join(Target, Target.id == Finding.target_id)
                .where(Finding.status != "superseded")
            )
            # 有同 host 类型集合时按类型 IN 走索引收窄；否则退化为按产品名（仍限量）。
            if type_aliases:
                stmt = stmt.where(Finding.vuln_type.in_(type_aliases))
            product_rows = (await session.execute(
                stmt.order_by(Finding.created_at.desc()).limit(400)
            )).all()
            seen_ids = {item.get("id") for item in history}
            added = 0
            for f, r, old_t in product_rows:
                if f.id in seen_ids:
                    continue
                same_product = bool(product) and dedup.title_product_key(f.title) == product
                if not same_product:
                    continue
                history.append(self._history_item(f, r, old_t.host or host_key))
                seen_ids.add(f.id)
                added += 1
                if added >= 30:
                    break

        # 通杀明细表也进入 worker 查重上下文：命中同 host 时，拦截同学校同通杀洞重复提交。
        sweep_rows = (await session.execute(
            select(Killsweep).where(
                Killsweep.is_killsweep == True,  # noqa: E712
            ).order_by(Killsweep.created_at.desc()).limit(KILLSWEEP_DEDUP_SCAN_LIMIT)
        )).scalars().all()
        for sw in sweep_rows:
            for item in (sw.affected_table or []):
                if not isinstance(item, dict):
                    continue
                item_host = item.get("host") or dedup.normalize_host(item.get("url", ""))
                if item_host != host_key:
                    continue
                history.append({
                    "id": item.get("dedup_key", ""),
                    "dedup_key": item.get("dedup_key", ""),
                    "source": "killsweep:affected_table",
                    "policy": "block",
                    "vuln_type": item.get("vuln_type") or sw.vuln_type,
                    "title": item.get("vuln_title") or sw.vuln_summary,
                    "target_url": item.get("url") or tgt.url,
                    "host": item_host,
                    "description": (
                        f"通杀查重库：{sw.product_name}；学校/单位：{item.get('school','待确认')}；"
                        f"状态：{item.get('status','candidate')}；依据：{item.get('evidence','')}"
                    )[:500],
                    "status": f"killsweep:{item.get('status','candidate')}",
                    "dedup_reason": "通杀 Hunter 已列入学校/通杀洞明细表，避免重复提交同一通杀洞",
                })
        # 只压缩池子，不把所有历史摊进 prompt；worker prompt 里仍只展示前 6 条摘要。
        return dedup.compact_history(history, target_ref=tgt.url or tgt.host, limit=60)

    async def _build_coverage_context(self, session: AsyncSession, task_id: str, tgt: Target) -> str:
        """同站协作覆盖摘要：后续 worker 启动时避免重复测同一批 API。"""
        host_key = dedup.normalize_host(tgt.url or tgt.host)
        if not host_key:
            return ""
        rows = (await session.execute(
            select(TaskEvent)
            .where(TaskEvent.task_id == task_id, TaskEvent.kind == "coverage_reported")
            .order_by(TaskEvent.id.desc())
            .limit(80)
        )).scalars().all()
        lines: list[str] = []
        seen: set[str] = set()
        for event in rows:
            payload = event.payload or {}
            if payload.get("host") != host_key:
                continue
            route = payload.get("route") or "unknown"
            summary = (payload.get("summary") or "")[:180]
            endpoints = payload.get("endpoints") or []
            sample = []
            for item in endpoints[:6]:
                if not isinstance(item, dict):
                    continue
                method = (item.get("method") or "GET").upper()
                path = item.get("path") or item.get("url") or ""
                status = item.get("status")
                result = item.get("result") or item.get("note") or ""
                sample.append(f"{method} {path} => {status or '-'} {result}".strip())
            key = f"{route}:{summary}:{'|'.join(sample)}"
            if key in seen:
                continue
            seen.add(key)
            tail = "；".join(sample[:4])
            line = f"- {route}: {summary}"
            if tail:
                line += f"（{tail[:260]}）"
            lines.append(line)
            if len(lines) >= 12:
                break
        if not lines:
            return ""
        return "# 同站协作覆盖摘要（前序 worker 上报）\n" + "\n".join(lines) + "\n"

    @staticmethod
    def _next_site_followup_source(used: set[str]) -> str:
        for idx in range(1, 100):
            source = f"site_f{idx:02d}"
            if source not in used:
                used.add(source)
                return source
        return ""

    async def _spawn_site_followups(
        self,
        session: AsyncSession,
        task_id: str,
        tgt: Target,
        coverage_items: list[dict],
    ) -> int:
        """把前序覆盖记录转成具体 API/路径的定向追打 worker。"""
        if not site_collab.is_site_source(tgt.source):
            return 0
        # follow-up 自己也会上报 coverage，避免无限派生。
        if (tgt.source or "").startswith("site_f"):
            return 0
        base_url = tgt.url or (f"https://{tgt.host}" if tgt.host else "")
        specs = site_collab.followup_specs_from_coverage(coverage_items, base_url=base_url, max_specs=8)
        if not specs:
            return 0

        added = 0
        existing_reasons = (await session.execute(
            select(Target.source, Target.priority_reason).where(Target.task_id == task_id, Target.host == tgt.host)
        )).all()
        used_sources = {str(r[0] or "") for r in existing_reasons}
        reason_pool = {str(r[1] or "") for r in existing_reasons}
        for spec in specs:
            reason = str(spec.get("reason") or "")[:300]
            if not reason or reason in reason_pool:
                continue
            source = self._next_site_followup_source(used_sources)
            if not source:
                break
            path = str(spec.get("path") or "").strip()
            follow_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/")) if path else base_url
            try:
                async with session.begin_nested():
                    session.add(Target(
                        task_id=task_id,
                        url=follow_url or base_url,
                        host=tgt.host,
                        source=source,
                        status="queued",
                        priority_score=float(spec.get("priority") or site_collab.FOCUSED_ROUTE.priority),
                        priority_reason=reason,
                    ))
            except IntegrityError:
                # 并发：两条 discovery worker 同时派生撞了同一 site_f 编号，跳过，
                # 不让唯一索引冲突在外层 commit 时炸掉整次 persist。
                continue
            reason_pool.add(reason)
            added += 1
        return added

    async def _spawn_site_theme_routes(
        self,
        session: AsyncSession,
        task_id: str,
        tgt: Target,
    ) -> int:
        """discovery 侦察路线(map/js)完成后，自动派发 5 条主题深挖路线。

        单站协作的真正分工在这里落地：先由 site_map/site_js 摸清入口与 JS/API，
        再由 认证越权 / 未授权配置 / 文件 / 注入RCE / 业务逻辑 五条主题路线分头深挖，
        每条主题 worker 派发时都会带上前序侦察的 coverage 上下文（见 _run_worker_inner）。

        - 仅在 discovery 路线(phase==0)完成后触发；
        - 每个 host 只派一次（靠 source 存在性去重 + 唯一索引 + savepoint 兜并发）；
        - 主题路线本身不会再触发本函数（phase>0）。
        """
        route = site_collab.route_for_source(tgt.source or "")
        if not route or route.phase != 0:
            return 0
        existing = (await session.execute(
            select(Target.source).where(Target.task_id == task_id, Target.host == tgt.host)
        )).all()
        existing_sources = {str(r[0] or "") for r in existing}
        added = 0
        for troute in site_collab.FOLLOWUP_ROUTES:
            if troute.source in existing_sources:
                continue
            try:
                async with session.begin_nested():
                    session.add(Target(
                        task_id=task_id,
                        url=tgt.url,
                        host=tgt.host,
                        source=troute.source,
                        status="queued",
                        priority_score=troute.priority,
                        priority_reason=site_collab.route_reason(troute),
                    ))
            except IntegrityError:
                # 并发：另一条 discovery worker 已派过同款主题路线，跳过。
                continue
            existing_sources.add(troute.source)
            added += 1
        return added

    async def _run_worker(self, task_id: str, target_id: str, url: str,
                          cancel_event: threading.Event) -> None:
        """worker 协程顶层守卫：确保任何未预期异常都被记录+落地，
        绝不让 worker「莫名其妙消失」(协程异常死亡 → _reap 静默吞掉 → 目标虚挂 scanning)。"""
        try:
            await self._run_worker_inner(task_id, target_id, url, cancel_event)
        except asyncio.CancelledError:
            # 正常取消(pause/stop/reclaim)：清理活态，目标回队由 cancel/reclaim 链路接管。
            self._live.pop(target_id, None)
            self._worker_last_activity.pop(target_id, None)
            self._worker_cancel_events.pop(target_id, None)
            raise
        except Exception as e:
            # 关键兜底：setup 阶段(建上下文/查重/取LLM/信号量)或任何未捕获异常，
            # 都在这里兜住——记后端日志 + 写事件流 + 给目标一个 error 终态，
            # 而不是让协程静默死亡、目标永远虚挂 scanning 直到被 reclaim 回队空转。
            summary = self._summarize_exc(e)
            host_hint = (url or "").split("://")[-1].rstrip("/")[:60]
            logger.warning(
                "TaskRunner[%s] worker crashed target=%s host=%s:\n%s",
                self.task_id, target_id[:8], host_hint, traceback.format_exc(),
            )
            self._live.pop(target_id, None)
            self._worker_last_activity.pop(target_id, None)
            self._worker_cancel_events.pop(target_id, None)
            try:
                async with SessionLocal() as s:
                    await self._log(s, "worker", "error",
                                    f"worker 异常退出（{host_hint}）：{summary}",
                                    level="error", target_id=target_id)
            except Exception:
                pass
            try:
                await self._persist_worker_result(
                    task_id, target_id,
                    {"verdict": "error", "findings": [], "error": summary},
                )
            except Exception:
                logger.warning("TaskRunner[%s] worker crash persist failed target=%s",
                               self.task_id, target_id[:8])

    async def _run_worker_inner(self, task_id: str, target_id: str, url: str,
                                cancel_event: threading.Event) -> None:
        loop = asyncio.get_running_loop()
        host = url.split("://")[-1].rstrip("/")
        started_monotonic = loop.time()
        self._worker_last_activity[target_id] = started_monotonic
        self._live[target_id] = {
            "target_id": target_id, "host": host, "url": url,
            "round": 0, "action": "启动中…", "findings": 0,
            "started_at": _now_iso(),
            "last_activity_at": _now_iso(),
        }

        def _update_live(kind: str, data: dict):
            st = self._live.get(target_id)
            if not st:
                return
            self._worker_last_activity[target_id] = loop.time()
            st["last_activity_at"] = _now_iso()
            if "round" in data:
                st["round"] = data["round"]
            if kind == "tool_http":
                st["action"] = f"HTTP {data.get('method','GET')} {data.get('url','')}"
            elif kind == "tool_shell":
                st["action"] = f"$ {data.get('command','')}"
            elif kind == "tool_shell_blocked":
                st["action"] = f"拦截低价值命令: {data.get('reason','')}"
            elif kind == "tool_arg_error":
                st["action"] = f"工具参数错误: {data.get('tool','')}"
            elif kind == "tool_exception":
                st["action"] = f"工具异常: {data.get('tool','')}"
            elif kind == "worker_thought":
                st["action"] = "💭 " + (data.get("text") or "")[:120]
            elif kind == "llm_round_start":
                st["action"] = "LLM 思考中…"
            elif kind == "llm_error":
                st["action"] = f"LLM 异常: {data.get('error','')}"
            elif kind == "worker_auto_finish":
                st["action"] = f"自动收敛: {data.get('summary','')}"
            elif kind == "finding_submitted":
                st["findings"] = st.get("findings", 0) + 1
                st["action"] = f"🎯 发现漏洞: {data.get('title','')}"
            elif kind == "duplicate_checked":
                st["action"] = (
                    f"查重: {'重复' if data.get('duplicate') else '未重复'} "
                    f"{data.get('title','')}"
                )
            elif kind == "finding_duplicate":
                st["action"] = f"重复漏洞已拦截: {data.get('title','')}"
            elif kind == "intel_reported":
                st["action"] = f"记录情报: {data.get('intel_kind','')}"
            elif kind == "worker_finish":
                st["action"] = f"收尾: {data.get('verdict','')}"

        def emit(kind: str, data: dict):
            if cancel_event.is_set():
                return
            # 线程内回调 → 投递到事件循环（更新活态 + 推送看板）
            def _do():
                if cancel_event.is_set():
                    return
                try:
                    # finding_submitted 携带完整 finding：实时落库（不丢洞），并从看板推送里剥离大字段。
                    finding_payload = data.pop("finding", None) if kind == "finding_submitted" else None
                    if finding_payload:
                        ft = asyncio.create_task(
                            self._persist_single_finding(task_id, target_id, finding_payload)
                        )
                        # 观测异常：finding 实时落库失败必须留痕，否则真洞可能静默丢失。
                        ft.add_done_callback(lambda f: _log_bg_task_exc(f, "persist_single_finding"))
                    _update_live(kind, data)
                    pt = asyncio.create_task(bus.publish(
                        task_id, {"agent": "worker", "kind": kind, "target_id": target_id, **data}))
                    pt.add_done_callback(lambda f: _log_bg_task_exc(f, "bus.publish"))
                except Exception:
                    logger.warning("TaskRunner[%s] emit dispatch failed target=%s kind=%s",
                                   self.task_id, target_id[:8], kind, exc_info=True)
            loop.call_soon_threadsafe(_do)

        deepen_context = None
        deepen_count = 0
        target_meta: dict = {}
        duplicate_history: list[dict] = []
        src_type = "edusrc"
        fofa_key = ""
        fofa_base_url = ""
        enable_worker_fofa_lookup = True
        async with SessionLocal() as session:
            tgt = await session.get(Target, target_id)
            task_obj = await session.get(Task, task_id)
            if task_obj:
                src_type = task_obj.src_type or "edusrc"
                fofa_key = resolve_fofa_key(task_obj)
                fofa_base_url = resolve_fofa_base_url(task_obj)
                enable_worker_fofa_lookup = getattr(task_obj, 'enable_worker_fofa_lookup', True)
            if tgt:
                tgt.status = "scanning"
                self._live[target_id]["score"] = tgt.priority_score
                self._live[target_id]["score_reason"] = tgt.priority_reason
                deepen_context = tgt.deepen_context or None
                deepen_count = tgt.deepen_count or 0
                # 资产情报：候选归属学校/org/title，供 worker 核实并写进报告 owner
                target_meta = {
                    "school": tgt.school or "", "org": tgt.org or "",
                    "title": tgt.title or "", "is_edu": tgt.is_edu,
                    "source": tgt.source or "", "priority_reason": tgt.priority_reason or "",
                    "leaked_creds": tgt.leaked_creds or [],
                    "user_credentials": tgt.user_credentials or None,
                    "cas_sso_config": (task_obj.cas_sso_config if task_obj else "") or "",
                }
                try:
                    plan = playbook_router.route_target(
                        url=tgt.url or url,
                        title=tgt.title or "",
                        priority_reason=tgt.priority_reason or "",
                        src_type=src_type,
                        source=tgt.source or "",
                        deepen_context=deepen_context,
                        leaked_creds=tgt.leaked_creds or [],
                    )
                    target_meta["playbook_route"] = plan.as_dict()
                    target_meta["playbook_block"] = playbook_router.render_playbook_block(plan)
                    self._live[target_id]["playbook"] = plan.label
                except Exception:
                    pass
                # 触发式检索全局情报库：按 root 域 + 系统指纹命中才注入（不冗余）。
                try:
                    root = target_cluster.root_domain(tgt.host or "")
                    fps = intel_lib.detect_fingerprints(tgt.host or "", tgt.title or "", tgt.org or "")
                    hits = await intel_lib.lookup_intel(session, root, fps)
                    block = intel_lib.render_intel_block(hits)
                    if block:
                        target_meta["intel_block"] = block
                except Exception:
                    pass
                try:
                    route = site_collab.route_for_source(tgt.source or "")
                    if route:
                        coverage_block = await self._build_coverage_context(session, task_id, tgt)
                        target_meta["site_collab_route"] = {
                            "source": route.source,
                            "label": route.label,
                            "focus": route.focus,
                            "js_first": route.js_first,
                        }
                        target_meta["site_collab_block"] = site_collab.render_context(
                            route,
                            site_info=(task_obj.fofa_query if task_obj else ""),
                            coverage_block=coverage_block,
                            focus_note=tgt.priority_reason or "",
                            skip_recon=site_collab.skip_recon_enabled(task_obj) if task_obj else False,
                        )
                        self._live[target_id]["mode"] = "site"
                        self._live[target_id]["playbook"] = route.label
                        self._live[target_id]["action"] = f"协作路线：{route.label}"
                except Exception:
                    pass
                if deepen_context:
                    self._live[target_id]["mode"] = "deepen"
                    self._live[target_id]["action"] = "🔁 定向深挖启动中…"
                duplicate_history = await self._build_duplicate_history(session, task_id, tgt)
                await session.commit()
            llm = _llm_for_task(task_obj)
            prompt_version = resolve_worker_prompt_version(task_obj)

        worker_holder: dict[str, Worker] = {}

        def do_work() -> dict:
            worker = Worker(url, llm=llm, on_event=emit,
                            deepen_context=deepen_context, target_meta=target_meta,
                            duplicate_history=duplicate_history,
                            cancel_event=cancel_event, src_type=src_type,
                            fofa_key=fofa_key, fofa_base_url=fofa_base_url,
                            prompt_version=prompt_version,
                            enable_fofa_lookup=enable_worker_fofa_lookup,
                            deepen_count=deepen_count)
            worker_holder["worker"] = worker
            try:
                return worker.run().model_dump(mode="json")
            finally:
                # 正常完成的清理：只杀残留子进程，绝不 set cancel_event。
                # （历史事故根因：这里曾调 cancel_running() 顺带 set 了 cancel_event，
                #  导致每个正常完成的 worker 都被 L680 判成"被取消"而丢弃结果，
                #  findings/done 永远为 0、出洞概率暴跌。）
                worker.executor.kill_processes()

        cancelled = False
        # 区分「超时」与「外部取消(pause/stop/reclaim)」：两者都会 set cancel_event(通知
        # 还在跑的 worker 线程停手)，但超时应当走正常 persist 落 timeout verdict(触发重试/dead
        # 状态机)，而外部取消才丢弃结果由回队逻辑接管。用独立标志把两者分开。
        is_timeout = False
        result: dict | None = None
        # 并发信号量：worker 实际并发由此封顶，保证不会占满 AGENT_EXECUTOR 把
        # reviewer/killsweep/assistant 饿死。信号量在 future 真正结束(含超时后线程
        # 仍在跑的情况)时才释放，避免线程未退就放行新 worker 导致池子超订。
        worker_sem = agent_semaphore("worker")
        # acquire 本身可能被取消(pause/stop)——此时还没建 heartbeat/future，无需清理。
        await worker_sem.acquire()
        # 心跳放在拿到并发位之后再起：确保它的生命周期与 worker_future 完全对齐，
        # 任何一条退出路径都能在下方 finally 里把它取消，杜绝心跳协程泄漏。
        heartbeat_task = asyncio.create_task(self._heartbeat_target(target_id))
        # 关键防泄漏：拿到信号量后，只要 future 没能挂上「结束即释放」的回调，
        # 就必须在这里立即把信号量还回去。否则 run_in_executor 一旦抛错(如池已
        # 关闭 RuntimeError)，这个并发位就永久丢失——攒够 8 个后 worker 永远
        # 起不来、后续所有 worker 静默卡死在 acquire()（"莫名其妙都不挖了"）。
        try:
            worker_future = loop.run_in_executor(AGENT_EXECUTOR, do_work)
        except BaseException:
            worker_sem.release()
            heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await heartbeat_task
            raise
        worker_future.add_done_callback(lambda _f: worker_sem.release())
        try:
            # 活跃续命：worker 有持续事件就不因旧的 30min 墙钟被误杀；
            # 真正卡死则按 idle timeout 回收，活跃过久也有 max wall 兜底。
            while True:
                try:
                    poll_limit = WORKER_IDLE_TIMEOUT if WORKER_IDLE_TIMEOUT > 0 else WORKER_WAIT_POLL_INTERVAL
                    poll = max(1.0, min(WORKER_WAIT_POLL_INTERVAL, poll_limit))
                    result = await asyncio.wait_for(asyncio.shield(worker_future), timeout=poll)
                    break
                except asyncio.TimeoutError:
                    now = loop.time()
                    reason = _worker_timeout_reason(
                        started_monotonic,
                        self._worker_last_activity.get(target_id, started_monotonic),
                        now,
                    )
                    if not reason:
                        continue
                    raise asyncio.TimeoutError(reason)
        except asyncio.TimeoutError as e:
            timeout_reason = str(e) or "worker 超时"
            logger.warning(
                "[cancel_set] TimeoutError target=%s idle=%s max_wall=%s reason=%s",
                target_id[:8], WORKER_IDLE_TIMEOUT, WORKER_MAX_WALL_TIMEOUT, timeout_reason,
            )
            cancel_event.set()
            is_timeout = True
            worker = worker_holder.get("worker")
            if worker:
                worker.executor.cancel_running()
            try:
                await asyncio.wait_for(asyncio.shield(worker_future), timeout=WORKER_CLEANUP_TIMEOUT)
            except Exception:
                worker_future.add_done_callback(_consume_task_exception)
            result = {"verdict": "timeout", "findings": [], "error": timeout_reason}
            async with SessionLocal() as s:
                await self._log(s, "worker", "timeout",
                                f"目标超时强制回收：{timeout_reason}，已触发工具子进程清理",
                                level="warn", target_id=target_id)
        except asyncio.CancelledError:
            logger.warning("[cancel_set] CancelledError target=%s", target_id[:8])
            cancelled = True
            cancel_event.set()
            worker = worker_holder.get("worker")
            if worker:
                worker.executor.cancel_running()
            worker_future.add_done_callback(_consume_task_exception)
        except Exception as e:
            result = {"verdict": "error", "findings": [], "error": str(e)}
        finally:
            heartbeat_task.cancel()
            # 吞掉一切：心跳可能早已因瞬时异常死亡，绝不能让它的残留异常在这里
            # 把一次本已拿到结果的 worker 连累成 error（历史坑：finally 里 await
            # 一个已异常结束的 task 会把该异常重新抛出）。
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await heartbeat_task

        live_snapshot = dict(self._live.get(target_id) or {})
        self._live.pop(target_id, None)
        self._worker_last_activity.pop(target_id, None)
        self._worker_cancel_events.pop(target_id, None)
        # 丢弃仅针对「外部取消」(pause/stop/reclaim)：这些路径已由回队逻辑接管目标状态。
        # 超时(is_timeout)虽然也 set 了 cancel_event，但要正常走 persist 落 timeout verdict，
        # 触发 _persist_worker_result 里的 timeout 重试/dead 分支，而不是被丢弃后靠 reclaim 兜底。
        externally_cancelled = cancelled or target_id in self._cancelled_targets or (
            cancel_event.is_set() and not is_timeout
        )
        if externally_cancelled:
            # 诊断：worker 结果被丢弃的真实原因（定位"挖了没落库"的关键路径）。
            n_find = len((result or {}).get("findings") or [])
            logger.warning(
                "[worker_discard] target=%s cancelled=%s cancel_event=%s in_cancelled_set=%s findings=%d verdict=%s",
                target_id[:8], cancelled, cancel_event.is_set(),
                target_id in self._cancelled_targets, n_find,
                (result or {}).get("verdict"),
            )
            self._cancelled_targets.discard(target_id)
            # 被取消（pause/stop/超时/reclaim）时，目标状态变更丢弃由回队逻辑接管；
            # 但 worker 若已经打出实锤 findings，绝不能跟着一起扔——洞是真金白银，
            # 这里单独把已发现的 findings 落库（幂等去重），避免"挖出洞却没入库"。
            salvage = (result or {}).get("findings") or []
            if salvage:
                try:
                    await self._salvage_findings(task_id, target_id, salvage)
                except Exception:
                    pass
            return
        final_result = result or {"verdict": "error", "findings": []}
        final_result.setdefault("_runtime", {})
        final_result["_runtime"].update({
            "started_at": live_snapshot.get("started_at"),
            "finished_at": _now_iso(),
            "duration_seconds": max(0.0, loop.time() - started_monotonic),
        })
        await self._persist_worker_result(task_id, target_id, final_result)

    async def _salvage_findings(self, task_id: str, target_id: str, findings: list) -> None:
        """被取消的 worker 已发现的 findings 抢救落库（只存洞，不改目标状态）。

        与 _persist_worker_result 的落库逻辑一致（dedup + 唯一索引兜底），
        但不触碰目标状态机——目标回队/dead 由 cancel/reclaim 链路自行决定。
        """
        if not findings:
            return
        async with SessionLocal() as session:
            tgt = await session.get(Target, target_id)
            if not tgt:
                return
            target_ref = tgt.url or tgt.host
            worker_id = tgt.assigned_worker
            saved = 0
            for f in findings:
                duplicate = await self._find_existing_duplicate(session, target_ref, f)
                if duplicate:
                    continue
                dedup_key = dedup.dedup_key(target_ref, f)
                try:
                    async with session.begin_nested():
                        session.add(Finding(
                            task_id=task_id, target_id=target_id, worker_id=worker_id,
                            vuln_type=f.get("vuln_type", ""), title=f.get("title", ""),
                            severity_claimed=f.get("severity_claimed", ""),
                            target_url=f.get("target_url", ""), owner=f.get("owner", ""),
                            description=f.get("description", ""), steps=f.get("steps", []),
                            poc=f.get("poc", ""), raw_request=f.get("raw_request", ""),
                            raw_response=f.get("raw_response", ""), evidence=f.get("evidence", {}),
                            affected_scope=f.get("affected_scope", ""),
                            kill_chain=f.get("kill_chain", []),
                            self_check=f.get("self_check", {}),
                            dedup_key=dedup_key, status="pending_review",
                        ))
                    saved += 1
                except IntegrityError:
                    continue
            if saved:
                await session.commit()
                await self._log(session, "orchestrator", "salvage",
                                f"被取消的 worker 抢救落库 {saved} 个漏洞（目标 {target_id[:8]}）",
                                level="warn", target_id=target_id, saved=saved)

    async def _persist_single_finding(self, task_id: str, target_id: str, f: dict) -> None:
        """worker 每 submit 一个洞就实时落库，进程被打断时不丢洞。

        幂等：dedup_key + 唯一索引兜底，与 _salvage_findings/_persist_worker_result
        共用同一去重模式，最终整轮落库不会产生重复。只存洞，不碰目标状态机。
        失败静默吞掉——实时落库是「加保险」，整轮 result 落库仍是兜底。
        """
        if not f:
            return
        try:
            async with SessionLocal() as session:
                tgt = await session.get(Target, target_id)
                if not tgt:
                    return
                target_ref = tgt.url or tgt.host
                worker_id = tgt.assigned_worker
                duplicate = await self._find_existing_duplicate(session, target_ref, f)
                if duplicate:
                    return
                dedup_key = dedup.dedup_key(target_ref, f)
                try:
                    async with session.begin_nested():
                        session.add(Finding(
                            task_id=task_id, target_id=target_id, worker_id=worker_id,
                            vuln_type=f.get("vuln_type", ""), title=f.get("title", ""),
                            severity_claimed=f.get("severity_claimed", ""),
                            target_url=f.get("target_url", ""), owner=f.get("owner", ""),
                            description=f.get("description", ""), steps=f.get("steps", []),
                            poc=f.get("poc", ""), raw_request=f.get("raw_request", ""),
                            raw_response=f.get("raw_response", ""), evidence=f.get("evidence", {}),
                            affected_scope=f.get("affected_scope", ""),
                            kill_chain=f.get("kill_chain", []),
                            self_check=f.get("self_check", {}),
                            dedup_key=dedup_key, status="pending_review",
                        ))
                    await session.commit()
                except IntegrityError:
                    return
                logger.info("[realtime_persist] target=%s title=%s 实时落库成功",
                            target_id[:8], (f.get("title") or "")[:40])
        except Exception:
            logger.warning("[realtime_persist] target=%s 实时落库失败（整轮 result 仍会兜底）",
                            target_id[:8], exc_info=True)

    async def _heartbeat_target(self, target_id: str) -> None:
        timeout_ref = WORKER_IDLE_TIMEOUT if WORKER_IDLE_TIMEOUT > 0 else WORKER_WALL_TIMEOUT
        interval = max(5.0, min(TARGET_HEARTBEAT_INTERVAL, max(5.0, timeout_ref / 4)))
        while True:
            await asyncio.sleep(interval)
            # 关键：心跳循环绝不能因一次瞬时 DB 异常而整条死掉——否则该 target
            # 停止续心跳，会被 _reclaim_stale 误判成幽灵回收/或在 finally 里把一次
            # 本已成功的 worker 结果连累成 error。单次失败就跳过，下一拍再试。
            try:
                async with SessionLocal() as session:
                    tgt = await session.get(Target, target_id)
                    if not tgt or tgt.status not in ("assigned", "scanning"):
                        return
                    tgt.heartbeat_at = _now()
                    await session.commit()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.debug("TaskRunner[%s] heartbeat tick failed target=%s (will retry)",
                             self.task_id, target_id[:8], exc_info=True)
                continue

    async def _harvest_intel(self, session, task_id: str, tgt, verdict: str,
                             findings: list, reported_intel: list | None = None) -> None:
        """从出洞结果提炼 + worker 主动上报，沉淀可复用情报入全局情报库（不冗余）。

        自动提炼（仅出洞时）：
        - fingerprint：该系统打出过什么漏洞 → 同款系统打法
        - endpoint：漏洞所在路径 → 同款系统有效端点
        - profile：技术栈/系统识别 → 本域画像
        worker 主动上报（reported_intel）：cred/endpoint/profile，无论出洞与否都收。
        """
        host = (tgt.host or "").strip()
        root = target_cluster.root_domain(host)
        fps = intel_lib.detect_fingerprints(host, tgt.title or "", tgt.org or "")
        src_task = task_id

        # ===== worker 主动上报的情报（cred 按 root 域，endpoint 按系统指纹，profile 按 root 域）=====
        for it in (reported_intel or []):
            if not isinstance(it, dict):
                continue
            kind = (it.get("kind") or "").strip().lower()
            payload = it.get("payload") if isinstance(it.get("payload"), dict) else {}
            if not payload:
                continue
            conf = "verified" if it.get("confidence") == "verified" else "likely"
            summ = it.get("summary") or ""
            if kind == "cred" and root:
                await intel_lib.record_intel(session, "cred", root, payload=payload,
                                             summary=summ, source_host=host,
                                             source_task_id=src_task, confidence=conf)
            elif kind == "endpoint":
                # 有系统指纹按指纹存（可跨域复用）；否则退而按 root 域存
                keys = fps or ([root] if root else [])
                for k in keys:
                    await intel_lib.record_intel(session, "endpoint", k, payload=payload,
                                                 summary=summ, source_host=host,
                                                 source_task_id=src_task, confidence=conf)
            elif kind == "profile" and root:
                await intel_lib.record_intel(session, "profile", root, payload=payload,
                                             summary=summ, source_host=host,
                                             source_task_id=src_task, confidence=conf)

        # ===== 自动提炼：只在确认出洞时（质量门槛，防冗余垃圾）=====
        if verdict != Verdict.found.value and not findings:
            return

        for f in findings:
            vuln_type = (f.get("vuln_type") or "").strip()
            title = (f.get("title") or "").strip()
            url = (f.get("target_url") or "").strip()
            if not vuln_type:
                continue
            # 提取路径（endpoint 情报）
            path = ""
            try:
                from urllib.parse import urlparse
                path = urlparse(url).path or ""
            except Exception:
                path = ""

            # fingerprint：同款系统打法（仅当识别出系统指纹时）
            for fp in fps:
                await intel_lib.record_intel(
                    session, "fingerprint", fp,
                    payload={"tactic": f"{vuln_type}：{title}"[:300], "vuln_type": vuln_type},
                    summary=f"{vuln_type}（来自 {host}）",
                    source_host=host, source_task_id=src_task, confidence="verified",
                )
                # endpoint：同款系统有效端点
                if path and path != "/":
                    await intel_lib.record_intel(
                        session, "endpoint", fp,
                        payload={"path": path, "vuln_type": vuln_type},
                        summary=f"（来自 {host} 出洞）",
                        source_host=host, source_task_id=src_task, confidence="verified",
                    )

        # profile：本域技术栈画像（仅当识别出指纹时，记一条系统类型）
        if root and fps:
            await intel_lib.record_intel(
                session, "profile", root,
                payload={"key": "系统类型", "value": ", ".join(fps)},
                summary="", source_host=host, source_task_id=src_task, confidence="likely",
            )

    async def _persist_worker_result(self, task_id: str, target_id: str, result: dict) -> None:
        async with SessionLocal() as session:
            tgt = await session.get(Target, target_id)
            if not tgt:
                return
            worker_id = tgt.assigned_worker or ""
            target_ref = tgt.url or tgt.host
            verdict = result.get("verdict", "error")
            findings = result.get("findings", [])
            error_text = result.get("error") or ""
            summary_text = result.get("summary") or ""
            auto_converged = (
                verdict == Verdict.no_vuln.value
                and not findings
                and (
                    "系统自动收敛" in summary_text
                    or summary_text.startswith("连续")
                    or summary_text.startswith("模型连续")
                )
            )
            quota_llm_error = (
                verdict == Verdict.error.value
                and not findings
                and self._is_quota_error(error_text)
            )
            transient_llm_error = (
                verdict == Verdict.error.value
                and not findings
                and self._is_transient_worker_error(error_text)
            )
            # 自动深挖回火标记（worker 突破有线索时设置，用于日志）。
            auto_deepen_info = None
            # worker 主动回队标记；回队不是终态，不能再记 target_done。
            worker_requeue_info = None
            # 临时错误回队有上限：模型持续抽风时不能让目标无限空转。
            transient_exhausted = False
            if transient_llm_error:
                cnt = self._transient_llm_requeue.get(target_id, 0) + 1
                self._transient_llm_requeue[target_id] = cnt
                if cnt > MAX_TRANSIENT_LLM_REQUEUE:
                    transient_llm_error = False
                    transient_exhausted = True

            # 落 Finding（含漏洞级去重；DB 唯一索引兜底，逐条 savepoint 容错并发重复）
            for f in findings:
                duplicate = await self._find_existing_duplicate(session, target_ref, f)
                if duplicate:
                    continue
                dedup_key = dedup.dedup_key(target_ref, f)
                try:
                    async with session.begin_nested():
                        session.add(Finding(
                            task_id=task_id, target_id=target_id, worker_id=worker_id,
                            vuln_type=f.get("vuln_type", ""), title=f.get("title", ""),
                            severity_claimed=f.get("severity_claimed", ""), target_url=f.get("target_url", ""),
                            owner=f.get("owner", ""),
                            description=f.get("description", ""), steps=f.get("steps", []),
                            poc=f.get("poc", ""), raw_request=f.get("raw_request", ""),
                            raw_response=f.get("raw_response", ""), evidence=f.get("evidence", {}),
                            affected_scope=f.get("affected_scope", ""),
                            kill_chain=f.get("kill_chain", []),
                            self_check=f.get("self_check", {}),
                            dedup_key=dedup_key, status="pending_review",
                        ))
                except IntegrityError:
                    continue  # 唯一索引拦下并发/重复，跳过即可

            # 情报库沉淀：出洞时从 finding 提炼 + worker 主动上报的情报，入全局库供复用。
            # 全程降级，任何异常都不影响 worker 结果落库。
            try:
                await self._harvest_intel(session, task_id, tgt, verdict, findings,
                                          result.get("reported_intel") or [])
            except Exception:
                pass

            coverage_records: list[dict] = []
            for item in (result.get("reported_coverage") or [])[:20]:
                if not isinstance(item, dict):
                    continue
                route = str(item.get("route") or tgt.source or "site")[:40]
                summary = str(item.get("summary") or "")[:300]
                if not summary:
                    continue
                coverage_record = {
                    "route": route,
                    "summary": summary,
                    "endpoints": (item.get("endpoints") or [])[:20],
                    "remaining": str(item.get("remaining") or "")[:400],
                }
                coverage_records.append(coverage_record)
                session.add(TaskEvent(
                    task_id=task_id,
                    agent="worker",
                    kind="coverage_reported",
                    level="info",
                    message=f"覆盖记录 {tgt.host} / {route}: {summary}",
                    payload={
                        "target_id": target_id,
                        "host": dedup.normalize_host(tgt.url or tgt.host),
                        **coverage_record,
                    },
                ))
            if coverage_records:
                spawned = await self._spawn_site_followups(session, task_id, tgt, coverage_records)
                if spawned:
                    session.add(TaskEvent(
                        task_id=task_id,
                        agent="orchestrator",
                        kind="site_followups_spawned",
                        level="info",
                        message=f"单站协作已根据 {tgt.source} 覆盖记录派生 {spawned} 个定向追打 worker",
                        payload={
                            "target_id": target_id,
                            "host": dedup.normalize_host(tgt.url or tgt.host),
                            "source": tgt.source,
                            "spawned": spawned,
                        },
                    ))

            # 单站协作幂等兜底：主题深挖路线现在已在开局(_site_collect)与侦察路线一起
            # 并发入队，这里不再是必经门禁，只作兜底——万一开局某条主题路线入队失败，
            # discovery 侦察路线跑完后在此补派一次（靠 source 存在性去重，正常情况全跳过=no-op）。
            _theme_deepen_lead = (result.get("deepen_lead") or "").strip()
            _discovery_ok = (verdict == Verdict.no_vuln.value or verdict == Verdict.found.value or findings)
            if _discovery_ok and not _is_actionable_worker_deepen_lead(_theme_deepen_lead):
                theme_spawned = await self._spawn_site_theme_routes(session, task_id, tgt)
                if theme_spawned:
                    session.add(TaskEvent(
                        task_id=task_id,
                        agent="orchestrator",
                        kind="site_theme_routes_spawned",
                        level="info",
                        message=f"单站协作侦察完成（{tgt.source}），已派发 {theme_spawned} 条主题深挖路线",
                        payload={
                            "target_id": target_id,
                            "host": dedup.normalize_host(tgt.url or tgt.host),
                            "source": tgt.source,
                            "spawned": theme_spawned,
                        },
                    ))

            if quota_llm_error:
                tgt.verdict = ""
                tgt.status = "queued"
                tgt.assigned_worker = ""
                tgt.heartbeat_at = None
                tgt.last_error = error_text[:500]
                tgt.dead_reason = ""
                await self._stop_task_for_quota(session, error_text, target_id=target_id)
            elif transient_llm_error:
                tgt.verdict = ""
                tgt.status = "queued"
                tgt.assigned_worker = ""
                tgt.heartbeat_at = None
                tgt.last_error = error_text[:500]
                tgt.dead_reason = ""
            else:
                tgt.verdict = verdict
            if quota_llm_error:
                pass
            elif transient_llm_error:
                pass
            elif verdict == Verdict.needs_auth.value:
                # 目标有攻击面但需要用户提供凭证/完成注册才能继续深入。
                assessment = result.get("auth_assessment") or {}
                reg_status = assessment.get("reg_status", "")
                if reg_status == "not_registrable":
                    # 不可注册（CAS/SSO/邮箱限制/邀请制等）→ 直接跳过，不进 pending_input
                    tgt.status = "skipped"
                    tgt.verdict = "needs_auth"
                    tgt.auth_assessment = assessment
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.last_error = ""
                    tgt.dead_reason = assessment.get("block_reason", "")[:300] or "目标不可注册，无法获取登录态"
                else:
                    # 可注册但仅差验证码 → 等待用户提交凭证
                    tgt.status = "pending_input"
                    tgt.verdict = "needs_auth"
                    tgt.auth_assessment = assessment
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.last_error = ""
                    tgt.dead_reason = ""
            elif verdict == Verdict.found.value or findings:
                tgt.status = "done"
                tgt.assigned_worker = ""
                tgt.heartbeat_at = None
                tgt.last_error = ""
                tgt.dead_reason = ""
            elif verdict == Verdict.no_vuln.value:
                # 自动深挖回火：worker 突破了入口但没打穿，给了 deepen_lead → 带定向指令再派一轮
                # （复用 deepen_count + DEEPEN_CAP 防死循环；优先于收敛/重试/dead）。
                deepen_lead = (result.get("deepen_lead") or "").strip()
                no_vuln_retry_reason = self._no_vuln_retry_reason(tgt)
                if (_is_actionable_worker_deepen_lead(deepen_lead) and verdict == Verdict.no_vuln.value
                        and tgt.deepen_count < DEEPEN_CAP):
                    tgt.deepen_context = {
                        "directive": deepen_lead,
                        "vuln_type": "",
                        "original_title": "",
                        "original_summary": summary_text[:1000],
                        "from_finding_id": "",
                        "source": "worker_lead",
                    }
                    tgt.deepen_count += 1
                    tgt.verdict = ""
                    tgt.status = "queued"
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.retry_count = 0  # 深挖是新方向，不计入普通重试
                    tgt.priority_score = (tgt.priority_score or 0) + 100.0
                    tgt.priority_reason = f"[自动深挖#{tgt.deepen_count}] {deepen_lead[:80]}"
                    tgt.last_error = ""
                    tgt.dead_reason = ""
                    auto_deepen_info = (tgt.host, tgt.deepen_count, deepen_lead[:120])
                elif auto_converged:
                    tgt.status = "dead"
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.last_error = ""
                    tgt.dead_reason = summary_text[:300] or "系统自动收敛，无可利用漏洞"
                elif no_vuln_retry_reason and tgt.retry_count < MAX_RETRY:
                    tgt.retry_count += 1
                    tgt.verdict = ""
                    tgt.status = "queued"  # 换角度再挖一次
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.last_error = (no_vuln_retry_reason or summary_text or "高价值入口未打穿，回队换角度重试")[:500]
                    tgt.dead_reason = ""
                    worker_requeue_info = (tgt.host, no_vuln_retry_reason, tgt.retry_count)
                else:
                    tgt.status = "dead"
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.last_error = ""
                    tgt.dead_reason = (
                        "高价值入口重试仍无果，无可利用漏洞"
                        if no_vuln_retry_reason else
                        (summary_text[:300] or "本轮确认无可利用漏洞，不再默认重试")
                    )
            elif verdict == "ip_banned":
                tgt.status = "ip_banned"
                tgt.ip_ban_confirmed = True
                tgt.assigned_worker = ""
                tgt.heartbeat_at = None
                tgt.last_error = (summary_text or "IP 被 WAF 封禁")[:500]
                tgt.dead_reason = ""
            elif verdict == "timeout":
                if tgt.retry_count < MAX_RETRY:
                    tgt.retry_count += 1
                    tgt.verdict = ""
                    tgt.status = "queued"
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.last_error = (result.get("error") or summary_text or "worker 超时，回队重试")[:500]
                    tgt.dead_reason = ""
                    worker_requeue_info = (tgt.host, "worker 超时", tgt.retry_count)
                else:
                    tgt.status = "dead"
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.last_error = ""
                    tgt.dead_reason = "超时×重试仍无果"
            elif transient_exhausted:
                tgt.status = "dead"
                tgt.assigned_worker = ""
                tgt.heartbeat_at = None
                tgt.last_error = error_text[:500]
                tgt.dead_reason = (
                    f"LLM 持续异常：临时错误回队已达上限 {MAX_TRANSIENT_LLM_REQUEUE} 次，模型服务可能不稳定"
                )[:300]
                self._transient_llm_requeue.pop(target_id, None)
            else:
                tgt.status = "dead"  # error：置 dead 并记因，避免无声卡死
                tgt.assigned_worker = ""
                tgt.heartbeat_at = None
                tgt.last_error = (result.get("error") or "worker 异常")[:500]
                tgt.dead_reason = (result.get("error") or "worker 异常")[:300]
            # 目标已离开「持续临时错误」状态（成功/无果/置dead），清理回队计数避免泄漏累积。
            if not transient_llm_error:
                self._transient_llm_requeue.pop(target_id, None)
            await session.commit()
            if auto_deepen_info:
                host, dc, lead = auto_deepen_info
                await self._log(session, "worker", "auto_deepen",
                                f"目标 {host} 突破入口未打穿，自动定向深挖#{dc}：{lead}",
                                level="info", target_id=target_id, verdict="deepen", findings=0)
            elif quota_llm_error:
                await self._log(session, "orchestrator", "quota_stop",
                                f"LLM/API 额度不足，任务已自动停止: {error_text[:120]}",
                                level="error", target_id=target_id, verdict="quota_stop", findings=0)
            elif transient_llm_error:
                await self._log(session, "worker", "target_requeued",
                                f"目标 {tgt.host} 因临时 LLM 错误回队列(第 "
                                f"{self._transient_llm_requeue.get(target_id, 0)}/{MAX_TRANSIENT_LLM_REQUEUE} 次): "
                                f"{error_text[:120]}",
                                level="warn", target_id=target_id, verdict="retry", findings=0)
            elif worker_requeue_info:
                host, reason, count = worker_requeue_info
                await self._log(session, "worker", "target_requeued",
                                f"目标 {host} {reason}，回队重试(第 {count}/{MAX_RETRY} 次)",
                                level="info", target_id=target_id, verdict="retry", findings=0)
            elif transient_exhausted:
                await self._log(session, "worker", "target_done",
                                f"目标 {tgt.host} 因 LLM 持续异常收敛置 dead（回队达上限 {MAX_TRANSIENT_LLM_REQUEUE} 次）",
                                level="warn", target_id=target_id, verdict="dead", findings=0)
            elif verdict == "ip_banned":
                await self._log(session, "worker", "target_ip_banned",
                                f"目标 {tgt.host} 确认 IP 被 WAF 封禁，等待首轮完成后代理复测",
                                level="warn", target_id=target_id, verdict="ip_banned", findings=0)
            elif verdict == "needs_auth":
                assessment = result.get("auth_assessment") or {}
                reg_status = assessment.get("reg_status", "")
                block_reason = assessment.get("block_reason", "")
                if reg_status == "not_registrable":
                    await self._log(session, "worker", "target_done",
                                    f"目标 {tgt.host} 不可注册，已自动跳过：{block_reason or reg_status}",
                                    level="info", target_id=target_id, verdict="skipped", findings=len(findings))
                else:
                    await self._log(session, "worker", "target_needs_auth",
                                    f"目标 {tgt.host} 需要手动注册/提供凭证：{block_reason or reg_status}",
                                    level="info", target_id=target_id, verdict="needs_auth", findings=len(findings))
            else:
                await self._log(session, "worker", "target_done",
                                f"目标 {tgt.host} 完成: {verdict}, {len(findings)} 个漏洞",
                                target_id=target_id, verdict=verdict, findings=len(findings))

    @staticmethod
    def _is_transient_worker_error(error: str) -> bool:
        text = (error or "").lower()
        if not any(k in text for k in ("llm 调用失败", "llm 请求", "llm 网络", "llm 上游")):
            return False
        if TaskRunner._is_quota_error(error):
            return False
        if any(k in text for k in ("api key", "unauthorized", "无效", "无权限", "invalid")):
            return False
        markers = (
            "rate limit", "限流", "too many requests", "429",
            "timeout", "timed out", "超时",
            "network", "connection", "连接失败",
            "temporarily", "temporary", "upstream", "临时异常", "上游",
            # 模型服务偶发抽风返回的「未知错误」也是临时性的：不该消耗 retry/置 dead，
            # 否则模型一抖动就把还能挖的目标白白打死（实测 20 个目标这么死的）。
            "未知错误", "模型服务返回", "底层细节已脱敏",
        )
        return "llm 调用失败" in text and any(m in text for m in markers)

    @staticmethod
    def _is_quota_error(error: str) -> bool:
        text = (error or "").lower()
        return any(k in text for k in ("额度不足", "余额不足", "insufficient_quota", "billing", "balance"))

    @staticmethod
    def _summarize_exc(exc: BaseException) -> str:
        """把异常压成可读诊断：异常类型 + 首行消息，专治 SQLAlchemy 把整条
        SQL 语句和全部参数（含 leaked_creds 明文）糊进 str(exc) 的问题——那既看不到
        病根，又会把敏感数据写进事件流。这里只取类名 + 消息首行，并砍掉 SQL 语句体。
        """
        parts: list[str] = []
        seen: set[int] = set()
        cur: BaseException | None = exc
        while cur is not None and id(cur) not in seen:
            seen.add(id(cur))
            cls = type(cur).__name__
            msg = str(cur)
            # SQLAlchemy: 消息形如 "(sqlite3.IntegrityError) UNIQUE ... [SQL: INSERT ...] [parameters: ...]"
            # 只保留到 [SQL: 之前的核心报错，丢弃 SQL 语句体与参数（可能含明文凭证）。
            for cut in ("\n[SQL:", " [SQL:", "[SQL:", "[parameters:"):
                idx = msg.find(cut)
                if idx != -1:
                    msg = msg[:idx]
            msg = " ".join(msg.split())[:200]
            parts.append(f"{cls}: {msg}" if msg else cls)
            cur = cur.__cause__ or cur.__context__
            if len(parts) >= 4:
                break
        return " ← ".join(parts)

    async def _stop_task_for_quota(self, session: AsyncSession, error: str, **payload) -> None:
        task = await session.get(Task, self.task_id)
        if task and task.status != "stopped":
            task.status = "stopped"
            await session.commit()
        self._stop.set()

    async def _dispatch_reviews(self, session: AsyncSession, task: Task) -> None:
        pending = (await session.execute(
            select(Finding).where(Finding.task_id == self.task_id, Finding.status == "pending_review").limit(5)
        )).scalars().all()
        now = asyncio.get_running_loop().time()
        for f in pending:
            if f.id in self._review_inflight:
                continue
            if self._review_backoff.get(f.id, 0) > now:
                continue
            self._review_inflight.add(f.id)
            self._review_tasks[f.id] = asyncio.create_task(self._run_review(task.id, f.id))

    async def _run_review(self, task_id: str, finding_id: str) -> None:
        # try/finally 兜底：任何异常路径都释放 inflight，避免 finding 永久卡死不被审核
        try:
            await self._run_review_inner(task_id, finding_id)
        except Exception:
            async with SessionLocal() as s:
                await self._log(s, "reviewer", "error",
                                f"审核协程异常: {traceback.format_exc()[:400]}", level="error",
                                finding_id=finding_id)
        finally:
            self._review_inflight.discard(finding_id)
            self._review_tasks.pop(finding_id, None)

    async def _run_review_inner(self, task_id: str, finding_id: str) -> None:
        loop = asyncio.get_running_loop()
        async with SessionLocal() as session:
            f = await session.get(Finding, finding_id)
            if not f:
                return
            task_obj = await session.get(Task, task_id)
            src_type = (task_obj.src_type if task_obj else "edusrc") or "edusrc"
            finding_schema = FindingSchema(
                vuln_type=f.vuln_type, title=f.title, severity_claimed=f.severity_claimed,
                target_url=f.target_url, description=f.description, steps=f.steps,
                poc=f.poc, raw_request=f.raw_request, raw_response=f.raw_response,
                evidence=f.evidence or {}, affected_scope=f.affected_scope,
                kill_chain=f.kill_chain or [], self_check=f.self_check or {},
                owner=f.owner or "",
            )
            llm = _llm_for_task(task_obj)

        def emit(kind: str, data: dict):
            asyncio.run_coroutine_threadsafe(
                bus.publish(task_id, {"agent": "reviewer", "kind": kind, "finding_id": finding_id, **data}),
                loop,
            )

        def do_review() -> dict:
            reviewer = Reviewer(llm=llm, on_event=emit, src_type=src_type)
            return reviewer.review(finding_schema).model_dump(mode="json")

        review_sem = agent_semaphore("review")
        await review_sem.acquire()
        try:
            review_future = loop.run_in_executor(AGENT_EXECUTOR, do_review)
        except BaseException:
            # submit 本身抛错(如池已关闭)——立即归还信号量，否则并发位永久丢失。
            review_sem.release()
            raise

        def _release_review(fut: asyncio.Future) -> None:
            review_sem.release()
            _consume_task_exception(fut)  # 超时/取消后 future 仍在后台跑，消费异常防告警

        review_future.add_done_callback(_release_review)
        try:
            rv = await asyncio.wait_for(
                asyncio.shield(review_future),
                timeout=REVIEW_WALL_TIMEOUT,
            )
        except asyncio.TimeoutError:
            self._review_backoff[finding_id] = loop.time() + REVIEW_RETRY_BACKOFF
            async with SessionLocal() as s:
                await self._log(s, "reviewer", "review_deferred",
                                f"审核超时(>{int(REVIEW_WALL_TIMEOUT)}s)，保留 pending_review，稍后重试",
                                level="warn", finding_id=finding_id)
            return
        except asyncio.CancelledError:
            self._review_backoff[finding_id] = loop.time() + REVIEW_RETRY_BACKOFF
            async with SessionLocal() as s:
                await self._log(s, "reviewer", "review_cancelled",
                                "审核任务被控制面取消，保留 pending_review，稍后重试",
                                level="warn", finding_id=finding_id)
            return
        except Exception as e:
            if self._is_quota_error(str(e)):
                async with SessionLocal() as s:
                    await self._stop_task_for_quota(s, str(e), finding_id=finding_id)
                    await self._log(s, "orchestrator", "quota_stop",
                                    f"审核阶段检测到 LLM/API 额度不足，任务已自动停止: {str(e)[:120]}",
                                    level="error", finding_id=finding_id)
                return
            self._review_backoff[finding_id] = loop.time() + REVIEW_RETRY_BACKOFF
            async with SessionLocal() as s:
                await self._log(s, "reviewer", "review_deferred",
                                f"审核异常，保留 pending_review，稍后重试: {str(e)[:160]}",
                                level="warn", finding_id=finding_id)
            return

        # accepted 必须有最终等级；LLM 漏填时按 worker 自评兜底，避免最终列表等级空白
        if rv.get("verdict") == "accepted" and not rv.get("severity_final"):
            async with SessionLocal() as s:
                f0 = await s.get(Finding, finding_id)
                rv["severity_final"] = (f0.severity_claimed if f0 else None) or "中危"
            rv["reviewer_notes"] = (rv.get("reviewer_notes", "") +
                                    "\n[系统] 审核未给最终等级，已按 worker 自评兜底。").strip()

        escalate_finding = False
        async with SessionLocal() as session:
            f = await session.get(Finding, finding_id)
            if f:
                session.add(Review(
                    finding_id=finding_id, task_id=task_id,
                    verdict=rv["verdict"], confidence=rv["confidence"],
                    severity_final=rv.get("severity_final"), score=rv["score"],
                    in_scope=rv["in_scope"], is_duplicate=rv.get("is_duplicate", False),
                    ignore_reasons=rv.get("ignore_reasons", []),
                    downgrade_reasons=rv.get("downgrade_reasons", []),
                    reproduced=rv.get("reproduced", False), reviewer_notes=rv.get("reviewer_notes", ""),
                    deepen_directive=rv.get("deepen_directive", ""),
                ))
                extra = ""
                if rv["verdict"] == "deepen":
                    extra = await self._apply_deepen(session, f, rv)
                else:
                    f.status = "reviewed"
                await session.commit()
                await self._log(session, "reviewer", "review_done",
                                f"审核「{f.title}」: {rv['verdict']} {rv.get('severity_final') or ''}{extra}",
                                finding_id=finding_id, verdict=rv["verdict"],
                                severity=rv.get("severity_final"), score=rv["score"])
                # 通杀 Hunter 不在 AI accepted 后触发；必须等人工复审 passed 后再启动。
                # 扩大危害 Hunter：AI accepted 后自动触发（仅对有纵向升级空间的洞），
                # 顺着已确认据点再打一层，显著升级才产出新 finding，否则丢弃。
                escalate_finding = (
                    rv["verdict"] == "accepted"
                    and f.worker_id != "escalation"  # 断递归：升级洞不再触发升级
                    and should_escalate(f.vuln_type, f.title, rv.get("severity_final") or "")
                )
        # commit 之后、脱离 session 再触发，避免把后台任务寿命绑在本次事务上。
        if escalate_finding:
            self.trigger_escalation(task_id, finding_id, rv.get("severity_final") or "")

    async def _apply_deepen(self, session: AsyncSession, finding: Finding, rv: dict) -> str:
        """审核打回深挖：复用共享回炉逻辑（与人工复审「继续深挖」同一套）。"""
        from app.agents.deepen import apply_deepen
        tgt = await session.get(Target, finding.target_id)
        _ok, suffix = apply_deepen(session, finding, tgt,
                                   rv.get("deepen_directive") or "", source="ai")
        return suffix

    def trigger_killsweep(self, task_id: str, finding_id: str) -> bool:
        """人工复审通过后启动通杀分析；finding 级 inflight 去重，避免重复点击。"""
        if finding_id in self._killsweep_inflight:
            return False
        self._killsweep_inflight.add(finding_id)
        self._killsweep_tasks[finding_id] = asyncio.create_task(self._run_killsweep(task_id, finding_id))
        return True

    async def _run_killsweep(self, task_id: str, finding_id: str) -> None:
        """通杀 Hunter：人工复审通过后，分析该漏洞所在系统能否一打一片。
        按产品指纹去重；判定可通杀且验证成功 → 把那个同款站点入挖掘队列出货。"""
        try:
            await self._run_killsweep_inner(task_id, finding_id)
        except Exception:
            async with SessionLocal() as s:
                await self._log(s, "killsweep", "error",
                                f"通杀分析异常: {traceback.format_exc()[:400]}", level="error",
                                finding_id=finding_id)
        finally:
            self._killsweep_inflight.discard(finding_id)
            self._killsweep_tasks.pop(finding_id, None)
            self._killsweep_cancel_events.pop(finding_id, None)

    async def _run_killsweep_inner(self, task_id: str, finding_id: str) -> None:
        from app.agents.killsweep import KillsweepHunter, product_key
        loop = asyncio.get_running_loop()

        async with SessionLocal() as session:
            f = await session.get(Finding, finding_id)
            if not f:
                return
            task = await session.get(Task, task_id)
            fofa_key = resolve_fofa_key(task)
            fofa_base_url = resolve_fofa_base_url(task)
            src_type = (task.src_type if task else "edusrc") or "edusrc"
            enable_killsweep_fofa_search = getattr(task, 'enable_killsweep_fofa_search', True) if task else True
            finding_dict = {
                "title": f.title, "vuln_type": f.vuln_type, "target_url": f.target_url,
                "owner": f.owner, "description": f.description, "poc": f.poc,
                "raw_response": f.raw_response,
            }
            origin_host = f.target_url

        if not fofa_key:
            async with SessionLocal() as s:
                await self._log(s, "killsweep", "skip", "无 FOFA key，跳过通杀分析",
                                level="warn", finding_id=finding_id)
            return

        llm = _llm_for_task(await self._get_task(task_id))
        cancel_event = threading.Event()
        self._killsweep_cancel_events[finding_id] = cancel_event

        def emit(kind: str, data: dict):
            asyncio.run_coroutine_threadsafe(
                bus.publish(task_id, {"agent": "killsweep", "kind": kind, "finding_id": finding_id, **data}),
                loop,
            )

        def do_hunt() -> dict:
            hunter = KillsweepHunter(
                finding_dict, fofa_key, llm=llm, on_event=emit,
                src_type=src_type, cancel_event=cancel_event,
                fofa_base_url=fofa_base_url,
                enable_fofa_search=enable_killsweep_fofa_search,
            )
            try:
                return hunter.run().model_dump(mode="json")
            finally:
                # 正常完成清理：只杀子进程，不污染 cancel_event（同 worker 修复）。
                hunter.executor.kill_processes()

        killsweep_sem = agent_semaphore("killsweep")
        await killsweep_sem.acquire()
        try:
            hunt_future = loop.run_in_executor(AGENT_EXECUTOR, do_hunt)
        except BaseException:
            killsweep_sem.release()
            raise

        def _release_killsweep(fut: asyncio.Future) -> None:
            killsweep_sem.release()
            _consume_task_exception(fut)

        hunt_future.add_done_callback(_release_killsweep)
        try:
            res = await asyncio.wait_for(
                asyncio.shield(hunt_future),
                timeout=KILLSWEEP_WALL_TIMEOUT,
            )
        except asyncio.TimeoutError:
            cancel_event.set()
            try:
                await asyncio.wait_for(asyncio.shield(hunt_future), timeout=WORKER_CLEANUP_TIMEOUT)
            except Exception:
                hunt_future.add_done_callback(_consume_task_exception)
            res = {"error": f"通杀分析超时(>{int(KILLSWEEP_WALL_TIMEOUT)}s)"}
        except asyncio.CancelledError:
            cancel_event.set()
            hunt_future.add_done_callback(_consume_task_exception)
            async with SessionLocal() as s:
                await self._log(s, "killsweep", "cancelled",
                                "通杀分析被控制面取消，未写入结果",
                                level="warn", finding_id=finding_id)
            return
        except Exception as e:
            res = {"error": str(e)}

        if res.get("error"):
            async with SessionLocal() as s:
                if self._is_quota_error(str(res["error"])):
                    await self._stop_task_for_quota(s, str(res["error"]), finding_id=finding_id)
                    await self._log(s, "orchestrator", "quota_stop",
                                    f"通杀阶段检测到 LLM/API 额度不足，任务已自动停止: {str(res['error'])[:120]}",
                                    level="error", finding_id=finding_id)
                else:
                    await self._log(s, "killsweep", "error", f"通杀分析失败: {res['error']}",
                                    level="warn", finding_id=finding_id)
            return

        pkey = product_key(res.get("product_name", ""), res.get("fofa_query", ""), res.get("fingerprint", ""))
        affected_table = res.get("affected_table") or []
        if res.get("verified_url") and not affected_table:
            vhost = collector.normalize_host(res["verified_url"])
            affected_table = [{
                "school": "待确认",
                "url": res["verified_url"],
                "host": vhost,
                "title": "",
                "vuln_type": finding_dict["vuln_type"],
                "vuln_title": finding_dict["title"],
                "status": "verified" if res.get("verified") else "candidate",
                "evidence": "通杀 Hunter 实打验证站点" if res.get("verified") else "通杀 Hunter 圈定候选",
                "dedup_key": hashlib.md5(
                    f"killsweep|{vhost}|{finding_dict['vuln_type'].lower()}|{finding_dict['title']}".encode()
                ).hexdigest(),
            }]
        async with SessionLocal() as session:
            # 产品指纹去重：同款系统同类洞已分析过则跳过（保留首条）
            exists = (await session.execute(
                select(Killsweep).where(Killsweep.task_id == task_id, Killsweep.product_key == pkey)
            )).scalar_one_or_none()
            if exists:
                await self._log(session, "killsweep", "dedup",
                                f"同款产品已分析过，跳过：{res.get('product_name','')}",
                                finding_id=finding_id)
                return
            try:
                async with session.begin_nested():
                    session.add(Killsweep(
                        task_id=task_id, origin_finding_id=finding_id, product_key=pkey,
                        product_name=res.get("product_name", ""), vuln_type=finding_dict["vuln_type"],
                        vuln_summary=finding_dict["title"], fofa_query=res.get("fofa_query", ""),
                        fingerprint=res.get("fingerprint", ""), asset_count=res.get("asset_count", 0),
                        edu_count=res.get("edu_count", 0), is_killsweep=res.get("is_killsweep", False),
                        confidence=res.get("confidence", ""), verified_url=res.get("verified_url", ""),
                        verified=res.get("verified", False), affected_table=affected_table,
                        notes=res.get("notes", ""),
                        status="done",
                    ))
            except IntegrityError:
                return  # 并发撞唯一索引，跳过

            # 判定可通杀 + 实证验证成功 → 把那个同款站点入挖掘队列出货
            enq = ""
            if res.get("is_killsweep") and res.get("verified") and res.get("verified_url"):
                added = await self._enqueue_killsweep_target(
                    session, task_id, res["verified_url"], origin_host)
                enq = "；已将验证成功的同款站点入队出货" if added else ""
            await session.commit()
            await self._log(session, "killsweep", "killsweep_done",
                            f"通杀分析「{res.get('product_name','')}」: "
                            f"{'可通杀' if res.get('is_killsweep') else '不可通杀'} "
                            f"(全网{res.get('asset_count',0)}/教育{res.get('edu_count',0)}){enq}",
                            finding_id=finding_id, is_killsweep=res.get("is_killsweep"),
                            asset_count=res.get("asset_count", 0))

    async def _enqueue_killsweep_target(self, session: AsyncSession, task_id: str,
                                        url: str, origin: str) -> bool:
        """把通杀验证成功的同款站点作为新目标入队（host 去重；拉高优先级）。"""
        host = collector.normalize_host(url)
        if not host or host == collector.normalize_host(origin):
            return False
        exists = (await session.execute(
            select(Target).where(Target.task_id == task_id, Target.host == host)
        )).scalar_one_or_none()
        if exists:
            return False
        try:
            async with session.begin_nested():
                session.add(Target(
                    task_id=task_id, url=collector._ensure_url(host), host=host,
                    source="killsweep", status="queued", is_edu=True,
                    priority_score=120.0, priority_reason="[通杀验证] 同款系统已实证中招，重点出货",
                ))
        except IntegrityError:
            return False
        return True

    def trigger_escalation(self, task_id: str, finding_id: str, orig_severity: str) -> bool:
        """AI accepted 后触发扩大危害深挖；finding 级 inflight 去重，单洞只打一次。"""
        if finding_id in self._escalation_inflight:
            return False
        self._escalation_inflight.add(finding_id)
        self._escalation_tasks[finding_id] = asyncio.create_task(
            self._run_escalation(task_id, finding_id, orig_severity)
        )
        return True

    async def _run_escalation(self, task_id: str, finding_id: str, orig_severity: str) -> None:
        try:
            await self._run_escalation_inner(task_id, finding_id, orig_severity)
        except Exception:
            async with SessionLocal() as s:
                await self._log(s, "escalation", "error",
                                f"扩大危害深挖异常: {traceback.format_exc()[:400]}", level="error",
                                finding_id=finding_id)
        finally:
            self._escalation_inflight.discard(finding_id)
            self._escalation_tasks.pop(finding_id, None)
            self._escalation_cancel_events.pop(finding_id, None)

    async def _run_escalation_inner(self, task_id: str, finding_id: str, orig_severity: str) -> None:
        from app.agents.escalate import EscalateHunter
        loop = asyncio.get_running_loop()

        async with SessionLocal() as session:
            f = await session.get(Finding, finding_id)
            if not f:
                return
            task = await session.get(Task, task_id)
            src_type = (task.src_type if task else "edusrc") or "edusrc"
            target_id = f.target_id
            finding_dict = {
                "title": f.title, "vuln_type": f.vuln_type, "target_url": f.target_url,
                "owner": f.owner, "description": f.description, "poc": f.poc,
                "raw_request": f.raw_request, "raw_response": f.raw_response,
                "kill_chain": f.kill_chain, "severity": orig_severity,
            }

        llm = _llm_for_task(await self._get_task(task_id))
        cancel_event = threading.Event()
        self._escalation_cancel_events[finding_id] = cancel_event

        def emit(kind: str, data: dict):
            asyncio.run_coroutine_threadsafe(
                bus.publish(task_id, {"agent": "escalation", "kind": kind, "finding_id": finding_id, **data}),
                loop,
            )

        def do_hunt() -> dict:
            hunter = EscalateHunter(
                finding_dict, llm=llm, on_event=emit,
                src_type=src_type, cancel_event=cancel_event,
            )
            try:
                return hunter.run().model_dump(mode="json")
            finally:
                hunter.executor.kill_processes()

        escalate_sem = agent_semaphore("escalation")
        await escalate_sem.acquire()
        try:
            hunt_future = loop.run_in_executor(AGENT_EXECUTOR, do_hunt)
        except BaseException:
            escalate_sem.release()
            raise

        def _release_escalation(fut: asyncio.Future) -> None:
            escalate_sem.release()
            _consume_task_exception(fut)

        hunt_future.add_done_callback(_release_escalation)
        try:
            res = await asyncio.wait_for(asyncio.shield(hunt_future), timeout=ESCALATE_WALL_TIMEOUT)
        except asyncio.TimeoutError:
            cancel_event.set()
            try:
                await asyncio.wait_for(asyncio.shield(hunt_future), timeout=WORKER_CLEANUP_TIMEOUT)
            except Exception:
                hunt_future.add_done_callback(_consume_task_exception)
            res = {"escalated": False, "reason": f"扩大危害深挖超时(>{int(ESCALATE_WALL_TIMEOUT)}s)"}
        except asyncio.CancelledError:
            cancel_event.set()
            hunt_future.add_done_callback(_consume_task_exception)
            return
        except Exception as e:
            res = {"error": str(e)}

        if res.get("error"):
            async with SessionLocal() as s:
                if self._is_quota_error(str(res["error"])):
                    await self._stop_task_for_quota(s, str(res["error"]), finding_id=finding_id)
                    await self._log(s, "orchestrator", "quota_stop",
                                    f"扩大危害阶段检测到 LLM/API 额度不足，任务已自动停止: {str(res['error'])[:120]}",
                                    level="error", finding_id=finding_id)
                else:
                    await self._log(s, "escalation", "error", f"扩大危害深挖失败: {res['error']}",
                                    level="warn", finding_id=finding_id)
            return

        # 显著性门槛：不显著就丢弃，只留一条事件，不产出新 finding、不污染报告。
        if not _escalation_is_significant(orig_severity, res):
            reason = res.get("reason") or "未达到显著升级门槛（等级未提升且影响面无质变）"
            async with SessionLocal() as s:
                await self._log(s, "escalation", "escalate_skip",
                                f"扩大危害未显著，已放弃: {reason[:160]}", finding_id=finding_id)
            return

        await self._persist_escalation_finding(task_id, target_id, finding_id, orig_severity, res)

    async def _persist_escalation_finding(self, task_id: str, target_id: str, origin_finding_id: str,
                                          orig_severity: str, res: dict) -> None:
        """显著升级 → 生成一个全新 Finding（走 pending_review 审核流程，进报告）。

        原 finding 不动；新 finding 用独立 dedup_key，避免被原洞查重拦掉。
        """
        title = res.get("title") or "扩大危害升级"
        vuln_type = res.get("vuln_type") or ""
        new_severity = res.get("severity") or orig_severity
        finding_payload = {
            "description": res.get("description", ""),
            "poc": res.get("poc", ""),
            "raw_request": res.get("raw_request", ""),
            "raw_response": res.get("raw_response", ""),
            "affected_scope": res.get("affected_scope", ""),
            "kill_chain": res.get("kill_chain", []),
        }
        async with SessionLocal() as session:
            origin = await session.get(Finding, origin_finding_id)
            if origin is None:
                return
            base_ref = origin.target_url or origin.owner or origin_finding_id
            payload_for_key = {
                "title": title, "vuln_type": vuln_type,
                "target_url": origin.target_url, "host": origin.target_url,
            }
            # 独立 dedup_key：拼上升级标记 + 源 finding，确保不与原洞撞键。
            base_key = dedup.dedup_key(base_ref, payload_for_key)
            new_key = f"{base_key}:esc:{origin_finding_id[:8]}"
            try:
                async with session.begin_nested():
                    session.add(Finding(
                        task_id=task_id, target_id=target_id, worker_id="escalation",
                        vuln_type=vuln_type, title=title,
                        severity_claimed=new_severity,
                        target_url=origin.target_url, owner=origin.owner,
                        description=finding_payload["description"],
                        steps=[], poc=finding_payload["poc"],
                        raw_request=finding_payload["raw_request"],
                        raw_response=finding_payload["raw_response"],
                        evidence={"escalated_from": origin_finding_id, "orig_severity": orig_severity,
                                  "impact_count": int(res.get("impact_count", 0) or 0)},
                        affected_scope=finding_payload["affected_scope"],
                        kill_chain=finding_payload["kill_chain"],
                        self_check={},
                        dedup_key=new_key, status="pending_review",
                    ))
                await session.commit()
            except IntegrityError:
                # 已存在同键升级洞（重复触发/并发），跳过。
                return
            await self._log(session, "escalation", "escalate_done",
                            f"扩大危害成功「{origin.title}」→「{title}」({orig_severity}→{new_severity})，"
                            f"已生成新洞进审核",
                            finding_id=origin_finding_id, new_severity=new_severity)

    async def _get_task(self, task_id: str) -> Task:
        async with SessionLocal() as s:
            return await s.get(Task, task_id)

    # stop/pause 的实现靠前定义；这里不再提供只置位的旧版 stop，避免绕过 worker 收回逻辑。


class OrchestratorManager:
    """管理所有任务的 runner。FastAPI lifespan 启动时恢复 running 任务。"""

    def __init__(self) -> None:
        self._runners: dict[str, TaskRunner] = {}
        self._tasks: dict[str, asyncio.Task] = {}

    def get_runner(self, task_id: str) -> "TaskRunner | None":
        return self._runners.get(task_id)

    def diagnostic_snapshot(self) -> dict:
        return {
            "runner_count": len(self._runners),
            "task_count": len(self._tasks),
            "runners": {
                task_id: runner.diagnostic_snapshot()
                for task_id, runner in self._runners.items()
            },
            "tasks": {
                task_id: {
                    "done": task.done(),
                    "cancelled": task.cancelled(),
                    "coro": getattr(task.get_coro(), "__qualname__", repr(task.get_coro())),
                }
                for task_id, task in self._tasks.items()
            },
        }

    async def trigger_killsweep(self, task_id: str, finding_id: str) -> bool:
        """人工复审通过后触发通杀 Hunter。

        任务即使当前不在 running，也允许做一次离线通杀分析；这里创建轻量 runner
        只承载该后台任务，不自动启动主挖掘循环。
        """
        runner = self._runners.get(task_id)
        if not runner:
            runner = TaskRunner(task_id)
            # 离线通杀也挂到 manager，后续 stop/pause 才能统一取消它。
            self._runners[task_id] = runner
        return runner.trigger_killsweep(task_id, finding_id)

    async def ensure_running(self, task_id: str) -> None:
        existing_task = self._tasks.get(task_id)
        if task_id in self._runners and existing_task and not existing_task.done():
            return
        if existing_task and existing_task.done():
            self._tasks.pop(task_id, None)
        runner = self._runners.get(task_id)
        if not runner or runner._stop.is_set():
            runner = TaskRunner(task_id)
            self._runners[task_id] = runner
        self._runners[task_id] = runner
        self._tasks[task_id] = asyncio.create_task(runner.run_forever())

    async def stop(self, task_id: str) -> None:
        runner = self._runners.pop(task_id, None)
        if runner:
            await runner.stop()
        t = self._tasks.pop(task_id, None)
        if t:
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await t

    async def pause(self, task_id: str) -> None:
        runner = self._runners.get(task_id)
        if runner:
            await runner.pause()

    async def restore_on_startup(self) -> None:
        """重启恢复：把 running/idle 的任务重新拉起。"""
        async with SessionLocal() as session:
            rows = await session.execute(select(Task).where(Task.status.in_(["running", "idle"])))
            for task in rows.scalars().all():
                await self.ensure_running(task.id)

    async def pause_on_startup(self) -> None:
        """安全启动模式：只恢复 Web/API，把历史运行任务暂停并回收半路目标。"""
        async with SessionLocal() as session:
            rows = (await session.execute(
                select(Task).where(Task.status.in_(["running", "idle"]))
            )).scalars().all()
            for task in rows:
                runner = TaskRunner(task.id)
                await runner.recover(session)
                task.status = "paused"
                await session.commit()
                await runner._log(
                    session, "orchestrator", "safe_startup_pause",
                    "安全启动模式：容器启动未自动恢复任务，已暂停历史 running/idle 任务",
                    level="warn",
                )

    async def shutdown(self) -> None:
        """应用退出时统一取消 runner，关闭线程池，避免子线程/子进程拖住 uvicorn。"""
        task_ids = list(self._runners.keys())
        await asyncio.gather(*(self.stop(task_id) for task_id in task_ids), return_exceptions=True)
        shutdown_agent_executor()


manager = OrchestratorManager()
