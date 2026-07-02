"""漏洞与审核结果 API：原始漏洞列表 / 最终结果列表(分档) / 详情 / 用户裁决。"""
from __future__ import annotations

import asyncio
import json
import os
import re
import threading
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_runtime import AGENT_EXECUTOR, agent_semaphore
from app.agents.deepen import apply_deepen
from app.settings_service import llm_client_for_task
from app.db.models import Finding, Killsweep, Review, Target, Task, TaskEvent
from app.db.session import get_session
from app.events import bus
from app.llm.client import LLMClient, LLMError
from app.tools.executor import ToolExecutor


def _now() -> datetime:
    return datetime.now(timezone.utc)

router = APIRouter(prefix="/api", tags=["findings"])

_ASSISTANT_WELCOME = (
    "我可以回答这份报告的证据、危害、复现、修复问题。"
    "你也可以让我再发一个请求或跑一个简短 curl 做补充验证。"
)
_ASSISTANT_MSG_CAP = 100
_ASSISTANT_WALL_TIMEOUT = float(os.environ.get("REPORT_ASSISTANT_WALL_TIMEOUT", "300"))
_ASSISTANT_HISTORY_TURNS = int(os.environ.get("REPORT_ASSISTANT_HISTORY_TURNS", "6"))
_ASSISTANT_HISTORY_CHARS = int(os.environ.get("REPORT_ASSISTANT_HISTORY_CHARS", "1000"))
_ASSISTANT_STATIC_PREFIX = (
    "下一条消息是当前漏洞报告的裁剪上下文。已保留请求、响应、证据、攻击链和审核备注的关键头尾；"
    "先基于上下文回答，只有用户明确要求复测时才调用工具。"
)


def _consume_future_exception(fut) -> None:
    try:
        fut.exception()
    except (asyncio.CancelledError, Exception):
        pass


def _default_assistant_messages() -> list[dict]:
    return [{"role": "assistant", "content": _ASSISTANT_WELCOME}]


def _sanitize_assistant_messages(msgs: list | None) -> list[dict]:
    out: list[dict] = []
    for m in msgs or []:
        role = m.get("role")
        content = (m.get("content") or "").strip()
        if role in ("user", "assistant") and content:
            out.append({"role": role, "content": content[:8000]})
    return out[-_ASSISTANT_MSG_CAP:]


def _clip_text(text: str, limit: int) -> str:
    text = str(text or "")
    if len(text) <= limit:
        return text
    head = max(1, int(limit * 0.65))
    tail = max(1, limit - head - 50)
    return f"{text[:head]}\n...[已截断 {len(text) - limit} 字]...\n{text[-tail:]}"


def _clip_json(value, limit: int) -> str:
    data = {} if value is None else value
    return _clip_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), limit)


def _matches_query(data: dict, q: str | None) -> bool:
    """列表搜索：跨标题、URL、类型、报告正文、审核理由等字段做轻量全文匹配。"""
    needle = (q or "").strip().lower()
    if not needle:
        return True
    haystack = json.dumps(data, ensure_ascii=False, default=str).lower()
    return needle in haystack


def _finding_dict(f: Finding, r: Review | None, *, compact: bool = False) -> dict:
    user_edits = r.user_edits or {} if r else {}
    item = {
        "id": f.id,
        "task_id": f.task_id,
        "target_id": f.target_id,
        "vuln_type": f.vuln_type,
        "title": f.title,
        "severity_claimed": f.severity_claimed,
        "target_url": f.target_url,
        "owner": f.owner,
        "status": f.status,
        "created_at": f.created_at.isoformat(),
        "review": None if not r else {
            "verdict": r.verdict,
            "confidence": r.confidence,
            "severity_final": r.severity_final,
            "score": r.score,
            "in_scope": r.in_scope,
            "is_duplicate": r.is_duplicate,
            "ignore_reasons": [] if compact else r.ignore_reasons,
            "downgrade_reasons": [] if compact else r.downgrade_reasons,
            "reproduced": r.reproduced,
            "reviewer_notes": "" if compact else r.reviewer_notes,
            "deepen_directive": "" if compact else r.deepen_directive,
            "user_status": r.user_status,
            "user_severity": r.user_severity,
            "user_notes": "" if compact else r.user_notes,
            "user_edits": (
                {"title": user_edits["title"]}
                if compact and user_edits.get("title")
                else ({} if compact else user_edits)
            ),
            "submitted": r.submitted,
            # 最终生效等级：用户调整优先，否则 AI 等级
            "effective_severity": r.user_severity or r.severity_final,
        },
    }
    if compact:
        return item
    item.update({
        "description": f.description,
        "steps": f.steps,
        "poc": f.poc,
        "raw_request": f.raw_request,
        "raw_response": f.raw_response,
        "evidence": f.evidence,
        "affected_scope": f.affected_scope,
        "kill_chain": f.kill_chain or [],
        "assistant_messages": _sanitize_assistant_messages(f.assistant_messages)
        if (f.assistant_messages or [])
        else _default_assistant_messages(),
        "self_check": f.self_check,
        # 写报告用的高校归属：这里先用「零阻塞」的纯 IP 查库（不做 DNS，避免拖慢列表）。
        # 域名目标的归属由 get_finding 详情接口异步补全（见 _resolve_edu_school_async）。
        "edu_school": _edu_school_fast(f.target_url),
    })
    return item


def _edu_school_fast(target_url: str | None) -> str | None:
    """零阻塞归属：仅当目标本身是 IP 时查库；域名一律返回 None（不触发 DNS）。"""
    if not target_url:
        return None
    try:
        from app.tools.edu_ip import school_name_no_dns
        return school_name_no_dns(target_url)
    except Exception:
        return None


async def _resolve_edu_school_async(target_url: str | None) -> str | None:
    """详情接口用：域名目标也解析（放线程池 + 3s 超时），任何异常返回 None。"""
    if not target_url:
        return None
    try:
        from app.tools.edu_ip import lookup_school_async
        info = await lookup_school_async(target_url, timeout=3.0)
        return info["school"] if info else None
    except Exception:
        return None


@router.get("/tasks/{task_id}/findings")
async def list_findings(task_id: str, status: Optional[str] = None,
                        search: Optional[str] = Query(None, alias="q"),
                        session: AsyncSession = Depends(get_session)):
    """所有原始漏洞（可按 status 过滤）。"""
    q = (
        select(Finding, Review)
        .outerjoin(Review, Review.finding_id == Finding.id)
        .where(Finding.task_id == task_id)
    )
    if status:
        q = q.where(Finding.status == status)
    q = q.order_by(Finding.created_at.desc())
    rows = (await session.execute(q)).all()
    out = [_finding_dict(f, r) for f, r in rows]
    return [d for d in out if _matches_query(d, search)]


@router.get("/tasks/{task_id}/results")
async def list_results(task_id: str, confidence: Optional[str] = None,
                       search: Optional[str] = Query(None, alias="q"),
                       session: AsyncSession = Depends(get_session)):
    """最终列表：仅 accepted 的漏洞，按信度分档（confirmed/likely/uncertain）。"""
    q = select(Finding, Review).join(Review, Review.finding_id == Finding.id).where(
        Finding.task_id == task_id, Review.verdict == "accepted")
    if confidence:
        q = q.where(Review.confidence == confidence)
    q = q.order_by(Review.score.desc())
    rows = (await session.execute(q)).all()
    out = [_finding_dict(f, r) for f, r in rows]
    return [d for d in out if _matches_query(d, search)]


@router.get("/tasks/{task_id}/deepen-list")
async def deepen_list(task_id: str, session: AsyncSession = Depends(get_session)):
    """打回深挖列表：审核判 deepen 的线索（含审核给的深挖指令）。
    供用户观察深挖管线——哪些线索被回炉、要证明什么。"""
    q = select(Finding, Review).join(Review, Review.finding_id == Finding.id).where(
        Finding.task_id == task_id, Review.verdict == "deepen"
    ).order_by(Review.reviewed_at.desc())
    rows = (await session.execute(q)).all()
    out = []
    for f, r in rows:
        d = _finding_dict(f, r)
        d["deepen_directive"] = r.deepen_directive
        # superseded=已回炉重挖中；reviewed=深挖未生效已归档
        d["deepen_state"] = "reinvestigating" if f.status == "superseded" else "archived"
        out.append(d)
    return out


@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str, session: AsyncSession = Depends(get_session)):
    f = await session.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "漏洞不存在")
    r = (await session.execute(select(Review).where(Review.finding_id == f.id))).scalar_one_or_none()
    d = _finding_dict(f, r)
    # 域名目标：详情接口异步补全归属（列表接口用零阻塞快路径，这里做完整 DNS 反查）
    if not d.get("edu_school"):
        d["edu_school"] = await _resolve_edu_school_async(f.target_url)
    return d


@router.get("/tasks/{task_id}/review-queue")
async def user_review_queue(task_id: str, search: Optional[str] = Query(None, alias="q"),
                            session: AsyncSession = Depends(get_session)):
    """用户复审队列：AI accepted 且用户尚未处理（pending）的漏洞。"""
    q = select(Finding, Review).join(Review, Review.finding_id == Finding.id).where(
        Finding.task_id == task_id, Review.verdict == "accepted", Review.user_status == "pending"
    ).order_by(Review.score.desc())
    rows = (await session.execute(q)).all()
    out = [_finding_dict(f, r) for f, r in rows]
    return [d for d in out if _matches_query(d, search)]


@router.get("/tasks/{task_id}/submit-list")
async def submit_list(task_id: str, submitted: Optional[bool] = None,
                      search: Optional[str] = Query(None, alias="q"),
                      compact: bool = False,
                      limit: int = Query(0, ge=0, le=500),
                      offset: int = Query(0, ge=0),
                      session: AsyncSession = Depends(get_session)):
    """待提交列表：用户复审通过(passed)的漏洞。submitted 过滤是否已提交。"""
    q = select(Finding, Review).join(Review, Review.finding_id == Finding.id).where(
        Finding.task_id == task_id, Review.user_status == "passed")
    if submitted is not None:
        q = q.where(Review.submitted == submitted)
    q = q.order_by(Review.submitted, Review.score.desc())
    if limit and not search:
        q = q.offset(offset).limit(limit + 1)
    rows = (await session.execute(q)).all()
    out = [_finding_dict(f, r, compact=compact) for f, r in rows]
    if search:
        out = [d for d in out if _matches_query(d, search)]
        if limit:
            out = out[offset:offset + limit + 1]
    if limit:
        return {
            "items": out[:limit],
            "has_more": len(out) > limit,
            "limit": limit,
            "offset": offset,
        }
    return out


@router.get("/tasks/{task_id}/rejected")
async def rejected_list(task_id: str, search: Optional[str] = Query(None, alias="q"),
                        session: AsyncSession = Depends(get_session)):
    """已驳回列表：用户复审判 rejected 的漏洞（可回看 / 恢复到复审队列）。"""
    q = select(Finding, Review).join(Review, Review.finding_id == Finding.id).where(
        Finding.task_id == task_id, Review.user_status == "rejected"
    ).order_by(Review.user_reviewed_at.desc().nullslast(), Review.score.desc())
    rows = (await session.execute(q)).all()
    out = [_finding_dict(f, r) for f, r in rows]
    return [d for d in out if _matches_query(d, search)]


@router.get("/tasks/{task_id}/killsweeps")
async def killsweep_list(task_id: str, only_hits: bool = True,
                         search: Optional[str] = Query(None, alias="q"),
                         session: AsyncSession = Depends(get_session)):
    """通杀列：人工复审通过后由通杀 Hunter 产出的可通杀候选。

    默认只返回 is_killsweep=true 的命中项，避免把不可通杀分析噪音摆到主列表里。
    """
    q = (
        select(Killsweep, Finding.title)
        .outerjoin(Finding, Finding.id == Killsweep.origin_finding_id)
        .where(Killsweep.task_id == task_id)
    )
    if only_hits:
        q = q.where(Killsweep.is_killsweep == True)  # noqa: E712
    q = q.order_by(Killsweep.verified.desc(), Killsweep.asset_count.desc(), Killsweep.created_at.desc())
    rows = (await session.execute(q)).all()
    out = []
    for k, origin_title in rows:
        item = {
            "id": k.id,
            "task_id": k.task_id,
            "origin_finding_id": k.origin_finding_id,
            "origin_title": origin_title or "",
            "product_name": k.product_name,
            "vuln_type": k.vuln_type,
            "vuln_summary": k.vuln_summary,
            "fofa_query": k.fofa_query,
            "fingerprint": k.fingerprint,
            "asset_count": k.asset_count,
            "edu_count": k.edu_count,
            "is_killsweep": k.is_killsweep,
            "confidence": k.confidence,
            "verified_url": k.verified_url,
            "verified": k.verified,
            "affected_table": k.affected_table or [],
            "notes": k.notes,
            "status": k.status,
            "created_at": k.created_at.isoformat(),
        }
        if _matches_query(item, search):
            out.append(item)
    return out


class UserReviewRequest(BaseModel):
    user_status: Optional[str] = None       # passed / rejected / pending
    user_severity: Optional[str] = None      # 严重/高危/中危/低危
    user_notes: Optional[str] = None
    user_edits: Optional[dict] = None        # {title, description, steps, poc, affected_scope, ...}
    submitted: Optional[bool] = None


class KillsweepInvalidRequest(BaseModel):
    reason: str = "人工标记无效"


@router.post("/tasks/{task_id}/killsweeps/{killsweep_id}/invalidate")
async def invalidate_killsweep(task_id: str, killsweep_id: str,
                               req: KillsweepInvalidRequest | None = None,
                               session: AsyncSession = Depends(get_session)):
    """人工把通杀候选标记为无效。

    默认通杀列表只返回 is_killsweep=true，因此置 false 后会立刻从主列表消失；
    原始记录保留在 DB 里，便于后续审计或人工回捞。
    """
    k = await session.get(Killsweep, killsweep_id)
    if not k or k.task_id != task_id:
        raise HTTPException(404, "通杀记录不存在")
    if k.status == "invalid" or not k.is_killsweep:
        return {"ok": True, "id": k.id, "status": k.status or "invalid", "already_invalid": True}
    reason = ((req.reason if req else "") or "人工标记无效").strip()[:500]
    now = _now()
    k.is_killsweep = False
    k.status = "invalid"
    k.updated_at = now
    marker = f"[人工标记无效] {reason}"
    k.notes = f"{(k.notes or '').strip()}\n{marker}".strip()
    session.add(TaskEvent(
        task_id=task_id,
        agent="killsweep",
        kind="killsweep_invalid",
        level="warn",
        message=f"通杀记录已标记无效：{k.product_name or k.vuln_summary or k.id}",
        payload={"killsweep_id": k.id, "product": k.product_name, "reason": reason},
    ))
    await session.commit()
    await bus.publish(task_id, {
        "agent": "killsweep",
        "kind": "killsweep_invalid",
        "level": "warn",
        "killsweep_id": k.id,
        "product": k.product_name,
        "reason": reason,
    })
    return {"ok": True, "id": k.id, "status": k.status}


class ReportAssistantRequest(BaseModel):
    message: str
    history: list[dict] = []  # 兼容旧前端；优先使用 DB 持久化历史


REPORT_ASSISTANT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "对该漏洞相关目标发一个 HTTP 请求，用于补充验证或查看响应。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "default": "GET"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "data": {"type": "string"},
                    "json_body": {"type": "object"},
                    "follow_redirects": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "执行简短验证命令（如 curl）。用于用户明确要求再操作/验证时。",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout": {"type": "integer", "default": 30},
                },
                "required": ["command"],
            },
        },
    },
]


def _llm_for_task(task: Task) -> LLMClient:
    return llm_client_for_task(task)


def _assistant_context(f: Finding, r: Review | None) -> str:
    rv = r
    return f"""# 当前漏洞报告完整上下文（你只围绕这一份报告工作）
- 标题：{f.title}
- 类型：{f.vuln_type}
- 目标 URL：{f.target_url}
- 归属单位：{f.owner}
- Worker 自评等级：{f.severity_claimed}
- 审核结论：verdict={rv.verdict if rv else '-'} / 最终等级={rv.severity_final if rv else '-'} / 信度={rv.confidence if rv else '-'} / score={rv.score if rv else '-'}
- 是否复现：{rv.reproduced if rv else '-'} / 是否重复：{rv.is_duplicate if rv else '-'} / 是否在范围：{rv.in_scope if rv else '-'}

## 漏洞描述
{_clip_text(f.description or '（无）', 1200)}

## 影响范围
{_clip_text(f.affected_scope or '（无）', 800)}

## 复现步骤
{_clip_json(f.steps or [], 1200)}

## PoC
{_clip_text(f.poc or '（无）', 1200)}

## 原始请求（取证包）
{_clip_text(f.raw_request or '（无）', 1600)}

## 原始响应（取证包）
{_clip_text(f.raw_response or '（无）', 2200)}

## 证据
{_clip_json(f.evidence or {}, 1200)}

## 攻击链路
{_clip_json(f.kill_chain or [], 1200)}

## Worker 自检
{_clip_json(f.self_check or {}, 800) if getattr(f, 'self_check', None) else '（无）'}

## AI 审核备注
{_clip_text((rv.reviewer_notes if rv else '') or '（无）', 900)}

## 人工复审备注
{_clip_text((rv.user_notes if rv else '') or '（无）', 900)}
"""


_ASSISTANT_SYSTEM_PROMPT = (
    "你是 AutoHunter 报告助手，只服务当前漏洞报告。基于上下文回答真实性、危害、复现、证据一致性、"
    "误报、修复和 SRC 口径；上下文已有请求/响应/PoC/证据/攻击链，先回答，别轻易说信息不足。"
    "仅当用户明确要求再发请求/curl/实测/看是否仍存在时，才用 http_request/run_shell 做少量定向验证；"
    "禁止扫描、批量攻击、改密、改数据、破坏现场。工具后必须用中文说明状态码、关键响应、结论影响；"
    "不能沉默或只说已完成。结论先行，简洁专业。"
)


_ASSISTANT_MAX_ROUNDS = int(os.environ.get("REPORT_ASSISTANT_MAX_ROUNDS", "10"))
_MD_URL_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")
_URL_RE = re.compile(r"https?://[^\s<>()'\"]+")


def _clean_assistant_url(value: str) -> str:
    text = str(value or "").strip().strip("`'\"<>")
    md = _MD_URL_RE.search(text)
    if md:
        return md.group(2).strip()
    url = _URL_RE.search(text)
    return (url.group(0) if url else text).strip()


def _clean_shell_command(command: str) -> str:
    text = str(command or "").replace("\r\n", "\n").replace("\r", "\n")
    text = _MD_URL_RE.sub(lambda m: m.group(2), text)
    # LLM 有时把多行 shell 的续行符压成 "\ -H"，这会让 curl 参数错位。
    text = re.sub(r"\\[ \t]+(?=-{1,2}[A-Za-z])", " ", text)
    return text.strip()


def _safe_timeout(value, *, default: int = 30, upper: int = 60) -> int:
    if isinstance(value, bool) or value is None:
        return default
    if isinstance(value, str):
        raw = value.strip().lower()
        if raw in {"", "false", "none", "null", "default", "auto"}:
            return default
        try:
            parsed = int(float(raw))
        except Exception:
            return default
    else:
        try:
            parsed = int(value)
        except Exception:
            return default
    return max(1, min(parsed, upper))


def _looks_like_unexecuted_tool_text(text: str) -> bool:
    low = (text or "").lower()
    if any(marker in low for marker in ("<｜｜dsml", "tool_calls", "invoke name=", "run_shell", "http_request")):
        return True
    return bool(re.search(r"(^|\n)\s*(#.*\n)?\s*curl\s+-", text or "", re.I))


def _tool_call_summary(name: str, args: dict) -> str:
    """把一次工具调用浓缩成一句人话，给前端实时展示『助手正在干什么』。"""
    if name == "http_request":
        method = (args.get("method") or "GET").upper()
        return f"{method} {args.get('url', '')}".strip()
    if name == "run_shell":
        return (args.get("command") or "").strip()[:200]
    return name


def _tool_result_summary(name: str, result: dict) -> str:
    """把工具结果浓缩成一句关键信息，给前端实时展示。"""
    if not isinstance(result, dict):
        return str(result)[:200]
    if result.get("blocked"):
        return f"已拦截：{result.get('error', '')}"[:200]
    if result.get("ok") is False:
        return f"失败：{result.get('error', '')}"[:200]
    if name == "http_request":
        status = result.get("status_code") or "?"
        blen = result.get("body_len")
        if blen is None:
            blen = len(result.get("body") or "")
        return f"HTTP {status} · 响应 {blen} 字节"
    if name == "run_shell":
        out = result.get("output") or ""
        rc = result.get("return_code")
        extra = " · 超时" if result.get("timed_out") else ""
        return f"退出码 {rc if rc is not None else '?'} · 输出 {len(out)} 字节{extra}"
    return "完成"


def _build_assistant_messages(f: Finding, r: Review | None, req: ReportAssistantRequest) -> list[dict]:
    messages: list[dict] = [
        {"role": "system", "content": _ASSISTANT_SYSTEM_PROMPT},
        {"role": "user", "content": _ASSISTANT_STATIC_PREFIX},
        {"role": "user", "content": _assistant_context(f, r)},
    ]
    for h in (req.history or [])[-_ASSISTANT_HISTORY_TURNS:]:
        role = h.get("role")
        content = _clip_text(h.get("content") or "", _ASSISTANT_HISTORY_CHARS)
        if role in ("user", "assistant") and content:
            messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": req.message})
    return messages


def _run_report_assistant(
    f: Finding,
    r: Review | None,
    task: Task,
    req: ReportAssistantRequest,
    cancel_event: threading.Event,
    emit=None,
) -> dict:
    """运行报告助手；emit(event:dict) 可选回调，每完成一步就推一条事件用于流式展示。"""
    llm = _llm_for_task(task)
    executor = ToolExecutor(f"report_assistant_{f.target_url or f.id}", cancel_event=cancel_event)
    messages = _build_assistant_messages(f, r, req)
    tool_logs: list[dict] = []

    def _emit(ev: dict) -> None:
        if emit:
            try:
                emit(ev)
            except Exception:
                pass

    try:
        return _run_report_assistant_loop(llm, executor, messages, tool_logs, cancel_event, _emit)
    finally:
        executor.kill_processes()


def _run_report_assistant_loop(
    llm: LLMClient,
    executor: ToolExecutor,
    messages: list[dict],
    tool_logs: list[dict],
    cancel_event: threading.Event,
    emit,
) -> dict:
    for round_idx in range(_ASSISTANT_MAX_ROUNDS):
        if cancel_event.is_set():
            return {"answer": "报告助手操作已超时或被取消。", "tool_logs": tool_logs}

        # 最后一轮强制收口：不再给工具，逼模型基于已有信息给出文字结论，避免「执行完就沉默」。
        last_round = round_idx == _ASSISTANT_MAX_ROUNDS - 1
        call_messages = messages
        if last_round:
            emit({"type": "thinking", "text": "正在汇总结论…"})
            call_messages = messages + [{
                "role": "user",
                "content": (
                    "这是最后收口轮。不要再提出新的 curl/工具调用，也不要用文字伪造 tool_calls。"
                    "只能基于已执行结果给出结论；如证据还不够，明确说明还差什么。"
                ),
            }]
            msg = llm.chat(call_messages, tools=REPORT_ASSISTANT_TOOLS, tool_choice="none", temperature=0.2)
        else:
            emit({"type": "thinking", "text": "正在分析…"})
            msg = llm.chat(call_messages, tools=REPORT_ASSISTANT_TOOLS, tool_choice="auto", temperature=0.2)

        tool_calls = getattr(msg, "tool_calls", None)
        # 模型在调工具前给的思考文字，也实时透出来。
        if msg.content and msg.content.strip():
            emit({"type": "assistant_partial", "text": msg.content.strip()})

        assistant_msg = {"role": "assistant", "content": msg.content or ""}
        if tool_calls and not last_round:
            assistant_msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in tool_calls
            ]
        messages.append(assistant_msg)

        if not tool_calls or last_round:
            answer = (msg.content or "").strip()
            if _looks_like_unexecuted_tool_text(answer):
                if not last_round:
                    messages.append({
                        "role": "user",
                        "content": (
                            "你刚才用文字写了一个待执行的命令/工具调用，但后端没有真正执行它。"
                            "如果还需要验证，请下一轮使用 function calling 调用 http_request 或 run_shell；"
                            "如果不需要，就直接给出结论。"
                        ),
                    })
                    continue
                answer = (
                    "助手达到本次辅助验证轮数上限，最后一轮仍提出了新的未执行验证动作。"
                    "我没有把这段伪工具调用当作结论；请基于上方已执行的工具结果判断，"
                    "或再次发起助手请求继续验证。"
                )
            if not answer:
                answer = _fallback_answer(tool_logs)
            emit({"type": "final", "text": answer})
            return {"answer": answer, "tool_logs": tool_logs}

        for tc in tool_calls:
            if cancel_event.is_set():
                return {"answer": "报告助手操作已超时或被取消。", "tool_logs": tool_logs}
            try:
                args = json.loads(tc.function.arguments or "{}")
            except Exception:
                args = {}
            emit({
                "type": "tool_call",
                "tool": tc.function.name,
                "summary": _tool_call_summary(tc.function.name, args),
            })
            if tc.function.name == "http_request":
                url = _clean_assistant_url(args.get("url") or "")
                args["url"] = url
                if not url:
                    result = {"ok": False, "error": "http_request 缺少 url"}
                else:
                    result = executor.http_request(
                        url=url, method=args.get("method", "GET"),
                        headers=args.get("headers"), data=args.get("data"),
                        json_body=args.get("json_body"), follow_redirects=args.get("follow_redirects", False),
                        timeout=20,
                    )
            elif tc.function.name == "run_shell":
                command = _clean_shell_command(args.get("command") or "")
                args["command"] = command
                timeout = _safe_timeout(args.get("timeout"), default=30, upper=90)
                args["timeout"] = timeout
                if not command:
                    result = {"ok": False, "error": "run_shell 缺少 command"}
                else:
                    result = executor.run_shell(command, timeout=timeout)
            else:
                result = {"ok": False, "error": f"未知工具: {tc.function.name}"}
            tool_logs.append({"tool": tc.function.name, "args": args, "result": result})
            emit({
                "type": "tool_result",
                "tool": tc.function.name,
                "summary": _tool_result_summary(tc.function.name, result),
            })
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                    "content": json.dumps(result, ensure_ascii=False)[:3500],
                })

    answer = _fallback_answer(tool_logs)
    emit({"type": "final", "text": answer})
    return {"answer": answer, "tool_logs": tool_logs}


def _fallback_answer(tool_logs: list[dict]) -> str:
    """模型最终没给文字时，基于已执行的工具动作兜底生成一段可读摘要，避免『啥也没返回』。"""
    if not tool_logs:
        return "我没有需要补充验证的动作。请把问题说得更具体些，例如让我判断某条证据是否成立、或要求我重新 curl 某个接口看状态码。"
    lines = ["我执行了以下验证动作，但模型未给出文字总结，先把关键结果列给你："]
    for i, log in enumerate(tool_logs, 1):
        name = log.get("tool", "")
        summary = _tool_call_summary(name, log.get("args") or {})
        res = _tool_result_summary(name, log.get("result") or {})
        lines.append(f"{i}. `{summary}` → {res}")
    lines.append("\n如需进一步解读，请追问。")
    return "\n".join(lines)


@router.post("/findings/{finding_id}/assistant")
async def report_assistant(finding_id: str, req: ReportAssistantRequest,
                           session: AsyncSession = Depends(get_session)):
    """报告底部的小助手：围绕当前漏洞答疑，也可做少量受控验证动作。"""
    msg = (req.message or "").strip()
    if not msg:
        raise HTTPException(400, "请输入问题或操作指令")
    f = await session.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "漏洞不存在")
    r = (await session.execute(select(Review).where(Review.finding_id == finding_id))).scalar_one_or_none()
    task = await session.get(Task, f.task_id)
    if not task:
        raise HTTPException(404, "任务不存在")

    persisted = _sanitize_assistant_messages(f.assistant_messages)
    if not persisted:
        persisted = _default_assistant_messages()
    llm_req = ReportAssistantRequest(message=msg, history=persisted[-_ASSISTANT_HISTORY_TURNS:])

    loop = asyncio.get_running_loop()
    tool_logs = []
    cancel_event = threading.Event()
    # 并发信号量：报告助手与 worker/reviewer/killsweep 共用 AGENT_EXECUTOR，
    # 必须封顶并发，避免一堆助手请求把池子占满拖垮挖掘。
    assistant_sem = agent_semaphore("assistant")
    await assistant_sem.acquire()
    future = loop.run_in_executor(
        AGENT_EXECUTOR, lambda: _run_report_assistant(f, r, task, llm_req, cancel_event),
    )

    def _release_assistant(fut) -> None:
        assistant_sem.release()
        _consume_future_exception(fut)

    future.add_done_callback(_release_assistant)
    try:
        result = await asyncio.wait_for(asyncio.shield(future), timeout=_ASSISTANT_WALL_TIMEOUT)
        tool_logs = result.get("tool_logs") or []
        suffix = f"\n\n（已执行 {len(tool_logs)} 个辅助动作）" if tool_logs else ""
        assistant_content = (result.get("answer") or "已完成。") + suffix
    except asyncio.TimeoutError:
        cancel_event.set()
        future.add_done_callback(_consume_future_exception)
        assistant_content = f"报告助手执行超时（>{int(_ASSISTANT_WALL_TIMEOUT)}s），已触发底层工具清理。"
    except LLMError as e:
        assistant_content = f"报告助手暂不可用：{e}"
    except Exception:
        assistant_content = "报告助手暂不可用：内部执行异常，已保护底层错误细节。"
    f.assistant_messages = _sanitize_assistant_messages(
        persisted + [{"role": "user", "content": msg}, {"role": "assistant", "content": assistant_content}],
    )
    await session.commit()
    return {
        "answer": assistant_content,
        "tool_logs": tool_logs,
        "messages": f.assistant_messages,
    }


def _sse(event: dict) -> str:
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n"


@router.post("/findings/{finding_id}/assistant/stream")
async def report_assistant_stream(finding_id: str, req: ReportAssistantRequest,
                                  session: AsyncSession = Depends(get_session)):
    """流式版报告助手：用 SSE 实时推送『分析 / 调用工具 / 工具结果 / 最终答复』每一步。"""
    msg = (req.message or "").strip()
    if not msg:
        raise HTTPException(400, "请输入问题或操作指令")
    f = await session.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "漏洞不存在")
    r = (await session.execute(select(Review).where(Review.finding_id == finding_id))).scalar_one_or_none()
    task = await session.get(Task, f.task_id)
    if not task:
        raise HTTPException(404, "任务不存在")

    persisted = _sanitize_assistant_messages(f.assistant_messages)
    if not persisted:
        persisted = _default_assistant_messages()
    llm_req = ReportAssistantRequest(message=msg, history=persisted[-_ASSISTANT_HISTORY_TURNS:])

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    cancel_event = threading.Event()

    def _emit(ev: dict) -> None:
        # 工作线程里调用：线程安全地把事件投递到 asyncio 队列。
        loop.call_soon_threadsafe(queue.put_nowait, ev)

    async def _gen():
        assistant_sem = agent_semaphore("assistant")
        await assistant_sem.acquire()
        future = loop.run_in_executor(
            AGENT_EXECUTOR,
            lambda: _run_report_assistant(f, r, task, llm_req, cancel_event, emit=_emit),
        )

        def _release_assistant(fut) -> None:
            assistant_sem.release()
            _consume_future_exception(fut)
            loop.call_soon_threadsafe(queue.put_nowait, {"type": "__done__"})

        future.add_done_callback(_release_assistant)

        final_answer = ""
        tool_count = 0
        timed_out = False
        try:
            yield _sse({"type": "start"})
            while True:
                try:
                    ev = await asyncio.wait_for(queue.get(), timeout=_ASSISTANT_WALL_TIMEOUT)
                except asyncio.TimeoutError:
                    cancel_event.set()
                    timed_out = True
                    break
                if ev.get("type") == "__done__":
                    break
                if ev.get("type") == "final":
                    final_answer = ev.get("text") or final_answer
                if ev.get("type") == "tool_call":
                    tool_count += 1
                yield _sse(ev)
        finally:
            # 取回真实结果（含完整 answer / tool_logs），落库历史。
            try:
                result = await asyncio.wait_for(asyncio.shield(future), timeout=5)
                final_answer = result.get("answer") or final_answer
                tool_count = len(result.get("tool_logs") or []) or tool_count
            except Exception:
                pass
            if timed_out and not final_answer:
                final_answer = f"报告助手执行超时（>{int(_ASSISTANT_WALL_TIMEOUT)}s），已触发底层工具清理。"
            if not final_answer:
                final_answer = "已完成。"
            suffix = f"\n\n（已执行 {tool_count} 个辅助动作）" if tool_count else ""
            stored = final_answer + suffix
            try:
                f.assistant_messages = _sanitize_assistant_messages(
                    persisted + [
                        {"role": "user", "content": msg},
                        {"role": "assistant", "content": stored},
                    ],
                )
                await session.commit()
            except Exception:
                await session.rollback()
            yield _sse({"type": "done", "answer": stored, "tool_count": tool_count})

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # 禁用 Nginx 缓冲，确保 SSE 实时
            "Connection": "keep-alive",
        },
    )


@router.patch("/results/{finding_id}")
async def user_review(finding_id: str, req: UserReviewRequest,
                      session: AsyncSession = Depends(get_session)):
    """用户复审：调整等级 / 通过-不通过 / 编辑内容 / 备注 / 标记已提交。"""
    r = (await session.execute(select(Review).where(Review.finding_id == finding_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "审核记录不存在")
    previous_user_status = r.user_status
    trigger_killsweep = False
    killsweep_skipped_reason = ""
    task_id = r.task_id
    f = await session.get(Finding, finding_id)
    tgt = await session.get(Target, f.target_id) if f else None
    if req.user_status is not None:
        if req.user_status not in ("passed", "rejected", "pending"):
            raise HTTPException(400, "user_status 非法")
        r.user_status = req.user_status
        r.user_reviewed_at = _now()
        trigger_killsweep = (
            req.user_status == "passed"
            and previous_user_status != "passed"
            and r.verdict == "accepted"
        )
        if trigger_killsweep and tgt and tgt.source == "killsweep":
            trigger_killsweep = False
            killsweep_skipped_reason = "该漏洞来自通杀验证目标，已断开通杀递归触发"
    if req.user_severity is not None:
        r.user_severity = req.user_severity
    if req.user_notes is not None:
        r.user_notes = req.user_notes
    if req.user_edits is not None:
        r.user_edits = req.user_edits
    if req.submitted is not None:
        r.submitted = req.submitted
    await session.commit()
    killsweep_triggered = False
    if trigger_killsweep:
        # 只有人工复审通过才启动通杀 Hunter；AI accepted 只是进入复审队列。
        from app.orchestrator import manager
        killsweep_triggered = await manager.trigger_killsweep(task_id, finding_id)
    return {
        "ok": True,
        "killsweep_triggered": killsweep_triggered,
        "killsweep_skipped_reason": killsweep_skipped_reason,
    }


class DeepenRequest(BaseModel):
    directive: str  # 人工附带的深挖指令：告诉 worker 这一轮去把什么打穿


@router.post("/results/{finding_id}/deepen")
async def user_deepen(finding_id: str, req: DeepenRequest,
                      session: AsyncSession = Depends(get_session)):
    """人工复审「继续深挖」：把该 finding 对应目标带定向指令重新入队，让 worker 再挖一轮。
    与 AI 审核打回深挖走同一套回炉逻辑（原 finding superseded + 目标拉到队首）。"""
    directive = (req.directive or "").strip()
    if not directive:
        raise HTTPException(400, "请填写深挖指令（告诉 worker 这一轮去把什么打穿）")
    f = await session.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "漏洞不存在")
    r = (await session.execute(select(Review).where(Review.finding_id == finding_id))).scalar_one_or_none()
    tgt = await session.get(Target, f.target_id)
    ok, suffix = apply_deepen(session, f, tgt, directive, source="user")
    if r:
        # 把这次人工动作记到审核记录上：复审备注 + 标记非通过非驳回（已回炉，从复审/驳回列表移走）
        r.deepen_directive = directive
        r.user_notes = ((r.user_notes or "") + f"\n[人工继续深挖] {directive}").strip()
        r.user_status = "deepening"
        r.user_reviewed_at = _now()
    await session.commit()
    if not ok:
        raise HTTPException(409, f"无法深挖：{suffix.strip(' →')}")
    return {"ok": True, "message": suffix.strip(" →")}
