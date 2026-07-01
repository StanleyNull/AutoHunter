"""通杀 Hunter Agent：审核 accepted 一个洞后，分析该系统能否「一打一片」。

流程（对应用户需求）：
  收到一个已采纳的 Finding → 认系统指纹 → FOFA 圈定同款系统+统计规模
  → 实打 1 个同款站点验证 → 判定是否可通杀 → 产出 KillsweepResult。

同步执行（内部 LLM/FOFA/工具均阻塞），由 orchestrator 在线程池里调用。
任何异常都降级返回，不阻断主循环。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import httpx

from app.agents.history import compact_messages
from app.agents.prompts import is_enterprise_src, killsweep_system_prompt
from app.llm.client import LLMClient
from app.tools.executor import ToolExecutor
from app.tools.schemas import KILLSWEEP_TOOL_SCHEMAS

_FOFA_BASE = "https://fofa.info"
# 通杀分析只做产品指纹、FOFA 圈定、抽样验证，必须有限轮数，避免模型递归空转。
_MAX_ROUNDS = int(os.environ.get("KILLSWEEP_MAX_ROUNDS", "24"))
# 叠加到查询上、把统计限定在教育行业的条件
_EDU_FILTER = '(domain=".edu.cn" || cert="edu" || org="edu")'


def _qbase64(q: str) -> str:
    return base64.b64encode(q.encode("utf-8")).decode("ascii")


def _normalize_host(url_or_host: str) -> str:
    s = (url_or_host or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "http://" + s
    try:
        p = urlparse(s)
    except Exception:
        return s.lower().strip("/")
    host = (p.hostname or "").lower()
    if p.port and p.port not in (80, 443):
        host = f"{host}:{p.port}"
    return host


def _affected_row_key(host: str, vuln_title: str, vuln_type: str) -> str:
    raw = f"killsweep|{host}|{(vuln_type or '').lower()}|{vuln_title or ''}"
    return hashlib.md5(raw.encode()).hexdigest()


def _normalize_affected_table(rows: Any, vuln_type: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(rows, list):
        return out
    seen: set[str] = set()
    for row in rows[:50]:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("host") or "").strip()
        host = _normalize_host(str(row.get("host") or url))
        if not host:
            continue
        vuln_title = str(row.get("vuln_title") or "").strip() or f"{host} - 通杀漏洞"
        key = _affected_row_key(host, vuln_title, vuln_type)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "school": str(row.get("school") or "待确认")[:120],
            "url": url if "://" in url else f"http://{host}",
            "host": host,
            "title": str(row.get("title") or "")[:200],
            "vuln_type": vuln_type,
            "vuln_title": vuln_title[:300],
            "status": row.get("status") if row.get("status") in ("verified", "candidate") else "candidate",
            "evidence": str(row.get("evidence") or "")[:1000],
            "dedup_key": key,
        })
    return out


def _fofa_search_sync(key: str, query: str, edu_only: bool = False,
                      size: int = 20, base_url: str | None = None) -> dict[str, Any]:
    """同步 FOFA 查询，返回 {size, sample:[{host,title,org}], query}。"""
    if not key:
        return {"size": 0, "sample": [], "query": query, "error": "缺少 FOFA key"}
    q = f"{query} && {_EDU_FILTER}" if edu_only else query
    base = (base_url or _FOFA_BASE).rstrip("/")
    params = {
        "key": key, "qbase64": _qbase64(q),
        "fields": "host,title,org", "page": "1", "size": str(size), "full": "false",
    }
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(f"{base}/api/v1/search/all", params=params)
            data = resp.json()
    except Exception as e:
        return {"size": 0, "sample": [], "query": q, "error": f"FOFA 调用失败: {e}"}
    if data.get("error"):
        return {"size": 0, "sample": [], "query": q, "error": data.get("errmsg", "FOFA 错误")}
    sample = []
    for row in data.get("results", [])[:size]:
        if isinstance(row, list):
            sample.append({"host": row[0] if len(row) > 0 else "",
                           "title": row[1] if len(row) > 1 else "",
                           "org": row[2] if len(row) > 2 else ""})
    return {"size": data.get("size", 0), "sample": sample, "query": q}


class KillsweepResult:
    def __init__(self, data: dict):
        self.data = data

    def model_dump(self, mode: str = "json") -> dict:
        return self.data


class KillsweepHunter:
    def __init__(
        self,
        finding: dict,
        fofa_key: str,
        llm: Optional[LLMClient] = None,
        on_event: Optional[Callable[[str, dict], None]] = None,
        src_type: str = "edusrc",
        cancel_event: Optional[threading.Event] = None,
        fofa_base_url: str = "",
    ):
        self.finding = finding
        self.fofa_key = fofa_key
        self.fofa_base_url = fofa_base_url
        self.llm = llm or LLMClient()
        self.cancel_event = cancel_event or threading.Event()
        self.executor = ToolExecutor(f"killsweep_{finding.get('target_url','x')}", cancel_event=self.cancel_event)
        self.on_event = on_event or (lambda kind, data: None)
        self._result: Optional[dict] = None
        self.src_type = src_type

    def _emit(self, kind: str, **data: Any) -> None:
        self.on_event(kind, data)

    def _brief(self) -> str:
        f = self.finding
        unit_label = "企业/系统归属" if is_enterprise_src(self.src_type) else "归属"
        return (
            f"# 待分析的已采纳漏洞\n"
            f"- 标题：{f.get('title','')}\n"
            f"- 漏洞类型：{f.get('vuln_type','')}\n"
            f"- 目标 URL：{f.get('target_url','')}\n"
            f"- {unit_label}：{f.get('owner','')}\n"
            f"- 描述：{(f.get('description') or '')[:600]}\n"
            f"- PoC：{(f.get('poc') or '')[:500]}\n"
            f"- 原始响应(片段)：{(f.get('raw_response') or '')[:800]}\n\n"
            f"请分析这套系统能否通杀。先认指纹→FOFA 圈定+统计→实打 1 个同款站点验证→调 submit_killsweep 下结论。"
        )

    def run(self) -> KillsweepResult:
        self._emit("killsweep_start", title=self.finding.get("title", ""))
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": killsweep_system_prompt(self.src_type)},
            {"role": "user", "content": self._brief()},
        ]
        rounds = 0
        while _MAX_ROUNDS <= 0 or rounds < _MAX_ROUNDS:
            if self.cancel_event.is_set():
                self.executor.cancel_running()
                return KillsweepResult({"error": "通杀分析已被取消"})
            rounds += 1
            try:
                send_messages = compact_messages(messages, rounds)
                msg = self.llm.chat(send_messages, tools=KILLSWEEP_TOOL_SCHEMAS, tool_choice="auto")
            except Exception as e:
                self._emit("killsweep_error", error=str(e))
                return KillsweepResult({"error": f"LLM 调用失败: {e}"})

            tool_calls = getattr(msg, "tool_calls", None)
            am: dict[str, Any] = {"role": "assistant", "content": msg.content or ""}
            if tool_calls:
                am["tool_calls"] = [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in tool_calls
                ]
            messages.append(am)

            if not tool_calls:
                messages.append({"role": "user", "content": "请继续，或调用 submit_killsweep 给出结论。"})
                continue

            for tc in tool_calls:
                if self.cancel_event.is_set():
                    self.executor.cancel_running()
                    return KillsweepResult({"error": "通杀分析已被取消"})
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                result = self._dispatch(tc.function.name, args)
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "content": json.dumps(result, ensure_ascii=False),
                                 "_round": rounds, "_tool": tc.function.name})

            if self._result is not None:
                break

        if self._result is not None:
            return KillsweepResult(self._result)
        return KillsweepResult({"error": f"未在 {_MAX_ROUNDS} 轮内给出结论"})

    def _dispatch(self, name: str, args: dict) -> dict:
        if self.cancel_event.is_set():
            return {"ok": False, "cancelled": True, "error": "通杀分析已被取消"}
        if name == "fofa_search":
            q = args.get("query", "")
            edu = bool(args.get("edu_only", False))
            self._emit("killsweep_fofa", query=q, edu_only=edu)
            return _fofa_search_sync(self.fofa_key, q, edu_only=edu, base_url=self.fofa_base_url)
        if name == "http_request":
            url = args.get("url")
            if not url:
                return {"ok": False, "error": "http_request 缺少 url"}
            self._emit("killsweep_http", url=args.get("url"))
            return self.executor.http_request(
                url=url, method=args.get("method", "GET"),
                headers=args.get("headers"), data=args.get("data"),
                json_body=args.get("json_body"), follow_redirects=args.get("follow_redirects", False),
            )
        if name == "run_shell":
            command = args.get("command")
            if not command:
                return {"ok": False, "error": "run_shell 缺少 command"}
            self._emit("killsweep_shell", command=args.get("command", "")[:160])
            return self.executor.run_shell(command, timeout=args.get("timeout"))
        if name == "submit_killsweep":
            self._result = {
                "is_generic_product": bool(args.get("is_generic_product", False)),
                "product_name": args.get("product_name", ""),
                "is_killsweep": bool(args.get("is_killsweep", False)),
                "confidence": args.get("confidence", "uncertain"),
                "fofa_query": args.get("fofa_query", ""),
                "fingerprint": args.get("fingerprint", ""),
                "asset_count": int(args.get("asset_count", 0) or 0),
                "edu_count": int(args.get("edu_count", 0) or 0),
                "verified_url": args.get("verified_url", ""),
                "verified": bool(args.get("verified", False)),
                "affected_table": _normalize_affected_table(args.get("affected_table", []), self.finding.get("vuln_type", "")),
                "notes": args.get("notes", ""),
            }
            self._emit("killsweep_done", is_killsweep=self._result["is_killsweep"],
                       product=self._result["product_name"], count=self._result["asset_count"])
            return {"ok": True, "message": "已记录通杀分析结论。"}
        return {"ok": False, "error": f"未知工具: {name}"}


def product_key(product_name: str, fofa_query: str = "", fingerprint: str = "") -> str:
    """产品指纹去重键：同款系统只分析一次，不按漏洞类型重复分析。"""
    raw = product_name or fofa_query or fingerprint or "unknown"
    name = "".join(ch.lower() for ch in raw if ch.isalnum() or '\u4e00' <= ch <= '\u9fff')
    return name[:120] or "unknown"
