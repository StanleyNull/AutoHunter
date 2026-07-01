"""Worker Agent：1:1 绑定一个目标，LLM + 工具真实挖洞。

流程（对应设计文档 §5.5）：
  只给一个裸 target → LLM 完全自主侦察+挖掘（function calling 循环）
  → 发现漏洞调 submit_finding → 挖完调 finish → 产出 WorkerResult。
"""
from __future__ import annotations

import json
import re
import threading
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from pydantic import ValidationError

from app.agents.history import compact_messages
from app.agents.prompts import is_enterprise_src, normalize_worker_prompt_version, worker_system_prompt
from app.config import worker_config
from app import dedup
from app.llm.client import LLMClient
from app.schemas import Finding, Verdict, WorkerResult
from app.tools.executor import ToolExecutor
from app.tools.schemas import (
    ENTERPRISE_SESSION_TOOL_SCHEMAS,
    JS_ANALYZER_TOOL_SCHEMAS,
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
        prompt_version: str | None = None,
    ):
        self.target = target
        self.llm = llm or LLMClient()
        self.cancel_event = cancel_event or threading.Event()
        self.src_type = src_type
        self._enterprise = is_enterprise_src(src_type)
        self.prompt_version = normalize_worker_prompt_version(prompt_version or worker_config.prompt_version)
        self.executor = ToolExecutor(
            target, cancel_event=self.cancel_event,
            enterprise=self._enterprise, fofa_key=fofa_key, fofa_base_url=fofa_base_url,
        )
        self.findings: list[Finding] = []
        self.on_event = on_event or (lambda kind, data: None)
        self._finished: Optional[dict] = None
        # 审核打回的定向深挖任务：{directive, vuln_type, original_title, original_summary}
        self.deepen_context = deepen_context or None
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
            return site + playbook + self._creds_block() + self._intel_lib_block()
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
        return "\n".join(lines) + "\n\n" + self._creds_block() + self._intel_lib_block()

    def _playbook_block(self) -> str:
        """目标打法路由：编排层生成的短路线块。"""
        return (self.target_meta or {}).get("playbook_block") or ""

    def _site_collab_block(self) -> str:
        """单站协作路线块：当前 worker 的分工和已有覆盖摘要。"""
        return (self.target_meta or {}).get("site_collab_block") or ""

    def _intel_lib_block(self) -> str:
        """全局情报库命中（编排层触发式检索后注入的现成文本块）。"""
        return (self.target_meta or {}).get("intel_block") or ""

    def _creds_block(self) -> str:
        """泄露凭证情报：搜集阶段查到的该域已泄露账号密码（已过滤打分）。"""
        creds = (self.target_meta or {}).get("leaked_creds") or []
        if not creds:
            return ""
        lines = [
            "# 泄露凭证情报（来自全网 stealer 日志库，搜集阶段已过滤打分）",
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
            {"role": "system", "content": worker_system_prompt(self.src_type, self.prompt_version)},
            {"role": "user", "content": _WORKER_STATIC_PREFIX},
            {"role": "user", "content": user_content},
        ]

        rounds = 0
        no_tool_rounds = 0
        consecutive_failures = 0
        consecutive_blocked = 0
        consecutive_arg_errors = 0
        consecutive_network_failures = 0
        # 按 src_type 取预算：企业模式给更大深挖空间（110/60），edu 走量沿用 90/45。
        max_rounds, soft_rounds = self._route_rounds(*worker_config.rounds_for(self.src_type))
        while rounds < max_rounds:
            if self.cancel_event.is_set():
                return self._cancelled_result(rounds)
            rounds += 1
            try:
                self._emit("llm_round_start", round=rounds)
                tools = list(TOOL_SCHEMAS)
                if self._enterprise:
                    tools += ENTERPRISE_SESSION_TOOL_SCHEMAS
                if self._js_tool_enabled:
                    tools += JS_ANALYZER_TOOL_SCHEMAS
                send_messages = compact_messages(messages, rounds)
                msg = self.llm.chat(send_messages, tools=tools, tool_choice="auto")
            except Exception as e:
                self._emit("llm_error", error=str(e))
                return WorkerResult(
                    target=self.target, verdict=Verdict.error,
                    findings=self.findings, rounds=rounds, error=f"LLM 调用失败: {e}",
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
                if no_tool_rounds >= 3:
                    self._auto_finish("模型连续 3 轮没有调用工具或 finish，系统自动收敛。")
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
                if consecutive_arg_errors >= 2:
                    self._auto_finish("连续 2 次工具参数错误，模型未修正，系统自动收敛。")
                    break
                if consecutive_network_failures >= 3:
                    self._auto_finish("连续 3 次网络/超时失败，目标当前不可稳定验证，系统自动收敛。")
                    break
                if consecutive_failures >= 5:
                    self._auto_finish("连续 5 次工具失败且无新证据，系统自动收敛。")
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
            error=None if self._finished else f"达到最大轮数 {max_rounds} 未主动结束",
            deepen_lead=(self._finished or {}).get("deepen_lead", ""),
            reported_intel=self._reported_intel,
            reported_coverage=self._reported_coverage,
        )

    def _route_rounds(self, max_rounds: int, soft_rounds: int) -> tuple[int, int]:
        """按打法路线微调软收敛节奏。

        deep 路线（Actuator/Nacos/API docs/低代码等）更容易需要多步链路，延后软催收；
        static_low_value 才收紧硬上限，避免门户/官网长时间空转。
        """
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
        )

    def _deepen_brief(self) -> str:
        ctx = self.deepen_context or {}
        directive = ctx.get("directive", "").strip()
        original = ctx.get("original_title", "") or ctx.get("vuln_type", "")
        summary = (ctx.get("original_summary", "") or "").strip()
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
            return self.executor.run_shell(command, timeout=args.get("timeout"))

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

    def _auto_finish(self, reason: str) -> None:
        verdict = "found" if self.findings else "no_vuln"
        self._finished = {"verdict": verdict, "summary": reason}
        self._emit("worker_auto_finish", verdict=verdict, summary=reason[:300])

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

        evidence_block = self._weak_write_evidence_reason(finding)
        if evidence_block:
            self._emit("finding_needs_more_evidence", title=finding.title, reason=evidence_block[:200])
            return {
                "ok": False,
                "kind": "needs_more_evidence",
                "submitted": False,
                "error": evidence_block,
                "guidance": (
                    "不要把这条半成品提交给 reviewer。请继续找真实存在的对象 ID、列表/详情/查询接口，"
                    "做 before/after 或响应差异验证；如果无法安全证明真实状态变化，调用 finish(verdict=no_vuln)，"
                    "并在 deepen_lead 写清下一轮要沿哪个接口/ID 继续验证。"
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

        这类 finding 会消耗 reviewer token，且大多被判 ignored。这里不终止 worker，
        只把提交退回，要求继续找真实 ID/前后状态差异，或用 deepen_lead 交棒。
        """
        if self._enterprise:
            return ""
        vuln_type = (finding.vuln_type or "").lower()
        title_desc = "\n".join([
            finding.title,
            finding.target_url,
            finding.description,
            finding.poc,
            finding.raw_request,
            finding.raw_response,
            finding.evidence.extracted_data_sample or "",
            finding.evidence.notes or "",
        ])
        low = title_desc.lower()
        if not any(marker in vuln_type for marker in ("unauthorized", "idor", "auth", "access", "越权", "未授权")):
            return ""
        write_markers = (
            "updatedel", "delete", "remove", "update", "modify", "edit", "save",
            "insert", "create", "del", "删除", "删", "修改", "更新", "写操作",
        )
        if not any(marker in low for marker in write_markers):
            return ""
        zero_effect_patterns = (
            r'"data"\s*:\s*0\b',
            r'"affected(?:rows)?"\s*:\s*0\b',
            r'"row(?:s|count)?"\s*:\s*0\b',
            r'"count"\s*:\s*0\b',
            r"\b0\s+rows?\b",
            r"影响\s*0",
            r"0\s*行",
            r"不存在",
            r"未实证",
            r"未证明",
        )
        if not any(re.search(pattern, low, re.IGNORECASE) for pattern in zero_effect_patterns):
            return ""
        positive_patterns = (
            r'"data"\s*:\s*[1-9]\d*\b',
            r'"affected(?:rows)?"\s*:\s*[1-9]\d*\b',
            r"再次查询.*(不存在|消失|已删除|状态变化|已更新)",
            r"(before|after|前后对比|状态变化|修改后查询|删除后查询)",
            r"(真实存在的|已存在的)\s*(id|记录|对象)",
        )
        if any(re.search(pattern, low, re.IGNORECASE) for pattern in positive_patterns):
            return ""
        return (
            "写/删/改接口证据不足：当前证据显示接口返回成功文案但影响为 0 或使用了不存在的对象，"
            "只能证明接口可被调用，不能证明真实删除/修改了受限数据。"
        )
