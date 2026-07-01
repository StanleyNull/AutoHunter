"""Reviewer Agent：极理性审核 + EduSRC 评级 + 垃圾洞过滤。

输入：worker 提交的 Finding（独立审核，不看 worker 挖掘过程）。
流程（对应设计文档 §7）：
  阶段① 规则匹配（快速过滤明显忽略项）— 由 LLM 在提示词内完成
  阶段② 证据链审查（LLM 核心）
  阶段③ 复现验证（仅当评定为 严重/高危 时触发，重新发包）
输出：Review 结论。
"""
from __future__ import annotations

import json
import threading
from typing import Any, Callable, Optional

from pydantic import ValidationError

from app.agents.prompts import normalize_src_type, reviewer_system_prompt
from app.llm.client import LLMClient, LLMError
from app.schemas import Confidence, Finding, Review, ReviewVerdict, Severity
from app.tools.executor import ToolExecutor
from app.tools.schemas import REVIEWER_TOOL_SCHEMAS

# 触发复现验证的等级
_HIGH_VALUE = {Severity.critical, Severity.high}
_DESTRUCTIVE_POC_MARKERS = (
    "delete", "remove", "drop ", "truncate",
)
_REVIEW_TEXT_LIMITS = {
    "description": 1800,
    "poc": 1800,
    "raw_request": 1800,
    "raw_response": 3200,
    "affected_scope": 1000,
    "owner": 500,
}

_REVIEW_STATIC_PREFIX = (
    "下一条是 Finding JSON。只按真实请求/响应/PoC/证据/自检审核；证据不足但可打穿则 deepen，垃圾 ignored。"
)

_REVIEW_NEVER_DEEPEN_MARKERS = (
    "反射型xss", "反射 xss", "self-xss", "self xss", "用户名枚举",
    "phpinfo", "拒绝服务", "dos",
    "非教育", "不在范围", "钓鱼", "中间人", "mitm", "本就公开", "公开展示", "公开接口",
)
_REVIEW_CAPTCHA_ONLY_IGNORE_MARKERS = ("图形验证码", "算术验证码")


def _review_text(finding: Finding, review: Review) -> str:
    parts: list[str] = [
        finding.vuln_type,
        finding.title,
        finding.target_url,
        finding.description,
        finding.poc,
        finding.raw_request,
        finding.raw_response,
        finding.affected_scope,
        json.dumps(finding.evidence.model_dump(mode="json"), ensure_ascii=False),
        json.dumps([s.model_dump(mode="json") for s in finding.kill_chain], ensure_ascii=False),
        " ".join(review.ignore_reasons or []),
        " ".join(review.downgrade_reasons or []),
        review.reviewer_notes,
    ]
    return "\n".join(str(p or "") for p in parts).lower()


def _has_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(m.lower() in text for m in markers)


def _ignored_deepen_directive(finding: Finding, review: Review, src_type: str) -> str:
    """把少数“真实入口但未打穿”的 ignored 兜底转成 deepen。

    这不是放宽 accepted 口径，只是避免 reviewer 把已有价值线索直接归档；
    真正垃圾/公开展示/图形验证码/反射 XSS 仍保持 ignored。
    """
    if review.verdict != ReviewVerdict.ignored or review.is_duplicate or not review.in_scope:
        return ""

    sc = finding.self_check
    if sc.is_reflected_xss or sc.needs_admin_login or sc.needs_mitm or sc.scanner_only_no_poc:
        return ""

    text = _review_text(finding, review)
    register_like = _has_any(text, ("注册", "register", "signup"))
    never_markers = _REVIEW_NEVER_DEEPEN_MARKERS
    if register_like:
        never_markers = tuple(m for m in never_markers if m not in {"本就公开", "公开接口"})
    if (
        _has_any(text, never_markers)
        or (_has_any(text, _REVIEW_CAPTCHA_ONLY_IGNORE_MARKERS) and not register_like)
    ):
        return ""

    auth_signal = _has_any(text, (
        "未授权", "无需登录", "无鉴权", "未鉴权", "unauthorized", "without auth", "no auth",
    ))
    config_signal = _has_any(text, (
        "系统配置", "配置项", "系统参数", "configkey", "initpassword", "init password",
        "sys.user.initpassword", "/config", "appconfig", "setting",
    ))
    register_signal = register_like and _has_any(text, (
        "注册", "批量注册", "无验证码", "免验证码", "register", "signup", "captcha",
    ))
    secret_context = _has_any(text, ("泄露", "硬编码", "暴露", "明文", "返回", "前端", "js", "配置", "config"))
    strong_secret_signal = _has_any(text, (
        "secret", "appsecret", "clientsecret", "api key", "apikey", "accesskey",
        "私钥", "密钥", "签名密钥",
    ))
    bearer_secret_signal = _has_any(text, ("token", "jwt", "session")) and secret_context
    secret_signal = strong_secret_signal or bearer_secret_signal
    upload_signal = _has_any(text, (
        "上传", "upload", "savefile", "fileupload", "multipart/form-data",
    ))
    write_signal = _has_any(text, (
        "修改", "删除", "新增", "保存", "重置", "update", "delete", "remove", "save", "reset",
    ))

    if config_signal and (auth_signal or secret_signal):
        return (
            "不要再把“配置项泄露”当最终成果提交；沿已证实的配置接口继续深挖："
            "枚举更多配置 key/接口地址，提取 token、secret、默认口令或后台路径，并实证能否登录后台、"
            "调用受限 API、读取死规矩敏感数据或执行敏感写操作。只拿到默认值/普通配置则 finish no_vuln。"
        )

    if register_signal:
        return (
            "基于已证实的注册入口继续深挖，不要把“可批量注册”单独当洞："
            "注册低影响测试账号后登录拿 token/session，枚举表单/用户/导出/后台 API，"
            "验证是否能读取或修改他人数据、批量导出、越权访问管理接口，或链到短信/改密/账号接管。"
            "若只能注册空账号且无下游危害，finish no_vuln。"
        )

    if secret_signal:
        return (
            "沿已发现的 key/secret/token 继续深挖：确认它是否可用，尝试伪造签名或携带凭证调用受限 API，"
            "必须打出读取敏感数据、后台权限、配额盗刷或敏感写操作的实证；仅证明字符串存在不要再提交。"
        )

    if upload_signal and auth_signal:
        return (
            "沿未授权上传入口继续深挖：验证可上传的扩展名、落点路径和访问方式，"
            "优先证明脚本可解析执行/可覆盖敏感文件/可读取敏感数据；只能上传并访问 txt 则 finish no_vuln。"
        )

    if write_signal and auth_signal:
        return (
            "沿未授权写接口继续深挖：先找到真实存在的对象 ID 和查询/详情接口，"
            "再用前后状态差异证明可修改、删除、重置或越权操作真实业务数据；只有成功文案没有状态变化不要提交。"
        )

    if src_type == "enterprise" and auth_signal:
        return (
            "该未授权线索尚未打出企业可收影响；继续验证是否能读取客户/员工/订单/审批/财务等受限数据，"
            "或执行权限、配置、业务状态类敏感写操作。无实际影响则 finish no_vuln。"
        )

    return ""


def _maybe_deepen_ignored(finding: Finding, review: Review, src_type: str) -> bool:
    directive = _ignored_deepen_directive(finding, review, normalize_src_type(src_type))
    if not directive:
        return False
    review.verdict = ReviewVerdict.deepen
    review.confidence = Confidence.uncertain
    review.severity_final = None
    review.score = min(max(review.score, 2.5), 3.9)
    review.deepen_directive = review.deepen_directive or directive
    review.reviewer_notes = (
        (review.reviewer_notes or "").strip()
        + "\n[系统改判] 该 Finding 不够 accepted，但属于“入口真实、下一步明确”的半成品；已从 ignored 改为 deepen，要求 worker 定向补链。"
    ).strip()
    return True


def _is_thinking_tool_choice_error(err: LLMError) -> bool:
    """DeepSeek v4 thinking mode rejects forced function tool_choice.

    The same model still supports tools with auto tool choice, so reviewer can
    safely fall back to auto and keep validating that submit_review was called.
    """
    raw = f"{err} {getattr(err, 'original', '')}".lower()
    return "thinking mode does not support this tool_choice" in raw


def _clip_text(text: str, limit: int) -> str:
    text = str(text or "")
    if len(text) <= limit:
        return text
    head = max(1, int(limit * 0.65))
    tail = max(1, limit - head - 60)
    return f"{text[:head]}\n...[已截断 {len(text) - limit} 字]...\n{text[-tail:]}"


def _clip_jsonish(value: Any, text_limit: int = 900, depth: int = 0) -> Any:
    if depth >= 3:
        return _clip_text(json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value), text_limit)
    if isinstance(value, str):
        return _clip_text(value, text_limit)
    if isinstance(value, list):
        if len(value) <= 12:
            items = value
        else:
            items = value[:8] + [f"...[已省略 {len(value) - 12} 项]..."] + value[-4:]
        return [_clip_jsonish(v, text_limit, depth + 1) for v in items]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k in sorted(value.keys(), key=str):
            out[str(k)] = _clip_jsonish(value[k], text_limit, depth + 1)
        return out
    return value


def _review_finding_payload(finding: Finding) -> dict[str, Any]:
    """压缩审核输入里的大字段；保留证据头尾和结构，减少 reviewer 输入 token。"""
    data = finding.model_dump(mode="json")
    for key, limit in _REVIEW_TEXT_LIMITS.items():
        if key in data:
            data[key] = _clip_text(data.get(key) or "", limit)
    data["steps"] = [_clip_text(str(s), 500) for s in (data.get("steps") or [])[:10]]
    data["kill_chain"] = _clip_jsonish(data.get("kill_chain") or [], 700)
    data["evidence"] = _clip_jsonish(data.get("evidence") or {}, 900)
    data["self_check"] = data.get("self_check") or {}
    return data


class Reviewer:
    def __init__(
        self,
        llm: Optional[LLMClient] = None,
        on_event: Optional[Callable[[str, dict], None]] = None,
        enable_reproduce: bool = True,
        src_type: str = "edusrc",
        cancel_event: Optional["threading.Event"] = None,
    ):
        self.llm = llm or LLMClient()
        self.on_event = on_event or (lambda kind, data: None)
        self.enable_reproduce = enable_reproduce
        self.src_type = normalize_src_type(src_type)
        self._last_llm_error = ""
        # 复现验证子进程的协作取消（超时/停止时传导杀进程组）
        self.cancel_event = cancel_event or threading.Event()

    def _emit(self, kind: str, **data: Any) -> None:
        self.on_event(kind, data)

    def review(self, finding: Finding) -> Review:
        self._emit("review_start", title=finding.title)

        # 阶段①②：把 Finding 全文喂给 LLM 审核
        review = self._llm_review(finding)
        if review is None:
            detail = f"：{self._last_llm_error}" if self._last_llm_error else ""
            raise RuntimeError(f"审核 LLM 调用异常或结构化输出无效{detail}，保留 pending_review 稍后重试。")

        if _maybe_deepen_ignored(finding, review, self.src_type):
            self._emit("review_auto_deepen", title=finding.title, directive=review.deepen_directive)

        # 阶段③：仅 accepted 且 严重/高危 才触发复现验证
        if (
            self.enable_reproduce
            and review.verdict == ReviewVerdict.accepted
            and review.severity_final in _HIGH_VALUE
        ):
            self._reproduce(finding, review)
            if not review.reproduced:
                review.verdict = ReviewVerdict.deepen
                review.confidence = Confidence.uncertain
                review.severity_final = None
                review.score = min(review.score, 3.9)
                if not review.deepen_directive:
                    review.deepen_directive = (
                        "当前高危/严重结论复现未通过，不能进入人工待审核。"
                        "请补充真实成功证据：例如证明密码重置后可用新密码登录，"
                        "或证明接口返回明确成功且状态已真实变化。"
                    )
                review.reviewer_notes += (
                    "\n[自动降级] 高危/严重漏洞必须有可复现实锤；本次系统复现未通过，"
                    "已改为 deepen，禁止以未证实结论进入人工复审队列。"
                )

        # 信度约束：未经系统复现的，不允许标 confirmed（最高 likely）
        if not review.reproduced and review.confidence == Confidence.confirmed:
            review.confidence = Confidence.likely

        self._emit(
            "review_done",
            verdict=review.verdict.value,
            severity=review.severity_final.value if review.severity_final else None,
            score=review.score,
            confidence=review.confidence.value,
            deepen_directive=review.deepen_directive if review.verdict == ReviewVerdict.deepen else None,
        )
        return review

    def _llm_review(self, finding: Finding) -> Optional[Review]:
        finding_text = json.dumps(_review_finding_payload(finding), ensure_ascii=False, separators=(",", ":"))
        mode_name = "企业 SRC" if self.src_type == "enterprise" else "EduSRC"
        messages = [
            {"role": "system", "content": reviewer_system_prompt(self.src_type)},
            {"role": "user", "content": _REVIEW_STATIC_PREFIX},
            {"role": "user", "content": (
                f"按 {mode_name} 标准审核并调用 submit_review：\n```json\n{finding_text}\n```"
            )},
        ]
        forced_tool_choice = True
        for _ in range(3):  # 最多 3 次让模型修正
            try:
                tool_choice = (
                    {"type": "function", "function": {"name": "submit_review"}}
                    if forced_tool_choice else "auto"
                )
                msg = self.llm.chat(
                    messages, tools=REVIEWER_TOOL_SCHEMAS,
                    tool_choice=tool_choice,
                )
            except LLMError as e:
                if e.kind == "quota":
                    raise
                self._last_llm_error = str(e)
                if forced_tool_choice and _is_thinking_tool_choice_error(e):
                    forced_tool_choice = False
                    self._emit(
                        "review_tool_choice_fallback",
                        error="thinking 模式不支持强制 submit_review，已降级为 auto tool_choice 重试",
                    )
                    messages.append({
                        "role": "user",
                        "content": (
                            "当前模型不支持强制指定工具。请你必须主动调用 submit_review 工具，"
                            "不要只输出自然语言；否则本次审核无法落库。"
                        ),
                    })
                    continue
                self._emit("review_error", error=self._last_llm_error)
                return None
            except Exception as e:
                self._last_llm_error = str(e)
                self._emit("review_error", error=self._last_llm_error)
                return None

            tool_calls = getattr(msg, "tool_calls", None)
            if not tool_calls:
                messages.append({"role": "assistant", "content": msg.content or ""})
                messages.append({"role": "user", "content": "请调用 submit_review 工具输出结构化结论。"})
                continue

            tc = tool_calls[0]
            try:
                args = json.loads(tc.function.arguments or "{}")
                review = Review(**args)
                # reproduced 只能由系统的复现阶段设置，不信任 LLM 自填
                review.reproduced = False
                return review
            except (json.JSONDecodeError, ValidationError) as e:
                messages.append({"role": "assistant", "content": "", "tool_calls": [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                ]})
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "content": f"校验失败，请修正后重新调用 submit_review: {e}"})
        return None

    def _reproduce(self, finding: Finding, review: Review) -> None:
        """复现验证：重新执行 PoC（高价值漏洞才做）。"""
        self._emit("reproduce_start", title=finding.title)
        executor = ToolExecutor(f"review_{finding.target_url}", cancel_event=self.cancel_event,
                                enterprise=(self.src_type == "enterprise"))
        # 用 PoC 重新发包（PoC 通常是 curl 命令）
        poc = finding.poc.strip()
        if not poc:
            review.reviewer_notes += "\n[复现] 无 PoC 可执行。"
            self._emit("reproduce_done", title=finding.title, reproduced=False)
            return
        if self._looks_destructive_poc(poc):
            review.reviewer_notes += (
                "\n[复现验证] SKIPPED：PoC 疑似会删除、清库或执行不可逆写操作，"
                "系统不会自动执行这类破坏性验证。该 PoC 不能作为已复现实锤。"
            )
            self._emit("reproduce_done", title=finding.title, reproduced=False)
            return
        result = executor.run_shell(poc, timeout=60)
        out = (result.get("output") or "")[:1000]
        # 让 LLM 判断复现输出是否支撑漏洞
        try:
            msg = self.llm.chat([
                {"role": "system", "content": "你在做漏洞复现验证。根据 PoC 的实际执行输出，判断该漏洞是否被成功复现。只回 YES 或 NO 加一句理由。"},
                {"role": "user", "content": (
                    f"漏洞: {finding.title}\n预期: {finding.description[:500]}\n\n"
                    f"PoC 实际执行输出:\n{out}\n\n该漏洞是否成功复现？"
                )},
            ], temperature=0.0)
            verdict_text = (msg.content or "").strip()
        except Exception as e:
            verdict_text = f"复现判断异常: {e}"

        reproduced = verdict_text.upper().startswith("YES")
        review.reproduced = reproduced
        if reproduced:
            review.confidence = Confidence.confirmed
        elif review.confidence == Confidence.confirmed:
            review.confidence = Confidence.likely
        review.reviewer_notes += f"\n[复现验证] {verdict_text}"
        self._emit("reproduce_done", title=finding.title, reproduced=reproduced)

    @staticmethod
    def _looks_destructive_poc(poc: str) -> bool:
        text = (poc or "").lower()
        return any(marker in text for marker in _DESTRUCTIVE_POC_MARKERS)
