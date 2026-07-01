"""搜集 Agent 的 LLM 辅助：意图→FOFA 语法生成 + edu 归属批量判定。

这两个函数都是同步的（内部调 LLMClient.chat），由 collector 在线程池里调用，
避免阻塞 orchestrator 的事件循环。任何异常都返回降级结果，不阻断主循环。
"""
from __future__ import annotations

import json
from typing import Optional

from app.agents.prompts import (
    COLLECTOR_EDU_PROMPT_COMPACT,
    collector_default_intent,
    collector_query_prompt,
    collector_scope_note,
)
from app.llm.client import LLMClient
from app.tools.schemas import COLLECTOR_EDU_SCHEMAS, COLLECTOR_QUERY_SCHEMAS


def _tool_args(msg, name: str) -> Optional[dict]:
    for tc in (getattr(msg, "tool_calls", None) or []):
        if tc.function.name == name:
            try:
                return json.loads(tc.function.arguments)
            except Exception:
                return None
    return None


def generate_query(llm: LLMClient, intent: str, vuln_types: list[str],
                   history: list[str], src_type: str = "edusrc") -> Optional[dict]:
    """把搜集意图翻译成一条新的 FOFA 语法。返回 {query, reason} 或 None。"""
    user = (
        f"# 搜集意图\n{intent or collector_default_intent(src_type)}\n\n"
        f"# 本任务关注的漏洞类型\n{', '.join(vuln_types) or '通用'}\n\n"
        f"{collector_scope_note(src_type)}"
        f"# 已经用过的 FOFA 语法（不要重复，换角度）\n"
        + ("\n".join(f"- {h}" for h in history[-10:]) if history else "（暂无）")
        + "\n\n请产出本轮的 1 条 FOFA 语法。"
    )
    msg = llm.chat(
        [{"role": "system", "content": collector_query_prompt(src_type)},
         {"role": "user", "content": user}],
        tools=COLLECTOR_QUERY_SCHEMAS,
        tool_choice={"type": "function", "function": {"name": "gen_query"}},
        temperature=0.5,
    )
    args = _tool_args(msg, "gen_query")
    if args and args.get("query"):
        return {"query": args["query"].strip(), "reason": args.get("reason", "")}
    return None


def judge_edu_batch(llm: LLMClient, assets: list[dict]) -> dict[int, dict]:
    """批量判定资产是否 edu + 归属学校。assets: [{host, ip, org, title}]。
    返回 {index: {is_edu: bool, school: str}}。"""
    if not assets:
        return {}
    lines = []
    for i, a in enumerate(assets):
        lines.append(
            f"[{i}] host={a.get('host','')} ip={a.get('ip','')} "
            f"org={a.get('org','')} title={a.get('title','')}"
        )
    user = "# 待判定资产\n" + "\n".join(lines) + "\n\n请逐个判定是否属于中国教育行业，并给出归属学校全称；不要输出理由。"
    msg = llm.chat(
        [{"role": "system", "content": COLLECTOR_EDU_PROMPT_COMPACT},
         {"role": "user", "content": user}],
        tools=COLLECTOR_EDU_SCHEMAS,
        tool_choice={"type": "function", "function": {"name": "judge_edu"}},
        temperature=0.0,
    )
    args = _tool_args(msg, "judge_edu")
    out: dict[int, dict] = {}
    if args:
        for r in args.get("results", []):
            try:
                out[int(r["index"])] = {
                    "is_edu": bool(r["is_edu"]),
                    "school": (r.get("school") or "").strip(),
                }
            except Exception:
                continue
    return out
