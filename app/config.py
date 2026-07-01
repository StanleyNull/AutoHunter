"""配置：全部从环境变量读取，凭证绝不硬编码进源码。"""
from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel


def _load_dotenv() -> None:
    """极简 .env 加载（不引第三方依赖）。已存在的环境变量不覆盖。"""
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)


_load_dotenv()


class LLMConfig(BaseModel):
    base_url: str = os.environ.get("LLM_BASE_URL", "https://api.deepseek.com/v1")
    api_key: str = os.environ.get("LLM_API_KEY", "")
    model: str = os.environ.get("LLM_MODEL", "deepseek-chat")
    temperature: float = float(os.environ.get("LLM_TEMPERATURE", "0.3"))


class WorkerConfig(BaseModel):
    # run_shell 单命令超时（秒）
    shell_timeout: int = int(os.environ.get("WORKER_SHELL_TIMEOUT", "120"))
    # 工具输出回传 LLM 前的截断字节数（当轮模型看完整一次即可，无需长期占历史）
    output_truncate: int = int(os.environ.get("WORKER_OUTPUT_TRUNCATE", "4096"))
    # 实际回传给 LLM 的工具输出上限。即使老环境把 WORKER_OUTPUT_TRUNCATE 设得很大，
    # 默认仍只给模型一份紧凑证据片段，完整内容继续落工作目录文件，避免动态上下文失控。
    llm_tool_output_truncate: int = int(os.environ.get("WORKER_LLM_TOOL_OUTPUT_TRUNCATE", "4096"))
    # 历史滑动窗口：保留最近 N 轮的完整 tool 响应，更早的 tool 响应在重发时
    # 压成一行摘要（保留状态/长度/关键字段，丢弃大 body）。这是省 token 的核心：
    # 模型决策主要依赖最近几轮，远古完整响应每轮重发是 190M 输入的主因。
    history_full_tool_rounds: int = int(os.environ.get("WORKER_HISTORY_FULL_TOOL_ROUNDS", "4"))
    # 硬上限：单目标最大工具调用轮数（LLM 自主决定 finish，这是兜底防失控）
    max_rounds: int = int(os.environ.get("WORKER_MAX_ROUNDS", "90"))
    # 软引导阈值：超过此轮数后每轮催 worker 收尾，减少低价值空转（不硬杀，保质量）
    soft_rounds: int = int(os.environ.get("WORKER_SOFT_ROUNDS", "45"))
    # 企业模式预算（深挖需要更大空间：分层递进 + 据点深挖 + 链式扩大）。
    # edu 走量沿用上面的 90/45；企业单目标挖透，给到 110/60。
    enterprise_max_rounds: int = int(os.environ.get("ENTERPRISE_WORKER_MAX_ROUNDS", "110"))
    enterprise_soft_rounds: int = int(os.environ.get("ENTERPRISE_WORKER_SOFT_ROUNDS", "60"))
    # 成本模式硬帽：设为 0 关闭硬帽，完全按 max/soft 运行。
    # 早期 24 轮软帽会让有攻击面的目标过早被催 no_vuln，默认关闭；需要省钱时显式打开。
    round_budget_cap: int = int(os.environ.get("WORKER_ROUND_BUDGET_CAP", "0"))
    soft_round_budget_cap: int = int(os.environ.get("WORKER_SOFT_ROUND_BUDGET_CAP", "0"))
    enterprise_round_budget_cap: int = int(os.environ.get("ENTERPRISE_WORKER_ROUND_BUDGET_CAP", "0"))
    enterprise_soft_round_budget_cap: int = int(os.environ.get("ENTERPRISE_WORKER_SOFT_ROUND_BUDGET_CAP", "0"))
    # JS 分析工具 schema 体积不小，默认按信号开启；设 1 可恢复每轮常驻。
    js_tool_always_on: bool = os.environ.get("WORKER_JS_TOOL_ALWAYS_ON", "0").lower() in {"1", "true", "yes"}
    # worker 提示词版本：legacy=2026-06-25 老版骨架+新工具说明；current=当前省 token 版；modern/full=当前完整版。
    prompt_version: str = os.environ.get("WORKER_PROMPT_VERSION", "legacy")
    # 工作目录根
    work_root: str = os.environ.get("WORKER_WORK_ROOT", "/tmp/autohunter/work")

    def rounds_for(self, src_type: str | None) -> tuple[int, int]:
        """按 src_type 返回 (max_rounds, soft_rounds)。企业模式给更大深挖预算。"""
        st = (src_type or "").strip().lower()
        if st in {"enterprise", "corp", "company", "企业", "企业src"}:
            max_rounds = self._cap(self.enterprise_max_rounds, self.enterprise_round_budget_cap)
            soft_rounds = self._cap(self.enterprise_soft_rounds, self.enterprise_soft_round_budget_cap)
        else:
            max_rounds = self._cap(self.max_rounds, self.round_budget_cap)
            soft_rounds = self._cap(self.soft_rounds, self.soft_round_budget_cap)
        return max(1, max_rounds), max(1, min(soft_rounds, max_rounds))

    @staticmethod
    def _cap(value: int, cap: int) -> int:
        return min(value, cap) if cap > 0 else value


llm_config = LLMConfig()
worker_config = WorkerConfig()
