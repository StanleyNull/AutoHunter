"""API 请求/响应 DTO。"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class ModelConfigDTO(BaseModel):
    base_url: str = "https://api.deepseek.com/v1"
    api_key: str = ""           # 留空则用服务端 .env 默认
    model: str = "deepseek-chat"
    prompt_version: str = ""     # current / legacy / modern；留空则用全局默认


class FofaConfigDTO(BaseModel):
    key: str = ""               # 留空则用服务端 .env 默认
    base_url: str = ""          # 自定义 FOFA API 端点；留空则用服务端 .env 默认(官方 https://fofa.info)
    max_pages: int = 20
    page_size: int = 100
    intent_mode: str = ""       # syntax=用户给的是FOFA语法 / intent=自然语言意图(LLM翻译) / 空=自动判断


class CreateTaskRequest(BaseModel):
    name: str
    src_type: str = "edusrc"
    vuln_types: list[str] = Field(default_factory=list)
    src_rules: str = ""
    target_source: str = "fofa"        # fofa / manual / both / site
    fofa_query: str = ""
    manual_targets: list[str] = Field(default_factory=list)
    model_config_data: ModelConfigDTO = Field(default_factory=ModelConfigDTO)
    fofa_config: FofaConfigDTO = Field(default_factory=FofaConfigDTO)
    concurrency: int = 3


class PartialModelConfigDTO(BaseModel):
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    prompt_version: Optional[str] = None


class PartialFofaConfigDTO(BaseModel):
    key: Optional[str] = None
    base_url: Optional[str] = None
    max_pages: Optional[int] = None
    page_size: Optional[int] = None
    intent_mode: Optional[str] = None


class UpdateTaskRequest(BaseModel):
    name: Optional[str] = None
    src_type: Optional[str] = None
    vuln_types: Optional[list[str]] = None
    src_rules: Optional[str] = None
    target_source: Optional[str] = None
    fofa_query: Optional[str] = None
    manual_targets: Optional[list[str]] = None
    model_config_data: Optional[PartialModelConfigDTO] = None
    fofa_config: Optional[PartialFofaConfigDTO] = None
    concurrency: Optional[int] = None


class TaskStats(BaseModel):
    queued: int = 0
    scanning: int = 0
    done: int = 0
    dead: int = 0          # 硬骨头库：重试/超时/异常仍无果
    skipped: int = 0       # 低分垃圾资产直接跳过
    findings_total: int = 0
    pending_review: int = 0
    accepted: int = 0
    ignored: int = 0
    deepen: int = 0        # 被审核打回深挖的线索数
    killsweep: int = 0     # 通杀列命中数（人工复审通过后触发通杀 Hunter）
    # 各 Tab 的权威计数（用户复审维度），供前端徽标/指标卡直接用，不再依赖懒加载数组
    review_pending: int = 0   # 复审队列：AI accepted 且用户 pending
    submit_ready: int = 0     # 待提交：用户复审 passed 且尚未提交
    rejected: int = 0         # 已驳回：用户复审 rejected


class TaskResponse(BaseModel):
    id: str
    name: str
    status: str
    src_type: str
    vuln_types: list[str]
    target_source: str
    fofa_query: str
    concurrency: int
    src_rules: str = ""
    manual_targets: list[str] = Field(default_factory=list)
    model_config_data: dict = Field(default_factory=dict)
    fofa_config: dict = Field(default_factory=dict)
    llm_usage: dict = Field(default_factory=dict)
    created_at: str
    updated_at: str
    stats: Optional[TaskStats] = None
    # 待人工复审数（AI accepted 且用户未处理）——任务卡片红点用，列表接口轻量填充
    pending_user_review: int = 0


class LLMSettingsDTO(BaseModel):
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    temperature: Optional[float] = None


class FofaSettingsDTO(BaseModel):
    key: Optional[str] = None
    base_url: Optional[str] = None
    max_pages: Optional[int] = None
    page_size: Optional[int] = None
    default_intent_mode: Optional[str] = None


class DefaultsSettingsDTO(BaseModel):
    concurrency: Optional[int] = None
    skip_score_threshold: Optional[float] = None
    worker_prompt_version: Optional[str] = None


class SettingsUpdateRequest(BaseModel):
    llm: Optional[LLMSettingsDTO] = None
    fofa: Optional[FofaSettingsDTO] = None
    defaults: Optional[DefaultsSettingsDTO] = None
