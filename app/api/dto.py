"""API 请求/响应 DTO。"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class ModelConfigDTO(BaseModel):
    base_url: str = "https://api.deepseek.com/v1"
    api_key: str = ""
    model: str = "deepseek-chat"
    prompt_version: str = ""


class FofaConfigDTO(BaseModel):
    key: str = ""
    base_url: str = ""
    max_pages: int = 20
    page_size: int = 100
    intent_mode: str = ""


class EngineConfigDTO(BaseModel):
    """多引擎配置。"""
    key: str = ""
    base_url: str = ""


class CreateTaskRequest(BaseModel):
    name: str
    src_type: str = "edusrc"
    vuln_types: list[str] = Field(default_factory=list)
    src_rules: str = ""
    target_source: str = "fofa"
    engine: str = ""                                           # 搜索引擎：fofa/quake/hunter/...
    fofa_query: str = ""
    manual_targets: list[str] = Field(default_factory=list)
    model_config_data: ModelConfigDTO = Field(default_factory=ModelConfigDTO)
    fofa_config: FofaConfigDTO = Field(default_factory=FofaConfigDTO)
    engine_config: EngineConfigDTO = Field(default_factory=EngineConfigDTO)  # 引擎 Key/URL
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


class PartialEngineConfigDTO(BaseModel):
    key: Optional[str] = None
    base_url: Optional[str] = None


class UpdateTaskRequest(BaseModel):
    name: Optional[str] = None
    src_type: Optional[str] = None
    vuln_types: Optional[list[str]] = None
    src_rules: Optional[str] = None
    target_source: Optional[str] = None
    engine: Optional[str] = None                                 # 切换引擎
    fofa_query: Optional[str] = None
    manual_targets: Optional[list[str]] = None
    model_config_data: Optional[PartialModelConfigDTO] = None
    fofa_config: Optional[PartialFofaConfigDTO] = None
    engine_config: Optional[PartialEngineConfigDTO] = None
    concurrency: Optional[int] = None


class TaskStats(BaseModel):
    queued: int = 0
    scanning: int = 0
    done: int = 0
    dead: int = 0
    skipped: int = 0
    pending_input: int = 0   # 需要用户提供凭证/完成注册的目标
    findings_total: int = 0
    pending_review: int = 0
    accepted: int = 0
    ignored: int = 0
    deepen: int = 0
    killsweep: int = 0
    review_pending: int = 0
    submit_ready: int = 0
    rejected: int = 0
    archived: int = 0


class TaskResponse(BaseModel):
    id: str
    name: str
    status: str
    src_type: str
    vuln_types: list[str]
    target_source: str
    engine: str = ""
    fofa_query: str
    concurrency: int
    src_rules: str = ""
    manual_targets: list[str] = Field(default_factory=list)
    model_config_data: dict = Field(default_factory=dict)
    fofa_config: dict = Field(default_factory=dict)
    engine_config: dict = Field(default_factory=dict)
    llm_usage: dict = Field(default_factory=dict)
    created_at: str
    updated_at: str
    stats: Optional[TaskStats] = None
    pending_user_review: int = 0
    # AI 未采纳归档数（ignored/deepen 且用户未处理）——任务卡片绿点用，列表接口轻量填充
    pending_archived: int = 0


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


class EngineSettingsDTO(BaseModel):
    """单个搜索引擎的设置。"""
    key: Optional[str] = None
    base_url: Optional[str] = None


class DefaultsSettingsDTO(BaseModel):
    concurrency: Optional[int] = None
    skip_score_threshold: Optional[float] = None
    worker_prompt_version: Optional[str] = None
    engine: Optional[str] = None


class ProxySettingsDTO(BaseModel):
    ssh_servers: Optional[str] = None
    ssh_key_path: Optional[str] = None


class SettingsUpdateRequest(BaseModel):
    llm: Optional[LLMSettingsDTO] = None
    fofa: Optional[FofaSettingsDTO] = None
    engines: Optional[dict[str, EngineSettingsDTO]] = None   # 按引擎名索引
    defaults: Optional[DefaultsSettingsDTO] = None
    proxy: Optional[ProxySettingsDTO] = None
