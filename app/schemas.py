"""核心数据结构 (Pydantic)。

Finding 是 worker 挖到漏洞后的标准输出格式，对应设计文档 §6。
SelfCheck 强制 worker 先对照当前 SRC 模式的忽略清单做一遍自检。
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "严重"
    high = "高危"
    medium = "中危"
    low = "低危"


class Verdict(str, Enum):
    found = "found"      # 挖到漏洞
    no_vuln = "no_vuln"  # 确认无漏洞
    error = "error"      # 出错
    ip_banned = "ip_banned"  # 确认 IP 被目标 WAF 封禁
    needs_auth = "needs_auth"  # 目标有攻击面但需要用户提供凭证/完成注册才能继续


class SelfCheck(BaseModel):
    """worker 提交漏洞前的垃圾洞自检，对照当前 SRC 模式忽略清单。"""
    is_reflected_xss: bool = Field(False, description="是否为反射型 XSS（按当前 SRC 规则判断是否忽略/降级）")
    needs_admin_login: bool = Field(False, description="是否需要登录管理员后台才能触发（会被忽略）")
    needs_mitm: bool = Field(False, description="是否需要中间人攻击（会被忽略）")
    is_pure_info_leak: bool = Field(False, description="是否为无实际利用的信息泄露，如 phpinfo/内网IP/源码（会被忽略）")
    scanner_only_no_poc: bool = Field(False, description="是否仅扫描器出结果但无法给出利用方法（会被忽略）")
    is_public_interface: bool = Field(False, description="该接口是否本就是面向公众的公开接口（若是，访问它通常不构成漏洞）")
    info_leak_hits_strict_list: bool = Field(False, description="若属信息泄露类：泄露数据是否命中当前 SRC 模式的高价值敏感数据口径")


class Evidence(BaseModel):
    extracted_data_sample: Optional[str] = Field(None, description="脱敏后的数据样本，证明能拿到数据")
    tool_output: Optional[str] = Field(None, description="关键工具输出片段")
    notes: Optional[str] = Field(None, description="其它证据说明")


class ChainStep(BaseModel):
    """攻击链路中的一步：用了什么方法 + 这步得到了什么。"""
    method: str = Field(..., description="这一步用的方法/动作，如『审计前端JS』『提取API端点』『测试越权』")
    detail: str = Field("", description="这步具体做了什么、发现/得到了什么")


class Finding(BaseModel):
    """worker 标准漏洞输出。缺关键字段审核会直接打回。"""
    vuln_type: str = Field(..., description="漏洞类型，如 sql_injection / rce / captcha_bypass / idor / unauthorized_access")
    title: str = Field(..., description="漏洞标题，格式：[目标] - [模块] - [简述]")
    severity_claimed: Severity = Field(..., description="worker 自评等级")
    target_url: str = Field(..., description="漏洞所在 URL")
    owner: str = Field("", description="归属单位/业务系统 + 确认依据。EduSRC 写学校；企业模式写企业/集团/系统")
    description: str = Field(..., description="漏洞类型、触发条件、影响范围")
    steps: list[str] = Field(..., description="复现步骤，逐条")
    poc: str = Field(..., description="可执行的 PoC，curl 命令 / payload")
    raw_request: str = Field("", description="原始请求包")
    raw_response: str = Field("", description="原始响应包（含证明漏洞的关键差异）")
    evidence: Evidence = Field(default_factory=Evidence)
    affected_scope: str = Field("", description="影响面，如可获取的数据量/权限")
    kill_chain: list[ChainStep] = Field(default_factory=list, description="攻击链路：按时间顺序记录怎么一步步打下来的（侦察→定位→利用→取证）")
    self_check: SelfCheck = Field(default_factory=SelfCheck)


class WorkerResult(BaseModel):
    """worker 对单个目标的最终结论。"""
    target: str
    verdict: Verdict
    findings: list[Finding] = Field(default_factory=list)
    summary: str = Field("", description="worker 对本次挖掘的总结")
    rounds: int = 0
    error: Optional[str] = None
    deepen_lead: str = Field("", description="突破入口但未打穿时的定向深挖线索，触发自动回火再派一轮")
    auth_assessment: Optional[dict] = Field(None, description="verdict=needs_auth 时的注册可行性评估，含 reg_status/block_reason 等")
    reported_intel: list[dict] = Field(default_factory=list, description="worker 主动上报的可复用情报，编排层落全局情报库")
    reported_coverage: list[dict] = Field(default_factory=list, description="单站协作覆盖记录，编排层写事件流供后续 worker 复用")


class AuthAssessment(BaseModel):
    """Worker 遇到注册/登录墙时的结构化判断，供编排器决策后续流程。"""
    reg_status: str = Field("", description="registrable_verification_needed=仅差手机/邮箱验证码 / not_registrable=不可注册 / registrable_no_blocker=可注册无阻断")
    block_reason: str = Field("", description="阻断原因，如'需要手机接收短信验证码'或'需要邮箱接收验证码'或'CAS/SSO 仅限校内师生'")
    registration_url: str = Field("", description="注册页面 URL（如有）")
    evidence_request: str = Field("", description="Worker 实际尝试注册/登录的 HTTP 请求响应摘要")
    what_user_needs_to_provide: str = Field("", description="用户需要提供什么：账号密码 / Cookie / 完成注册后的登录态")
    next_steps: str = Field("", description="拿到登录态后该测哪些接口/功能")


class ReviewVerdict(str, Enum):
    accepted = "accepted"  # 进最终列表
    ignored = "ignored"    # 垃圾洞/不收，丢弃
    deepen = "deepen"      # 线索有价值但利用没打穿，打回定向深挖


class Confidence(str, Enum):
    confirmed = "confirmed"  # 证据完整(+复现成功)，可直接提交
    likely = "likely"        # 证据合理但未完全复现
    uncertain = "uncertain"  # 合理但有疑点，交用户裁决


class Review(BaseModel):
    """审核 agent 对单个 Finding 的结论，对应设计文档 §5 Review 表。"""
    verdict: ReviewVerdict = Field(..., description="accepted=进最终列表 / ignored=丢弃 / deepen=打回深挖")
    confidence: Confidence = Field(..., description="信度分档")
    severity_final: Optional[Severity] = Field(None, description="审核后的最终等级（accepted 时必填）")
    score: float = Field(..., ge=0, le=10, description="0-10 评分")
    in_scope: bool = Field(..., description="是否在当前任务 SRC 范围内")
    is_duplicate: bool = Field(False, description="是否与已有漏洞重复")
    ignore_reasons: list[str] = Field(default_factory=list, description="忽略理由（ignored 时必填）")
    downgrade_reasons: list[str] = Field(default_factory=list, description="降级理由")
    reproduced: bool = Field(False, description="是否复现验证过")
    reviewer_notes: str = Field("", description="审核备注：判断依据")
    # deepen 时必填：明确告诉 worker 这一轮要把什么利用链打穿
    deepen_directive: str = Field("", description="深挖指令（verdict=deepen 时必填）：具体要证明/打穿什么")
