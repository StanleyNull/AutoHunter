"""SQLAlchemy 数据库模型（对应设计文档 §5 + §8.5 状态机）。

设计为 24x7 不停歇：所有状态全部持久化，进程重启可从这些表完整恢复。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


CST = timezone(timedelta(hours=8))  # 东八区（北京时间）


def to_cst_iso(dt: datetime | None) -> str | None:
    """数据库存 UTC naive 时间（列无时区信息），输出统一转东八区 ISO 字符串。

    前端用 slice(0,19) 截取时直接得到东八区时间值；用 new Date 解析时按
    +08:00 偏移正确换算本地时区。
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(CST).isoformat()


class Base(DeclarativeBase):
    pass


class Task(Base):
    """一个挖掘任务 = 一个资产范围（FOFA 语法 / 域名清单），running 时永不自停。"""
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200))
    src_type: Mapped[str] = mapped_column(String(20), default="edusrc")
    vuln_types: Mapped[list] = mapped_column(JSON, default=list)        # 选定漏洞类型
    src_rules: Mapped[str] = mapped_column(Text, default="")            # SRC 规则全文（审核用）
    target_source: Mapped[str] = mapped_column(String(20), default="fofa")  # fofa / manual / both / site
    fofa_query: Mapped[str] = mapped_column(Text, default="")
    manual_targets: Mapped[list] = mapped_column(JSON, default=list)
    # 用户登录凭据绑定列表：[{target, username, password, cookie, authorization, login_url, raw, note}]
    auth_bindings: Mapped[list] = mapped_column(JSON, default=list)
    model_config_json: Mapped[dict] = mapped_column("model_config", JSON, default=dict)
    fofa_config: Mapped[dict] = mapped_column(JSON, default=dict)       # keys/max_pages/page_size/cursor
    engine: Mapped[str] = mapped_column(String(20), default="")         # 搜索引擎：fofa/quake/hunter/zoomeye/shodan/censys
    concurrency: Mapped[int] = mapped_column(Integer, default=3)
    # created / running / paused / stopped / idle
    status: Mapped[str] = mapped_column(String(20), default="created")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    targets: Mapped[list["Target"]] = relationship(back_populates="task", cascade="all, delete-orphan")


class Target(Base):
    """单个待挖目标（host 级）。状态机贯穿 24x7 恢复逻辑。"""
    __tablename__ = "targets"
    # 目标库去重：普通搜集同一 source 下 host 唯一；单站协作可让同一 host 按不同路线并行。
    __table_args__ = (
        Index("ux_targets_task_host", "task_id", "host", "source", unique=True),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    url: Mapped[str] = mapped_column(String(500))
    host: Mapped[str] = mapped_column(String(255), index=True)         # 去重键
    ip: Mapped[str] = mapped_column(String(64), default="")
    org: Mapped[str] = mapped_column(String(300), default="")
    title: Mapped[str] = mapped_column(String(500), default="")
    source: Mapped[str] = mapped_column(String(20), default="fofa")    # fofa / manual
    is_edu: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    school: Mapped[str] = mapped_column(String(200), default="")  # 搜集阶段判定的候选归属学校

    # EduSRC 目标优先级评分（决定 worker 先打谁，高分先派；只排序不过滤）
    priority_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    priority_reason: Mapped[str] = mapped_column(String(300), default="")
    # queued / assigned / scanning / done / skipped / dead
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    verdict: Mapped[str] = mapped_column(String(20), default="")       # found / no_vuln / error
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    # 硬骨头库：仅记录终态 dead/skipped 的原因，便于审计与回捞
    dead_reason: Mapped[str] = mapped_column(String(300), default="")
    # 非终态最近错误：临时 LLM/网络/恢复回队等，不再污染 dead_reason
    last_error: Mapped[str] = mapped_column(String(500), default="")
    # 审核打回深挖：本轮要定向打穿什么(指令+原 finding 摘要)，以及已深挖次数(防死循环)
    deepen_context: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    deepen_count: Mapped[int] = mapped_column(Integer, default=0)
    # 搜集阶段顺带查到的、过滤打分后的该域泄露凭证（喂给 worker 作额外攻击面）。
    leaked_creds: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # 用户凭据：入队时从 Task.auth_bindings 匹配写入；worker 启动 bootstrap 用。
    auth_context: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # 最近一次凭据使用反馈（无明文）：status/kinds/reason/...
    auth_status: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    assigned_worker: Mapped[str] = mapped_column(String(64), default="")
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    task: Mapped["Task"] = relationship(back_populates="targets")
    findings: Mapped[list["Finding"]] = relationship(back_populates="target", cascade="all, delete-orphan")


class Finding(Base):
    """worker 产出的原始漏洞，对应 schemas.Finding。"""
    __tablename__ = "findings"
    # 漏洞库去重：全局 dedup_key 唯一（空 key 不约束；superseded 会改写 key 腾位）
    __table_args__ = (
        Index("ux_findings_dedup_global", "dedup_key", unique=True, sqlite_where=text("dedup_key != ''")),
        # 跨 host 查重按归一化类型的别名集合做 IN 预筛，复合索引覆盖 (vuln_type, status)
        # 让 `WHERE vuln_type IN (...) AND status != superseded` 走索引而非全表扫。
        Index("ix_findings_vuln_type_status", "vuln_type", "status"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), index=True)
    worker_id: Mapped[str] = mapped_column(String(64), default="")
    vuln_type: Mapped[str] = mapped_column(String(80))
    title: Mapped[str] = mapped_column(String(500))
    severity_claimed: Mapped[str] = mapped_column(String(10))
    target_url: Mapped[str] = mapped_column(String(500))
    owner: Mapped[str] = mapped_column(String(300), default="")  # 归属单位(学校)+确认依据
    description: Mapped[str] = mapped_column(Text, default="")
    steps: Mapped[list] = mapped_column(JSON, default=list)
    poc: Mapped[str] = mapped_column(Text, default="")
    raw_request: Mapped[str] = mapped_column(Text, default="")
    raw_response: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    affected_scope: Mapped[str] = mapped_column(Text, default="")
    kill_chain: Mapped[list] = mapped_column(JSON, default=list)  # 攻击链路：[{method, detail}, ...]
    # 报告助手对话历史：[{role:'user'|'assistant', content:'...'}]，按 finding 持久化
    assistant_messages: Mapped[list] = mapped_column(JSON, default=list)
    self_check: Mapped[dict] = mapped_column(JSON, default=dict)
    dedup_key: Mapped[str] = mapped_column(String(128), default="", index=True)  # 漏洞级去重
    # pending_review / reviewed
    status: Mapped[str] = mapped_column(String(20), default="pending_review", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    target: Mapped["Target"] = relationship(back_populates="findings")
    review: Mapped["Review | None"] = relationship(back_populates="finding", uselist=False, cascade="all, delete-orphan")


class Review(Base):
    """审核 agent 对 Finding 的结论，对应 schemas.Review。"""
    __tablename__ = "reviews"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True, unique=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    verdict: Mapped[str] = mapped_column(String(20))           # accepted / ignored
    confidence: Mapped[str] = mapped_column(String(20))        # confirmed / likely / uncertain
    severity_final: Mapped[str | None] = mapped_column(String(10), nullable=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    is_duplicate: Mapped[bool] = mapped_column(Boolean, default=False)
    ignore_reasons: Mapped[list] = mapped_column(JSON, default=list)
    downgrade_reasons: Mapped[list] = mapped_column(JSON, default=list)
    reproduced: Mapped[bool] = mapped_column(Boolean, default=False)
    reviewer_notes: Mapped[str] = mapped_column(Text, default="")
    deepen_directive: Mapped[str] = mapped_column(Text, default="")  # verdict=deepen 时的深挖指令
    reviewed_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    # ===== 用户复审（人工二次审核，仅 AI accepted 进入）=====
    # pending=待复审 / passed=通过(进待提交) / rejected=不通过
    user_status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    user_severity: Mapped[str | None] = mapped_column(String(10), nullable=True)  # 用户调整后的等级
    user_notes: Mapped[str] = mapped_column(Text, default="")                     # 用户复审备注
    # 用户编辑后的报告内容（覆盖 finding 原值，None 表示用原值）
    user_edits: Mapped[dict] = mapped_column(JSON, default=dict)
    # 待提交后：是否已提交到 SRC
    submitted: Mapped[bool] = mapped_column(Boolean, default=False)
    user_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    finding: Mapped["Finding"] = relationship(back_populates="review")


class Killsweep(Base):
    """通杀候选：审核 accepted 一个洞后，通杀 Hunter 分析该系统是否为通用产品、能否一打一片。

    按「产品指纹」去重——同款系统（同一 product_key）只分析一条。
    """
    __tablename__ = "killsweeps"
    __table_args__ = (
        # 同一任务内同款产品只留一条（产品指纹去重）
        Index("ux_killsweeps_task_product", "task_id", "product_key", unique=True),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    origin_finding_id: Mapped[str] = mapped_column(String(32), default="")  # 触发分析的源漏洞
    product_key: Mapped[str] = mapped_column(String(120), default="", index=True)  # 产品指纹去重键(归一化)
    product_name: Mapped[str] = mapped_column(String(200), default="")  # 通用产品/框架名称
    vuln_type: Mapped[str] = mapped_column(String(80), default="")
    vuln_summary: Mapped[str] = mapped_column(Text, default="")          # 通杀漏洞说明
    fofa_query: Mapped[str] = mapped_column(Text, default="")            # 圈定同款系统的 FOFA 语法
    fingerprint: Mapped[str] = mapped_column(Text, default="")           # 指纹依据(title/body/server/favicon)
    asset_count: Mapped[int] = mapped_column(Integer, default=0)         # 全网同款资产规模
    edu_count: Mapped[int] = mapped_column(Integer, default=0)           # 教育行业同款规模
    is_killsweep: Mapped[bool] = mapped_column(Boolean, default=False)   # 是否判定可通杀
    confidence: Mapped[str] = mapped_column(String(20), default="")      # confirmed/likely/uncertain
    verified_url: Mapped[str] = mapped_column(String(500), default="")   # 实际验证的同款站点
    verified: Mapped[bool] = mapped_column(Boolean, default=False)       # 是否打了1个同款验证成功
    # 通杀影响明细表：[{school, url, host, title, vuln_title, status, evidence, dedup_key}]
    # 既用于前端展示，也会进入 worker 查重上下文，避免同学校同通杀洞反复提交。
    affected_table: Mapped[list] = mapped_column(JSON, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")                 # 分析结论/批量建议
    # analyzing / done / failed
    status: Mapped[str] = mapped_column(String(20), default="analyzing", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)


class TaskEvent(Base):
    """审计/实时日志事件。"""
    __tablename__ = "task_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    agent: Mapped[str] = mapped_column(String(20), default="")     # orchestrator/collector/worker/reviewer
    level: Mapped[str] = mapped_column(String(10), default="info")  # info/warn/error
    kind: Mapped[str] = mapped_column(String(40), default="")       # 事件类型
    message: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    ts: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)


class Intel(Base):
    """全局情报库（跨任务共享）：沉淀挖洞过程中可复用的知识。

    单表四类，用 kind 区分，避免多表冗余：
      - cred         验证过的有效凭证/撞库结果   match_key=root域
      - fingerprint  指纹→打法映射(CVE/payload/默认口令)  match_key=系统指纹标识
      - endpoint     有效路径/未授权端点          match_key=系统指纹标识
      - profile      目标画像(技术栈/WAF/突破口)   match_key=root域

    去重：(kind, match_key, dedup_hash) 唯一；重复命中只 +hit_count、更新 last_seen，绝不新增行。
    检索：触发式——按当前目标的 root域/系统指纹匹配 match_key，命中才注入，不冗余。
    """
    __tablename__ = "intel"
    __table_args__ = (
        # 全局去重：同类+同检索键+同内容指纹只留一条
        Index("ux_intel_dedup", "kind", "match_key", "dedup_hash", unique=True),
        # 检索加速：按 kind+match_key 查
        Index("ix_intel_lookup", "kind", "match_key"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(20), index=True)          # cred/fingerprint/endpoint/profile
    match_key: Mapped[str] = mapped_column(String(255), default="")    # 触发检索键(root域 或 系统指纹)
    dedup_hash: Mapped[str] = mapped_column(String(64), default="")    # 内容指纹(去重)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)          # 实际情报内容(按 kind 不同结构)
    summary: Mapped[str] = mapped_column(String(500), default="")      # 一句话摘要(注入 prompt 用)
    source_host: Mapped[str] = mapped_column(String(255), default="")  # 贡献该情报的 host
    source_task_id: Mapped[str] = mapped_column(String(32), default="")
    confidence: Mapped[str] = mapped_column(String(20), default="likely")  # verified(出洞验证)/likely(声称有效)
    hit_count: Mapped[int] = mapped_column(Integer, default=1, index=True)  # 命中/复用次数(越高越可信)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)


class SystemSettings(Base):
    """全局系统配置（单行 id=global）。任务级配置可覆盖此处默认值。"""
    __tablename__ = "system_settings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default="global")
    llm: Mapped[dict] = mapped_column(JSON, default=dict)       # base_url/api_key/model/temperature
    fofa: Mapped[dict] = mapped_column(JSON, default=dict)      # key/max_pages/page_size/default_intent_mode
    engines: Mapped[dict] = mapped_column(JSON, default=dict)   # {engine_name: {key, base_url, ...}}
    defaults: Mapped[dict] = mapped_column(JSON, default=dict)  # concurrency/skip_score_threshold/engine
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)
