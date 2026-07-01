"""目标同款系统聚类与冷却策略。

解决 FOFA 搜集到同一厂商/同一套系统的大量不同前缀资产时，worker 反复打同款无果、
持续烧 token 的问题。这里不落新字段，实时从 host/title/org 计算 cluster key。
"""
from __future__ import annotations

import os
import re
from urllib.parse import urlparse

CLUSTER_DEAD_THRESHOLD = int(os.environ.get("TARGET_CLUSTER_DEAD_THRESHOLD", "3"))
CLUSTER_PENDING_LIMIT = int(os.environ.get("TARGET_CLUSTER_PENDING_LIMIT", "3"))
# 企业 SRC 默认关闭同款簇限流：企业目标本就集中在用户指定的少数根域名下
# （xxx.厂.com 一大片都是该打的指定资产，product_title 多为空会退化成按 root 聚类），
# 若沿用 EduSRC 的「同 root 域名簇 pending<=3」限流，会把绝大多数企业资产误判成
# 「同款刷屏」直接 skip（实测 51 个目标卡 skip_cluster_pending）。设为 0/false 即禁用。
ENTERPRISE_CLUSTER_LIMIT = os.environ.get("ENTERPRISE_CLUSTER_LIMIT", "0").lower() in ("1", "true", "yes")


def cluster_limit_enabled(src_type: str | None) -> bool:
    """该 src_type 是否启用同款簇限流。EduSRC 启用；企业 SRC 默认禁用。"""
    from app.agents.prompts import is_enterprise_src
    if is_enterprise_src(src_type):
        return ENTERPRISE_CLUSTER_LIMIT
    return True

_CN_2LD_SUFFIXES = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
}


def root_domain(host_or_url: str) -> str:
    host = _host_only(host_or_url)
    if not host:
        return ""
    # IP/localhost 不做域名拆分
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", host) or host == "localhost":
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    suffix2 = ".".join(labels[-2:])
    suffix3 = ".".join(labels[-3:])
    if suffix2 in _CN_2LD_SUFFIXES and len(labels) >= 3:
        return suffix3
    return ".".join(labels[-2:])


def target_cluster_key(host_or_url: str, title: str = "", org: str = "") -> str:
    root = root_domain(host_or_url)
    if not root:
        return ""
    product = product_title(title)
    # 有产品标题时用 root+产品；没有标题时用 root 兜底，专治同厂商多租户前缀刷屏。
    if product:
        return f"{root}|{product}"
    org_key = _norm(org)
    if org_key:
        return f"{root}|org:{org_key[:40]}"
    return root


def product_title(title: str) -> str:
    text = _norm(title)
    if not text:
        return ""
    # 去掉常见学校/单位前缀，让「东南大学作业管理平台」「四川大学作业管理平台」
    # 聚成同一个产品标题。
    text = re.sub(r"^[\u4e00-\u9fff]{2,24}(?:大学|学院|学校|中学|小学|中心|研究院|职业技术学院)", "", text)
    text = re.sub(r"^(?:欢迎登录|登录|首页|智慧|数字化)", "", text)
    text = re.sub(r"(?:系统首页|首页|登录)$", "", text)
    if len(text) < 4:
        return ""
    return text[:60]


def should_cooldown_cluster(state: dict[str, int]) -> bool:
    return int(state.get("deadish", 0)) >= CLUSTER_DEAD_THRESHOLD


def cooldown_reason(state: dict[str, int], sample: str = "") -> str:
    deadish = int(state.get("deadish", 0))
    sample_part = f"，样本：{sample}" if sample else ""
    return f"同款系统簇已有 {deadish} 个目标打不穿/进入硬骨头库{sample_part}，后续同簇资产冷却跳过以节省 token"


def pending_limit_reason(state: dict[str, int], limit: int | None = None) -> str:
    pending = int(state.get("pending", 0))
    lim = limit if limit is not None else CLUSTER_PENDING_LIMIT
    return f"同款系统簇当前待派发/运行中 {pending} 个，已达上限 {lim}，后续同簇资产暂跳过以防队列刷屏"


def _host_only(host_or_url: str) -> str:
    raw = (host_or_url or "").strip().lower()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parsed = urlparse(raw)
    except Exception:
        return raw.strip("/")
    host = parsed.hostname or ""
    if parsed.port and parsed.port not in (80, 443):
        return f"{host}:{parsed.port}"
    return host


def _norm(value: str) -> str:
    return "".join(
        ch.lower() for ch in (value or "")
        if ch.isalnum() or "\u4e00" <= ch <= "\u9fff"
    )
