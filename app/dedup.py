"""Finding 去重：统一指纹、软匹配和给 worker 的压缩上下文。

设计原则：
- DB 的 dedup_key 只做并发/重复写入兜底，业务查重必须走这里；
- key 不含 task_id/target_id，才能跨任务复用；
- key = 系统(host) + endpoint(path/参数名/method) + 漏洞类型；
  这样「同系统同 endpoint 同类型」从 DB 层也不能重复写入。
- 软匹配负责识别同一漏洞换标题/换任务重复提交。
"""
from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
import hashlib
import re
from urllib.parse import parse_qsl, urlparse


_SPACE_RE = re.compile(r"\s+")
_TYPE_SPLIT_RE = re.compile(r"[\s/_\-]+")

# 漏洞类型归一化：LLM 自由填写，同一类洞常被写成中英文/缩写/不同分隔符的多种形态。
# 这里把常见同义写法折叠到一个规范类别，避免「写法不同→same_type=False→漏判重」。
# key 为规范类别，value 为该类别的同义关键词（已小写、去分隔符）。命中任一即归并。
_VULN_TYPE_ALIASES: dict[str, tuple[str, ...]] = {
    "idor": (
        "idor", "横向越权", "水平越权", "水平权限", "horizontalprivilege",
        "objectlevelauthorization", "bola", "越权访问", "平行越权",
    ),
    "privilege_escalation": (
        "privilegeescalation", "垂直越权", "提权", "权限提升", "verticalprivilege",
        "越权提权",
    ),
    "unauthorized_access": (
        "unauthorizedaccess", "unauthorized", "noauth", "未授权", "未授权访问",
        "无授权", "无需鉴权", "鉴权缺失", "认证缺失", "missingauth", "authbypass",
        "认证绕过", "授权绕过", "未鉴权",
    ),
    "sql_injection": (
        "sqlinjection", "sqli", "sql注入", "注入sql", "sql",
    ),
    "rce": (
        "rce", "remotecodeexecution", "命令注入", "commandinjection", "命令执行",
        "代码执行", "远程命令执行", "远程代码执行", "codeinjection",
    ),
    "ssrf": ("ssrf", "服务端请求伪造", "serversiderequestforgery"),
    "xss": (
        "xss", "crosssitescripting", "跨站脚本", "存储型xss", "反射型xss", "domxss",
    ),
    "csrf": ("csrf", "crosssiterequestforgery", "跨站请求伪造"),
    "file_upload": (
        "fileupload", "任意文件上传", "文件上传", "上传漏洞", "arbitraryfileupload",
    ),
    "file_read": (
        "fileread", "任意文件读取", "文件读取", "arbitraryfileread", "路径穿越",
        "目录穿越", "pathtraversal", "directorytraversal", "lfi", "本地文件包含",
    ),
    "info_leak": (
        "infoleak", "informationleak", "informationdisclosure", "信息泄露",
        "敏感信息泄露", "敏感信息", "数据泄露", "sensitiveinfo", "sensitivedata",
    ),
    "weak_password": (
        "weakpassword", "弱口令", "弱密码", "默认口令", "默认密码", "defaultcredentials",
    ),
    "captcha_bypass": (
        "captchabypass", "验证码绕过", "验证码爆破", "短信验证码绕过",
    ),
    "xxe": ("xxe", "xmlexternalentity", "xml外部实体"),
    "deserialization": (
        "deserialization", "反序列化", "insecuredeserialization",
    ),
    "ssti": ("ssti", "模板注入", "serversidetemplateinjection"),
    "open_redirect": ("openredirect", "任意url跳转", "url跳转", "开放重定向", "重定向"),
    "logic_flaw": (
        "logicflaw", "业务逻辑", "逻辑漏洞", "businesslogic", "支付逻辑", "金额篡改",
    ),
    "backdoor_compromised": (
        "backdoorcompromised", "疑似后门", "疑似被黑", "服务器被攻陷", "被攻陷",
        "被挂马", "挂马", "网页被篡改", "被篡改", "后门", "webshell", "compromised",
        "hacked", "defaced", "被黑", "植入后门", "web后门", "网页挂马", "暗链",
    ),
}

# 反向索引：同义关键词 -> 规范类别（构建一次）。
_VULN_TYPE_LOOKUP: dict[str, str] = {}
for _canon, _aliases in _VULN_TYPE_ALIASES.items():
    _VULN_TYPE_LOOKUP[_canon] = _canon
    for _alias in _aliases:
        _VULN_TYPE_LOOKUP[_alias] = _canon


def normalize_vuln_type(raw: str) -> str:
    """把 LLM 自由填写的漏洞类型折叠到规范类别。

    - 命中别名表 → 返回规范类别（如 idor / unauthorized_access）；
    - 未命中 → 返回去分隔符的小写形态，至少保证「同写法」仍能相等比较，
      不会因为大小写/空格/下划线差异而误判成不同类型。
    """
    s = (raw or "").strip().lower()
    if not s:
        return ""
    collapsed = _TYPE_SPLIT_RE.sub("", s)
    if not collapsed:
        return ""
    hit = _VULN_TYPE_LOOKUP.get(collapsed)
    if hit:
        return hit
    # 中文写法可能带「漏洞」后缀，去掉再试一次
    if collapsed.endswith("漏洞"):
        hit = _VULN_TYPE_LOOKUP.get(collapsed[:-2])
        if hit:
            return hit
    return collapsed


def vuln_type_alias_set(raw: str) -> set[str]:
    """给定任意写法，返回它归一化后所属类别的【所有已知原始写法】集合。

    用途：DB 层用 `Finding.vuln_type IN (alias_set)` 走索引预筛，既避免全表扫，
    又不会因为归一化而漏掉库里以别名写法存储的旧记录。

    注意：这只覆盖别名表里登记过的写法。库里若存在表外的自由写法（如某次 LLM
    乱填的同义词），DB 预筛会漏掉它——这是性能与召回的折中，故调用方仍需
    保留「按时间倒序 + 数量上限」的兜底，且业务判重最终以 Python 侧归一化为准。
    """
    canon = normalize_vuln_type(raw)
    if not canon:
        return set()
    out: set[str] = {canon}
    aliases = _VULN_TYPE_ALIASES.get(canon)
    if aliases:
        out.update(aliases)
    out.add((raw or "").strip().lower())
    return {x for x in out if x}


@dataclass(frozen=True)
class Fingerprint:
    key: str
    host: str
    endpoint: str
    vuln_type: str
    method: str
    title_key: str


def normalize_host(url_or_host: str) -> str:
    s = (url_or_host or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "http://" + s
    try:
        parsed = urlparse(s)
    except Exception:
        return s.lower().strip("/")
    host = (parsed.hostname or "").lower()
    if parsed.port and parsed.port not in (80, 443):
        host = f"{host}:{parsed.port}"
    return host


def normalize_endpoint(url_or_host: str) -> str:
    """host + path + query 参数名集合。

    参数值经常是用户 ID / token / 随机数，不能进查重键；参数名能区分同一路径下不同入口。
    """
    s = (url_or_host or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "http://" + s
    try:
        parsed = urlparse(s)
    except Exception:
        return s.lower().rstrip("/")
    host = normalize_host(s)
    path = (parsed.path or "").rstrip("/").lower()
    params = sorted({k.lower() for k, _ in parse_qsl(parsed.query or "", keep_blank_values=True) if k})
    query_sig = f"?{'&'.join(params)}" if params else ""
    return f"{host}{path}{query_sig}"


def normalize_endpoint_path(url_or_host: str) -> str:
    """path + query 参数名集合，不含 host。

    用于同一产品存在域名/IP/反代别名时的软查重：host 不同但路径、产品名、
    漏洞类型一致，通常就是同款系统同一洞的重复产出。
    """
    s = (url_or_host or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "http://" + s
    try:
        parsed = urlparse(s)
    except Exception:
        return ""
    path = (parsed.path or "").rstrip("/").lower()
    params = sorted({k.lower() for k, _ in parse_qsl(parsed.query or "", keep_blank_values=True) if k})
    query_sig = f"?{'&'.join(params)}" if params else ""
    return f"{path}{query_sig}"


def normalize_method(finding: dict) -> str:
    method = (finding.get("method") or "").strip().upper()
    if method:
        return method[:12]
    raw = (finding.get("raw_request") or "").lstrip()
    first = raw.splitlines()[0] if raw else ""
    m = re.match(r"^([A-Z]{3,12})\s+", first)
    return m.group(1) if m else ""


def normalize_text(text: str) -> str:
    text = _SPACE_RE.sub("", text or "").lower()
    return "".join(ch for ch in text if ch.isalnum() or "\u4e00" <= ch <= "\u9fff")


def _title_key(title: str, description: str = "") -> str:
    raw = normalize_text(title) or normalize_text(description)
    return raw[:80]


def title_product_key(title: str) -> str:
    """提取报告标题里的产品/系统名前缀。

    例：「中医疫病古籍整理数据库-未授权访问...」→「中医疫病古籍整理数据库」。
    只返回有一定长度的中文/字母数字前缀，避免短词误伤。
    """
    raw = (title or "").strip()
    if not raw:
        return ""
    prefix = re.split(r"\s*[-—–－:：]\s*", raw, maxsplit=1)[0]
    key = normalize_text(prefix)
    return key if len(key) >= 6 else ""


def fingerprint(target_ref: str, finding: dict) -> Fingerprint:
    target_url = (finding.get("target_url") or "").strip()
    endpoint = normalize_endpoint(target_url) or normalize_endpoint(target_ref)
    host = normalize_host(target_url) or normalize_host(target_ref)
    vuln_type = normalize_vuln_type(finding.get("vuln_type", ""))
    method = normalize_method(finding)
    title_key = _title_key(finding.get("title", ""), finding.get("description", ""))
    raw = "|".join([host, endpoint, method, vuln_type])
    return Fingerprint(
        key=hashlib.sha256(raw.encode()).hexdigest(),
        host=host,
        endpoint=endpoint,
        vuln_type=vuln_type,
        method=method,
        title_key=title_key,
    )


def dedup_key(target_ref: str, finding: dict) -> str:
    return fingerprint(target_ref, finding).key


def _record_fingerprint(record: dict, fallback_target: str = "") -> Fingerprint:
    target_ref = record.get("target_url") or record.get("target") or record.get("host") or fallback_target
    return fingerprint(target_ref, record)


def duplicate_matches(candidate: dict, history: list[dict], *, target_ref: str = "") -> list[dict]:
    c_fp = fingerprint(target_ref, candidate)
    c_title = normalize_text(candidate.get("title", ""))
    c_product = title_product_key(candidate.get("title", ""))
    c_path = normalize_endpoint_path(candidate.get("target_url") or target_ref)
    matches: list[dict] = []

    for old in history:
        o_fp = _record_fingerprint(old, target_ref)
        o_title = normalize_text(old.get("title", ""))
        o_product = title_product_key(old.get("title", ""))
        o_path = normalize_endpoint_path(old.get("target_url") or old.get("target") or old.get("host") or target_ref)
        reasons: list[str] = []

        old_key = old.get("dedup_key")
        if old_key and old_key == c_fp.key:
            reasons.append("全局 dedup_key 完全一致")

        same_type = bool(c_fp.vuln_type and o_fp.vuln_type and c_fp.vuln_type == o_fp.vuln_type)
        same_endpoint = bool(c_fp.endpoint and o_fp.endpoint and c_fp.endpoint == o_fp.endpoint)
        same_path = bool(c_path and o_path and c_path == o_path)
        same_host = bool(c_fp.host and o_fp.host and c_fp.host == o_fp.host)
        same_method = not c_fp.method or not o_fp.method or c_fp.method == o_fp.method
        same_product = bool(c_product and o_product and c_product == o_product)

        if same_endpoint and same_type and same_method:
            reasons.append("同系统同 endpoint 同漏洞类型")

        if same_product and same_path and same_type and same_method:
            reasons.append("同产品别名站点 + 同路径 + 同漏洞类型")

        # P2 兜底：标题没有【可靠】产品名前缀（纯英文/无分隔符长句会把整句当前缀，
        # 不能用来跨 host 关联）时，无法靠 same_product 跨 host 查重。此时若 host 不同
        # 但归一化路径完全一致 + 同漏洞类型 + 同 method，几乎可断定是同款系统挂在不同
        # 域名/IP/反代别名上的同一个洞。要求路径有实际区分度（含具体 path 段而非根路径），
        # 避免「都打根路径」误伤。同产品规则已覆盖 same_product 的情况，这里只补它的盲区。
        c_path_specific = bool(c_path and c_path.split("?")[0].strip("/"))
        if (
            not same_host
            and not same_product
            and same_path and c_path_specific
            and same_type and same_method
        ):
            reasons.append("跨 host 同路径 + 同漏洞类型（无可靠产品名兜底）")

        if same_host and same_type and c_title and o_title:
            ratio = SequenceMatcher(None, c_title, o_title).ratio()
            if ratio >= 0.86:
                reasons.append(f"同 host + 同漏洞类型 + 标题高度相似({ratio:.2f})")

        # 同产品标题相似只能作为兜底：如果双方都有明确路径且路径不同，
        # 不能仅凭产品名前缀带来的高相似度拦截，否则会误伤同产品其它 endpoint 的新洞。
        if same_product and same_type and c_title and o_title and (same_path or not c_path or not o_path):
            ratio = SequenceMatcher(None, c_title, o_title).ratio()
            if ratio >= 0.78:
                reasons.append(f"同产品 + 同漏洞类型 + 标题高度相似({ratio:.2f})")

        if same_endpoint and same_type and c_title and o_title:
            ratio = SequenceMatcher(None, c_title, o_title).ratio()
            if ratio >= 0.62:
                reasons.append(f"同 endpoint + 同漏洞类型 + 标题相似({ratio:.2f})")
        elif same_endpoint and c_title and o_title:
            ratio = SequenceMatcher(None, c_title, o_title).ratio()
            if ratio >= 0.74:
                reasons.append(f"同 endpoint + 标题相似({ratio:.2f})")

        if not reasons:
            continue
        matches.append({
            "title": old.get("title", ""),
            "vuln_type": old.get("vuln_type", ""),
            "target_url": old.get("target_url", ""),
            "source": old.get("source", "history"),
            "policy": old.get("policy", "block"),
            "status": old.get("status", ""),
            "dedup_reason": old.get("dedup_reason", ""),
            "reason": "；".join(dict.fromkeys(reasons)),
            "dedup_key": old.get("dedup_key", ""),
        })

    return matches[:5]


def is_duplicate(candidate: dict, history: list[dict], *, target_ref: str = "") -> tuple[bool, list[dict]]:
    matches = duplicate_matches(candidate, history, target_ref=target_ref)
    return bool(matches), matches


def compact_history(history: list[dict], *, target_ref: str = "", limit: int = 60) -> list[dict]:
    compact: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for item in history:
        fp = _record_fingerprint(item, target_ref)
        sig = (fp.vuln_type, fp.endpoint, fp.title_key)
        if sig in seen:
            continue
        seen.add(sig)
        compact.append(item)
        if len(compact) >= limit:
            break
    return compact
