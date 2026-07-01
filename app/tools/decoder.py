"""decode_transform 工具：凭证/编码快速解析，专治越权/凭证利用链中间环节。

设计铁律（吸取 js_analyzer ReDoS 把平台搞崩的教训）：
- 所有输入一进来就硬截断到 _MAX_INPUT，绝不在超长输入上做任何处理。
- 不使用任何可能灾难回溯的正则；判别用 str 方法 / 固定字符集校验，O(n) 线性。
- 纯 CPU 操作，单次调用处理量受 _MAX_INPUT 封顶（几十 KB），不会长时间持 GIL。
- 任何分支都 try/except 兜底，绝不让异常冒到 worker 主循环。
- 不发网络、不读写磁盘、不执行子进程——纯内存计算，无外部副作用。
"""
from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import json
import urllib.parse
from typing import Any

# 单次输入硬上限：凭证/token/编码串都很短，64KB 足够且杜绝大输入拖垮 CPU。
_MAX_INPUT = 64 * 1024
# 单个解码结果回传上限，防止"解出一个巨型 blob"撑爆消息体。
_MAX_OUTPUT = 16 * 1024

_HEX_CHARS = set("0123456789abcdefABCDEF")
_B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_B64URL_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")


def _clip(s: str, limit: int = _MAX_OUTPUT) -> str:
    if len(s) <= limit:
        return s
    return s[:limit] + f"\n...[已截断，原长 {len(s)}]"


def _printable_ratio(s: str) -> float:
    """可打印字符占比，用于判断解码结果是否"像有意义的文本"。"""
    if not s:
        return 0.0
    printable = sum(1 for ch in s if ch == "\n" or ch == "\t" or 0x20 <= ord(ch) < 0x7F or ord(ch) > 0x9F)
    return printable / len(s)


def _try_base64(s: str) -> dict[str, Any] | None:
    raw = s.strip()
    if len(raw) < 4:
        return None
    try:
        # 优先标准；失败再试 urlsafe（补 padding）。
        chars = set(raw)
        if chars <= _B64_CHARS and len(raw) % 4 == 0:
            decoded = base64.b64decode(raw, validate=True)
        elif chars <= _B64URL_CHARS:
            pad = "=" * (-len(raw) % 4)
            decoded = base64.urlsafe_b64decode(raw + pad)
        else:
            return None
    except (binascii.Error, ValueError):
        return None
    text = decoded.decode("utf-8", "replace")
    return {
        "scheme": "base64",
        "result": _clip(text),
        "is_text": _printable_ratio(text) >= 0.85,
        "byte_len": len(decoded),
    }


def _try_hex(s: str) -> dict[str, Any] | None:
    raw = s.strip()
    if len(raw) < 4 or len(raw) % 2 != 0:
        return None
    if not set(raw) <= _HEX_CHARS:
        return None
    try:
        decoded = bytes.fromhex(raw)
    except ValueError:
        return None
    text = decoded.decode("utf-8", "replace")
    return {
        "scheme": "hex",
        "result": _clip(text),
        "is_text": _printable_ratio(text) >= 0.85,
        "byte_len": len(decoded),
    }


def _try_url(s: str) -> dict[str, Any] | None:
    if "%" not in s and "+" not in s:
        return None
    try:
        decoded = urllib.parse.unquote_plus(s)
    except Exception:
        return None
    if decoded == s:
        return None
    return {"scheme": "url", "result": _clip(decoded)}


def _try_jwt(s: str) -> dict[str, Any] | None:
    raw = s.strip()
    parts = raw.split(".")
    if len(parts) != 3:
        return None
    # JWT 三段必须都是 base64url，且 header/payload 解出来是 JSON。
    try:
        def _b64url(seg: str) -> bytes:
            if not seg or not set(seg) <= _B64URL_CHARS:
                raise ValueError("not b64url")
            return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))

        header = json.loads(_b64url(parts[0]).decode("utf-8", "replace"))
        payload = json.loads(_b64url(parts[1]).decode("utf-8", "replace"))
    except (ValueError, json.JSONDecodeError, UnicodeError):
        return None
    if not isinstance(header, dict):
        return None
    alg = str(header.get("alg", "")).lower()
    notes = []
    if alg in ("none", ""):
        notes.append("⚠ alg=none：可能可去签名伪造（直接改 payload + 空签名重试）。")
    if alg.startswith("hs"):
        notes.append("HS* 对称签名：若密钥弱可爆破（jwt_tool/hashcat 跑弱密钥），爆出后可任意伪造。")
    if alg.startswith("rs") or alg.startswith("es"):
        notes.append("RS*/ES* 非对称：尝试 alg 混淆攻击（RS→HS 用公钥当 HMAC 密钥）。")
    return {
        "scheme": "jwt",
        "header": header,
        "payload": _clip_obj(payload),
        "alg": header.get("alg", ""),
        "attack_notes": notes,
    }


def _clip_obj(obj: Any) -> Any:
    """对 JWT payload 等对象做体积保护：序列化超限则转字符串截断。"""
    try:
        s = json.dumps(obj, ensure_ascii=False)
    except Exception:
        return str(obj)[:_MAX_OUTPUT]
    if len(s) <= _MAX_OUTPUT:
        return obj
    return {"_truncated": s[:_MAX_OUTPUT]}


def _identify_hash(s: str) -> dict[str, Any] | None:
    raw = s.strip()
    if not raw or not set(raw) <= _HEX_CHARS:
        return None
    guesses = {32: ["MD5", "NTLM"], 40: ["SHA1"], 56: ["SHA224"],
               64: ["SHA256"], 96: ["SHA384"], 128: ["SHA512"]}
    candidates = guesses.get(len(raw))
    if not candidates:
        return None
    return {
        "scheme": "hash_identify",
        "length": len(raw),
        "candidates": candidates,
        "attack_notes": "纯 hex 且长度匹配常见哈希；可用 hashcat/在线彩虹表尝试还原（只读取证，勿改库）。",
    }


def _compute_hashes(s: str) -> dict[str, str]:
    data = s.encode("utf-8", "replace")
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def decode_transform(value: str, mode: str = "auto") -> dict[str, Any]:
    """对一段文本做编码/解码/哈希分析。

    mode:
      - auto   : 自动尝试 jwt / base64 / hex / url，并附哈希识别，返回所有命中。
      - base64 / hex / url / jwt : 只做指定解码。
      - hash   : 计算 md5/sha1/sha256（用于自查/构造），并识别输入是否像某哈希。
    """
    try:
        if not isinstance(value, str):
            value = str(value)
        if not value.strip():
            return {"ok": False, "kind": "arg_error",
                    "error": "value 不能为空", "guidance": "传入要解析的编码串/凭证/token。"}
        # 铁律：超长输入直接截断，绝不在大输入上跑解析。
        clipped = value[:_MAX_INPUT]
        truncated_input = len(value) > _MAX_INPUT
        mode = (mode or "auto").strip().lower()

        single = {
            "base64": _try_base64, "hex": _try_hex,
            "url": _try_url, "jwt": _try_jwt,
        }
        if mode in single:
            res = single[mode](clipped)
            if res is None:
                return {"ok": False,
                        "error": f"输入不是合法的 {mode} 编码", "input_truncated": truncated_input}
            return {"ok": True, "input_truncated": truncated_input, **res}

        if mode == "hash":
            return {"ok": True, "input_truncated": truncated_input,
                    "scheme": "hash", "hashes": _compute_hashes(clipped),
                    "identify": _identify_hash(clipped)}

        # auto：依次尝试，收集所有命中（jwt 最具体优先展示）。
        decodings: list[dict[str, Any]] = []
        for fn in (_try_jwt, _try_base64, _try_hex, _try_url):
            try:
                r = fn(clipped)
            except Exception:
                r = None
            if r is not None:
                decodings.append(r)
        hash_id = None
        try:
            hash_id = _identify_hash(clipped)
        except Exception:
            hash_id = None

        if not decodings and not hash_id:
            return {"ok": True, "input_truncated": truncated_input,
                    "decodings": [], "hash_identify": None,
                    "guidance": "未识别出常见编码；可能是明文或自定义编码。"}
        return {
            "ok": True,
            "input_truncated": truncated_input,
            "decodings": decodings,
            "hash_identify": hash_id,
            "guidance": "解码只是中间情报；拿到 token/凭证后必须用 http_request 实证越权/接管才算洞。",
        }
    except Exception as e:
        return {"ok": False, "error": f"decode_transform 异常: {type(e).__name__}: {e}"}
