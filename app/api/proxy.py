"""代理池 API：/api/proxy 列表/新增/编辑/删除/导入/测试/总开关。

配置持久化在 SystemSettings.proxy JSON 列；运行态（轮转/冷却）在 proxy_service 内存。
"""
from __future__ import annotations

import time
import uuid

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import SystemSettings
from app.db.session import get_session
from app.proxy_service import (
    PROXY_PROTOCOLS,
    apply_config,
    clear_cooldown,
    parse_proxy_text,
    proxy_url,
    snapshot_view,
)
from app.settings_service import SETTINGS_ID, is_masked_secret

router = APIRouter(prefix="/api/proxy", tags=["proxy"])

# 探测请求超时（秒）
_TEST_TIMEOUT = 12.0
# 探测地址按序兜底：gstatic 在境内服务器不可达，msftconnecttest（微软 NCSI）境内外一般都通。
_TEST_PROBE_URLS = (
    "https://www.gstatic.com/generate_204",
    "http://www.msftconnecttest.com/connecttest.txt",
)


async def _load_row(session: AsyncSession) -> SystemSettings:
    row = await session.get(SystemSettings, SETTINGS_ID)
    if row is None:
        row = SystemSettings(id=SETTINGS_ID)
        session.add(row)
        await session.commit()
        await session.refresh(row)
    return row


@router.get("")
async def list_proxies(session: AsyncSession = Depends(get_session)):
    await _load_row(session)
    return snapshot_view()


class ProxyAddRequest(BaseModel):
    name: str = ""
    protocol: str = "http"
    host: str
    port: int
    username: str = ""
    password: str = ""
    enabled: bool = True


@router.post("")
async def add_proxy(
    body: ProxyAddRequest,
    session: AsyncSession = Depends(get_session),
):
    row = await _load_row(session)
    cfg = dict(row.proxy or {})
    old = list(cfg.get("proxies") or [])
    protocol = (body.protocol or "http").strip().lower()
    if protocol not in PROXY_PROTOCOLS:
        raise HTTPException(status_code=400, detail=f"协议仅支持 {'/'.join(sorted(PROXY_PROTOCOLS))}")
    host = (body.host or "").strip().strip("[]")
    if not host or not (1 <= int(body.port) <= 65535):
        raise HTTPException(status_code=400, detail="host/port 非法")
    # 同 scheme+host+port 视为重复
    for item in old:
        if (
            str(item.get("protocol")) == protocol
            and str(item.get("host", "")).strip("[]").lower() == host.lower()
            and int(item.get("port") or 0) == int(body.port)
        ):
            return JSONResponse(status_code=409, content={"detail": "该代理已存在"})
    # uuid 后缀：纯毫秒时间戳在同毫秒连续两次添加时会撞 id，apply_config 按 id 去重
    # 会把后一条静默吞掉。
    pid = f"px-{uuid.uuid4().hex[:12]}"
    entry = {
        "id": pid,
        "name": (body.name or "").strip() or f"proxy-{len(old) + 1}",
        "protocol": protocol,
        "host": host,
        "port": int(body.port),
        "username": body.username or "",
        "password": body.password or "",
        "enabled": body.enabled is not False,
    }
    cfg["proxies"] = old + [entry]
    cfg.setdefault("enabled", False)
    row.proxy = cfg
    await session.commit()
    apply_config(cfg)
    return {"ok": True, "proxy": _public_entry(entry), **snapshot_view()}


def _public_entry(entry: dict) -> dict:
    return {k: v for k, v in entry.items() if k != "password"}


class ProxyToggleRequest(BaseModel):
    enabled: bool


@router.put("/toggle")
async def toggle_proxy_pool(
    body: ProxyToggleRequest,
    session: AsyncSession = Depends(get_session),
):
    """代理池总开关：关闭后所有 worker 直连。"""
    row = await _load_row(session)
    cfg = dict(row.proxy or {})
    cfg["enabled"] = body.enabled is True
    row.proxy = cfg
    await session.commit()
    apply_config(cfg)
    return {"ok": True, **snapshot_view()}


class ProxyUpdateRequest(BaseModel):
    name: str | None = None
    protocol: str | None = None
    host: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = None
    enabled: bool | None = None


@router.put("/{proxy_id}")
async def update_proxy(
    proxy_id: str,
    body: ProxyUpdateRequest,
    session: AsyncSession = Depends(get_session),
):
    row = await _load_row(session)
    cfg = dict(row.proxy or {})
    entries = list(cfg.get("proxies") or [])
    target = next((e for e in entries if str(e.get("id")) == proxy_id), None)
    if target is None:
        raise HTTPException(status_code=404, detail="代理不存在")
    updates = body.model_dump(exclude_unset=True, exclude_none=True)
    # 密码为脱敏占位 → 不覆盖真实值
    if "password" in updates and (not updates["password"] or is_masked_secret(updates["password"])):
        updates.pop("password")
    for key, value in updates.items():
        target[key] = value
    # 归一化校验
    target["protocol"] = str(target.get("protocol") or "http").lower()
    if target["protocol"] not in PROXY_PROTOCOLS:
        raise HTTPException(status_code=400, detail="协议非法")
    # host 必须先校验再落库：脏 host 会让 apply_config 清洗时把该条从内存快照里
    # 静默丢弃，造成 DB 与运行态不一致（重启后又"复活"）。
    host_val = str(target.get("host") or "").strip().strip("[]")
    if not host_val or " " in host_val:
        raise HTTPException(status_code=400, detail="host 非法")
    target["host"] = host_val
    target["port"] = int(target.get("port") or 0)
    if not (1 <= target["port"] <= 65535):
        raise HTTPException(status_code=400, detail="端口非法")
    cfg["proxies"] = entries
    row.proxy = cfg
    await session.commit()
    apply_config(cfg)
    return {"ok": True, "proxy": _public_entry(target), **snapshot_view()}


@router.delete("/{proxy_id}")
async def delete_proxy(proxy_id: str, session: AsyncSession = Depends(get_session)):
    row = await _load_row(session)
    cfg = dict(row.proxy or {})
    entries = list(cfg.get("proxies") or [])
    remaining = [e for e in entries if str(e.get("id")) != proxy_id]
    if len(remaining) == len(entries):
        raise HTTPException(status_code=404, detail="代理不存在")
    cfg["proxies"] = remaining
    row.proxy = cfg
    await session.commit()
    apply_config(cfg)
    return {"ok": True, **snapshot_view()}


@router.post("/import")
async def import_proxies(
    session: AsyncSession = Depends(get_session),
    text: str | None = Form(default=None),
    file: UploadFile | None = File(default=None),
):
    """批量导入：JSON body {"text": "..."} 或 multipart 文件。返回 added/skipped/invalid。"""
    if file is not None:
        raw = await file.read()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("gbk", "replace")
    if not text or not str(text).strip():
        raise HTTPException(status_code=400, detail="导入内容为空（传 text 或上传 txt 文件）")
    parsed, invalid = parse_proxy_text(str(text))
    row = await _load_row(session)
    cfg = dict(row.proxy or {})
    old = list(cfg.get("proxies") or [])
    existing = {
        (str(e.get("protocol")), str(e.get("host", "")).strip("[]").lower(), int(e.get("port") or 0))
        for e in old
    }
    added = 0
    skipped = 0
    seq = len(old)
    for item in parsed:
        key = (item["protocol"], item["host"].lower(), item["port"])
        if key in existing:
            skipped += 1
            continue
        seq += 1
        existing.add(key)
        old.append({
            "id": f"px-{int(time.time() * 1000)}-{seq}",
            "name": item["protocol"] + "-" + item["host"],
            "protocol": item["protocol"],
            "host": item["host"],
            "port": item["port"],
            "username": item["username"],
            "password": item["password"],
            "enabled": True,
        })
        added += 1
    cfg["proxies"] = old[:200]
    cfg.setdefault("enabled", False)
    row.proxy = cfg
    await session.commit()
    apply_config(cfg)
    return {"ok": True, "added": added, "skipped": skipped, "invalid": invalid, **snapshot_view()}


class ProxyTestRequest(BaseModel):
    id: str = ""
    # 未保存的临时配置也可直接测（前端"新增前测试"用）
    protocol: str = "http"
    host: str = ""
    port: int = 0
    username: str = ""
    password: str = ""


@router.post("/test")
async def test_proxy(body: ProxyTestRequest, session: AsyncSession = Depends(get_session)):
    """经代理发一次探测请求，返回是否连通 + 延迟。

    代理地址不做 SSRF 拦截：本地/内网代理（127.0.0.1:7890、10.x 等）是合法且常见的
    配置，且能进设置页改代理的角色本就有 run_shell 级权限，这里拦截只会误伤。
    """
    entry: dict | None = None
    if body.id:
        row = await _load_row(session)
        entry = next((e for e in (row.proxy or {}).get("proxies") or [] if str(e.get("id")) == body.id), None)
        if entry is None:
            raise HTTPException(status_code=404, detail="代理不存在")
    else:
        entry = {
            "protocol": body.protocol, "host": body.host, "port": body.port,
            "username": body.username, "password": body.password,
        }
    url = proxy_url(entry)
    started = time.perf_counter()
    last_error = ""
    for probe_url in _TEST_PROBE_URLS:
        try:
            async with httpx.AsyncClient(proxy=url, verify=False, timeout=_TEST_TIMEOUT) as client:
                resp = await client.get(probe_url)
            latency = int((time.perf_counter() - started) * 1000)
            if resp.status_code < 500:
                if body.id:
                    clear_cooldown(body.id)
                return {"ok": True, "status_code": resp.status_code, "latency_ms": latency}
            last_error = f"探测返回 {resp.status_code}"
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"[:300]
    return {"ok": False, "latency_ms": int((time.perf_counter() - started) * 1000),
            "error": last_error or "探测失败"}
