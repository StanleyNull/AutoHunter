"""全局系统配置 API。"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dto import SettingsUpdateRequest
from app.db.session import get_session
from app.engines import get_engine, list_engines
from app.engines.translator import translate_fofa_query
from app.settings_service import (
    list_available_models,
    public_settings_view,
    refresh_cache,
    resolve_proxy_config,
    resolve_engine_key,
    resolve_engine_base_url,
    update_settings,
)

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
async def get_settings(session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    return public_settings_view()


class ModelsProbeRequest(BaseModel):
    base_url: str | None = None
    api_key: str | None = None


@router.post("/models")
async def probe_models(
    body: ModelsProbeRequest,
    session: AsyncSession = Depends(get_session),
):
    """拉取模型商可用模型列表，供前端下拉选择。base_url/api_key 留空用有效配置。
    注意：api_key 为脱敏占位（如 ****）时视为未传，回退到服务端已存的真实 key。"""
    await refresh_cache(session)
    key = (body.api_key or "").strip()
    if key and set(key) <= {"*", "•", "·", "●"}:
        key = ""  # 前端回显的脱敏占位，丢弃
    return await list_available_models(base_url=body.base_url, api_key=key or None)


@router.put("")
async def put_settings(
    body: SettingsUpdateRequest,
    session: AsyncSession = Depends(get_session),
):
    payload = body.model_dump(exclude_unset=True)
    return await update_settings(session, payload)


# ===== 一键连通性测试 =====


@router.post("/test/llm")
async def test_llm(session: AsyncSession = Depends(get_session)):
    """测试 LLM 连通性：拉取模型列表，能拉到即连通。"""
    await refresh_cache(session)
    result = await list_available_models()
    if result.get("ok"):
        return {"ok": True, "message": f"连通正常，可用模型 {len(result.get('models', []))} 个"}
    return {"ok": False, "message": result.get("error", "测试失败")}


@router.post("/test/fofa")
async def test_fofa(session: AsyncSession = Depends(get_session)):
    """测试 FOFA 连通性（兼容旧端点，内部走通用引擎测试）。"""
    return await test_engine("fofa", session)


@router.post("/test/engine/{engine_name}")
async def test_engine(engine_name: str, session: AsyncSession = Depends(get_session)):
    """测试任意搜索引擎连通性：用最小查询验证 API Key 有效性。

    对每个引擎发送 ip="1.1.1.1" 查询（自动翻译为目标引擎语法），
    page=1, page_size=1，只要不报错即视为连通正常。
    """
    await refresh_cache(session)

    engine = get_engine(engine_name)
    if engine is None:
        available = [e["name"] for e in list_engines()]
        return {"ok": False, "message": f"未知引擎 '{engine_name}'，可用：{', '.join(available)}"}

    key = resolve_engine_key(engine_name)
    base_url = resolve_engine_base_url(engine_name)
    if not key:
        return {"ok": False, "message": f"未配置 {engine.display_name} key"}

    # 将 FOFA 语法翻译为目标引擎语法
    test_query = translate_fofa_query('ip="1.1.1.1"', engine_name)
    try:
        result = await engine.search(
            api_key=key, query=test_query, page=1, page_size=1, base_url=base_url,
        )
        total = result.size
        return {"ok": True, "message": f"连通正常，{engine.display_name} 返回 size={total}"}
    except Exception as e:
        return {"ok": False, "message": f"{engine.display_name} 测试失败: {e}"}


@router.post("/test/ssh")
async def test_ssh(session: AsyncSession = Depends(get_session)):
    """测试 SSH 代理连通性：对每台配置的服务器（测试服务器 + 专用探活服务器）执行 echo ok。"""
    await refresh_cache(session)
    pc = resolve_proxy_config()
    test_servers = pc.server_list
    probe_servers = pc.probe_server_list
    if not test_servers and not probe_servers:
        return {"ok": False, "message": "未配置代理服务器"}

    async def _test_one(srv: str, srv_type: str) -> dict:
        """测试单台 SSH 服务器连通性。"""
        # 解析 user@host:port
        if ":" in srv.split("@")[-1]:
            user_host, port = srv.rsplit(":", 1)
        else:
            user_host, port = srv, "22"
        key_path = pc.ssh_key_path
        cmd = [
            "ssh", "-i", key_path,
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            "-p", port, user_host, "echo ok",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
            out = stdout.decode("utf-8", "replace").strip()
            err = stderr.decode("utf-8", "replace").strip()
            if proc.returncode == 0 and "ok" in out:
                return {"server": srv, "type": srv_type, "ok": True, "message": "连通正常"}
            else:
                return {"server": srv, "type": srv_type, "ok": False,
                        "message": err[:200] or out[:200] or f"exit={proc.returncode}"}
        except asyncio.TimeoutError:
            return {"server": srv, "type": srv_type, "ok": False, "message": "超时（15s）"}
        except Exception as e:
            return {"server": srv, "type": srv_type, "ok": False,
                    "message": f"{type(e).__name__}: {e}"}

    results = []
    all_ok = True
    # 先测测试服务器，再测探活服务器
    for srv in test_servers:
        r = await _test_one(srv, "测试服务器")
        results.append(r)
        if not r["ok"]:
            all_ok = False
    for srv in probe_servers:
        r = await _test_one(srv, "探活服务器")
        results.append(r)
        if not r["ok"]:
            all_ok = False

    summary = "; ".join(
        f"[{r['type']}] {r['server']}: {'OK' if r['ok'] else r['message']}" for r in results
    )
    return {"ok": all_ok, "message": summary, "details": results}
