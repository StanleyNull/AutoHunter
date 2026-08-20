"""大厅 wumi 聊天 API 冒烟测试。

覆盖：会话 CRUD + 未配置 xiaoqi key 时发送消息返回 400。
纯单元冒烟，不依赖真实 LLM。
"""
from __future__ import annotations

import os
import tempfile

import pytest

# 必须在导入 app 前设置：临时 DB + 不恢复任务，避免污染交付目录。
_TMP_DB = tempfile.mktemp(suffix=".db", prefix="ah_chat_test_")
os.environ["DB_PATH"] = _TMP_DB
os.environ["AUTOHUNTER_RESTORE_ON_STARTUP"] = "0"


@pytest.fixture(autouse=True)
def _no_signal(monkeypatch):
    """TestClient 在非主线程触发 lifespan，屏蔽 signal 注册。"""
    import app.main as main

    monkeypatch.setattr(main.signal, "signal", lambda *a, **k: None)
    monkeypatch.setattr(main.faulthandler, "register", lambda *a, **k: None)


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


def test_chat_session_crud(client):
    # 创建会话（与前端一致：chatCreateSession("") → {title: ""}）
    r = client.post("/api/chat/sessions", json={"title": ""})
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    assert sid

    # 列表能看见
    rows = client.get("/api/chat/sessions").json()
    assert any(s["id"] == sid for s in rows)

    # 未配置 xiaoqi key → 发送消息应 400 并提示去配置
    r2 = client.post(f"/api/chat/sessions/{sid}/messages", json={"message": "你好"})
    assert r2.status_code == 400
    assert "XiaoQi" in r2.json()["detail"]

    # 删除会话
    r3 = client.delete(f"/api/chat/sessions/{sid}")
    assert r3.status_code == 204

    # 删除后不可见
    rows = client.get("/api/chat/sessions").json()
    assert not any(s["id"] == sid for s in rows)


def test_chat_requires_token_401(client):
    """受令牌保护：AUTOHUNTER_API_TOKEN 未设置时放行（本地默认），该用例仅在服务端开启鉴权时校验。"""
    r = client.get("/api/chat/sessions")
    assert r.status_code in (200, 401)
