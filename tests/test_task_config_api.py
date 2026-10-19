"""任务配置通过真实 API 保存，并由运行时解析；使用隔离 SQLite。"""
from __future__ import annotations

import unittest
from unittest.mock import patch

import httpx
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import tasks
from app.db.models import Base
from app.db.session import get_session


class TaskConfigApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with self.engine.begin() as con:
            await con.run_sync(Base.metadata.create_all)
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)
        app = FastAPI()
        app.include_router(tasks.router)

        async def session_dependency():
            async with self.sessions() as session:
                yield session

        app.dependency_overrides[get_session] = session_dependency
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test",
        )
        self.settings = {
            "llm": {"base_url": "https://model.invalid/v1", "api_key": "",
                    "model": "fixture", "protocol": "auto", "temperature": 0.3},
            "fofa": {}, "engines": {}, "defaults": {"engine": "fofa"},
        }
        self.settings_patch = patch(
            "app.settings_service.effective_settings", return_value=self.settings,
        )
        self.settings_patch.start()

    async def asyncTearDown(self):
        self.settings_patch.stop()
        await self.client.aclose()
        await self.engine.dispose()

    async def create_task(self, **fields):
        response = await self.client.post("/api/tasks", json={"name": "fixture", **fields})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    async def test_non_fofa_task_key_and_url_override_global_settings(self):
        self.settings["engines"]["quake"] = {
            "key": "global-fixture", "base_url": "https://global-engine.invalid",
        }
        task = await self.create_task(
            engine="quake", engine_config={
                "key": "task-fixture", "base_url": "https://task-engine.invalid",
            },
        )
        self.assertEqual(task["fofa_config"]["base_url"], "https://task-engine.invalid")
        self.settings["engines"] = {}
        response = await self.client.get("/api/tasks/" + task["id"])
        self.assertTrue(response.json()["fofa_config"]["key_set"])

    async def test_edit_engine_settings_and_switch_do_not_reuse_old_credentials(self):
        task = await self.create_task(
            engine="fofa", fofa_config={"key": "old-fixture", "base_url": "https://old.invalid"},
        )
        response = await self.client.patch("/api/tasks/" + task["id"], json={"engine": "quake"})
        self.assertFalse(response.json()["fofa_config"]["key_set"])
        self.assertNotEqual(response.json()["fofa_config"]["base_url"], "https://old.invalid")
        response = await self.client.patch("/api/tasks/" + task["id"], json={
            "fofa_config": {"key": "new-fixture", "base_url": "https://new.invalid"},
        })
        self.assertTrue(response.json()["fofa_config"]["key_set"])
        self.assertEqual(response.json()["fofa_config"]["base_url"], "https://new.invalid")

    async def test_default_engine_change_does_not_move_task_override(self):
        task = await self.create_task(fofa_config={"key": "fofa-fixture"})
        self.settings["defaults"]["engine"] = "quake"
        response = await self.client.get("/api/tasks/" + task["id"])
        self.assertFalse(response.json()["fofa_config"]["key_set"])

    async def test_edit_after_default_engine_change_binds_only_new_overrides(self):
        task = await self.create_task(fofa_config={
            "key": "old-fofa-fixture", "base_url": "https://old-fofa.invalid",
        })
        self.settings["defaults"]["engine"] = "quake"
        response = await self.client.patch("/api/tasks/" + task["id"], json={
            "engine_config": {"base_url": "https://new-quake.invalid"},
        })
        self.assertFalse(response.json()["fofa_config"]["key_set"])
        response = await self.client.patch("/api/tasks/" + task["id"], json={
            "fofa_config": {"key": "new-quake-fixture"},
        })
        self.assertTrue(response.json()["fofa_config"]["key_set"])

    async def test_fofa_config_edit_after_default_change_binds_new_key(self):
        task = await self.create_task(fofa_config={"key": "old-fofa-fixture"})
        self.settings["defaults"]["engine"] = "quake"
        response = await self.client.patch("/api/tasks/" + task["id"], json={
            "fofa_config": {"key": "new-quake-fixture"},
        })
        self.assertTrue(response.json()["fofa_config"]["key_set"])

    async def test_site_recon_toggle_can_be_edited_both_ways(self):
        task = await self.create_task(
            target_source="site", manual_targets=["https://example.invalid"],
        )
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                response = await self.client.patch("/api/tasks/" + task["id"], json={
                    "fofa_config": {"skip_site_recon": enabled},
                })
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["fofa_config"]["skip_site_recon"], enabled)
