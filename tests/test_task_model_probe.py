from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_DOTENV = PROJECT_ROOT / ".env"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

_path_exists = Path.exists
_path_read_text = Path.read_text


def _is_project_dotenv(path: Path) -> bool:
    return os.path.normcase(os.path.abspath(path)) == os.path.normcase(str(PROJECT_DOTENV))


def _exists_without_project_dotenv(path: Path) -> bool:
    return False if _is_project_dotenv(path) else _path_exists(path)


def _read_text_without_project_dotenv(path: Path, *args, **kwargs) -> str:
    if _is_project_dotenv(path):
        raise AssertionError("Tests must not read the project .env file")
    return _path_read_text(path, *args, **kwargs)


with (
    patch.object(Path, "exists", _exists_without_project_dotenv),
    patch.object(Path, "read_text", _read_text_without_project_dotenv),
):
    from app.api import tasks as tasks_api
    from app.config import LLMConfig


FAKE_SECRET = "task-key-not-a-real-secret"
TASK_BASE_URL = "https://task-model.invalid/v1"


def _task() -> SimpleNamespace:
    return SimpleNamespace(model_config_json={
        "inherit_global": False,
        "base_url": TASK_BASE_URL,
        "api_key": FAKE_SECRET,
        "model": "task-model",
        "protocol": "openai_chat",
    })


def _task_config() -> LLMConfig:
    return LLMConfig(
        base_url=TASK_BASE_URL,
        api_key=FAKE_SECRET,
        model="task-model",
        protocol="openai_chat",
    )


class TaskModelProbeTests(unittest.TestCase):
    def test_public_task_config_returns_reference_without_plaintext_key(self) -> None:
        with (
            patch.object(tasks_api, "resolve_llm_config", return_value=_task_config()),
            patch.object(tasks_api, "resolve_llm_providers", return_value=[_task_config()]),
            patch.object(tasks_api, "resolve_worker_prompt_version", return_value="legacy"),
        ):
            public = tasks_api._public_model_config(_task())

        self.assertEqual(public["key_ref"], tasks_api.secret_ref(FAKE_SECRET))
        self.assertNotIn(FAKE_SECRET, json.dumps(public))

    def test_task_probe_reuses_saved_key_only_for_matching_endpoint(self) -> None:
        session = SimpleNamespace(get=AsyncMock(return_value=_task()))
        probe = AsyncMock(return_value={"ok": True, "models": ["task-model"]})
        body = tasks_api.TaskModelsProbeRequest(
            base_url=f"{TASK_BASE_URL}/",
            key_ref=tasks_api.secret_ref(FAKE_SECRET),
            protocol="openai_chat",
        )

        with (
            patch.object(tasks_api, "resolve_llm_config", return_value=_task_config()),
            patch.object(tasks_api, "list_available_models", probe),
        ):
            result = asyncio.run(tasks_api.probe_task_models("task-1", body, session))

        self.assertTrue(result["ok"])
        probe.assert_awaited_once_with(
            base_url=f"{TASK_BASE_URL}/",
            api_key=FAKE_SECRET,
            protocol="openai_chat",
        )

    def test_task_probe_does_not_send_saved_key_to_changed_endpoint(self) -> None:
        session = SimpleNamespace(get=AsyncMock(return_value=_task()))
        probe = AsyncMock()
        body = tasks_api.TaskModelsProbeRequest(
            base_url="https://changed.invalid/v1",
            key_ref=tasks_api.secret_ref(FAKE_SECRET),
            protocol="openai_chat",
        )

        with (
            patch.object(tasks_api, "resolve_llm_config", return_value=_task_config()),
            patch.object(tasks_api, "list_available_models", probe),
        ):
            result = asyncio.run(tasks_api.probe_task_models("task-1", body, session))

        self.assertFalse(result["ok"])
        self.assertEqual(result["models"], [])
        probe.assert_not_awaited()

    def test_task_probe_does_not_send_saved_key_to_changed_protocol(self) -> None:
        session = SimpleNamespace(get=AsyncMock(return_value=_task()))
        probe = AsyncMock()
        body = tasks_api.TaskModelsProbeRequest(
            base_url=TASK_BASE_URL,
            key_ref=tasks_api.secret_ref(FAKE_SECRET),
            protocol="anthropic_messages",
        )

        with (
            patch.object(tasks_api, "resolve_llm_config", return_value=_task_config()),
            patch.object(tasks_api, "list_available_models", probe),
        ):
            result = asyncio.run(tasks_api.probe_task_models("task-1", body, session))

        self.assertFalse(result["ok"])
        self.assertEqual(result["models"], [])
        probe.assert_not_awaited()

    def test_task_probe_without_base_uses_bound_task_endpoint(self) -> None:
        session = SimpleNamespace(get=AsyncMock(return_value=_task()))
        probe = AsyncMock(return_value={"ok": True, "models": ["task-model"]})
        body = tasks_api.TaskModelsProbeRequest(
            key_ref=tasks_api.secret_ref(FAKE_SECRET),
            protocol="openai_chat",
        )

        with (
            patch.object(tasks_api, "resolve_llm_config", return_value=_task_config()),
            patch.object(tasks_api, "list_available_models", probe),
        ):
            result = asyncio.run(tasks_api.probe_task_models("task-1", body, session))

        self.assertTrue(result["ok"])
        probe.assert_awaited_once_with(
            base_url=TASK_BASE_URL,
            api_key=FAKE_SECRET,
            protocol="openai_chat",
        )

    def test_task_probe_without_protocol_uses_bound_task_protocol(self) -> None:
        session = SimpleNamespace(get=AsyncMock(return_value=_task()))
        probe = AsyncMock(return_value={"ok": True, "models": ["task-model"]})
        body = tasks_api.TaskModelsProbeRequest(
            key_ref=tasks_api.secret_ref(FAKE_SECRET),
        )

        with (
            patch.object(tasks_api, "resolve_llm_config", return_value=_task_config()),
            patch.object(tasks_api, "list_available_models", probe),
        ):
            result = asyncio.run(tasks_api.probe_task_models("task-1", body, session))

        self.assertTrue(result["ok"])
        probe.assert_awaited_once_with(
            base_url=TASK_BASE_URL,
            api_key=FAKE_SECRET,
            protocol="openai_chat",
        )


if __name__ == "__main__":
    unittest.main()
