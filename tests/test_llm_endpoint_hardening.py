from __future__ import annotations

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_DOTENV = PROJECT_ROOT / ".env"
_path_exists = Path.exists
_path_read_text = Path.read_text


def _is_project_dotenv(path: Path) -> bool:
    return path.resolve() == PROJECT_DOTENV.resolve()


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
    from app import settings_service
    from app.api import settings as settings_api
    from app.api import tasks as tasks_api
    from app.api.dto import PartialModelConfigDTO, UpdateTaskRequest
    from app.config import LLMConfig
    from app.llm import client as client_module
    from app.llm import health


GLOBAL_KEY = "global-key-for-tests"
POOL_KEY = "pool-key-for-tests"
GLOBAL_PROVIDER = {
    "base_url": "https://global.example/v1",
    "api_key": GLOBAL_KEY,
    "model": "global-model",
    "protocol": "openai_chat",
}
POOL_PROVIDER = {
    "name": "pool-primary",
    "base_url": "https://pool.example/v1",
    "api_key": POOL_KEY,
    "model": "pool-model",
    "protocol": "openai_chat",
    "enabled": True,
}


def _settings() -> dict:
    return {
        "llm": {
            "mode": "pool",
            **GLOBAL_PROVIDER,
            "temperature": 0.3,
            "providers": [POOL_PROVIDER],
        },
        "fofa": {},
        "engines": {},
        "defaults": {},
    }


@pytest.fixture(autouse=True)
def reset_health_state():
    with health._LOCK:
        health._HEALTH.clear()
    yield
    with health._LOCK:
        health._HEALTH.clear()


def test_behavior_probe_retry_delay_is_capped():
    base_url = "https://behavior-probe.example/v1"
    model = "behavior-model"
    api_key = "behavior-key"
    ref = health.provider_ref(base_url, model, api_key)

    with (
        patch.object(health, "_BEHAVIOR_FAIL_THRESHOLD", 1),
        patch.object(health, "_BEHAVIOR_PROBE_SECONDS", 900),
    ):
        health.mark_provider_behavior_failed(base_url, model, "behavior failure", api_key)
        with health._LOCK:
            health._HEALTH[ref]["behavior_cooldown_until_ts"] = 0
        assert health.acquire_provider_slot(base_url, model, api_key, owner="worker-a")[0]
        assert 1 <= health.provider_retry_after_seconds(base_url, model, api_key) <= 5


def test_behavior_half_open_probe_is_not_claimed_while_transport_is_blocked():
    base_url = "https://blocked-transport.example/v1"
    model = "behavior-model"
    api_key = "behavior-key"
    ref = health.provider_ref(base_url, model, api_key)

    health.mark_provider_behavior_failed(base_url, model, "behavior failure", api_key)
    health.mark_provider_failed(base_url, model, "transport failure", api_key)
    with health._LOCK:
        health._HEALTH[ref]["behavior_retry_at_ts"] = 0

    assert health.acquire_provider_slot(
        base_url, model, api_key, owner="worker-a"
    ) == (False, "failed")
    with health._LOCK:
        assert health._HEALTH[ref].get("behavior_probe_owner") in (None, "")
        health._HEALTH[ref]["failed_retry_at_ts"] = 0

    assert health.acquire_provider_slot(
        base_url, model, api_key, owner="worker-b"
    ) == (True, "half_open")
    with health._LOCK:
        assert health._HEALTH[ref]["behavior_probe_owner"] == "worker-b"


def test_failure_callback_exception_does_not_break_failover():
    primary = LLMConfig(
        base_url="https://primary.example/v1",
        api_key="primary-key",
        model="primary-model",
        protocol="openai_chat",
    )
    secondary = LLMConfig(
        base_url="https://secondary.example/v1",
        api_key="secondary-key",
        model="secondary-model",
        protocol="openai_chat",
    )
    callback = Mock(side_effect=RuntimeError("callback failure"))
    first_error = client_module.LLMError("network", "primary failed")
    expected = object()

    with patch.object(client_module.LLMClient, "_build_client", return_value=Mock()):
        llm = client_module.LLMClient(
            providers=[primary, secondary],
            on_provider_failure=callback,
        )
        with (
            patch.object(llm, "_provider_order", return_value=[primary, secondary]),
            patch.object(llm, "_chat_current_provider", side_effect=[first_error, expected]),
            patch.object(client_module.logger, "exception") as logged,
        ):
            assert llm.chat([{"role": "user", "content": "test"}]) is expected

    callback.assert_called_once()
    logged.assert_called_once()


@pytest.mark.parametrize(
    "value",
    [
        "api_key: abcdefghijk",
        '"api_key":"abcdefghijk"',
        "token=abcdefghijk",
        "password = secret123",
        "x-api-key: abcdefghijk",
    ],
)
def test_safe_error_masks_common_secret_fields(value: str):
    assert "abcdefghijk" not in settings_api._safe_error(value)
    assert "secret123" not in settings_api._safe_error(value)


def test_safe_error_masks_exact_nonstandard_provider_key():
    assert POOL_KEY not in settings_api._safe_error(
        f"credential rejected: {POOL_KEY}", POOL_KEY
    )


def _update_llm_settings(current_llm: dict, llm_update: dict):
    row = SimpleNamespace(llm=dict(current_llm), fofa={}, engines={}, defaults={})
    session = SimpleNamespace(
        get=AsyncMock(return_value=row),
        add=Mock(),
        commit=AsyncMock(),
        refresh=AsyncMock(),
    )
    current = {
        "llm": dict(current_llm),
        "fofa": {},
        "engines": {},
        "defaults": {},
    }
    with (
        patch.object(settings_service, "effective_settings", return_value=current),
        patch.object(settings_service, "refresh_cache", new=AsyncMock()),
        patch.object(settings_service, "public_settings_view", return_value={}),
    ):
        asyncio.run(settings_service.update_settings(session, {"llm": llm_update}))
    return row


@pytest.mark.parametrize(
    "llm_update",
    [
        {"base_url": "https://changed.example/v1"},
        {"protocol": "anthropic_messages"},
    ],
)
def test_single_settings_endpoint_change_clears_stored_key(llm_update: dict):
    row = _update_llm_settings(
        {**GLOBAL_PROVIDER, "mode": "single", "temperature": 0.3},
        llm_update,
    )
    assert "api_key" not in row.llm


def test_single_settings_model_change_keeps_stored_key():
    row = _update_llm_settings(
        {**GLOBAL_PROVIDER, "mode": "single", "temperature": 0.3},
        {"model": "new-model"},
    )
    assert row.llm["api_key"] == GLOBAL_KEY


def test_single_settings_endpoint_change_accepts_explicit_new_key():
    replacement = "replacement-key-for-tests"
    row = _update_llm_settings(
        {**GLOBAL_PROVIDER, "mode": "single", "temperature": 0.3},
        {
            "base_url": "https://changed.example/v1",
            "api_key": replacement,
        },
    )
    assert row.llm["api_key"] == replacement


def test_key_only_update_snapshots_endpoint_identity():
    db_key = "db-key-for-tests"
    current_llm = {
        **GLOBAL_PROVIDER,
        "api_key": "env-key-for-tests",
        "mode": "single",
        "temperature": 0.3,
    }
    row = SimpleNamespace(llm={}, fofa={}, engines={}, defaults={})
    session = SimpleNamespace(
        get=AsyncMock(return_value=row),
        add=Mock(),
        commit=AsyncMock(),
        refresh=AsyncMock(),
    )
    with (
        patch.object(settings_service, "effective_settings", return_value={
            "llm": current_llm,
            "fofa": {},
            "engines": {},
            "defaults": {},
        }),
        patch.object(settings_service, "refresh_cache", new=AsyncMock()),
        patch.object(settings_service, "public_settings_view", return_value={}),
    ):
        asyncio.run(settings_service.update_settings(
            session, {"llm": {"api_key": db_key}}
        ))

    assert row.llm["base_url"] == GLOBAL_PROVIDER["base_url"]
    assert row.llm["protocol"] == GLOBAL_PROVIDER["protocol"]

    changed_env = {
        "LLM_PROVIDERS_JSON": "",
        "LLM_BASE_URL": "https://changed-env.example/v1",
        "LLM_API_KEY": "changed-env-key-for-tests",
        "LLM_MODEL": GLOBAL_PROVIDER["model"],
        "LLM_PROTOCOL": GLOBAL_PROVIDER["protocol"],
    }
    cache = {"llm": row.llm, "fofa": {}, "engines": {}, "defaults": {}}
    with (
        patch.dict(os.environ, changed_env, clear=False),
        patch.object(settings_service, "_cache", cache),
    ):
        assert settings_service.resolve_llm_key_for_identity(
            GLOBAL_PROVIDER["base_url"],
            GLOBAL_PROVIDER["model"],
            GLOBAL_PROVIDER["protocol"],
        ) == db_key
        assert settings_service.resolve_llm_key_for_identity(
            changed_env["LLM_BASE_URL"],
            GLOBAL_PROVIDER["model"],
            GLOBAL_PROVIDER["protocol"],
        ) == changed_env["LLM_API_KEY"]


def test_public_single_key_state_uses_endpoint_bound_key():
    cache = {
        "llm": {
            "mode": "single",
            "base_url": "https://db.example/v1",
            "model": "db-model",
            "protocol": "openai_chat",
        },
        "fofa": {},
        "engines": {},
        "defaults": {},
        "updated_at": None,
    }
    env = {
        "LLM_PROVIDER_MODE": "single",
        "LLM_PROVIDERS_JSON": "",
        "LLM_BASE_URL": "https://env.example/v1",
        "LLM_API_KEY": GLOBAL_KEY,
        "LLM_MODEL": "env-model",
        "LLM_PROTOCOL": "openai_chat",
    }
    with (
        patch.dict(os.environ, env, clear=False),
        patch.object(settings_service, "_cache", cache),
        patch.object(settings_service, "list_engines", return_value=[]),
        patch.object(settings_service, "llm_health_snapshot", return_value={}),
    ):
        public = settings_service.public_settings_view()["llm"]

    assert public["api_key"] == ""
    assert public["api_key_set"] is False
    assert public["key_ref"] == ""


def test_db_single_key_overrides_env_key_for_same_endpoint():
    db_key = "db-replacement-key-for-tests"
    cache = {
        "llm": {
            "mode": "single",
            **GLOBAL_PROVIDER,
            "api_key": db_key,
        },
        "fofa": {},
        "engines": {},
        "defaults": {},
        "updated_at": None,
    }
    env = {
        "LLM_PROVIDER_MODE": "single",
        "LLM_PROVIDERS_JSON": "",
        "LLM_BASE_URL": GLOBAL_PROVIDER["base_url"],
        "LLM_API_KEY": GLOBAL_KEY,
        "LLM_MODEL": GLOBAL_PROVIDER["model"],
        "LLM_PROTOCOL": GLOBAL_PROVIDER["protocol"],
    }
    with (
        patch.dict(os.environ, env, clear=False),
        patch.object(settings_service, "_cache", cache),
        patch.object(settings_service, "list_engines", return_value=[]),
        patch.object(settings_service, "llm_health_snapshot", return_value={}),
    ):
        providers = settings_service.resolve_llm_providers()
        public = settings_service.public_settings_view()["llm"]

    assert providers[0].api_key == db_key
    assert public["key_ref"] == settings_service.secret_ref(db_key)


@pytest.mark.parametrize(
    "model_patch",
    [
        PartialModelConfigDTO(base_url="https://changed.example/v1"),
        PartialModelConfigDTO(protocol="anthropic_messages"),
        PartialModelConfigDTO(
            base_url="https://changed.example/v1",
            api_key="********",
        ),
    ],
)
def test_fixed_task_endpoint_change_drops_embedded_key(model_patch):
    task = SimpleNamespace(
        model_config_json={"inherit_global": False, **GLOBAL_PROVIDER},
        fofa_query="",
    )
    session = SimpleNamespace(
        get=AsyncMock(return_value=task),
        commit=AsyncMock(),
        refresh=AsyncMock(),
    )
    request = UpdateTaskRequest(model_config_data=model_patch)
    current = _settings()
    current["llm"]["mode"] = "single"

    async def run_update():
        with (
            patch.object(settings_service, "effective_settings", return_value=current),
            patch.object(tasks_api, "_compute_stats", new=AsyncMock(return_value=Mock())),
            patch.object(tasks_api, "_task_to_dto", return_value={"ok": True}),
        ):
            return await tasks_api.update_task("task-1", request, session)

    assert asyncio.run(run_update()) == {"ok": True}
    assert "api_key" not in task.model_config_json


def test_models_probe_does_not_use_ref_or_global_key_for_arbitrary_url():
    with patch.object(settings_service, "effective_settings", return_value=_settings()):
        result = asyncio.run(settings_service.list_available_models(
            base_url="https://arbitrary.example/v1",
            protocol="openai_chat",
            key_ref=settings_service.secret_ref(POOL_KEY),
            model="pool-model",
        ))
    assert result["ok"] is False
    assert result["models"] == []
    assert "API Key" in result["error"]


def test_models_probe_can_reuse_masked_provider_identity():
    class Response:
        status_code = 200

        def json(self):
            return {"data": [{"id": "pool-model"}]}

    class AsyncClient:
        captured = None

        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, headers):
            AsyncClient.captured = (url, headers)
            return Response()

    with (
        patch.object(settings_service, "effective_settings", return_value=_settings()),
        patch("httpx.AsyncClient", AsyncClient),
        patch("app.tools.netguard.assert_safe_outbound_url"),
    ):
        result = asyncio.run(settings_service.list_available_models(
            base_url=POOL_PROVIDER["base_url"],
            protocol=POOL_PROVIDER["protocol"],
            key_ref=settings_service.secret_ref(POOL_KEY),
        ))

    assert result["ok"] is True
    assert AsyncClient.captured[1]["Authorization"] == f"Bearer {POOL_KEY}"


@pytest.mark.parametrize(
    ("protocol", "model", "expected_url"),
    [
        ("openai_chat", "gpt-4o", "https://relay.example/v1/chat/completions"),
        ("anthropic_messages", "claude-3-5-sonnet", "https://relay.example/v1/messages"),
    ],
)
def test_llm_connection_probe_uses_runtime_user_agent(protocol, model, expected_url):
    class Response:
        status_code = 200
        text = ""

        def json(self):
            return {
                "choices": [{"message": {"content": "ok"}}],
                "content": [{"type": "text", "text": "ok"}],
            }

    class AsyncClient:
        captured = None

        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, headers, json):
            AsyncClient.captured = (url, headers, json)
            return Response()

    provider = LLMConfig(
        base_url="https://relay.example/v1",
        api_key=POOL_KEY,
        model=model,
        protocol=protocol,
    )
    with (
        patch("httpx.AsyncClient", AsyncClient),
        patch.object(settings_api, "assert_safe_outbound_url"),
        patch.object(settings_api, "_resolve_user_agent", return_value="probe-UA/1.0") as resolve_ua,
        patch.object(settings_api, "mark_provider_ok"),
    ):
        result = asyncio.run(settings_api._test_llm_one("probe", provider))

    assert result["ok"] is True
    assert AsyncClient.captured[0] == expected_url
    assert AsyncClient.captured[1]["User-Agent"] == "probe-UA/1.0"
    assert AsyncClient.captured[1]["Accept"] == "application/json"
    resolve_ua.assert_called_once_with(model, "https://relay.example/v1")
    if protocol == "anthropic_messages":
        assert AsyncClient.captured[1]["x-api-key"] == POOL_KEY
