from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from fastapi import HTTPException


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_DOTENV = PROJECT_ROOT / ".env"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

_path_exists = Path.exists
_path_read_text = Path.read_text


def _is_project_dotenv(path: Path) -> bool:
    return os.path.normcase(os.path.abspath(path)) == os.path.normcase(str(PROJECT_DOTENV))


def _exists_without_project_dotenv(path: Path) -> bool:
    if _is_project_dotenv(path):
        return False
    return _path_exists(path)


def _read_text_without_project_dotenv(path: Path, *args, **kwargs) -> str:
    if _is_project_dotenv(path):
        raise AssertionError("Tests must not read the project .env file")
    return _path_read_text(path, *args, **kwargs)


with (
    patch.object(Path, "exists", _exists_without_project_dotenv),
    patch.object(Path, "read_text", _read_text_without_project_dotenv),
):
    from app.config import LLMConfig
    from app import settings_service
    from app.api import settings as settings_api
    from app.api import tasks as tasks_api
    from app.api.dto import (
        LLMSettingsDTO,
        CreateTaskRequest,
        ModelConfigDTO,
        PartialModelConfigDTO,
        SettingsUpdateRequest,
        UpdateTaskRequest,
    )
    from app.llm import client as client_module
    from app.llm import health


FAKE_SECRET = "test-key-not-a-real-secret"


def _provider(name: str, *, weight: int = 1) -> LLMConfig:
    return LLMConfig(
        base_url=f"https://{name}.invalid/v1",
        api_key=f"{FAKE_SECRET}-{name}",
        model=f"model-{name}",
        protocol="openai_chat",
        weight=weight,
        enabled=True,
    )


class StateResetMixin:
    def setUp(self) -> None:
        with health._LOCK:
            health._HEALTH.clear()
        with client_module._RR_LOCK:
            client_module._RR_STATE.clear()

    def tearDown(self) -> None:
        with health._LOCK:
            health._HEALTH.clear()
        with client_module._RR_LOCK:
            client_module._RR_STATE.clear()


class SettingsServiceTests(StateResetMixin, unittest.TestCase):
    def test_protocol_normalization_supports_aliases_and_legacy_values(self) -> None:
        cases = {
            None: "auto",
            "detect": "auto",
            "openai": "openai_chat",
            "chat": "openai_chat",
            "completions": "openai_chat",
            "messages": "anthropic_messages",
            "anthropic": "anthropic_messages",
            "unsupported-value": "auto",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(settings_service.normalize_llm_protocol(value), expected)

    def test_provider_cleaning_clamps_values_and_keeps_disabled_state(self) -> None:
        providers = settings_service._clean_llm_providers([
            {
                "name": "disabled",
                "base": "https://disabled.invalid/v1",
                "key": f"{FAKE_SECRET}-disabled",
                "model": "model-disabled",
                "temperature": -1,
                "weight": 0,
                "enabled": "off",
            },
            {
                "name": "heavy",
                "base_url": "https://heavy.invalid/v1",
                "api_key": f"{FAKE_SECRET}-heavy",
                "model": "model-heavy",
                "temperature": 9,
                "weight": 999,
            },
            {
                "name": "missing-key",
                "base_url": "https://missing.invalid/v1",
                "model": "model-missing",
            },
        ])

        self.assertEqual(len(providers), 2)
        self.assertFalse(providers[0]["enabled"])
        self.assertEqual(providers[0]["weight"], 1)
        self.assertEqual(providers[0]["temperature"], 0.0)
        self.assertTrue(providers[1]["enabled"])
        self.assertEqual(providers[1]["weight"], 100)
        self.assertEqual(providers[1]["temperature"], 2.0)

    def test_provider_key_round_trip_never_exposes_plaintext(self) -> None:
        old_provider = {
            "name": "primary",
            "base_url": "https://primary.invalid/v1",
            "api_key": FAKE_SECRET,
            "model": "model-primary",
        }
        incoming = {
            "name": "primary",
            "base_url": old_provider["base_url"],
            "api_key": "********",
            "key_ref": settings_service.secret_ref(FAKE_SECRET),
            "model": old_provider["model"],
        }

        preserved = settings_service._preserve_provider_keys([incoming], [old_provider])
        self.assertEqual(preserved[0]["api_key"], FAKE_SECRET)

        public = settings_service._public_llm_provider(preserved[0])
        serialized = json.dumps(public, ensure_ascii=False)
        self.assertNotIn(FAKE_SECRET, serialized)
        self.assertEqual(public["api_key"], "")
        self.assertTrue(public["api_key_set"])
        self.assertEqual(public["key_ref"], settings_service.secret_ref(FAKE_SECRET))
        self.assertNotEqual(settings_service.mask_secret(FAKE_SECRET), FAKE_SECRET)

    def test_pool_mode_rejects_update_without_complete_enabled_provider(self) -> None:
        body = SettingsUpdateRequest(llm=LLMSettingsDTO(
            mode="pool",
            providers=[{
                "name": "disabled",
                "base_url": "https://disabled.invalid/v1",
                "api_key": FAKE_SECRET,
                "model": "model-disabled",
                "enabled": False,
            }],
        ))

        with patch.object(settings_api, "effective_settings", return_value={"llm": {}}):
            with self.assertRaises(HTTPException) as raised:
                import asyncio
                asyncio.run(settings_api.put_settings(body, Mock()))

        self.assertEqual(raised.exception.status_code, 400)

    def test_pool_mode_accepts_preserved_provider_key(self) -> None:
        old_provider = {
            "name": "primary",
            "base_url": "https://primary.invalid/v1",
            "api_key": FAKE_SECRET,
            "model": "model-primary",
            "enabled": True,
        }
        body = SettingsUpdateRequest(llm=LLMSettingsDTO(
            mode="pool",
            providers=[{
                **old_provider,
                "api_key": "",
                "key_ref": settings_service.secret_ref(FAKE_SECRET),
            }],
        ))

        async def fake_update(_session, _payload):
            return {"ok": True}

        with (
            patch.object(
                settings_api,
                "effective_settings",
                return_value={"llm": {"mode": "pool", "providers": [old_provider]}},
            ),
            patch.object(settings_api, "update_settings", side_effect=fake_update),
        ):
            import asyncio
            result = asyncio.run(settings_api.put_settings(body, Mock()))

        self.assertEqual(result, {"ok": True})

    def test_explicit_global_inheritance_ignores_stale_single_override(self) -> None:
        global_provider = {
            "name": "global",
            "base_url": "https://global.invalid/v1",
            "api_key": f"{FAKE_SECRET}-global",
            "model": "model-global",
        }
        task = SimpleNamespace(model_config_json={
            "inherit_global": True,
            "base_url": "https://stale.invalid/v1",
            "api_key": f"{FAKE_SECRET}-stale",
            "model": "model-stale",
        })

        with patch.object(
            settings_service,
            "effective_settings",
            return_value={"llm": {
                "mode": "pool",
                "providers": [global_provider],
                "temperature": 0.3,
                "base_url": "",
                "api_key": "",
                "model": "",
                "protocol": "auto",
            }},
        ):
            providers = settings_service.resolve_llm_providers(task)

        self.assertEqual([provider.model for provider in providers], ["model-global"])

    def test_fixed_single_task_bypasses_global_pool(self) -> None:
        task = SimpleNamespace(model_config_json={
            "inherit_global": False,
            "base_url": "https://fixed.invalid/v1",
            "api_key": f"{FAKE_SECRET}-fixed",
            "model": "model-fixed",
            "protocol": "openai_chat",
        })
        with patch.object(
            settings_service,
            "effective_settings",
            return_value={"llm": {
                "mode": "pool",
                "providers": [{
                    "name": "global",
                    "base_url": "https://global.invalid/v1",
                    "api_key": f"{FAKE_SECRET}-global",
                    "model": "model-global",
                }],
                "temperature": 0.3,
                "base_url": "https://single.invalid/v1",
                "api_key": f"{FAKE_SECRET}-single",
                "model": "model-single",
                "protocol": "auto",
            }},
        ):
            providers = settings_service.resolve_llm_providers(task)

        self.assertEqual(len(providers), 1)
        self.assertEqual(providers[0].model, "model-fixed")

    def test_explicit_fixed_single_without_overrides_does_not_fall_back_to_pool(self) -> None:
        task = SimpleNamespace(model_config_json={"inherit_global": False})
        with patch.object(
            settings_service,
            "effective_settings",
            return_value={"llm": {
                "mode": "pool",
                "providers": [{
                    "name": "global",
                    "base_url": "https://global.invalid/v1",
                    "api_key": f"{FAKE_SECRET}-global",
                    "model": "model-global",
                }],
                "temperature": 0.3,
                "base_url": "https://single.invalid/v1",
                "api_key": f"{FAKE_SECRET}-single",
                "model": "model-single",
                "protocol": "openai_chat",
            }},
        ):
            providers = settings_service.resolve_llm_providers(task)

        self.assertEqual(len(providers), 1)
        self.assertEqual(providers[0].model, "model-single")

    def test_switching_task_back_to_global_clears_stale_override(self) -> None:
        task = SimpleNamespace(
            model_config_json={
                "inherit_global": False,
                "base_url": "https://fixed.invalid/v1",
                "api_key": f"{FAKE_SECRET}-fixed",
                "model": "model-fixed",
                "protocol": "openai_chat",
                "prompt_version": "modern",
            },
            fofa_query="",
        )
        session = SimpleNamespace(
            get=AsyncMock(return_value=task),
            commit=AsyncMock(),
            refresh=AsyncMock(),
        )
        request = UpdateTaskRequest(model_config_data=PartialModelConfigDTO(inherit_global=True))

        async def run_update():
            with (
                patch.object(tasks_api, "_compute_stats", new=AsyncMock(return_value=Mock())),
                patch.object(tasks_api, "_task_to_dto", return_value={"ok": True}),
            ):
                return await tasks_api.update_task("task-1", request, session)

        import asyncio
        result = asyncio.run(run_update())

        self.assertEqual(result, {"ok": True})
        self.assertEqual(task.model_config_json, {
            "prompt_version": "modern",
            "inherit_global": True,
        })

    def test_editing_legacy_task_keeps_key_when_effective_protocol_is_unchanged(self) -> None:
        task = SimpleNamespace(
            model_config_json={
                "inherit_global": False,
                "base_url": "https://legacy.invalid/v1",
                "api_key": f"{FAKE_SECRET}-legacy",
                "model": "model-legacy",
            },
            fofa_query="",
        )
        session = SimpleNamespace(
            get=AsyncMock(return_value=task),
            commit=AsyncMock(),
            refresh=AsyncMock(),
        )
        request = UpdateTaskRequest(model_config_data=PartialModelConfigDTO(
            inherit_global=False,
            base_url="https://legacy.invalid/v1",
            model="model-legacy",
            protocol="openai_chat",
        ))
        runtime_config = LLMConfig(
            base_url="https://legacy.invalid/v1",
            api_key=f"{FAKE_SECRET}-legacy",
            model="model-legacy",
            protocol="openai_chat",
        )

        async def run_update():
            with (
                patch.object(tasks_api, "resolve_llm_config", return_value=runtime_config),
                patch.object(tasks_api, "_compute_stats", new=AsyncMock(return_value=Mock())),
                patch.object(tasks_api, "_task_to_dto", return_value={"ok": True}),
            ):
                return await tasks_api.update_task("task-1", request, session)

        import asyncio
        result = asyncio.run(run_update())

        self.assertEqual(result, {"ok": True})
        self.assertEqual(task.model_config_json["api_key"], f"{FAKE_SECRET}-legacy")
        self.assertEqual(task.model_config_json["protocol"], "openai_chat")

    def test_legacy_create_payload_with_model_fields_keeps_fixed_single(self) -> None:
        request = CreateTaskRequest(
            name="legacy-client",
            model_config_data=ModelConfigDTO(
                base_url="https://legacy.invalid/v1",
                api_key=f"{FAKE_SECRET}-legacy",
                model="model-legacy",
                protocol="openai_chat",
            ),
        )
        session = SimpleNamespace(add=Mock(), commit=AsyncMock(), refresh=AsyncMock())

        async def run_create():
            with patch.object(tasks_api, "_task_to_dto", return_value={"ok": True}):
                return await tasks_api.create_task(request, session)

        import asyncio
        result = asyncio.run(run_create())
        created_task = session.add.call_args.args[0]

        self.assertEqual(result, {"ok": True})
        self.assertFalse(created_task.model_config_json["inherit_global"])
        self.assertEqual(created_task.model_config_json["model"], "model-legacy")


class ProviderHealthTests(StateResetMixin, unittest.TestCase):
    def test_health_state_is_isolated_by_protocol(self) -> None:
        base_url = "https://protocol.invalid/v1"
        model = "model-protocol"
        api_key = f"{FAKE_SECRET}-protocol"

        with (
            patch.object(health, "_FAIL_THRESHOLD", 1),
            patch.object(health, "_COOLDOWN_STEPS", [60]),
        ):
            health.mark_provider_failed(
                base_url,
                model,
                "mock OpenAI protocol failure",
                api_key,
                "openai_chat",
                kind="network",
            )

        self.assertNotEqual(
            health.provider_ref(base_url, model, api_key, "openai_chat"),
            health.provider_ref(base_url, model, api_key, "anthropic_messages"),
        )
        self.assertFalse(
            health.acquire_provider_slot(
                base_url, model, api_key, "openai_chat"
            )[0]
        )
        self.assertEqual(
            health.acquire_provider_slot(
                base_url, model, api_key, "anthropic_messages"
            ),
            (True, "ready"),
        )

    def test_cooldown_allows_one_half_open_probe_then_recovers(self) -> None:
        base_url = "https://health.invalid/v1"
        model = "model-health"
        api_key = f"{FAKE_SECRET}-health"
        ref = health.provider_ref(base_url, model, api_key)

        with (
            patch.object(health, "_FAIL_THRESHOLD", 1),
            patch.object(health, "_COOLDOWN_STEPS", [60]),
        ):
            state = health.mark_provider_failed(
                base_url, model, "mock transport failure", api_key, kind="network"
            )
            self.assertEqual(state["status"], "cooldown")
            self.assertFalse(health.acquire_provider_slot(base_url, model, api_key)[0])

            with health._LOCK:
                health._HEALTH[ref]["cooldown_until_ts"] = 0

            self.assertEqual(
                health.acquire_provider_slot(base_url, model, api_key),
                (True, "half_open"),
            )
            self.assertEqual(
                health.acquire_provider_slot(base_url, model, api_key),
                (False, "half_open_inflight"),
            )

            health.mark_provider_ok(base_url, model, api_key)
            self.assertEqual(
                health.acquire_provider_slot(base_url, model, api_key),
                (True, "ready"),
            )
            self.assertEqual(health.snapshot()[ref]["status"], "ok")

    def test_failed_provider_gets_one_half_open_probe_after_retry_delay(self) -> None:
        base_url = "https://recover.invalid/v1"
        model = "model-recover"
        api_key = f"{FAKE_SECRET}-recover"
        ref = health.provider_ref(base_url, model, api_key)

        with patch.object(health, "_FAIL_THRESHOLD", 2):
            health.mark_provider_failed(base_url, model, "mock failure", api_key, kind="network")
            self.assertFalse(health.acquire_provider_slot(base_url, model, api_key, owner="a")[0])
            with health._LOCK:
                health._HEALTH[ref]["failed_retry_at_ts"] = 0

            self.assertEqual(health.snapshot()[ref]["status"], "half_open")
            self.assertEqual(
                health.acquire_provider_slot(base_url, model, api_key, owner="a"),
                (True, "half_open"),
            )
            self.assertEqual(
                health.acquire_provider_slot(base_url, model, api_key, owner="b"),
                (False, "half_open_inflight"),
            )

    def test_invalid_request_never_creates_global_health_failure(self) -> None:
        base_url = "https://request-error.invalid/v1"
        model = "model-request-error"
        api_key = f"{FAKE_SECRET}-request-error"
        ref = health.provider_ref(base_url, model, api_key)

        for _ in range(10):
            state = health.mark_provider_failed(
                base_url,
                model,
                "mock request validation failure",
                api_key,
                kind="invalid_request",
            )
            self.assertEqual(state["status"], "ok")

        self.assertNotIn(ref, health.snapshot())
        self.assertEqual(
            health.acquire_provider_slot(base_url, model, api_key, owner="worker-a"),
            (True, "ready"),
        )

    def test_invalid_request_releases_half_open_probe_leases(self) -> None:
        base_url = "https://request-probe.invalid/v1"
        model = "model-request-probe"
        api_key = f"{FAKE_SECRET}-request-probe"
        ref = health.provider_ref(base_url, model, api_key)

        with (
            patch.object(health, "_FAIL_THRESHOLD", 2),
            patch.object(health, "_BEHAVIOR_FAIL_THRESHOLD", 2),
        ):
            health.mark_provider_failed(
                base_url, model, "mock transport failure", api_key, kind="network"
            )
            health.mark_provider_behavior_failed(
                base_url, model, "mock behavior failure", api_key
            )
            with health._LOCK:
                health._HEALTH[ref]["failed_retry_at_ts"] = 0
                health._HEALTH[ref]["behavior_retry_at_ts"] = 0

            self.assertEqual(health.snapshot()[ref]["status"], "half_open")
            self.assertEqual(
                health.acquire_provider_slot(
                    base_url, model, api_key, owner="worker-a"
                ),
                (True, "half_open"),
            )

            state = health.mark_provider_failed(
                base_url,
                model,
                "mock request validation failure",
                api_key,
                kind="invalid_request",
            )
            self.assertEqual(state["transition"], "request_rejected")
            self.assertEqual(
                health.acquire_provider_slot(
                    base_url, model, api_key, owner="worker-b"
                ),
                (True, "half_open"),
            )

    def test_behavior_cooldown_probe_is_bound_to_one_worker(self) -> None:
        base_url = "https://behavior.invalid/v1"
        model = "model-behavior"
        api_key = f"{FAKE_SECRET}-behavior"
        ref = health.provider_ref(base_url, model, api_key)

        with (
            patch.object(health, "_BEHAVIOR_FAIL_THRESHOLD", 1),
            patch.object(health, "_COOLDOWN_STEPS", [60]),
        ):
            health.mark_provider_behavior_failed(
                base_url, model, "mock empty tool loop", api_key
            )
            with health._LOCK:
                health._HEALTH[ref]["behavior_cooldown_until_ts"] = 0

            self.assertEqual(health.snapshot()[ref]["status"], "half_open")
            self.assertEqual(
                health.acquire_provider_slot(base_url, model, api_key, owner="worker-a"),
                (True, "ready"),
            )
            self.assertEqual(
                health.acquire_provider_slot(base_url, model, api_key, owner="worker-b"),
                (False, "behavior_half_open_inflight"),
            )
            health.mark_provider_behavior_ok(base_url, model, api_key)
            self.assertEqual(
                health.acquire_provider_slot(base_url, model, api_key, owner="worker-b"),
                (True, "ready"),
            )


class LLMClientPoolTests(StateResetMixin, unittest.TestCase):
    def test_error_classification_covers_non_retryable_provider_failures(self) -> None:
        cases = {
            400: ("参数无效", "invalid_request"),
            403: ("mock upstream response", "blocked"),
            422: ("mock upstream response", "invalid_request"),
        }
        for status, (message, expected) in cases.items():
            error = RuntimeError(message)
            error.status_code = status
            with self.subTest(status=status):
                classified = client_module._classify_error(error)
                self.assertEqual(classified.kind, expected)
                self.assertTrue(client_module._should_try_next_provider(classified))

        not_found = client_module.LLMError("unknown", "endpoint not found", status=404)
        self.assertTrue(client_module._should_try_next_provider(not_found))

    def test_auth_failure_does_not_retry_same_provider(self) -> None:
        provider = _provider("auth-failure")
        error = RuntimeError("invalid api key")
        error.status_code = 401

        with patch.object(client_module.LLMClient, "_build_client", return_value=Mock()):
            llm = client_module.LLMClient(providers=[provider])
            llm.client.chat.completions.create.side_effect = error
            with (
                patch.object(client_module.time, "sleep") as sleep,
                self.assertRaises(client_module.LLMError) as raised,
            ):
                llm._chat_current_provider([{"role": "user", "content": "mock request"}])

        self.assertEqual(raised.exception.kind, "auth")
        self.assertEqual(llm.client.chat.completions.create.call_count, 1)
        sleep.assert_not_called()

    def test_weighted_round_robin_uses_configured_distribution(self) -> None:
        primary = _provider("weighted-primary", weight=3)
        secondary = _provider("weighted-secondary", weight=1)

        with patch.object(client_module.LLMClient, "_build_client", return_value=Mock()):
            llm = client_module.LLMClient(providers=[primary, secondary])
            first_models = [llm._provider_order()[0].model for _ in range(4)]

        self.assertEqual(
            first_models,
            [primary.model, primary.model, secondary.model, primary.model],
        )

    def test_smooth_round_robin_keeps_duplicate_entries_independent(self) -> None:
        primary = _provider("duplicate-provider")
        duplicate = primary.model_copy()

        with patch.object(client_module.LLMClient, "_build_client", return_value=Mock()):
            llm = client_module.LLMClient(providers=[primary, duplicate])
            selected = [llm._provider_order()[0] for _ in range(2)]

        self.assertIs(selected[0], primary)
        self.assertIs(selected[1], duplicate)

    def test_pool_with_one_enabled_provider_keeps_single_provider_retries(self) -> None:
        provider = _provider("single-enabled-provider")
        expected = SimpleNamespace(content="ok", tool_calls=None)
        response = SimpleNamespace(
            choices=[SimpleNamespace(message=expected)],
            usage=None,
        )
        api_client = Mock()
        api_client.chat.completions.create.side_effect = [
            RuntimeError("network connection failed"),
            response,
        ]

        with (
            patch.object(client_module.LLMClient, "_build_client", return_value=api_client),
            patch.object(client_module.time, "sleep"),
        ):
            llm = client_module.LLMClient(providers=[provider], pool_mode=True)
            result = llm.chat([{"role": "user", "content": "mock request"}])

        self.assertFalse(llm.pool_mode)
        self.assertIs(result, expected)
        self.assertEqual(api_client.chat.completions.create.call_count, 2)

    def test_sticky_provider_does_not_advance_weighted_round_robin(self) -> None:
        primary = _provider("sticky-weighted-primary", weight=3)
        secondary = _provider("sticky-weighted-secondary")

        with patch.object(client_module.LLMClient, "_build_client", return_value=Mock()):
            llm = client_module.LLMClient(providers=[primary, secondary])
            llm._provider_order()
            with client_module._RR_LOCK:
                before = dict(client_module._RR_STATE)
            llm._sticky_provider_ref = health.provider_ref(
                primary.base_url,
                primary.model,
                primary.api_key,
                primary.protocol,
            )

            for _ in range(8):
                self.assertIs(llm._provider_order()[0], primary)

            with client_module._RR_LOCK:
                after = dict(client_module._RR_STATE)

        self.assertEqual(after, before)

    def test_single_provider_cooldown_raises_structured_retry(self) -> None:
        provider = _provider("single-cooldown")
        with (
            patch.object(health, "_FAIL_THRESHOLD", 1),
            patch.object(health, "_COOLDOWN_STEPS", [60]),
        ):
            health.mark_provider_failed(
                provider.base_url,
                provider.model,
                "mock provider failure",
                provider.api_key,
                provider.protocol,
                kind="network",
            )

        with patch.object(client_module.LLMClient, "_build_client", return_value=Mock()):
            llm = client_module.LLMClient(providers=[provider], pool_mode=False)
            with (
                patch.object(llm, "_chat_current_provider") as invoke,
                self.assertRaises(client_module.LLMError) as raised,
            ):
                llm.chat([{"role": "user", "content": "mock request"}])

        self.assertEqual(raised.exception.kind, "provider_cooldown")
        self.assertGreaterEqual(raised.exception.retry_after, 1)
        invoke.assert_not_called()

    def test_single_provider_failure_that_starts_cooldown_returns_structured_retry(self) -> None:
        provider = _provider("single-starts-cooldown")
        failure = client_module.LLMError("network", "mock provider failure")

        with (
            patch.object(health, "_FAIL_THRESHOLD", 1),
            patch.object(health, "_COOLDOWN_STEPS", [60]),
            patch.object(client_module.LLMClient, "_build_client", return_value=Mock()),
        ):
            llm = client_module.LLMClient(providers=[provider], pool_mode=False)
            with (
                patch.object(llm, "_chat_current_provider", side_effect=failure),
                self.assertRaises(client_module.LLMError) as raised,
            ):
                llm.chat([{"role": "user", "content": "mock request"}])

        self.assertEqual(raised.exception.kind, "provider_cooldown")
        self.assertGreaterEqual(raised.exception.retry_after, 1)

    def test_failed_provider_falls_through_to_next_provider(self) -> None:
        primary = _provider("failover-primary")
        secondary = _provider("failover-secondary")
        expected = object()
        first_error = client_module.LLMError("network", "mock first endpoint failure")

        with patch.object(client_module.LLMClient, "_build_client", return_value=Mock()):
            llm = client_module.LLMClient(providers=[primary, secondary])
            with (
                patch.object(llm, "_provider_order", return_value=[primary, secondary]),
                patch.object(
                    llm,
                    "_chat_current_provider",
                    side_effect=[first_error, expected],
                ) as invoke
            ):
                result = llm.chat([{"role": "user", "content": "mock request"}])

        self.assertIs(result, expected)
        self.assertEqual(invoke.call_count, 2)
        self.assertEqual(llm.config.model, secondary.model)

    def test_all_quota_failures_preserve_quota_error(self) -> None:
        primary = _provider("quota-primary")
        secondary = _provider("quota-secondary")

        with patch.object(client_module.LLMClient, "_build_client", return_value=Mock()):
            llm = client_module.LLMClient(providers=[primary, secondary])
            with (
                patch.object(llm, "_provider_order", return_value=[primary, secondary]),
                patch.object(
                    llm,
                    "_chat_current_provider",
                    side_effect=[
                        client_module.LLMError("quota", "primary quota exhausted"),
                        client_module.LLMError("quota", "secondary quota exhausted"),
                    ],
                ),
                self.assertRaises(client_module.LLMError) as raised,
            ):
                llm.chat([{"role": "user", "content": "mock request"}])

        self.assertEqual(raised.exception.kind, "quota")

    def test_actual_error_is_preserved_when_other_provider_is_cooling(self) -> None:
        primary = _provider("actual-auth-error")
        secondary = _provider("already-cooling")
        auth_error = client_module.LLMError("auth", "invalid test credential")

        with (
            patch.object(health, "_FAIL_THRESHOLD", 1),
            patch.object(health, "_COOLDOWN_STEPS", [60]),
        ):
            health.mark_provider_failed(
                secondary.base_url,
                secondary.model,
                "mock endpoint outage",
                secondary.api_key,
                secondary.protocol,
                kind="network",
            )

            with patch.object(client_module.LLMClient, "_build_client", return_value=Mock()):
                llm = client_module.LLMClient(providers=[primary, secondary])
                with (
                    patch.object(llm, "_provider_order", return_value=[primary, secondary]),
                    patch.object(
                        llm,
                        "_chat_current_provider",
                        side_effect=auth_error,
                    ) as invoke,
                    self.assertRaises(client_module.LLMError) as raised,
                ):
                    llm.chat([{"role": "user", "content": "mock request"}])

        self.assertEqual(raised.exception.kind, "auth")
        invoke.assert_called_once()

    def test_invalid_request_failover_does_not_poison_global_health(self) -> None:
        primary = _provider("invalid-request-primary")
        secondary = _provider("invalid-request-secondary")
        expected = object()

        with patch.object(client_module.LLMClient, "_build_client", return_value=Mock()):
            llm = client_module.LLMClient(providers=[primary, secondary])
            with (
                patch.object(llm, "_provider_order", return_value=[primary, secondary]),
                patch.object(
                    llm,
                    "_chat_current_provider",
                    side_effect=[
                        client_module.LLMError(
                            "invalid_request",
                            "request rejected",
                            status=400,
                        ),
                        expected,
                    ],
                ),
            ):
                self.assertIs(
                    llm.chat([{"role": "user", "content": "mock request"}]),
                    expected,
                )

        ref = health.provider_ref(
            primary.base_url,
            primary.model,
            primary.api_key,
            primary.protocol,
        )
        snapshot = health.snapshot()
        state = snapshot.get(ref, {})
        self.assertNotIn(ref, snapshot)
        self.assertNotIn(state.get("status"), {"failed", "cooldown"})
        self.assertEqual(int(state.get("consecutive_failures") or 0), 0)

    def test_selection_callback_reports_each_attempted_provider(self) -> None:
        primary = _provider("selection-primary")
        secondary = _provider("selection-secondary")
        selections = []
        first_error = client_module.LLMError("network", "mock first endpoint failure")

        with patch.object(client_module.LLMClient, "_build_client", return_value=Mock()):
            llm = client_module.LLMClient(
                providers=[primary, secondary],
                on_provider_selected=selections.append,
            )
            with (
                patch.object(llm, "_provider_order", return_value=[primary, secondary]),
                patch.object(
                    llm,
                    "_chat_current_provider",
                    side_effect=[first_error, object()],
                ),
            ):
                llm.chat([{"role": "user", "content": "mock request"}])

        self.assertEqual(
            [item["model"] for item in selections],
            [primary.model, secondary.model],
        )
        self.assertIs(llm.selected_provider, secondary)

    def test_successful_provider_stays_sticky_for_worker_session(self) -> None:
        primary = _provider("sticky-primary")
        secondary = _provider("sticky-secondary")
        seen_models = []

        with patch.object(client_module.LLMClient, "_build_client", return_value=Mock()):
            llm = client_module.LLMClient(providers=[primary, secondary])

            def invoke(*_args, **_kwargs):
                seen_models.append(llm.config.model)
                return object()

            with patch.object(llm, "_chat_current_provider", side_effect=invoke):
                llm.chat([{"role": "user", "content": "first"}])
                llm.chat([{"role": "user", "content": "second"}])

        self.assertEqual(seen_models, [primary.model, primary.model])

    def test_pool_mode_does_not_retry_bad_endpoint_before_failover(self) -> None:
        primary = _provider("fast-primary")
        secondary = _provider("fast-secondary")
        first_client = Mock()
        second_client = Mock()
        first_client.chat.completions.create.side_effect = client_module.LLMError(
            "network", "primary unavailable"
        )
        second_client.chat.completions.create.side_effect = client_module.LLMError(
            "network", "secondary unavailable"
        )

        with (
            patch.object(
                client_module.LLMClient,
                "_build_client",
                side_effect=[first_client, second_client],
            ),
            patch.object(client_module.time, "sleep") as sleep,
        ):
            llm = client_module.LLMClient(providers=[primary, secondary])
            with self.assertRaises(client_module.LLMError):
                llm.chat([{"role": "user", "content": "mock request"}])

        self.assertEqual(first_client.chat.completions.create.call_count, 1)
        self.assertEqual(second_client.chat.completions.create.call_count, 1)
        sleep.assert_not_called()

    def test_all_cooling_providers_return_retry_delay_without_calling_network(self) -> None:
        providers = [_provider("cooldown-a"), _provider("cooldown-b")]
        with (
            patch.object(health, "_FAIL_THRESHOLD", 1),
            patch.object(health, "_COOLDOWN_STEPS", [60]),
        ):
            for provider in providers:
                health.mark_provider_failed(
                    provider.base_url,
                    provider.model,
                    "mock cooldown failure",
                    provider.api_key,
                    provider.protocol,
                    kind="network",
                )

            with patch.object(client_module.LLMClient, "_build_client", return_value=Mock()):
                llm = client_module.LLMClient(providers=providers)
                with patch.object(llm, "_chat_current_provider") as invoke:
                    with self.assertRaises(client_module.LLMError) as raised:
                        llm.chat([{"role": "user", "content": "mock request"}])

        self.assertEqual(raised.exception.kind, "provider_cooldown")
        self.assertGreaterEqual(raised.exception.retry_after, 1)
        invoke.assert_not_called()

    def test_tls_downgrade_is_remembered_only_for_affected_provider(self) -> None:
        primary = _provider("tls-primary")
        secondary = _provider("tls-secondary")

        with patch.object(client_module.LLMClient, "_build_client", return_value=Mock()):
            llm = client_module.LLMClient(providers=[primary, secondary])
            self.assertTrue(llm._maybe_downgrade_tls(Exception("certificate verify failed")))
            self.assertTrue(llm._insecure_tls)

            llm._activate_provider(secondary)
            self.assertFalse(llm._insecure_tls)

            llm._activate_provider(primary)
            self.assertTrue(llm._insecure_tls)


if __name__ == "__main__":
    unittest.main()
