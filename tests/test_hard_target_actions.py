"""硬骨头库删除/深挖（#61/#62）与「非目标问题不进硬骨头」（#63）的行为测试。"""
from __future__ import annotations

import asyncio
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


with (
    patch.object(
        Path, "exists", lambda p: False if _is_project_dotenv(p) else _path_exists(p)
    ),
    patch.object(
        Path,
        "read_text",
        lambda p, *a, **kw: (
            (_ for _ in ()).throw(AssertionError("Tests must not read the project .env file"))
            if _is_project_dotenv(p) else _path_read_text(p, *a, **kw)
        ),
    ),
):
    from app.api import assets as assets_api
    from app.orchestrator import MAX_TRANSIENT_LLM_REQUEUE, TaskRunner


def _target(**overrides):
    base = dict(
        id="target-1",
        task_id="task-1",
        host="example.invalid",
        url="https://example.invalid",
        status="dead",
        verdict="error",
        dead_reason="无可利用漏洞",
        last_error="",
        priority_score=1.0,
        priority_reason="",
        source="manual",
        leaked_creds=None,
        deepen_count=0,
        deepen_context=None,
        retry_count=0,
        assigned_worker="",
        heartbeat_at=object(),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class _Result:
    """最小 SQLAlchemy Result 替身：支持 scalar() 与 scalars().all()。"""

    def __init__(self, rows):
        self._rows = list(rows)

    def scalar(self):
        return self._rows[0] if self._rows else None

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None


class _AssetSession:
    """assets 路由用的假会话：get 返回预置目标，execute 返回预置标量。"""

    def __init__(self, target, *, task=None, live_findings=0):
        self._target = target
        self._task = task
        self._live_findings = live_findings
        self.added: list = []
        self.deleted: list = []
        self.commits = 0

    async def get(self, _model, key):
        if _model.__name__ == "Task":
            return self._task if key == "task-1" else None
        if self._target is None or key != self._target.id:
            return None
        return self._target

    async def execute(self, *_args, **_kwargs):
        return _Result([self._live_findings])

    def add(self, obj):
        self.added.append(obj)

    async def delete(self, obj):
        # AsyncSession.delete 是要 await 的，夹具必须同样是协程。
        self.deleted.append(obj)

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        pass


class HardTargetDeleteTests(unittest.TestCase):
    """#61：硬骨头库删除必须彻底删掉记录，并把「误删」挡在外面。"""

    def test_deletes_dead_target_and_writes_audit_event(self) -> None:
        tgt = _target()
        session = _AssetSession(tgt)

        result = asyncio.run(assets_api.delete_asset("target-1", session))

        self.assertTrue(result["ok"])
        self.assertEqual(result["host"], "example.invalid")
        self.assertEqual(session.deleted, [tgt])
        self.assertEqual(session.commits, 1)
        kinds = [e.kind for e in session.added if getattr(e, "kind", "") == "target_deleted"]
        self.assertEqual(kinds, ["target_deleted"])

    def test_refuses_target_outside_hard_bone_library(self) -> None:
        # queued 目标不在硬骨头库里：属于「正在排队要挖」的资产，不能从这里删。
        session = _AssetSession(_target(status="queued"))

        with self.assertRaises(HTTPException) as raised:
            asyncio.run(assets_api.delete_asset("target-1", session))

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("硬骨头库", str(raised.exception.detail))
        self.assertEqual(session.deleted, [])
        self.assertEqual(session.commits, 0)

    def test_refuses_target_that_still_has_live_findings(self) -> None:
        # 目标上挂着有效漏洞时删除会连带删洞（cascade），必须拒绝并说清原因。
        session = _AssetSession(_target(), live_findings=2)

        with self.assertRaises(HTTPException) as raised:
            asyncio.run(assets_api.delete_asset("target-1", session))

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("2 条漏洞", str(raised.exception.detail))
        self.assertEqual(session.deleted, [])

    def test_superseded_findings_do_not_block_delete(self) -> None:
        # superseded 是深挖让位的旧线索，随目标一起清掉；这里 live 计数为 0 即可删。
        session = _AssetSession(_target(status="skipped"), live_findings=0)

        result = asyncio.run(assets_api.delete_asset("target-1", session))

        self.assertTrue(result["ok"])

    def test_batch_delete_reports_per_id_reasons(self) -> None:
        tgt = _target()
        session = _AssetSession(tgt, live_findings=0)

        result = asyncio.run(assets_api.batch_delete_assets(
            assets_api.BatchDeleteRequest(ids=["target-1", "missing-1"]), session
        ))

        self.assertEqual(result["success_count"], 1)
        self.assertEqual(len(result["failed"]), 1)
        self.assertEqual(result["failed"][0]["id"], "missing-1")


class HardTargetDeepenTests(unittest.TestCase):
    """#62：硬骨头深挖回炉——带回执指令、复用任务的深挖次数上限。"""

    def _task(self, cap=2):
        return SimpleNamespace(id="task-1", status="running", deepen_cap=cap)

    def test_deepen_requeues_target_with_directive(self) -> None:
        tgt = _target(status="dead", dead_reason="系统自动收敛，无可利用漏洞")
        session = _AssetSession(tgt, task=self._task())

        result = asyncio.run(assets_api.deepen_asset(
            "target-1", assets_api.DeepenRequest(directive="打 /uploads 上传点"), session
        ))

        self.assertTrue(result["ok"])
        self.assertTrue(result["queued_now"])
        self.assertEqual(tgt.status, "queued")
        self.assertEqual(tgt.verdict, "")
        self.assertEqual(tgt.dead_reason, "")
        self.assertEqual(tgt.deepen_count, 1)
        self.assertEqual(tgt.deepen_context["directive"], "打 /uploads 上传点")
        self.assertEqual(tgt.deepen_context["source"], "user")
        self.assertGreater(tgt.priority_score, 1.0)
        self.assertEqual([e.kind for e in session.added], ["target_deepen"])

    def test_deepen_rejects_empty_directive(self) -> None:
        session = _AssetSession(_target(), task=self._task())

        with self.assertRaises(HTTPException) as raised:
            asyncio.run(assets_api.deepen_asset(
                "target-1", assets_api.DeepenRequest(directive="   "), session
            ))

        self.assertEqual(raised.exception.status_code, 400)

    def test_deepen_rejects_running_target(self) -> None:
        session = _AssetSession(_target(status="scanning"), task=self._task())

        with self.assertRaises(HTTPException) as raised:
            asyncio.run(assets_api.deepen_asset(
                "target-1", assets_api.DeepenRequest(directive="再打一轮"), session
            ))

        self.assertEqual(raised.exception.status_code, 409)

    def test_deepen_is_capped_by_task_setting(self) -> None:
        tgt = _target(status="dead", deepen_count=2)
        session = _AssetSession(tgt, task=self._task(cap=2))

        with self.assertRaises(HTTPException) as raised:
            asyncio.run(assets_api.deepen_asset(
                "target-1", assets_api.DeepenRequest(directive="再打一轮"), session
            ))

        self.assertEqual(raised.exception.status_code, 409)
        self.assertEqual(tgt.status, "dead")
        self.assertEqual(tgt.deepen_count, 2)

    def test_deepen_rejected_when_task_turned_it_off(self) -> None:
        session = _AssetSession(_target(), task=self._task(cap=0))

        with self.assertRaises(HTTPException) as raised:
            asyncio.run(assets_api.deepen_asset(
                "target-1", assets_api.DeepenRequest(directive="再打一轮"), session
            ))

        self.assertEqual(raised.exception.status_code, 409)

    def test_deepen_works_when_task_is_not_running(self) -> None:
        session = _AssetSession(_target(), task=SimpleNamespace(
            id="task-1", status="stopped", deepen_cap=2
        ))

        result = asyncio.run(assets_api.deepen_asset(
            "target-1", assets_api.DeepenRequest(directive="再打一轮"), session
        ))

        self.assertTrue(result["ok"])
        self.assertFalse(result["queued_now"])


class _SessionContext:
    def __init__(self, session) -> None:
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


class HardTargetRouteTests(unittest.TestCase):
    """路由级冒烟：确认前端真正调用的 URL/方法确实挂着处理函数。"""

    @staticmethod
    def _client(target, *, task=None):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.db.session import get_session

        app = FastAPI()
        app.include_router(assets_api.router)
        app.dependency_overrides[get_session] = lambda: _AssetSession(target, task=task)
        return TestClient(app)

    def test_deepen_route_accepts_directive(self) -> None:
        target = _target()
        client = self._client(target, task=SimpleNamespace(
            id="task-1", status="running", deepen_cap=2
        ))

        ok = client.post("/api/assets/target-1/deepen", json={"directive": "打上传点"})
        self.assertEqual(ok.status_code, 200)
        self.assertTrue(ok.json()["ok"])

        bad = client.post("/api/assets/target-1/deepen", json={"directive": "  "})
        self.assertEqual(bad.status_code, 400)

    def test_delete_route_deletes_and_reports_conflicts(self) -> None:
        ok = self._client(_target()).delete("/api/assets/target-1")
        self.assertEqual(ok.status_code, 200)
        self.assertTrue(ok.json()["ok"])

        # 正在挖掘（assigned）的目标不在硬骨头库里 → 409 且带可读原因。
        r = self._client(_target(status="assigned")).delete("/api/assets/target-1")
        self.assertEqual(r.status_code, 409)
        self.assertIn("硬骨头库", r.json()["detail"])

    def test_batch_delete_route_returns_failure_reasons(self) -> None:
        client = self._client(_target())
        r = client.post("/api/assets/batch/delete", json={"ids": ["target-1", "ghost"]})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["success_count"], 1)
        self.assertEqual(body["failed"][0]["id"], "ghost")


class InfraFailureClassificationTests(unittest.TestCase):
    """#63：只有「跟目标无关」的失败才算基础设施问题。"""

    def test_infra_kinds_are_recognised(self) -> None:
        for kind in (
            "provider_cooldown", "rate_limit", "timeout", "network", "upstream",
            "unknown", "blocked", "invalid_request", "auth", "model_behavior",
            "tool_argument",
        ):
            with self.subTest(kind=kind):
                self.assertTrue(TaskRunner._is_infra_failure({"failure_kind": kind}))

    def test_target_side_failures_are_not_infra(self) -> None:
        self.assertFalse(TaskRunner._is_infra_failure({"failure_kind": "", "error": ""}))
        self.assertFalse(TaskRunner._is_infra_failure(
            {"failure_kind": "no_vuln", "summary": "本轮确认无可利用漏洞"}
        ))

    def test_worker_auto_converge_on_network_is_infra(self) -> None:
        # worker 明确写「连续 3 次网络/超时失败…系统自动收敛」时没有 failure_kind，
        # 只能按文案兜底识别——否则会把这个目标误收进硬骨头库。
        self.assertTrue(TaskRunner._is_infra_failure({
            "failure_kind": "",
            "summary": "连续 3 次网络/超时失败，目标当前不可稳定验证，系统自动收敛。",
        }))

    def test_hard_bone_library_query_excludes_stalled_status(self) -> None:
        # 硬骨头库只聚合 dead/skipped；stalled 目标不能被算进去。
        from app.api import tasks as tasks_api
        import inspect

        source = inspect.getsource(tasks_api.global_hard_targets)
        self.assertIn('["dead", "skipped"]', source)
        self.assertNotIn('"stalled"', source)


class InfraFailurePersistenceTests(unittest.IsolatedAsyncioTestCase):
    """#63：基础设施失败的目标要么回队、要么 stall，绝不置 dead。"""

    async def _persist(self, runner, target, result):
        session = SimpleNamespace(
            get=AsyncMock(return_value=target),
            commit=AsyncMock(),
            add=Mock(),
            # 终态 dead 会触发深挖前身救回查询，给个空结果即可。
            execute=AsyncMock(return_value=_Result([])),
        )
        with patch("app.orchestrator.SessionLocal", return_value=_SessionContext(session)):
            await runner._persist_worker_result("task-1", "target-1", result)
        return session

    def _runner(self) -> TaskRunner:
        runner = TaskRunner("task-1")
        runner._harvest_intel = AsyncMock()
        runner._log = AsyncMock()
        return runner

    async def test_llm_outage_requeues_first_then_stalls(self) -> None:
        target = _target(status="scanning", verdict="error", dead_reason="")
        target.last_error = ""
        runner = self._runner()
        result = {
            "verdict": "error",
            "findings": [],
            "error": "LLM 调用失败：模型服务返回未知错误。",
            "failure_kind": "unknown",
        }

        await self._persist(runner, target, result)
        # 第一次：回队重试，不消耗 retry_count，更不进硬骨头库。
        self.assertEqual(target.status, "queued")
        self.assertEqual(target.dead_reason, "")

        # 把回队预算用光后再来一次：转 stalled 停摆，而不是 dead。
        runner._transient_llm_requeue["target-1"] = MAX_TRANSIENT_LLM_REQUEUE
        await self._persist(runner, target, result)

        self.assertEqual(target.status, "stalled")
        self.assertEqual(target.verdict, "")
        self.assertEqual(target.dead_reason, "")
        self.assertIn("LLM", target.last_error)

    async def test_bad_credentials_do_not_land_in_hard_bone(self) -> None:
        target = _target(status="scanning", verdict="error", dead_reason="")
        target.last_error = ""
        runner = self._runner()
        runner._transient_llm_requeue["target-1"] = MAX_TRANSIENT_LLM_REQUEUE

        await self._persist(runner, target, {
            "verdict": "error",
            "findings": [],
            "error": "LLM API Key 无效或无权限，请检查任务配置或服务端 .env。",
            "failure_kind": "auth",
        })

        self.assertEqual(target.status, "stalled")
        self.assertEqual(target.dead_reason, "")

    async def test_worker_network_converge_does_not_land_in_hard_bone(self) -> None:
        target = _target(status="scanning", verdict="error", dead_reason="")
        target.last_error = ""
        runner = self._runner()
        runner._transient_llm_requeue["target-1"] = MAX_TRANSIENT_LLM_REQUEUE

        await self._persist(runner, target, {
            "verdict": "no_vuln",
            "findings": [],
            "summary": "连续 3 次网络/超时失败，目标当前不可稳定验证，系统自动收敛。",
            "failure_kind": "",
        })

        self.assertEqual(target.status, "stalled")

    async def test_target_side_no_vuln_still_lands_in_hard_bone(self) -> None:
        # 反例保护：目标真的确认没洞时，仍然要照旧进硬骨头库。
        target = _target(status="scanning", verdict="error", dead_reason="")
        target.last_error = ""
        runner = self._runner()

        await self._persist(runner, target, {
            "verdict": "no_vuln",
            "findings": [],
            "summary": "本轮确认无可利用漏洞，不再默认重试",
            "failure_kind": "",
        })

        self.assertEqual(target.status, "dead")
        self.assertNotEqual(target.dead_reason, "")

    async def test_release_stalled_puts_targets_back_to_queue(self) -> None:
        parked = _target(status="stalled")
        runner = self._runner()
        runner._transient_llm_requeue["target-1"] = 3
        session = SimpleNamespace(
            execute=AsyncMock(return_value=_Result([parked])),
            commit=AsyncMock(),
        )

        released = await runner._release_stalled_targets(session)

        self.assertEqual(released, 1)
        self.assertEqual(parked.status, "queued")
        self.assertNotIn("target-1", runner._transient_llm_requeue)


class PoolUsableEndpointTests(unittest.TestCase):
    """停摆目标只在端点池确实还有可用端点时才放行，避免白跑一轮。"""

    def setUp(self) -> None:
        from app.llm import health
        with health._LOCK:
            health._HEALTH.clear()

    def tearDown(self) -> None:
        from app.llm import health
        with health._LOCK:
            health._HEALTH.clear()

    @staticmethod
    def _provider(name: str):
        return SimpleNamespace(
            base_url=f"https://{name}.invalid/v1",
            model=f"model-{name}",
            api_key="test-key-not-a-real-secret",
            protocol="openai_chat",
        )

    def test_no_providers_is_not_usable(self) -> None:
        self.assertFalse(TaskRunner._pool_has_usable_endpoint([]))

    def test_provider_without_failure_record_is_usable(self) -> None:
        self.assertTrue(TaskRunner._pool_has_usable_endpoint([self._provider("fresh")]))

    def test_all_providers_cooling_is_not_usable(self) -> None:
        from app.llm import health

        provider = self._provider("down")
        with (
            patch.object(health, "_FAIL_THRESHOLD", 1),
            patch.object(health, "_COOLDOWN_STEPS", [600]),
        ):
            health.mark_provider_failed(
                provider.base_url, provider.model, "mock outage",
                provider.api_key, provider.protocol, kind="network",
            )
            self.assertFalse(TaskRunner._pool_has_usable_endpoint([provider]))

            # 池里补一个没失败过的端点 → 又变得可用。
            self.assertTrue(TaskRunner._pool_has_usable_endpoint(
                [provider, self._provider("healthy")]
            ))


class StalledReleaseTriggerTests(unittest.IsolatedAsyncioTestCase):
    """周期性放行的触发条件：间隔节流 + 端点池可用判定。"""

    def _runner(self) -> TaskRunner:
        runner = TaskRunner("task-1")
        runner._log = AsyncMock()
        runner._release_stalled_targets = AsyncMock(return_value=0)
        return runner

    async def test_release_is_skipped_when_no_endpoint_is_usable(self) -> None:
        runner = self._runner()
        session = SimpleNamespace()

        with patch("app.orchestrator.resolve_llm_providers", return_value=[]):
            await runner._maybe_release_stalled(session, SimpleNamespace(id="task-1"))

        runner._release_stalled_targets.assert_not_awaited()

    async def test_release_runs_when_endpoint_is_usable(self) -> None:
        runner = self._runner()
        session = SimpleNamespace()
        provider = PoolUsableEndpointTests._provider("usable")

        with patch("app.orchestrator.resolve_llm_providers", return_value=[provider]):
            await runner._maybe_release_stalled(session, SimpleNamespace(id="task-1"))

        runner._release_stalled_targets.assert_awaited_once_with(session)

    async def test_release_is_throttled_by_interval(self) -> None:
        runner = self._runner()
        session = SimpleNamespace()
        provider = PoolUsableEndpointTests._provider("usable")

        with patch("app.orchestrator.resolve_llm_providers", return_value=[provider]):
            await runner._maybe_release_stalled(session, SimpleNamespace(id="task-1"))
            runner._release_stalled_targets.reset_mock()
            # 刚放过一次，第二次调用不该再放（否则每个 tick 都会空转）。
            await runner._maybe_release_stalled(session, SimpleNamespace(id="task-1"))

        runner._release_stalled_targets.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
