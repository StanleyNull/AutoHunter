"""用户换/撤凭据后的派发、共享会话与续跑行为，不调用真实 LLM/目标。"""
from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from app.agents.auth_bootstrap import resolve_auth_context_for_target
from app.agents.worker import Worker
from app.db.models import Target, Task
from app.llm.client import LLMError
from app.orchestrator import _refresh_target_auth
from app.tools import cookie_manager


class StopLLM:
    def chat(self, *_args, **_kwargs):
        raise LLMError("auth", "fixture-stop")


class AuthRefreshTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root_patch = patch.object(cookie_manager.worker_config, "work_root", self.tmp.name)
        self.manager_patch = patch.object(cookie_manager, "_MANAGER", cookie_manager.CookieManager())
        self.root_patch.start()
        self.manager_patch.start()
        self.url = "https://example.invalid"

    def tearDown(self):
        self.manager_patch.stop()
        self.root_patch.stop()
        self.tmp.cleanup()

    def context(self, cookie):
        return resolve_auth_context_for_target([
            {"target": self.url, "cookie": cookie},
        ], self.url, [self.url])

    def run_worker(self, ctx, deepen_context=None, binding_changed=False):
        worker = Worker(self.url, task_id="fixture", llm=StopLLM(),
                        target_meta={"auth_context": ctx, "auth_binding_changed": binding_changed},
                        deepen_context=deepen_context)
        return worker, worker.run()

    def test_next_dispatch_replaces_saved_target_binding(self):
        task = Task(auth_bindings=[{"target": self.url, "cookie": "session=new"}], manual_targets=[self.url])
        target = Target(url=self.url, auth_context=self.context("session=old"))
        _refresh_target_auth(target, task, self.url)
        self.assertEqual(target.auth_context["cookies"], {"session": "new"})

    def test_changed_binding_does_not_restore_old_resume_session(self):
        self.run_worker(self.context("session=old"))
        _, result = self.run_worker(self.context("session=new"), {
            "source": "llm_interrupt", "worker_notes": "fixture notes",
            "session_cookies": {"session": "old", "obsolete": "old"},
            "session_headers": {"Authorization": "Bearer old-fixture"},
        })
        self.assertEqual(result.resume_context["session_cookies"], {"session": "new"})
        self.assertEqual(result.resume_context["session_headers"], {})
        self.assertEqual(result.resume_context["worker_notes"], "fixture notes")

    def test_removed_binding_clears_target_and_shared_session_after_restart(self):
        self.run_worker(self.context("session=old"))
        # 持久化 Cookie 也必须撤销，不能仅清掉当前进程的缓存。
        cookie_manager._MANAGER = cookie_manager.CookieManager()
        target = Target(url=self.url, auth_context=self.context("session=old"), deepen_context={
            "source": "llm_interrupt", "session_cookies": {"session": "old"},
            "worker_notes": "fixture notes",
        })
        _refresh_target_auth(target, Task(auth_bindings=[], manual_targets=[self.url]), self.url)
        worker, _ = self.run_worker(target.auth_context, target.deepen_context)
        self.assertIsNone(target.auth_context)
        state = worker.executor.export_resume_state()
        self.assertEqual(state["session_cookies"], {})
        self.assertEqual(state["worker_notes"], "fixture notes")

    def test_unchanged_binding_preserves_refreshed_cookie_and_blocks_late_old_push(self):
        old_worker, _ = self.run_worker(self.context("session=old"))
        old_worker.executor.session_set(cookies={"session": "refreshed"})
        same_worker, same_result = self.run_worker(self.context("session=old"))
        self.assertEqual(same_result.resume_context["session_cookies"], {"session": "refreshed"})
        new_worker, _ = self.run_worker(self.context("session=new"))
        old_worker.executor.session_set(cookies={"session": "late-old"})
        same_worker.executor.session_set(cookies={"session": "late-refreshed"})
        _, final_result = self.run_worker(self.context("session=new"))
        self.assertEqual(final_result.resume_context["session_cookies"], {"session": "new"})

    def test_removing_binding_invalidates_legacy_persisted_session(self):
        # 模拟旧版本持久化格式：没有 auth_context_ref。
        hub = cookie_manager.CookieHub("fixture", self.url)
        hub.remember_from_auth_context(self.context("session=legacy"))
        cookie_manager._MANAGER = cookie_manager.CookieManager()
        # 同站未绑定的 worker 先派发，不能把旧会话标成已撤销的新格式。
        _, sibling_result = self.run_worker(None)
        self.assertEqual(sibling_result.resume_context["session_cookies"], {"session": "legacy"})
        target = Target(url=self.url, auth_context=self.context("session=legacy"))
        changed = _refresh_target_auth(target, Task(auth_bindings=[], manual_targets=[]), self.url)
        worker, _ = self.run_worker(target.auth_context, binding_changed=changed)
        self.assertEqual(worker.executor.export_resume_state()["session_cookies"], {})
