import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.agents.worker import Worker  # noqa: E402
from app.tools import cookie_manager  # noqa: E402


class WorkerSharedLoginTest(unittest.TestCase):
    def test_timed_out_worker_skips_login_and_later_reuses_owner_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cookie_manager.worker_config, "work_root", tmp):
                mgr = cookie_manager.CookieManager()
                with patch.object(cookie_manager, "_MANAGER", mgr):
                    events = []
                    worker = Worker(
                        "https://example.invalid/admin",
                        llm=Mock(),
                        task_id="shared-task",
                        target_meta={"user_auth": {
                            "matched": True, "kinds": ["password"],
                            "username": "fake-user", "password": "fake-password",
                        }},
                        on_event=lambda kind, data: events.append((kind, data)),
                    )
                    slot = mgr.slot("shared-task", worker.target)
                    clock = [1000.0]

                    def advance_clock(timeout):
                        clock[0] += timeout

                    with (
                        patch.object(cookie_manager.time, "monotonic", side_effect=lambda: clock[0]),
                        patch.object(slot.cond, "wait", side_effect=advance_clock),
                        patch.object(worker.executor, "http_request", return_value={"ok": False}) as request,
                    ):
                        with mgr.login_turn("shared-task", worker.target):
                            worker._bootstrap_user_auth()
                            request.assert_not_called()
                            self.assertEqual(clock[0], 1090.0)
                            self.assertEqual(worker.target_meta["auth_attempt"]["status"], "unused")
                            self.assertFalse(worker._cookie_hub.bootstrapping)
                            self.assertEqual(events[-1][0], "auth_status")
                            self.assertIn("超时", events[-1][1]["reason"])
                            with mgr.login_turn("shared-task", worker.target) as action:
                                self.assertEqual(action, "timeout")
                            mgr.remember_from_auth_context(
                                "shared-task", worker.target, {"cookies": {"SESSION": "fake-session"}},
                            )
                        worker._bootstrap_user_auth()
                        request.assert_not_called()
                        self.assertEqual(worker.target_meta["auth_attempt"]["status"], "injected")
                        self.assertEqual(worker.executor._session_cookies["SESSION"], "fake-session")


if __name__ == "__main__":
    unittest.main()
