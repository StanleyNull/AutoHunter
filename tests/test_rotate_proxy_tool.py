"""rotate_proxy 工具分发测试：worker._dispatch 分支返回结构 + 事件上报。"""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import proxy_service as ps  # noqa: E402
from app.agents.worker import Worker  # noqa: E402
from app.tools.executor import ToolExecutor  # noqa: E402


def _worker_with_executor(executor: ToolExecutor) -> tuple[Worker, list]:
    """绕过 __init__ 构造最小 Worker：只填 _dispatch("rotate_proxy") 依赖的属性。"""
    events: list = []
    w = object.__new__(Worker)
    w._tool_counts = {}
    w._last_js_analysis_round = 0
    w._post_js_validation_count = 0
    w.executor = executor
    w.on_event = lambda kind, data: events.append((kind, data))
    return w, events


class RotateProxyDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        ps.apply_config({})
        self.ex = ToolExecutor("http://target.example", work_dir=tempfile.mkdtemp())

    def tearDown(self) -> None:
        ps.apply_config({})
        self.ex.close_http_client()

    def test_dispatch_returns_rotation_result_and_emits_events(self) -> None:
        ps.apply_config({
            "enabled": True,
            "proxies": [
                {"id": "px-1", "name": "a", "protocol": "http", "host": "10.0.0.1",
                 "port": 8080, "username": "", "password": "", "enabled": True},
                {"id": "px-2", "name": "b", "protocol": "http", "host": "10.0.0.2",
                 "port": 8080, "username": "", "password": "", "enabled": True},
            ],
        })
        self.ex._proxy_id = "px-1"
        self.ex._proxy_url = "http://10.0.0.1:8080"
        w, events = _worker_with_executor(self.ex)
        result = w._dispatch("rotate_proxy", {"reason": "整站 403 拦截页"}, 3)
        self.assertTrue(result["ok"])
        self.assertEqual(result["reason"], "整站 403 拦截页")
        self.assertNotIn("http://10.0.0.1:8080", [result["proxy"]])
        self.assertIn("px-1", self.ex._used_proxy_ids)
        kinds = [kind for kind, _ in events]
        self.assertIn("tool_rotate_proxy", kinds)
        self.assertIn("proxy_rotated", kinds)

    def test_dispatch_without_reason_uses_default(self) -> None:
        w, _events = _worker_with_executor(self.ex)
        result = w._dispatch("rotate_proxy", {}, 1)
        self.assertTrue(result["ok"])
        self.assertEqual(result["proxy"], "direct")
        self.assertNotEqual(result["reason"], "")

    def test_tool_schema_registered_for_worker(self) -> None:
        # worker 实际下发的是 TOOL_SCHEMAS + SESSION_TOOL_SCHEMAS（worker.py 运行轮拼接）
        from app.tools.schemas import SESSION_TOOL_SCHEMAS, TOOL_SCHEMAS

        names = [s["function"]["name"] for s in TOOL_SCHEMAS + SESSION_TOOL_SCHEMAS]
        self.assertIn("rotate_proxy", names)
        schema = next(s for s in TOOL_SCHEMAS + SESSION_TOOL_SCHEMAS if s["function"]["name"] == "rotate_proxy")
        self.assertIn("reason", schema["function"]["parameters"]["properties"])


if __name__ == "__main__":
    unittest.main()
