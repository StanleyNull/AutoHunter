"""覆盖 _HTTP_MAX_BYTES 常量及响应截断逻辑。

历史背景：_read_limited_response 曾引用 _HTTP_MAX_BYTES 但全库无定义，走到截断分支会抛 NameError。
本用例断言该常量已定义，并验证大响应被截断、小响应原样放行。
"""
import unittest

import httpx

from app.tools.executor import ToolExecutor, _HTTP_MAX_BYTES


class TestHttpResponseLimit(unittest.TestCase):
    def test_limit_constant_defined_and_positive(self):
        self.assertIsInstance(_HTTP_MAX_BYTES, int)
        self.assertGreater(_HTTP_MAX_BYTES, 0)

    def test_large_response_truncated(self):
        big = b"x" * (_HTTP_MAX_BYTES * 2)
        resp = httpx.Response(200, content=big, headers={"Content-Type": "text/plain"})
        body, truncated = ToolExecutor._read_limited_response(resp)
        self.assertTrue(truncated)
        self.assertLessEqual(len(body), _HTTP_MAX_BYTES + 200)

    def test_small_response_passes_through(self):
        resp = httpx.Response(200, content=b"hello", headers={"Content-Type": "text/plain"})
        body, truncated = ToolExecutor._read_limited_response(resp)
        self.assertFalse(truncated)
        self.assertIn("hello", body)


if __name__ == "__main__":
    unittest.main()