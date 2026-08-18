"""自动并发档：按机器规格缩放，覆盖 1C1G 到大机器。"""
from __future__ import annotations

import unittest

from app.agent_runtime import _auto_worker_base_from


class AutoWorkerBaseTests(unittest.TestCase):
    def test_tiny_1c1g(self):
        self.assertEqual(_auto_worker_base_from(1, 1.0), 3)

    def test_2c4g(self):
        self.assertEqual(_auto_worker_base_from(2, 4.0), 8)

    def test_4c8g(self):
        self.assertEqual(_auto_worker_base_from(4, 8.0), 12)

    def test_8c16g(self):
        self.assertEqual(_auto_worker_base_from(8, 16.0), 20)

    def test_16c32g(self):
        self.assertEqual(_auto_worker_base_from(16, 32.0), 24)

    def test_big_box_caps_at_32(self):
        self.assertEqual(_auto_worker_base_from(28, 62.0), 32)
        self.assertEqual(_auto_worker_base_from(64, 256.0), 32)

    def test_memory_bound_small_ram(self):
        self.assertEqual(_auto_worker_base_from(8, 2.0), 4)

    def test_unknown_memory_uses_cpu_only(self):
        self.assertEqual(_auto_worker_base_from(4, 0), 12)

    def test_fractional_cpu_quota(self):
        self.assertEqual(_auto_worker_base_from(1.5, 4.0), 8)

    def test_agent_pool_keeps_four_slot_buffer(self):
        from app.agent_runtime import (
            AGENT_THREAD_POOL_SIZE,
            ASSISTANT_MAX_CONCURRENCY,
            ESCALATION_MAX_CONCURRENCY,
            KILLSWEEP_MAX_CONCURRENCY,
            REVIEW_MAX_CONCURRENCY,
            WORKER_MAX_CONCURRENCY,
        )
        total = (
            WORKER_MAX_CONCURRENCY
            + REVIEW_MAX_CONCURRENCY
            + KILLSWEEP_MAX_CONCURRENCY
            + ESCALATION_MAX_CONCURRENCY
            + ASSISTANT_MAX_CONCURRENCY
        )
        self.assertGreaterEqual(AGENT_THREAD_POOL_SIZE, total + 4)


if __name__ == "__main__":
    unittest.main()
