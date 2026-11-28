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
        self.assertEqual(_auto_worker_base_from(8, 2.0), 5)

    def test_4c4g_not_over_constrained_by_memory(self):
        # 4C/3.6G 是常见云主机规格：按 250MB/槽位算 by_mem=14，最终由 CPU 档 12 收口。
        # 早期按 500MB/槽位会把这里压到 7，实测同规格跑 18~20 路时 load 仍低于 1。
        self.assertEqual(_auto_worker_base_from(4, 3.6), 12)

    def test_memory_no_longer_dominates_normal_box(self):
        # 8C/8G：by_mem=32 时不应再成为瓶颈，应跟 CPU 档 20 走。
        self.assertEqual(_auto_worker_base_from(8, 8.0), 20)

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
