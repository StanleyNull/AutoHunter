"""通杀列：失败可重启，不必把复审改回 pending。"""
from __future__ import annotations

import unittest

from app.killsweep_status import killsweep_retryable


class KillsweepRetryableTests(unittest.TestCase):
    def test_failed_and_cancelled_can_retry(self):
        self.assertTrue(killsweep_retryable("failed", False))
        self.assertTrue(killsweep_retryable("cancelled", False))
        self.assertTrue(killsweep_retryable("analyzing", False))

    def test_no_sites_done_can_retry(self):
        self.assertTrue(killsweep_retryable("done", False))

    def test_hit_or_invalid_cannot_retry(self):
        self.assertFalse(killsweep_retryable("done", True))
        self.assertFalse(killsweep_retryable("invalid", True))
        self.assertFalse(killsweep_retryable("invalid", False))


if __name__ == "__main__":
    unittest.main()
