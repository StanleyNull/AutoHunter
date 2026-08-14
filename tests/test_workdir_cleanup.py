import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from app.config import worker_config
from app.workdir_cleanup import (
    PROTECTED_DIR_NAMES,
    cleanup_workdir,
    get_workdir_stats,
)


class WorkdirCleanupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ah-work-")
        self._old_root = worker_config.work_root
        self._old_days = worker_config.work_retention_days
        worker_config.work_root = self.tmp
        worker_config.work_retention_days = 7

    def tearDown(self):
        worker_config.work_root = self._old_root
        worker_config.work_retention_days = self._old_days
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _age(self, path: Path, days: float) -> None:
        ts = time.time() - days * 86400
        os.utime(path, (ts, ts))
        if path.is_dir():
            for child in path.rglob("*"):
                os.utime(child, (ts, ts))

    def test_retention_zero_deletes_nothing(self):
        d = Path(self.tmp) / "old_target"
        d.mkdir()
        (d / "log.txt").write_text("x")
        self._age(d, 30)
        result = cleanup_workdir(retention_days=0, dry_run=False)
        self.assertEqual(result["deleted_dirs"], 0)
        self.assertTrue(d.exists())

    def test_dry_run_does_not_delete(self):
        d = Path(self.tmp) / "stale_target"
        d.mkdir()
        (d / "log.txt").write_text("old")
        self._age(d, 10)
        result = cleanup_workdir(retention_days=7, dry_run=True)
        self.assertEqual(result["deleted_dirs"], 1)
        self.assertTrue(d.exists())

    def test_deletes_stale_target_dir(self):
        d = Path(self.tmp) / "stale_target"
        d.mkdir()
        (d / "log.txt").write_text("old")
        self._age(d, 10)
        result = cleanup_workdir(retention_days=7, dry_run=False)
        self.assertEqual(result["deleted_dirs"], 1)
        self.assertFalse(d.exists())

    def test_recent_file_activity_skips_even_if_dir_looks_old(self):
        d = Path(self.tmp) / "live_target"
        d.mkdir()
        log = d / "log.txt"
        log.write_text("old")
        self._age(d, 10)
        log.write_text("still running")
        os.utime(log, None)
        result = cleanup_workdir(retention_days=7, dry_run=False)
        self.assertEqual(result["deleted_dirs"], 0)
        self.assertTrue(d.exists())

    def test_protected_dirs_are_kept(self):
        for name in PROTECTED_DIR_NAMES:
            d = Path(self.tmp) / name
            d.mkdir()
            (d / "keep").write_text("x")
            self._age(d, 30)
        result = cleanup_workdir(retention_days=7, dry_run=False)
        self.assertEqual(result["deleted_dirs"], 0)
        for name in PROTECTED_DIR_NAMES:
            self.assertTrue((Path(self.tmp) / name).exists())

    def test_stats_counts_target_dirs(self):
        (Path(self.tmp) / "a").mkdir()
        (Path(self.tmp) / "b").mkdir()
        (Path(self.tmp) / "node_modules").mkdir()
        stats = get_workdir_stats()
        self.assertEqual(stats["total_dirs"], 2)
        self.assertTrue(stats["auto_cleanup_enabled"])


if __name__ == "__main__":
    unittest.main()
