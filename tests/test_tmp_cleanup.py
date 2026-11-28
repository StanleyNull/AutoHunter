"""容器内 /tmp 自动清理：按天数回收 + 总量上限兜底。"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from app.tmp_cleanup import cleanup_tmp, get_tmp_stats

_DAY = 86400


class TmpCleanupTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="ah-tmp-test-"))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    # ---------- helpers ----------
    def _make(self, name: str, size: int, age_seconds: float) -> Path:
        p = self.root / name
        if name.endswith("/"):
            p.mkdir(parents=True, exist_ok=True)
            f = p / "payload.bin"
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            f = p
        f.write_bytes(b"x" * size)
        ts = time.time() - age_seconds
        os.utime(f, (ts, ts))
        try:
            os.utime(p, (ts, ts))
        except OSError:
            pass
        return p

    # ---------- 按天数清理 ----------
    def test_deletes_entry_older_than_retention(self):
        self._make("old.apk", 1024, age_seconds=3 * _DAY)
        result = cleanup_tmp(retention_days=1, max_bytes=0, root=self.root)
        self.assertEqual(result["deleted_entries"], 1)
        self.assertGreater(result["freed_bytes"], 0)
        self.assertFalse((self.root / "old.apk").exists())

    def test_keeps_entry_within_retention(self):
        self._make("fresh.apk", 1024, age_seconds=2 * 3600)
        result = cleanup_tmp(retention_days=1, max_bytes=0, root=self.root)
        self.assertEqual(result["deleted_entries"], 0)
        self.assertTrue((self.root / "fresh.apk").exists())

    def test_keeps_entry_inside_min_idle_window_even_if_past_retention(self):
        # 刚写入 60 秒：即使 retention=0（纯上限模式）也必须保住，避免删掉正在下载的包
        self._make("downloading.apk", 1024, age_seconds=60)
        result = cleanup_tmp(retention_days=0, max_bytes=1, root=self.root)
        self.assertEqual(result["deleted_entries"], 0)
        self.assertEqual(result["skipped_recent"], 1)
        self.assertTrue((self.root / "downloading.apk").exists())

    def test_dry_run_does_not_delete(self):
        self._make("old.apk", 1024, age_seconds=3 * _DAY)
        result = cleanup_tmp(retention_days=1, max_bytes=0, dry_run=True, root=self.root)
        self.assertEqual(result["deleted_entries"], 1)
        self.assertTrue((self.root / "old.apk").exists())

    # ---------- 总量上限兜底 ----------
    def test_size_cap_deletes_oldest_first(self):
        # 三个都在保留期内（不会被按天数删），但总量超上限 → 按最旧优先删
        self._make("a_oldest.bin", 400, age_seconds=10 * 3600)
        self._make("b_middle.bin", 400, age_seconds=6 * 3600)
        self._make("c_newest.bin", 400, age_seconds=2 * 3600)
        result = cleanup_tmp(retention_days=7, max_bytes=500, root=self.root)
        self.assertTrue(result["deleted_entries"] >= 1)
        self.assertFalse((self.root / "a_oldest.bin").exists())
        self.assertLessEqual(result["size_after_bytes"], 500)

    def test_size_cap_noop_when_under_limit(self):
        self._make("a.bin", 100, age_seconds=10 * 3600)
        result = cleanup_tmp(retention_days=7, max_bytes=10 ** 9, root=self.root)
        self.assertEqual(result["deleted_entries"], 0)
        self.assertTrue((self.root / "a.bin").exists())

    # ---------- 安全边界 ----------
    def test_skips_protected_names(self):
        self._make("systemd-private-abc/tmp/x.bin", 512, age_seconds=5 * _DAY)
        result = cleanup_tmp(retention_days=1, max_bytes=0, root=self.root)
        self.assertTrue((self.root / "systemd-private-abc").exists())

    def test_skips_symlinks(self):
        outside = Path(tempfile.mkdtemp(prefix="ah-outside-"))
        try:
            victim = outside / "keep.txt"
            victim.write_text("keep", encoding="utf-8")
            os.utime(victim, (time.time() - 5 * _DAY,) * 2)
            link = self.root / "link-to-outside"
            try:
                link.symlink_to(victim)
            except (OSError, NotImplementedError):
                self.skipTest("当前环境不支持创建符号链接")
            cleanup_tmp(retention_days=1, max_bytes=0, root=self.root)
            self.assertTrue(victim.exists(), "符号链接指向的外部文件不能被删")
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_disabled_when_both_limits_zero(self):
        self._make("old.apk", 1024, age_seconds=30 * _DAY)
        result = cleanup_tmp(retention_days=0, max_bytes=0, root=self.root)
        self.assertEqual(result["deleted_entries"], 0)
        self.assertEqual(result["reason"], "disabled")
        self.assertTrue((self.root / "old.apk").exists())

    def test_missing_root_is_handled(self):
        result = cleanup_tmp(retention_days=1, max_bytes=0,
                             root=self.root / "does-not-exist")
        self.assertEqual(result["deleted_entries"], 0)
        self.assertEqual(result["reason"], "no_tmp_root")

    # ---------- 统计 ----------
    def test_stats_counts_and_deletable(self):
        self._make("old.apk", 2048, age_seconds=3 * _DAY)
        self._make("fresh.apk", 1024, age_seconds=3600)
        stats = get_tmp_stats(root=self.root)
        self.assertEqual(stats["entries"], 2)
        self.assertEqual(stats["total_size_bytes"], 3072)
        self.assertEqual(stats["deletable_entries"], 1)
        self.assertEqual(stats["deletable_size_bytes"], 2048)

    def test_directory_entry_is_removed_recursively(self):
        self._make("jsdump/", 700, age_seconds=4 * _DAY)
        result = cleanup_tmp(retention_days=1, max_bytes=0, root=self.root)
        self.assertEqual(result["deleted_entries"], 1)
        self.assertFalse((self.root / "jsdump").exists())


if __name__ == "__main__":
    unittest.main()
