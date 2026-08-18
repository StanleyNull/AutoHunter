import io
import json
import os
import sqlite3
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import backup as bak
from app.waf import inspect_request


def _make_db(path: Path, marker: str = "hello") -> None:
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("DROP TABLE IF EXISTS items")
        conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, note TEXT)")
        conn.execute("INSERT INTO items(note) VALUES (?)", (marker,))
        conn.commit()
    finally:
        conn.close()


def _read_note(path: Path) -> str:
    conn = sqlite3.connect(str(path))
    try:
        return conn.execute("SELECT note FROM items").fetchone()[0]
    finally:
        conn.close()


class _FakeRequest:
    def __init__(self, path: str, method: str = "POST", content_length: int = 0):
        self.url = type("U", (), {"path": path, "query": ""})()
        self.method = method
        self.headers = {"content-length": str(content_length), "user-agent": "Mozilla/5.0"}
        self.client = type("C", (), {"host": "127.0.0.1"})()


class BackupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ah-backup-test-"))
        self.live = self.tmp / "autohunter.db"
        self.work = self.tmp / "work"
        self.work.mkdir()
        _make_db(self.live, "v1")
        (self.work / "keep.txt").write_text("work-data")
        self._db_patch = patch("app.backup.db_path", lambda: self.live)
        self._dir_patch = patch("app.backup.backups_dir", lambda: self.tmp / "backups")
        self._work_patch = patch("app.backup._safe_work_root", lambda: self.work)
        self._db_patch.start()
        self._dir_patch.start()
        self._work_patch.start()

    def tearDown(self):
        self._db_patch.stop()
        self._dir_patch.stop()
        self._work_patch.stop()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_snapshot_is_consistent_copy(self):
        dest = self.tmp / "snap.db"
        bak.snapshot_sqlite(self.live, dest)
        self.assertTrue(dest.is_file())
        self.assertEqual(_read_note(dest), "v1")
        ok, msg = bak.integrity_check(dest)
        self.assertTrue(ok, msg)

    def test_integrity_check_rejects_truncated(self):
        dest = self.tmp / "bad.db"
        dest.write_bytes(b"SQLite format 3\x00not-a-db")
        ok, msg = bak.integrity_check(dest)
        self.assertFalse(ok)
        self.assertTrue(msg)

    def test_archive_roundtrip_db_only(self):
        archive = self.tmp / "bak.tar.gz"
        meta = bak.create_archive(archive, include_work=False)
        self.assertEqual(meta["magic"], bak.MAGIC)
        self.assertFalse(meta["include_work"])
        self.assertTrue(archive.is_file())

        _make_db(self.live, "v2-live-changed")
        (self.work / "keep.txt").write_text("changed-work")
        result = bak.restore_archive(archive, include_work=False, live_db=self.live, work_root=self.work)
        self.assertTrue(result["ok"])
        self.assertEqual(_read_note(self.live), "v1")
        self.assertEqual((self.work / "keep.txt").read_text(), "changed-work")

    def test_archive_roundtrip_with_work(self):
        nested = self.work / "target-a"
        nested.mkdir()
        (nested / "log.txt").write_text("poc")
        archive = self.tmp / "full.tar.gz"
        bak.create_archive(archive, include_work=True)

        (nested / "log.txt").write_text("wiped")
        _make_db(self.live, "other")
        bak.restore_archive(archive, include_work=True, live_db=self.live, work_root=self.work)
        self.assertEqual(_read_note(self.live), "v1")
        self.assertEqual((nested / "log.txt").read_text(), "poc")

    def test_restore_rejects_path_traversal(self):
        archive = self.tmp / "evil.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            manifest = json.dumps({
                "magic": bak.MAGIC, "version": bak.FORMAT_VERSION,
                "created_at": "now", "include_work": True,
                "db_bytes": 1, "work_bytes": 1, "integrity": "ok",
            }).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size = len(manifest)
            tar.addfile(info, io.BytesIO(manifest))
            db_bytes = self.live.read_bytes()
            dinfo = tarfile.TarInfo("db/autohunter.db")
            dinfo.size = len(db_bytes)
            tar.addfile(dinfo, io.BytesIO(db_bytes))
            payload = b"pwned"
            evil = tarfile.TarInfo("work/../../outside.txt")
            evil.size = len(payload)
            tar.addfile(evil, io.BytesIO(payload))
        with self.assertRaises(ValueError):
            bak.restore_archive(archive, include_work=True, live_db=self.live, work_root=self.work)
        self.assertFalse((self.tmp / "outside.txt").exists())

    def test_restore_rejects_wrong_magic(self):
        archive = self.tmp / "nope.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            payload = json.dumps({"magic": "other", "version": 1}).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        with self.assertRaises(ValueError) as ctx:
            bak.inspect_archive(archive)
        self.assertIn("AutoHunter", str(ctx.exception))

    def test_snapshot_rotation_keeps_n(self):
        with patch("app.backup.backup_keep", lambda: 2):
            a = bak.snapshot_now()
            b = bak.snapshot_now()
            c = bak.snapshot_now()
        names = {p["name"] for p in bak.list_snapshots()}
        self.assertIn(c["name"], names)
        self.assertIn(b["name"], names)
        self.assertNotIn(a["name"], names)
        self.assertEqual(len(names), 2)

    def test_snapshot_file_rejects_traversal(self):
        with self.assertRaises(ValueError):
            bak.snapshot_file("../autohunter.db")
        with self.assertRaises(ValueError):
            bak.snapshot_file("foo.txt")

    def test_create_archive_skips_protected_work_dirs(self):
        prot = self.work / "node_modules"
        prot.mkdir()
        (prot / "big.js").write_text("skip-me")
        archive = self.tmp / "skip.tar.gz"
        bak.create_archive(archive, include_work=True)
        with tarfile.open(archive, "r:gz") as tar:
            names = tar.getnames()
        self.assertFalse(any("node_modules" in n for n in names))

    def test_waf_allows_large_restore_body(self):
        huge = 500 * 1024 * 1024
        blocked = inspect_request(_FakeRequest("/api/settings", content_length=huge))
        self.assertFalse(blocked.allowed)
        self.assertEqual(blocked.reason, "body_too_large")
        allowed = inspect_request(_FakeRequest("/api/backup/restore", content_length=huge))
        self.assertTrue(allowed.allowed)


if __name__ == "__main__":
    unittest.main()
