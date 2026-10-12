"""备份响应的临时文件生命周期；实际生成并传输归档。"""
from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from starlette.requests import Request

from app.api import backup as backup_api


class FrozenDatetime:
    @classmethod
    def now(cls):
        return datetime(2026, 9, 30, 12, 0, 0)


class BackupDownloadTests(unittest.IsolatedAsyncioTestCase):
    async def test_same_second_downloads_remain_independent_until_sent(self):
        with tempfile.TemporaryDirectory() as tmp:
            live = Path(tmp) / "live.db"
            with sqlite3.connect(live) as con:
                con.execute("CREATE TABLE fixture (value TEXT)")
                con.execute("INSERT INTO fixture VALUES ('backup-fixture')")
            scope = {"type": "http", "method": "POST", "path": "/api/backup/export", "headers": []}
            with patch.dict(os.environ, {
                "DB_PATH": str(live), "AUTOHUNTER_BACKUP_RESERVE_MB": "0",
                "AUTOHUNTER_API_TOKEN": "", "AUTOHUNTER_READ_TOKEN": "", "AUTOHUNTER_OBSERVER_TOKEN": "",
            }), patch.object(backup_api, "datetime", FrozenDatetime):
                first = backup_api.export_backup(Request(scope), include_work=False)
                second = backup_api.export_backup(Request(scope), include_work=False)
                first_body, second_body = [], []

                async def receive():
                    return {"type": "http.request", "body": b"", "more_body": False}

                async def send_first(message):
                    if message["type"] == "http.response.body":
                        first_body.append(message["body"])

                async def send_second(message):
                    if message["type"] == "http.response.body":
                        second_body.append(message["body"])

                await first(scope, receive, send_first)
                await second(scope, receive, send_second)
                self.assertTrue(b"".join(first_body))
                self.assertTrue(b"".join(second_body))
                self.assertFalse(Path(first.path).exists())
                self.assertFalse(Path(second.path).exists())
