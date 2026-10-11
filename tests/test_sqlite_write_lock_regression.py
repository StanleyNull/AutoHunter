import asyncio
import importlib
import os
import tempfile
from pathlib import Path

import pytest
from sqlalchemy import text


@pytest.mark.asyncio
async def test_sqlite_session_does_not_force_begin_immediate(monkeypatch):
    db_dir = tempfile.mkdtemp(prefix="autohunter-db-lock-")
    db_path = str(Path(db_dir) / "autohunter.db")
    monkeypatch.setenv("DB_PATH", db_path)

    import app.db.session as session_mod
    importlib.reload(session_mod)

    assert len(session_mod.engine.sync_engine.dispatch.begin.listeners) == 0

    async with session_mod.engine.begin() as conn:
        await conn.execute(text("CREATE TABLE IF NOT EXISTS lock_test (id INTEGER PRIMARY KEY, value TEXT)"))

    async def reader():
        async with session_mod.SessionLocal() as session:
            await session.execute(text("SELECT * FROM lock_test"))
            await asyncio.sleep(0.2)

    async def writer():
        async with session_mod.SessionLocal() as session:
            await session.execute(text("INSERT INTO lock_test (value) VALUES (:value)"), {"value": "ok"})
            await session.commit()
            return "inserted"

    await asyncio.gather(reader(), writer())
