"""覆盖情报库有效期过滤：lookup_intel 应忽略 last_seen 超过 INTEL_MAX_AGE_SECONDS 的过时情报。

用内存 SQLite + aiosqlite 构造异步会话，插入一条新鲜、一条过时情报，断言只返回新鲜那条。
"""
import unittest
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.agents.intel import lookup_intel
from app.db.models import Base, Intel

# 与 intel.py 默认一致的 7 天有效期，便于测试可读。
_DEFAULT_TTL_DAYS = 7


class TestIntelFreshness(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.Session = async_sessionmaker(self.engine, expire_on_commit=False)

    async def asyncTearDown(self):
        await self.engine.dispose()

    async def _seed(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        async with self.Session() as s:
            s.add(Intel(
                kind="cred", match_key="example.com", dedup_hash="fresh",
                payload={"username": "u", "password": "p"}, summary="fresh cred",
                confidence="verified", last_seen=now,
            ))
            s.add(Intel(
                kind="cred", match_key="example.com", dedup_hash="stale",
                payload={"username": "v", "password": "q"}, summary="stale cred",
                confidence="verified", last_seen=now - timedelta(days=_DEFAULT_TTL_DAYS + 1),
            ))
            await s.commit()

    async def test_stale_intel_excluded(self):
        await self._seed()
        async with self.Session() as s:
            result = await lookup_intel(s, "example.com", [])
        creds = result.get("cred") or []
        self.assertEqual(len(creds), 1, creds)
        self.assertEqual(creds[0].dedup_hash, "fresh")

    async def test_fresh_intel_returned_when_within_ttl(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        async with self.Session() as s:
            s.add(Intel(
                kind="endpoint", match_key="framework_ruoyi", dedup_hash="ep",
                payload={"path": "/actuator", "vuln_type": "unauthorized_access"},
                summary="actuator exposed", confidence="likely", last_seen=now,
            ))
            await s.commit()
            result = await lookup_intel(s, root="", fingerprints=["framework_ruoyi"])
        endpoints = result.get("endpoint") or []
        self.assertEqual([e.dedup_hash for e in endpoints], ["ep"])


if __name__ == "__main__":
    unittest.main()