"""覆盖通杀闭环：_enqueue_killsweep_affected 批量派发已实证受影响站点入队打洞。

规则：只入队 status=verified 的行；跳过 origin 自身、无效/敏感主机、重复 host；
candidate 不入队；受 KILLSWEEP_REPLAY_ENQUEUE_LIMIT 上限约束。
"""
import unittest

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.models import Base, Target
from app.orchestrator import TaskRunner

ORIGIN = "https://https.test.school.edu.cn"
_ORIGIN_HOST = "https.test.school.edu.cn"


class TestKillsweepClosedLoop(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.Session = async_sessionmaker(self.engine, expire_on_commit=False)

    async def asyncTearDown(self):
        await self.engine.dispose()

    async def _hosts(self, task_id: str) -> set:
        async with self.Session() as s:
            rows = (await s.execute(
                select(Target.host).where(Target.task_id == task_id)
            )).scalars().all()
        return set(rows)

    @staticmethod
    def _runner():
        # 用一个不触发 __init__ 的空壳实例绑定目标方法，仅供单测调用。
        runner = object.__new__(TaskRunner)
        runner._enqueue_killsweep_target = TaskRunner._enqueue_killsweep_target.__get__(runner, TaskRunner)
        return runner

    async def test_verified_dispatched_candidate_and_origin_skipped(self):
        table = [
            {"url": "http://a.school.edu.cn", "status": "verified"},
            {"url": "http://b.school.edu.cn", "status": "verified"},
            {"url": "http://c.school.edu.cn", "status": "candidate"},  # 不入队
            {"url": ORIGIN, "status": "verified"},                     # 源站自身，跳过
            {"url": "http://a.school.edu.cn", "status": "verified"},   # 重复 host，跳过
        ]
        async with self.Session() as s:
            count = await self._runner()._enqueue_killsweep_affected(
                s, "task_t1", table, ORIGIN)
            await s.commit()
        self.assertEqual(count, 2)
        self.assertEqual(await self._hosts("task_t1"), {"a.school.edu.cn", "b.school.edu.cn"})

    async def test_empty_table_returns_zero(self):
        async with self.Session() as s:
            count = await self._runner()._enqueue_killsweep_affected(
                s, "task_t2", [], ORIGIN)
        self.assertEqual(count, 0)
        self.assertEqual(await self._hosts("task_t2"), set())


if __name__ == "__main__":
    unittest.main()