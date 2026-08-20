"""性能/健壮性加固回归测试（对应 8 项排查里已修复的部分）。

覆盖：
- #2C  edu_ip._lookup_ip 加 lru_cache（含 None 结果缓存）
- #2AB findings 列表 compact + 分页（默认全量全字段，向后兼容；搜索仍覆盖重字段）
- #3   executor 持久 http client 复用 + kill_processes 关闭
- #6   history.compact_messages 越窗摘要缓存复用、内部字段不泄漏
- #7   executor._write_log 节流校准扫描 + 防撞盘语义（捕获 shell 直落文件）
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ---------- #6 compact_messages 摘要缓存 ----------
def test_compact_messages_caches_summary(monkeypatch):
    from app.agents import history
    from app.config import worker_config

    calls = {"n": 0}
    real = history.summarize_tool_content

    def spy(content, tool):
        calls["n"] += 1
        return real(content, tool)

    monkeypatch.setattr(history, "summarize_tool_content", spy)
    window = worker_config.history_full_tool_rounds
    msgs = [{"role": "tool", "tool_call_id": "a",
             "content": "BODY" + "x" * 6000, "_round": 0, "_tool": "run_shell"}]
    cur = window + 3
    out1 = history.compact_messages(msgs, cur)
    out2 = history.compact_messages(msgs, cur + 1)
    assert calls["n"] == 1, "越窗 tool 消息应只摘要一次并缓存复用（消除 O(rounds²)）"
    assert out1[0]["content"] == out2[0]["content"]
    # 内部字段绝不泄漏进发给 LLM 的 clean 副本
    assert "_summary" not in out1[0]
    assert "_round" not in out1[0] and "_tool" not in out1[0]
    # 缓存写在原始消息上，跨轮复用；越窗后原始大 body 也替换成摘要以释放内存
    assert msgs[0].get("_summary")
    assert msgs[0]["content"] == msgs[0]["_summary"]
    assert len(msgs[0]["content"]) < 6000


def test_compact_messages_not_windowed_unchanged():
    from app.agents import history
    from app.config import worker_config

    window = worker_config.history_full_tool_rounds
    msgs = [{"role": "tool", "tool_call_id": "a", "content": "FULLBODY",
             "_round": 5, "_tool": "x"}]
    out = history.compact_messages(msgs, 5 + window - 1)  # 未越窗
    assert out[0]["content"] == "FULLBODY"
    assert "_summary" not in msgs[0]


# ---------- #2C _lookup_ip lru_cache ----------
def test_lookup_ip_is_cached():
    from app.tools import edu_ip

    edu_ip._lookup_ip_cached.cache_clear()
    edu_ip._lookup_ip("202.115.32.1")
    before = edu_ip._lookup_ip_cached.cache_info()
    edu_ip._lookup_ip("202.115.32.1")
    after = edu_ip._lookup_ip_cached.cache_info()
    assert after.hits == before.hits + 1, "同一 IP 第二次应命中缓存，不再查 sqlite"

    edu_ip._lookup_ip_cached.cache_clear()
    edu_ip._lookup_ip("0.0.0.0")
    edu_ip._lookup_ip("0.0.0.0")
    assert edu_ip._lookup_ip_cached.cache_info().hits >= 1, "确定性查询 None 结果也应缓存"


def test_lookup_ip_transient_db_unavailable_not_cached(monkeypatch):
    """DB 瞬态不可用（卷 late-mount/首连失败）返回的 None 不能被缓存，
    否则 DB 恢复后该 IP 永久查不到归属、无法自愈（回归防护）。"""
    from app.tools import edu_ip

    edu_ip._lookup_ip_cached.cache_clear()
    monkeypatch.setattr(edu_ip, "_get_conn", lambda: None)  # 模拟 DB 暂不可用
    assert edu_ip._lookup_ip("202.115.32.1") is None
    assert edu_ip._lookup_ip_cached.cache_info().currsize == 0, "conn 为 None 时绝不写入缓存"


# ---------- #3 executor 持久 http client ----------
def test_executor_reuses_and_closes_http_client():
    from app.tools.executor import ToolExecutor

    with tempfile.TemporaryDirectory() as d:
        e = ToolExecutor("http://target.example", work_dir=d)
        c1 = e._get_http_client()
        c2 = e._get_http_client()
        assert c1 is c2, "同一 executor 应复用同一 client（连接池，免重复 TCP+TLS）"
        e.close_http_client()
        assert e._client is None
        c3 = e._get_http_client()
        assert c3 is not c1, "关闭后应重建新 client"
        e.close_http_client()


def test_kill_processes_closes_http_client():
    from app.tools.executor import ToolExecutor

    with tempfile.TemporaryDirectory() as d:
        e = ToolExecutor("http://target.example", work_dir=d)
        e._get_http_client()
        assert e._client is not None
        e.kill_processes()  # worker 正常完成清理
        assert e._client is None, "kill_processes 应释放持久 client"


# ---------- #7 _write_log 节流校准 + 防撞盘语义 ----------
def test_write_log_soft_limit_stops(monkeypatch):
    from app.tools import executor as ex

    monkeypatch.setattr(ex, "_WORKDIR_MAX_BYTES", 1000)
    monkeypatch.setattr(ex, "_WORKDIR_RESCAN_EVERY", 4)
    with tempfile.TemporaryDirectory() as d:
        e = ex.ToolExecutor("http://t", work_dir=d)
        results = [e._write_log("x" * 300) for _ in range(12)]
        assert results[0] is not None, "上限前应正常落盘"
        assert None in results, "累计超上限后应停止落盘（软上限）"


def test_write_log_counts_shell_written_files(monkeypatch):
    """防撞盘语义护栏：shell 子进程直落 work_dir 的大文件必须在校准时被计入，
    这正是不能用纯计数器（只统计 _write_log 自身写入）的原因。"""
    from app.tools import executor as ex

    monkeypatch.setattr(ex, "_WORKDIR_MAX_BYTES", 5000)
    monkeypatch.setattr(ex, "_WORKDIR_RESCAN_EVERY", 4)
    with tempfile.TemporaryDirectory() as d:
        e = ex.ToolExecutor("http://t", work_dir=d)
        # 自身写入很小（8*100=800 < 5000，单看自身计数永不触限）……
        # 但 shell 子进程直落一个超限大文件到真正的 work_dir（不经过 _write_log）
        (e.work_dir / "downloaded.bin").write_bytes(b"y" * 6000)
        results = [e._write_log("z" * 100) for _ in range(8)]
        assert None in results, "全目录校准应捕获 shell 直落的大文件并停止落盘"


# ---------- #2AB findings 列表 compact + 分页 ----------
class FindingsPaginationTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from app.db.models import Base, Task, Target, Finding, Review
        from sqlalchemy.ext.asyncio import (
            AsyncSession, async_sessionmaker, create_async_engine,
        )

        self.tmp = tempfile.TemporaryDirectory()
        db = Path(self.tmp.name) / "t.db"
        self.engine = create_async_engine(f"sqlite+aiosqlite:///{db}", future=True)
        self.SL = async_sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.tid = "t" * 32
        async with self.SL() as s:
            s.add(Task(id=self.tid, name="pg", status="running"))
            s.add(Target(id="g" * 32, task_id=self.tid, url="http://x",
                         host="x", status="scanning"))
            for i in range(3):
                fid = f"f{i}".ljust(32, "0")
                s.add(Finding(
                    id=fid, task_id=self.tid, target_id="g" * 32, vuln_type="rce",
                    title=f"T{i}", severity_claimed="high", target_url="http://x",
                    owner="w", status="reviewed", raw_request="NEEDLEHAYSTACK",
                ))
                s.add(Review(finding_id=fid, task_id=self.tid, verdict="accepted",
                             confidence="likely", user_status="pending", score=float(i)))
            await s.commit()

    async def asyncTearDown(self):
        await self.engine.dispose()
        self.tmp.cleanup()

    async def test_default_is_bare_list_full_fields(self):
        import app.api.findings as fa
        async with self.SL() as s:
            out = await fa.user_review_queue(self.tid, search=None, compact=False,
                                             limit=0, offset=0, session=s)
        self.assertIsInstance(out, list)
        self.assertEqual(len(out), 3)
        self.assertIn("raw_request", out[0])  # 默认全字段，向后兼容

    async def test_compact_drops_heavy_fields(self):
        import app.api.findings as fa
        async with self.SL() as s:
            out = await fa.user_review_queue(self.tid, search=None, compact=True,
                                             limit=0, offset=0, session=s)
        self.assertIsInstance(out, list)
        self.assertNotIn("raw_request", out[0])

    async def test_pagination_envelope(self):
        import app.api.findings as fa
        async with self.SL() as s:
            out = await fa.user_review_queue(self.tid, search=None, compact=False,
                                             limit=2, offset=0, session=s)
        self.assertIsInstance(out, dict)
        self.assertEqual(len(out["items"]), 2)
        self.assertTrue(out["has_more"])
        self.assertEqual(out["limit"], 2)

    async def test_search_covers_heavy_fields_when_not_compact(self):
        import app.api.findings as fa
        async with self.SL() as s:
            out = await fa.user_review_queue(self.tid, search="needlehaystack",
                                             compact=False, limit=0, offset=0, session=s)
        self.assertEqual(len(out), 3)  # 默认非 compact，搜索仍能命中 raw_request 内容
