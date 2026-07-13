"""异步数据库会话管理（SQLite + aiosqlite）。"""
from __future__ import annotations

import os
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import Base

DB_PATH = os.environ.get("DB_PATH", str(Path(__file__).resolve().parent.parent.parent / "data" / "autohunter.db"))
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"

engine = create_async_engine(
    DATABASE_URL, echo=False, future=True,
    # 默认 QueuePool 只有 pool_size=5 + max_overflow=10 = 15 条连接。
    # orchestrator 高并发时（多 worker × 心跳/落库/情报 + reviewer +
    # killsweep + escalate + API/WebSocket），同时存活的 session 远超 15，
    # 导致连接获取超时。SQLite 是文件级 DB，连接创建开销极低，可以放心调大。
    pool_size=20,
    max_overflow=40,
    pool_timeout=60,
)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# 每条物理连接建立时统一设置 PRAGMA（init_db 的一次性 PRAGMA 只作用于建库那条连接，
# aiosqlite 连接池里后续每条新连接都需要重新设，否则 busy_timeout 默认为 0、
# 一遇写锁立刻 SQLITE_BUSY）。24x7 下 orchestrator 写事件 + N 个 heartbeat +
# API 读 + worker 落库高并发，这几项是缓解锁竞争性价比最高的优化。
_CONNECT_PRAGMAS = (
    "PRAGMA busy_timeout=5000;",          # 写锁最多等 5s 再报错，吸收瞬时竞争
    "PRAGMA synchronous=NORMAL;",         # WAL 下安全，显著降低写延迟
    "PRAGMA foreign_keys=ON;",
    "PRAGMA cache_size=-64000;",          # 约 64MB page cache，减少看板/列表热读扫盘
    "PRAGMA mmap_size=268435456;",        # 256MB mmap，SQLite 读多写少场景更稳
    "PRAGMA temp_store=MEMORY;",          # ORDER BY/GROUP BY 临时表走内存
    "PRAGMA wal_autocheckpoint=1000;",
)


@event.listens_for(engine.sync_engine, "connect")
def _set_sqlite_pragma(dbapi_connection, _connection_record):
    cursor = dbapi_connection.cursor()
    try:
        for pragma in _CONNECT_PRAGMAS:
            cursor.execute(pragma)
    finally:
        cursor.close()


# 轻量自动迁移：新增列时无需删库（demo 友好）
# (table, column, "TYPE DEFAULT ...")
_MIGRATIONS = [
    ("reviews", "user_status", "VARCHAR(20) DEFAULT 'pending'"),
    ("reviews", "user_severity", "VARCHAR(10)"),
    ("reviews", "user_notes", "TEXT DEFAULT ''"),
    ("reviews", "user_edits", "JSON DEFAULT '{}'"),
    ("reviews", "submitted", "BOOLEAN DEFAULT 0"),
    ("reviews", "user_reviewed_at", "DATETIME"),
    ("targets", "priority_score", "FLOAT DEFAULT 0"),
    ("targets", "priority_reason", "VARCHAR(300) DEFAULT ''"),
    ("reviews", "deepen_directive", "TEXT DEFAULT ''"),
    ("targets", "deepen_context", "JSON"),
    ("targets", "deepen_count", "INTEGER DEFAULT 0"),
    ("targets", "leaked_creds", "JSON"),
    ("targets", "dead_reason", "VARCHAR(300) DEFAULT ''"),
    ("targets", "last_error", "VARCHAR(500) DEFAULT ''"),
    ("targets", "school", "VARCHAR(200) DEFAULT ''"),
    ("findings", "owner", "VARCHAR(300) DEFAULT ''"),
    ("findings", "kill_chain", "JSON"),
    ("findings", "assistant_messages", "JSON DEFAULT '[]'"),
    ("killsweeps", "affected_table", "JSON DEFAULT '[]'"),
    ("system_settings", "engines", "JSON DEFAULT '{}'"),
    ("tasks", "engine", "VARCHAR(20) DEFAULT ''"),
]

# 唯一索引：目标库(host)/漏洞库(dedup_key)的 DB 级查重兜底。
# 名字与 models.__table_args__ 保持一致；老库表已存在不会被 create_all 补，靠这里建。
_UNIQUE_INDEXES = [
    ("ux_targets_task_host",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_targets_task_host ON targets(task_id, host, source)"),
    ("ux_findings_dedup_global",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_findings_dedup_global ON findings(dedup_key) "
     "WHERE dedup_key <> ''"),
]

# 普通索引：跨 host 查重按归一化类型别名集合做 IN 预筛时走索引，避免全表扫。
# create_all 不会给已存在的老表补索引，这里显式建。
_SECONDARY_INDEXES = [
    ("ix_findings_vuln_type_status",
     "CREATE INDEX IF NOT EXISTS ix_findings_vuln_type_status ON findings(vuln_type, status)"),
    # 派发热点：_pop_queued 按 (task_id, status='queued') 过滤 + priority_score 排序。
    ("ix_targets_task_status_priority",
     "CREATE INDEX IF NOT EXISTS ix_targets_task_status_priority "
     "ON targets(task_id, status, priority_score)"),
    ("ix_targets_task_status_priority_created",
     "CREATE INDEX IF NOT EXISTS ix_targets_task_status_priority_created "
     "ON targets(task_id, status, priority_score, created_at)"),
    # 审核派发：_dispatch_reviews 按 (task_id, status='pending_review') 取。
    ("ix_findings_task_status",
     "CREATE INDEX IF NOT EXISTS ix_findings_task_status ON findings(task_id, status)"),
    ("ix_findings_task_status_created",
     "CREATE INDEX IF NOT EXISTS ix_findings_task_status_created ON findings(task_id, status, created_at)"),
    # findings 列表/详情排序：按 (task_id, created_at DESC)。
    ("ix_findings_task_created",
     "CREATE INDEX IF NOT EXISTS ix_findings_task_created ON findings(task_id, created_at)"),
    # 看板统计 + results/submit-list/review-queue/rejected 联表过滤的核心复合索引。
    ("ix_reviews_task_verdict_user",
     "CREATE INDEX IF NOT EXISTS ix_reviews_task_verdict_user "
     "ON reviews(task_id, verdict, user_status, submitted)"),
    ("ix_reviews_task_verdict_score",
     "CREATE INDEX IF NOT EXISTS ix_reviews_task_verdict_score "
     "ON reviews(task_id, verdict, score)"),
    ("ix_reviews_task_verdict_user_score",
     "CREATE INDEX IF NOT EXISTS ix_reviews_task_verdict_user_score "
     "ON reviews(task_id, verdict, user_status, score)"),
    ("ix_reviews_task_user_submitted_score",
     "CREATE INDEX IF NOT EXISTS ix_reviews_task_user_submitted_score "
     "ON reviews(task_id, user_status, submitted, score)"),
    ("ix_reviews_task_user_reviewed_score",
     "CREATE INDEX IF NOT EXISTS ix_reviews_task_user_reviewed_score "
     "ON reviews(task_id, user_status, user_reviewed_at, score)"),
    # 全局漏洞库 /api/vulns：跨任务按 (user_status='passed', submitted) 过滤。
    ("ix_reviews_user_status_submitted",
     "CREATE INDEX IF NOT EXISTS ix_reviews_user_status_submitted "
     "ON reviews(user_status, submitted)"),
    # 全局硬骨头库：按 (status IN dead/skipped) 过滤 + updated_at DESC 排序。
    ("ix_targets_status_updated",
     "CREATE INDEX IF NOT EXISTS ix_targets_status_updated ON targets(status, updated_at)"),
    # 看板 killsweep 计数 + 列表：按 (task_id, is_killsweep)。
    ("ix_killsweeps_task_iskillsweep",
     "CREATE INDEX IF NOT EXISTS ix_killsweeps_task_iskillsweep "
     "ON killsweeps(task_id, is_killsweep)"),
    ("ix_killsweeps_task_hit_rank",
     "CREATE INDEX IF NOT EXISTS ix_killsweeps_task_hit_rank "
     "ON killsweeps(task_id, is_killsweep, verified, asset_count, created_at)"),
    # 运行异常日志：按 level/agent 过滤 + ts DESC 排序。
    ("ix_task_events_level_ts",
     "CREATE INDEX IF NOT EXISTS ix_task_events_level_ts ON task_events(level, ts)"),
    # 看板历史回放：WHERE task_id=? ORDER BY id DESC LIMIT N。
    ("ix_task_events_task_id_id",
     "CREATE INDEX IF NOT EXISTS ix_task_events_task_id_id ON task_events(task_id, id)"),
]

# 废弃的残留列：老 schema 里是 NOT NULL 无默认值，新代码不再写入会导致 INSERT 失败。
# SQLite 不支持 DROP COLUMN/ALTER COLUMN（旧版），用"给残留列补默认值"的方式重建表。
# (table, [废弃列名])
_DROP_COLUMNS = [
    ("reviews", ["user_decision"]),
]


async def init_db() -> None:
    async with engine.begin() as conn:
        # SQLite 并发：开启 WAL，提升 24x7 读写并发能力
        await conn.exec_driver_sql("PRAGMA journal_mode=WAL;")
        await conn.run_sync(Base.metadata.create_all)
        await _auto_migrate(conn)
        await _ensure_unique_indexes(conn)
        await _ensure_secondary_indexes(conn)


async def _ensure_unique_indexes(conn) -> None:
    """为老库补建唯一索引（查重 DB 级兜底）。
    若历史数据已有重复导致唯一索引建不上，降级为普通索引——保数据不丢，
    新数据仍由应用层 dedup 拦截。"""
    # targets 去重索引从「同任务 host 唯一」升级为「同任务 host+source 唯一」。
    # 单站协作需要同一真实 host 以不同 source(路线) 并行入队；普通 fofa/manual
    # 仍然 source 相同，继续由 DB 兜底去重。
    rows = await conn.exec_driver_sql(
        "SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='targets'"
    )
    target_indexes = {r[0]: (r[1] or "") for r in rows.fetchall()}
    target_unique_sql = target_indexes.get("ux_targets_task_host", "")
    target_shape = target_unique_sql.replace("\n", " ").lower()
    if target_unique_sql and "source" not in target_shape:
        try:
            await conn.exec_driver_sql("DROP INDEX IF EXISTS ux_targets_task_host")
        except Exception:
            pass

    # findings 去重索引从「(task_id, dedup_key)」升级为「(dedup_key) 全局唯一」。
    # 老库若已有旧索引，先删后建，确保跨任务查重真正由 DB 兜底。
    rows = await conn.exec_driver_sql(
        "SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='findings'"
    )
    indexes = {r[0]: (r[1] or "") for r in rows.fetchall()}
    old_sql = indexes.get("ux_findings_task_dedup", "")
    new_sql = indexes.get("ux_findings_dedup_global", "")
    wants_old_shape = "task_id, dedup_key" in old_sql.replace("\n", " ")
    wants_new_shape = "ON findings(dedup_key)" in new_sql.replace("\n", " ")
    if wants_old_shape or (new_sql and not wants_new_shape):
        try:
            await conn.exec_driver_sql("DROP INDEX IF EXISTS ux_findings_task_dedup")
        except Exception:
            pass
        try:
            await conn.exec_driver_sql("DROP INDEX IF EXISTS ux_findings_dedup_global")
        except Exception:
            pass

    for name, sql in _UNIQUE_INDEXES:
        try:
            await conn.exec_driver_sql(sql)
        except Exception:
            try:
                await conn.exec_driver_sql(sql.replace("UNIQUE INDEX", "INDEX"))
            except Exception:
                pass


async def _ensure_secondary_indexes(conn) -> None:
    """为老库补建普通查询索引（性能优化，失败不阻断启动）。"""
    for _name, sql in _SECONDARY_INDEXES:
        try:
            await conn.exec_driver_sql(sql)
        except Exception:
            pass


async def _auto_migrate(conn) -> None:
    for table, col, decl in _MIGRATIONS:
        rows = await conn.exec_driver_sql(f"PRAGMA table_info({table})")
        existing = {r[1] for r in rows.fetchall()}
        if col not in existing:
            await conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")

    # 清理废弃残留列（老 schema 的 NOT NULL 列会阻塞新代码 INSERT）
    for table, cols in _DROP_COLUMNS:
        rows = await conn.exec_driver_sql(f"PRAGMA table_info({table})")
        existing = {r[1] for r in rows.fetchall()}
        for col in cols:
            if col in existing:
                try:
                    await conn.exec_driver_sql(f"ALTER TABLE {table} DROP COLUMN {col}")
                except Exception:
                    # 旧 SQLite 不支持 DROP COLUMN 时不阻断启动；线上镜像用新版 SQLite 会正常清理。
                    pass


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with SessionLocal() as session:
        yield session
