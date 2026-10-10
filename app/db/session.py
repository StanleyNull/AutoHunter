"""异步数据库会话管理（SQLite + aiosqlite）。"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import Base

logger = logging.getLogger("autohunter.db")

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
    # 写锁最多等 30s 再报错。BEGIN IMMEDIATE 下每次写都要拿全库写锁，24x7 高并发下
    # 单次持锁偶尔会到数秒（几十个 session 排队）。5s 太短，会在排队时直接抛
    # SQLITE_BUSY（表现为 tick error / worker crashed 的 database is locked）。
    # 30s 覆盖最坏排队，正常路径毫秒级返回，不影响吞吐。可用 DB_BUSY_TIMEOUT_MS 覆盖。
    f"PRAGMA busy_timeout={os.environ.get('DB_BUSY_TIMEOUT_MS', '30000')};",
    "PRAGMA synchronous=NORMAL;",         # WAL 下安全，显著降低写延迟
    "PRAGMA foreign_keys=ON;",
    "PRAGMA cache_size=-16000;",          # 约 16MB page cache；每条连接一份，不能再开 64MB
    "PRAGMA mmap_size=67108864;",         # 64MB mmap，避免把整库映射进 cgroup
    "PRAGMA temp_store=MEMORY;",          # ORDER BY/GROUP BY 临时表走内存
    "PRAGMA wal_autocheckpoint=1000;",
    # checkpoint 后把 WAL 截断回 0 字节，避免 24x7 下 WAL 只增不减（历史上曾涨到 11GB）。
    "PRAGMA journal_size_limit=268435456;",  # 256MB：checkpoint 后回收多余空间
)


@event.listens_for(engine.sync_engine, "connect")
def _set_sqlite_pragma(dbapi_connection, _connection_record):
    # 关键：关闭 pysqlite 的「隐式 BEGIN」，改由下方 begin 事件发显式 BEGIN IMMEDIATE。
    #
    # 默认（isolation_level=""）下，SQLAlchemy 延迟到第一条语句才开事务，而多数 session
    # 的第一条语句是 SELECT——于是拿到的是一个「读事务」。WAL 模式下读事务会固定一个
    # 快照；只要此后任何其它连接提交过写（N 个 worker 心跳/落库 + API 写），快照即失效，
    # 该 session 再要写（尤其 ORM autoflush）就得做「读→写升级」，而升级遇到失效快照会
    # 立即返回 SQLITE_BUSY_SNAPSHOT(517)——busy_timeout 对升级失败【完全不生效】。
    # 现象就是 worker 在 session.get() 之后、_build_duplicate_history 的 autoflush 处
    # 抛 “database is locked” 而整条协程崩溃。
    #
    # isolation_level=None 让 SQLAlchemy 自己发 BEGIN；配合 begin 事件的 BEGIN IMMEDIATE，
    # 事务一开就拿到写锁，从此不存在「读→写升级」，busy_timeout 也恢复正常生效。
    dbapi_connection.isolation_level = None
    cursor = dbapi_connection.cursor()
    try:
        for pragma in _CONNECT_PRAGMAS:
            cursor.execute(pragma)
        # WAL 是库级持久设置，但每条新连接显式确认一次，杜绝任何非 WAL 连接混入。
        cursor.execute("PRAGMA journal_mode=WAL;")
    finally:
        cursor.close()


@event.listens_for(engine.sync_engine, "begin")
def _begin_immediate(conn):
    # 显式 BEGIN IMMEDIATE：事务起点即取写锁，消除 WAL 读→写升级失败（SQLITE_BUSY_SNAPSHOT）。
    # 注意：BEGIN IMMEDIATE 会把写锁持有到事务结束，因此绝不能让 session 在事务中途
    # await 长时间的外部 IO（如报告助手 300s 线程）——那会把写锁占满导致全库写阻塞。
    conn.exec_driver_sql("BEGIN IMMEDIATE")


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
    ("findings", "llm_model", "VARCHAR(200) DEFAULT ''"),
    ("findings", "llm_base_url", "VARCHAR(300) DEFAULT ''"),
    ("killsweeps", "affected_table", "JSON DEFAULT '[]'"),
    ("system_settings", "engines", "JSON DEFAULT '{}'"),
    ("tasks", "engine", "VARCHAR(20) DEFAULT ''"),
    ("tasks", "auth_bindings", "JSON"),
    ("targets", "auth_context", "JSON"),
    ("targets", "auth_status", "JSON"),
    ("tasks", "deepen_cap", "INTEGER DEFAULT 2"),
    ("system_settings", "ui", "JSON DEFAULT '{}'"),
    # 用户置顶标记：全局漏洞库/资产库列表中置顶行优先展示。
    # NOT NULL + DEFAULT 0：老库补列时现有行全部置为 False，向前兼容。
    ("findings", "is_top", "BOOLEAN DEFAULT 0 NOT NULL"),
    ("targets", "is_top", "BOOLEAN DEFAULT 0 NOT NULL"),
    ("tasks", "is_top", "BOOLEAN DEFAULT 0 NOT NULL"),
    ("tasks", "runtime_stats", "JSON DEFAULT '{}'"),
    ("system_settings", "proxy", "JSON DEFAULT '{}'"),
    ("tasks", "auto_killsweep", "BOOLEAN DEFAULT 1 NOT NULL"),
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
    ("ix_killsweeps_origin_finding",
     "CREATE INDEX IF NOT EXISTS ix_killsweeps_origin_finding "
     "ON killsweeps(origin_finding_id)"),
    # 运行异常日志：按 level/agent 过滤 + ts DESC 排序。
    ("ix_task_events_level_ts",
     "CREATE INDEX IF NOT EXISTS ix_task_events_level_ts ON task_events(level, ts)"),
    # 看板历史回放：WHERE task_id=? ORDER BY id DESC LIMIT N。
    ("ix_task_events_task_id_id",
     "CREATE INDEX IF NOT EXISTS ix_task_events_task_id_id ON task_events(task_id, id)"),
    # 置顶排序：全局漏洞库 / 资产库 ORDER BY is_top DESC, created_at/updated_at DESC。
    # 布尔列基数低，复合索引让置顶行优先走索引扫描，避免全表排。
    ("ix_findings_is_top_created",
     "CREATE INDEX IF NOT EXISTS ix_findings_is_top_created ON findings(is_top, created_at)"),
    ("ix_targets_is_top_updated",
     "CREATE INDEX IF NOT EXISTS ix_targets_is_top_updated ON targets(is_top, updated_at)"),
    ("ix_tasks_is_top_created",
     "CREATE INDEX IF NOT EXISTS ix_tasks_is_top_created ON tasks(is_top, created_at)"),
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


# 周期 checkpoint 间隔（秒）。默认 300s；设为 0 关闭。24x7 写不断时被动 checkpoint
# 推不动，靠这个把 WAL 定期截断回收。
WAL_CHECKPOINT_INTERVAL = float(os.environ.get("AUTOHUNTER_WAL_CHECKPOINT_INTERVAL", "300"))


async def checkpoint_wal(mode: str = "TRUNCATE") -> dict | None:
    """执行一次 WAL checkpoint，回收 WAL 空间。

    24x7 下 worker/心跳/API 的写几乎从不间断，SQLite 的被动 checkpoint 很难推进到把
    WAL 清空，导致 .db-wal 只增不减（历史上曾涨到 11GB）。定期主动 checkpoint：
    - PASSIVE：只尽力推进，不阻塞写，但可能推不动（有读者时停在旧帧）；
    - TRUNCATE：checkpoint 后把 WAL 截断回 0 字节，能真正回收磁盘。

    用独立的原始 aiosqlite 连接执行——刻意绕过 SQLAlchemy 引擎：本模块给引擎挂了
    「begin → BEGIN IMMEDIATE」事件，而 wal_checkpoint 不能在已开启的事务里跑
    （会报 database table is locked）。裸连接没有这个包装，PRAGMA 直接生效。
    失败只告警不抛——清理是尽力而为。
    返回 {busy, log, checkpointed}；busy=1 表示有活跃读者/写者导致没能推进到位（正常，
    下一轮再试）。失败返回 None。
    """
    import aiosqlite

    try:
        conn = await aiosqlite.connect(DB_PATH, timeout=5.0)
        try:
            await conn.execute("PRAGMA busy_timeout=5000;")
            cursor = await conn.execute(f"PRAGMA wal_checkpoint({mode});")
            row = await cursor.fetchone()
            await cursor.close()
        finally:
            await conn.close()
        if not row:
            return None
        return {"busy": int(row[0]), "log": int(row[1]), "checkpointed": int(row[2])}
    except Exception as exc:  # noqa: BLE001
        logger.warning("WAL checkpoint(%s) 失败：%s", mode, exc)
        return None


async def run_periodic_wal_checkpoint() -> None:
    """后台周期 TRUNCATE checkpoint，把 WAL 截断回收，避免只增不减。

    interval<=0 时关闭。首拍延迟一个 interval 再跑（启动时刚 init_db，不必立刻截断）。
    TRUNCATE 需短暂写锁：拿不到就 busy=1 跳过，下一轮再试——绝不阻塞主流程。
    """
    import asyncio

    interval = WAL_CHECKPOINT_INTERVAL
    if interval <= 0:
        logger.info("WAL 周期 checkpoint 已关闭（AUTOHUNTER_WAL_CHECKPOINT_INTERVAL=0）")
        return
    while True:
        await asyncio.sleep(interval)
        result = await checkpoint_wal("TRUNCATE")
        if result and result.get("checkpointed"):
            logger.info(
                "WAL checkpoint: 已回收 log=%d checkpointed=%d busy=%d",
                result.get("log", 0), result.get("checkpointed", 0), result.get("busy", 0),
            )
