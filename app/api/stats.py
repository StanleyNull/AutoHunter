"""日历统计 API：按日期聚合产出 + Token 成本。

产出统计从 findings/reviews 表按 CST 日期聚合；
Token 成本从 token_usage_daily 表读取，按 pricing 配置实时计算。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Finding, Review
from app.db.session import engine, get_session
from app.settings_service import resolve_pricing

router = APIRouter(prefix="/api/stats", tags=["stats"])

CST = timezone(timedelta(hours=8))


def _cst_date_from_utc(col) -> str:
    """SQL: UTC naive 时间列 -> CST 日期字符串。"""
    # SQLite: datetime(col, '+8 hours') 把 UTC 加 8 小时得 CST，再 DATE() 取日期
    return func.date(func.datetime(col, "+8 hours"))


def _calc_cost(prompt_tokens: int, completion_tokens: int,
               cache_hit_tokens: int, pricing: dict) -> float:
    """按模型计价计算单行成本（元）。"""
    price_in = float(pricing.get("input", 0) or 0)
    price_out = float(pricing.get("output", 0) or 0)
    price_cache = float(pricing.get("cache_hit", 0) or 0)
    # 缓存命中部分按缓存价计费，非缓存输入按输入价
    non_cache_input = max(0, prompt_tokens - cache_hit_tokens)
    cost = (
        non_cache_input * price_in / 1_000_000
        + completion_tokens * price_out / 1_000_000
        + cache_hit_tokens * price_cache / 1_000_000
    )
    return round(cost, 4)


@router.get("/pool")
async def pool_stats():
    """数据库连接池实时状态（不需要 DB session，不消耗连接）。"""
    pool = engine.pool
    return {
        "pool_size": pool.size(),          # 基础容量
        "max_overflow": pool._max_overflow,  # 最大溢出
        "checkedout": pool.checkedout(),   # 当前在用连接数
        "checkedin": pool.checkedin(),     # 空闲可用连接数
        "overflow": pool.overflow(),       # 当前溢出连接数
        "total_capacity": pool.size() + pool._max_overflow,  # 总上限
        "timeout": pool._timeout,          # 获取连接超时(秒)
    }


@router.get("/daily")
async def daily_stats(
    date: str = Query(None, description="YYYY-MM-DD，默认今天 CST"),
    session: AsyncSession = Depends(get_session),
):
    """指定日期的产出统计 + Token 成本明细。"""
    if not date:
        date = datetime.now(CST).strftime("%Y-%m-%d")

    # 1) 产出统计：findings 按 CST 日期聚合
    # findings.created_at 存 UTC naive，用 SQL 转换
    cst_date_expr = _cst_date_from_utc(Finding.created_at)

    # 当日 findings 总数
    findings_total_q = select(func.count(Finding.id)).where(cst_date_expr == date)
    findings_total = (await session.execute(findings_total_q)).scalar() or 0

    # 当日 findings 按 status 分布
    status_q = (
        select(Finding.status, func.count(Finding.id))
        .where(cst_date_expr == date)
        .group_by(Finding.status)
    )
    status_counts = {(row[0]): row[1] for row in (await session.execute(status_q)).all()}
    pending_review = status_counts.get("pending_review", 0)
    reviewed = status_counts.get("reviewed", 0)

    # 当日 reviews 按 verdict 分布（需 join findings 取 created_at 日期）
    review_verdict_q = (
        select(Review.verdict, func.count(Review.id))
        .join(Finding, Review.finding_id == Finding.id)
        .where(_cst_date_from_utc(Finding.created_at) == date)
        .group_by(Review.verdict)
    )
    verdict_counts = {row[0]: row[1] for row in (await session.execute(review_verdict_q)).all()}

    # 当日 reviews 按 user_status 分布（仅 accepted 的才进用户复审流程）
    user_status_q = (
        select(Review.user_status, func.count(Review.id))
        .join(Finding, Review.finding_id == Finding.id)
        .where(_cst_date_from_utc(Finding.created_at) == date)
        .where(Review.verdict == "accepted")
        .group_by(Review.user_status)
    )
    user_status_counts = {row[0]: row[1] for row in (await session.execute(user_status_q)).all()}

    # 当日已提交数（仅 accepted 的）
    submitted_q = (
        select(func.count(Review.id))
        .join(Finding, Review.finding_id == Finding.id)
        .where(_cst_date_from_utc(Finding.created_at) == date)
        .where(Review.verdict == "accepted")
        .where(Review.submitted == True)  # noqa: E712
    )
    submitted_count = (await session.execute(submitted_q)).scalar() or 0

    # 2) Token 成本：从 token_usage_daily 表读取，按模型合并（跨任务聚合）
    token_q = text(
        "SELECT model, SUM(prompt_tokens), SUM(completion_tokens), SUM(cache_hit_tokens), "
        "SUM(cache_miss_tokens), SUM(requests) "
        "FROM token_usage_daily WHERE date = :date GROUP BY model"
    )
    token_rows = (await session.execute(token_q, {"date": date})).all()
    pricing_config = resolve_pricing()

    by_model = []
    total_cost = 0.0
    total_prompt = 0
    total_completion = 0
    total_cache_hit = 0
    total_requests = 0
    for row in token_rows:
        model, pt, ct, cht, cmt, req = row
        pricing = pricing_config.get(model, {}) if model else {}
        cost = _calc_cost(pt, ct, cht, pricing)
        by_model.append({
            "model": model,
            "prompt_tokens": pt,
            "completion_tokens": ct,
            "cache_hit_tokens": cht,
            "cache_miss_tokens": cmt,
            "requests": req,
            "cost": cost,
            "pricing": pricing,
        })
        total_cost += cost
        total_prompt += pt
        total_completion += ct
        total_cache_hit += cht
        total_requests += req

    return {
        "date": date,
        "findings": {
            "total": findings_total,
            "pending_review": pending_review,
            "reviewed": reviewed,
        },
        "reviews": {
            "accepted": verdict_counts.get("accepted", 0),
            "ignored": verdict_counts.get("ignored", 0),
            "deepen": verdict_counts.get("deepen", 0),
        },
        "user_reviews": {
            "pending": user_status_counts.get("pending", 0),
            "passed": user_status_counts.get("passed", 0),
            "rejected": user_status_counts.get("rejected", 0),
            "submitted": submitted_count,
        },
        "token_usage": {
            "total_cost": round(total_cost, 4),
            "total_prompt_tokens": total_prompt,
            "total_completion_tokens": total_completion,
            "total_cache_hit_tokens": total_cache_hit,
            "total_requests": total_requests,
            "by_model": by_model,
        },
    }


@router.get("/daily-overview")
async def daily_overview(
    month: str = Query(None, description="YYYY-MM，默认当月 CST"),
    session: AsyncSession = Depends(get_session),
):
    """月度日历概览：每天一行汇总，用于日历格着色。"""
    if not month:
        month = datetime.now(CST).strftime("%Y-%m")

    # 解析月份范围
    try:
        year, mon = map(int, month.split("-"))
        month_start = datetime(year, mon, 1, tzinfo=CST)
        if mon == 12:
            month_end = datetime(year + 1, 1, 1, tzinfo=CST)
        else:
            month_end = datetime(year, mon + 1, 1, tzinfo=CST)
    except (ValueError, IndexError):
        return {"month": month, "days": []}

    # 1) 产出统计：findings 按 CST 日期聚合
    cst_date_expr = _cst_date_from_utc(Finding.created_at)
    findings_q = (
        select(cst_date_expr.label("d"), func.count(Finding.id))
        .where(cst_date_expr >= month_start.strftime("%Y-%m-%d"))
        .where(cst_date_expr < month_end.strftime("%Y-%m-%d"))
        .group_by(cst_date_expr)
    )
    findings_by_day = {row[0]: row[1] for row in (await session.execute(findings_q)).all()}

    # reviews accepted/submitted 按 CST 日期
    accepted_q = (
        select(cst_date_expr.label("d"), func.count(Review.id))
        .join(Finding, Review.finding_id == Finding.id)
        .where(Review.verdict == "accepted")
        .where(cst_date_expr >= month_start.strftime("%Y-%m-%d"))
        .where(cst_date_expr < month_end.strftime("%Y-%m-%d"))
        .group_by(cst_date_expr)
    )
    accepted_by_day = {row[0]: row[1] for row in (await session.execute(accepted_q)).all()}

    submitted_q = (
        select(cst_date_expr.label("d"), func.count(Review.id))
        .join(Finding, Review.finding_id == Finding.id)
        .where(Review.submitted == True)  # noqa: E712
        .where(cst_date_expr >= month_start.strftime("%Y-%m-%d"))
        .where(cst_date_expr < month_end.strftime("%Y-%m-%d"))
        .group_by(cst_date_expr)
    )
    submitted_by_day = {row[0]: row[1] for row in (await session.execute(submitted_q)).all()}

    # 2) Token 成本：按日期+模型聚合，用 pricing 实时计算
    pricing_config = resolve_pricing()
    token_model_q = text(
        "SELECT date, model, prompt_tokens, completion_tokens, cache_hit_tokens "
        "FROM token_usage_daily "
        "WHERE date >= :start AND date < :end"
    )
    token_model_rows = (await session.execute(token_model_q, {
        "start": month_start.strftime("%Y-%m-%d"),
        "end": month_end.strftime("%Y-%m-%d"),
    })).all()

    cost_by_day: dict[str, float] = {}
    requests_by_day: dict[str, int] = {}
    for row in token_model_rows:
        d, model, pt, ct, cht = row
        pricing = pricing_config.get(model, {}) if model else {}
        cost = _calc_cost(pt, ct, cht, pricing)
        cost_by_day[d] = round(cost_by_day.get(d, 0) + cost, 4)
        requests_by_day[d] = requests_by_day.get(d, 0) + 1

    # 合并所有日期
    all_dates = set(findings_by_day.keys()) | set(accepted_by_day.keys()) | set(submitted_by_day.keys()) | set(cost_by_day.keys())
    days = []
    for d in sorted(all_dates):
        days.append({
            "date": d,
            "findings_total": findings_by_day.get(d, 0),
            "accepted": accepted_by_day.get(d, 0),
            "submitted": submitted_by_day.get(d, 0),
            "cost": cost_by_day.get(d, 0),
            "requests": requests_by_day.get(d, 0),
        })

    return {"month": month, "days": days}
