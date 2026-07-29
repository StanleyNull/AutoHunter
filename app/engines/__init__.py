"""多测绘引擎统一接口。"""

from app.engines.base import EngineResult, SearchEngine, get_default_engine, get_engine, list_engines, register_engine
from app.engines.quake import QuakeRateLimitError
from app.engines.sync import engine_display_name, engine_search_sync, result_rows_to_dicts

# 导入所有引擎以触发注册
import app.engines.fofa  # noqa: F401
import app.engines.quake  # noqa: F401
import app.engines.hunter  # noqa: F401
import app.engines.zoomeye  # noqa: F401
import app.engines.shodan  # noqa: F401
import app.engines.censys  # noqa: F401

__all__ = [
    "EngineResult", "SearchEngine", "QuakeRateLimitError",
    "get_engine", "list_engines", "get_default_engine", "register_engine",
    "engine_search_sync", "result_rows_to_dicts", "engine_display_name",
]