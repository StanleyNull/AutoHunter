"""引擎抽象基类 — 所有测绘搜索引擎统一接口。"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EngineResult:
    """统一返回格式，collector 层依赖此结构。"""
    fields: list[str] = field(default_factory=lambda: ["host", "ip", "port", "title", "domain", "org"])
    results: list[list[Any]] = field(default_factory=list)
    size: int = 0
    page: int = 1
    engine: str = ""
    # Censys 等引擎用 cursor 翻页；无则保持 None，collector 继续用 page。
    next_cursor: str | None = None


class SearchEngine(ABC):
    """搜索引擎基类。"""

    @property
    @abstractmethod
    def name(self) -> str:
        """引擎标识符，如 'fofa', 'quake', 'hunter'。"""
        ...

    @property
    @abstractmethod
    def display_name(self) -> str:
        """引擎展示名，如 'FOFA', '360 Quake'。"""
        ...

    @property
    @abstractmethod
    def env_key_name(self) -> str:
        """环境变量名后缀，如 'FOFA_KEY' 中的 FOFA。"""
        ...

    @abstractmethod
    async def search(
        self,
        api_key: str,
        query: str,
        page: int = 1,
        page_size: int = 100,
        base_url: str | None = None,
        cursor: str | None = None,
    ) -> EngineResult:
        """执行搜索，返回统一格式的 EngineResult。"""
        ...

    def translate_query(self, query: str, from_engine: str = "fofa") -> str:
        """将 from_engine（默认 FOFA）语法翻译为本引擎语法。"""
        if from_engine != "fofa" or self.name == "fofa":
            return query
        from app.engines.translator import translate_fofa_query
        return translate_fofa_query(query, self.name)

    def get_default_base_url(self) -> str:
        """默认 API 端点。"""
        return ""


# ─── 引擎注册表 ───────────────────────────────────────────────
_engines: dict[str, type[SearchEngine]] = {}


def register_engine(engine_cls: type[SearchEngine]) -> type[SearchEngine]:
    """注册引擎类到全局注册表。"""
    inst = engine_cls()
    _engines[inst.name] = engine_cls
    return engine_cls


def get_engine(name: str) -> SearchEngine | None:
    """按名称获取引擎实例。"""
    cls = _engines.get(name)
    if cls is None:
        return None
    return cls()


def list_engines() -> list[dict[str, str]]:
    """列出所有已注册引擎的信息。"""
    return [
        {"name": cls().name, "display_name": cls().display_name}
        for cls in _engines.values()
    ]


def get_default_engine() -> str:
    """默认引擎。"""
    return "fofa"