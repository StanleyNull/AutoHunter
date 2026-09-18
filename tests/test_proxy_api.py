"""代理池 API 单元测试（直接调用路由函数，mock AsyncSession；不碰网络）。"""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock

from fastapi import HTTPException
from fastapi.responses import JSONResponse


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import proxy_service as ps  # noqa: E402
from app.api import proxy as proxy_api  # noqa: E402
from app.db.models import SystemSettings  # noqa: E402


def _row(proxy_cfg: dict | None = None) -> SystemSettings:
    return SystemSettings(id="global", proxy=proxy_cfg or {})


def _session(row: SystemSettings):
    s = type("S", (), {})()
    s.get = AsyncMock(return_value=row)
    s.add = lambda *_: None
    s.commit = AsyncMock()
    s.refresh = AsyncMock()
    return s


class ProxyApiTests(unittest.TestCase):
    def setUp(self) -> None:
        ps.apply_config({})
        self.row = _row({"enabled": False, "proxies": []})

    def tearDown(self) -> None:
        ps.apply_config({})

    def test_add_and_duplicate_conflict(self) -> None:
        res = asyncio.run(proxy_api.add_proxy(
            proxy_api.ProxyAddRequest(host="1.2.3.4", port=8080), _session(self.row)
        ))
        self.assertTrue(res["ok"])
        self.assertEqual(len(self.row.proxy["proxies"]), 1)
        dup = asyncio.run(proxy_api.add_proxy(
            proxy_api.ProxyAddRequest(host="1.2.3.4", port=8080), _session(self.row)
        ))
        self.assertIsInstance(dup, JSONResponse)
        self.assertEqual(dup.status_code, 409)
        # 协议不同不算重复
        res2 = asyncio.run(proxy_api.add_proxy(
            proxy_api.ProxyAddRequest(protocol="socks5", host="1.2.3.4", port=1080), _session(self.row)
        ))
        self.assertTrue(res2["ok"])

    def test_add_rejects_bad_protocol(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            asyncio.run(proxy_api.add_proxy(
                proxy_api.ProxyAddRequest(protocol="ftp", host="1.2.3.4", port=21), _session(self.row)
            ))
        self.assertEqual(raised.exception.status_code, 400)

    def test_update_masks_password_placeholder(self) -> None:
        asyncio.run(proxy_api.add_proxy(
            proxy_api.ProxyAddRequest(host="1.2.3.4", port=8080, password="real-pass"), _session(self.row)
        ))
        pid = self.row.proxy["proxies"][0]["id"]
        res = asyncio.run(proxy_api.update_proxy(
            pid,
            proxy_api.ProxyUpdateRequest(name="renamed", password="••••••••"),
            _session(self.row),
        ))
        entry = self.row.proxy["proxies"][0]
        self.assertEqual(entry["name"], "renamed")
        self.assertEqual(entry["password"], "real-pass")  # 占位不覆盖
        self.assertNotIn("password", res["proxy"])

    def test_delete_unknown_returns_404(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            asyncio.run(proxy_api.delete_proxy("nope", _session(self.row)))
        self.assertEqual(raised.exception.status_code, 404)

    def test_import_counts_and_dedup(self) -> None:
        text = "\n".join([
            "http://1.1.1.1:8080",
            "1.1.1.1:8080",           # 同文本内同键去重 → 计入 invalid
            "socks5://2.2.2.2:1080",
            "garbage",
        ])
        res = asyncio.run(proxy_api.import_proxies(_session(self.row), text=text))
        self.assertEqual(res["added"], 2)
        self.assertEqual(res["skipped"], 0)  # 库里原本为空，没有可跳过的
        self.assertEqual(res["invalid"], 2)  # 文本内去重 1 + 非法行 1
        # 再导入同批 → 有效行全部 skipped
        res2 = asyncio.run(proxy_api.import_proxies(_session(self.row), text=text))
        self.assertEqual(res2["added"], 0)
        self.assertEqual(res2["skipped"], 2)

    def test_import_empty_raises_400(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            asyncio.run(proxy_api.import_proxies(_session(self.row), text="   \n"))
        self.assertEqual(raised.exception.status_code, 400)

    def test_toggle_switches_pool_enabled(self) -> None:
        res = asyncio.run(proxy_api.toggle_proxy_pool(
            proxy_api.ProxyToggleRequest(enabled=True), _session(self.row)
        ))
        self.assertTrue(res["enabled"])
        self.assertTrue(ps.enabled())

    def test_test_proxy_unreachable_reports_error(self) -> None:
        # 127.0.0.1:1 无监听 → 连接拒绝，两个探测地址都失败 → ok=False 且带错误信息
        asyncio.run(proxy_api.add_proxy(
            proxy_api.ProxyAddRequest(host="127.0.0.1", port=1), _session(self.row)
        ))
        pid = self.row.proxy["proxies"][0]["id"]
        res = asyncio.run(proxy_api.test_proxy(
            proxy_api.ProxyTestRequest(id=pid), _session(self.row)
        ))
        self.assertFalse(res["ok"])
        self.assertTrue(res.get("error"))

    def test_test_proxy_unknown_id_404(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            asyncio.run(proxy_api.test_proxy(
                proxy_api.ProxyTestRequest(id="ghost"), _session(self.row)
            ))
        self.assertEqual(raised.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
