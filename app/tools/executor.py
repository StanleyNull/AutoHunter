"""工具执行器：worker 真实挖洞的底层能力。

提供给 LLM 通过 function calling 调用：
- run_shell: 受控执行任意命令（带超时、输出截断、自毁防护、工作目录隔离）
- http_request: 发原始 HTTP 请求，返回完整请求包+响应包（取证用）
"""
from __future__ import annotations

import os
import selectors
import shlex
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Optional

import httpx

from app.config import worker_config
from app.tools.decoder import decode_transform as _decode_transform
from app.tools.guard import CommandBlocked, check_command
from app.tools.js_analyzer import analyze_javascript as analyze_js_text
from app.tools.js_analyzer import analyze_url as analyze_js_url
from app.tools.waf_advisor import suggest_waf_bypass as _suggest_waf_bypass

_FOFA_BASE = "https://fofa.info"
# FOFA 只读查询硬上限：worker 用它确认归属/探攻击面，不是测绘，给小额度即可。
_FOFA_LOOKUP_MAX_SIZE = 30
# 企业 session cookie jar 上限，防异常站点塞爆内存。
_SESSION_MAX_COOKIES = 50
_SESSION_MAX_HEADERS = 30

# 单目标工作目录落地日志体积上限（字节）。24x7 防撞盘：超限后停止写新日志文件，
# 仍把截断输出回传给 LLM，不影响挖掘，只是不再落地完整证据。
_WORKDIR_MAX_BYTES = int(os.environ.get("WORKER_WORKDIR_MAX_BYTES", str(50 * 1024 * 1024)))
_SHELL_CAPTURE_MAX_BYTES = int(os.environ.get("WORKER_SHELL_CAPTURE_MAX_BYTES", str(512 * 1024)))
_HTTP_MAX_BYTES = int(os.environ.get("WORKER_HTTP_MAX_BYTES", str(1024 * 1024)))


def _truncate(text: str, limit: Optional[int] = None) -> str:
    if limit is None:
        limit = worker_config.output_truncate
        if worker_config.llm_tool_output_truncate > 0:
            limit = min(limit, worker_config.llm_tool_output_truncate)
    else:
        limit = int(limit)
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-limit // 4 :]
    return f"{head}\n\n...[输出过长已截断，完整内容已写入工作目录文件]...\n\n{tail}"


class ToolExecutor:
    def __init__(
        self,
        target: str,
        work_dir: Optional[str] = None,
        cancel_event: Optional[threading.Event] = None,
        enterprise: bool = False,
        fofa_key: str = "",
        fofa_base_url: str = "",
    ):
        self.target = target
        self.cancel_event = cancel_event or threading.Event()
        # 企业模式：对目标生产环境的破坏性命令做额外硬拦截。
        self.enterprise = enterprise
        self.fofa_key = fofa_key or ""
        self.fofa_base_url = (fofa_base_url or _FOFA_BASE).rstrip("/")
        # 每个目标独立工作目录
        safe_name = "".join(c if c.isalnum() else "_" for c in target)[:60]
        self.work_dir = Path(work_dir or worker_config.work_root) / safe_name
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._log_seq = 0
        self._active_procs: set[subprocess.Popen] = set()
        # 企业专属会话态：worker 登录/拿到 token 后，自动携带到后续 http_request，
        # 解决"明明登进去了，深挖请求却忘带凭证导致越权失败"的断链问题。
        # 仅企业模式启用（edu 走量不需要维持复杂会话）。
        self._session_cookies: dict[str, str] = {}
        self._session_headers: dict[str, str] = {}

    def cancel_running(self) -> None:
        """协作取消：置取消信号 + 杀子进程。仅用于控制面真取消（pause/stop/超时）。

        注意：会 set cancel_event，worker 据此判定"被取消、结果丢弃"。所以
        【正常完成后的清理】绝不能调这个（否则正常结果会被误判成取消而丢弃，
        历史事故根因：每个 worker 完成都被丢弃、findings/done 永远为 0）。
        正常完成清理请用 kill_processes()。
        """
        self.cancel_event.set()
        self.kill_processes()

    def kill_processes(self) -> None:
        """只杀掉当前 executor 启动的所有子进程组，不触碰 cancel_event。

        用于 worker 正常完成后的资源清理（杀残留子进程），不污染取消信号。
        """
        for proc in list(self._active_procs):
            self._kill_process_group(proc)

    # ---- run_shell ----
    def run_shell(self, command: str, timeout: Optional[int] = None) -> dict[str, Any]:
        timeout = timeout or worker_config.shell_timeout
        try:
            check_command(command, enterprise=self.enterprise)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}

        start = time.time()
        proc: subprocess.Popen | None = None
        timed_out = False
        cancelled = False
        omitted_bytes = 0
        chunks: list[bytes] = []
        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                cwd=str(self.work_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,  # 独立进程组，便于超时整组 kill
            )
            self._active_procs.add(proc)
            deadline = start + timeout
            if proc.stdout is None:
                rc = proc.wait(timeout=timeout)
            else:
                selector = selectors.DefaultSelector()
                selector.register(proc.stdout, selectors.EVENT_READ)
                try:
                    while True:
                        if self.cancel_event.is_set():
                            cancelled = True
                            self._kill_process_group(proc)
                        elif time.time() >= deadline:
                            timed_out = True
                            self._kill_process_group(proc)

                        for key, _ in selector.select(timeout=0.2):
                            data = key.fileobj.read1(8192)
                            if not data:
                                continue
                            room = max(0, _SHELL_CAPTURE_MAX_BYTES - sum(len(c) for c in chunks))
                            if room:
                                chunks.append(data[:room])
                            if len(data) > room:
                                omitted_bytes += len(data) - room

                        rc = proc.poll()
                        if rc is not None:
                            # 进程退出后再 drain 一次，保证 wait/reap 前尽量拿到尾部输出。
                            while True:
                                data = proc.stdout.read1(8192)
                                if not data:
                                    break
                                room = max(0, _SHELL_CAPTURE_MAX_BYTES - sum(len(c) for c in chunks))
                                if room:
                                    chunks.append(data[:room])
                                if len(data) > room:
                                    omitted_bytes += len(data) - room
                            break
                    rc = proc.wait(timeout=3)
                finally:
                    selector.close()
            cancelled = cancelled or self.cancel_event.is_set()
        except Exception as e:
            return {"ok": False, "error": f"命令执行异常: {e}"}
        finally:
            if proc is not None:
                self._active_procs.discard(proc)
                if proc.poll() is None:
                    self._kill_process_group(proc)
                    try:
                        proc.wait(timeout=3)
                    except Exception:
                        pass

        elapsed = round(time.time() - start, 2)
        full_out = b"".join(chunks).decode("utf-8", "replace")
        if omitted_bytes:
            full_out += f"\n\n...[输出超过 {_SHELL_CAPTURE_MAX_BYTES} 字节，已丢弃约 {omitted_bytes} 字节以保护内存]..."
        # 完整输出落地，避免截断丢证据（带体积上限，防 24x7 撞盘）
        log_file = self._write_log(f"$ {command}\n\n{full_out}")

        return {
            "ok": rc == 0 and not timed_out and not cancelled,
            "return_code": rc,
            "timed_out": timed_out,
            "cancelled": cancelled,
            "elapsed_sec": elapsed,
            "output": _truncate(full_out),
            "output_file": str(log_file) if log_file else "",
        }

    @staticmethod
    def _kill_process_group(proc: subprocess.Popen) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _dir_size(self) -> int:
        try:
            return sum(f.stat().st_size for f in self.work_dir.glob("*") if f.is_file())
        except Exception:
            return 0

    def _write_log(self, content: str) -> Optional[Path]:
        """落地日志文件；工作目录超体积上限则跳过（返回 None），不再写盘。"""
        if self._dir_size() >= _WORKDIR_MAX_BYTES:
            return None
        self._log_seq += 1
        log_file = self.work_dir / f"shell_{self._log_seq}.log"
        try:
            log_file.write_text(content, encoding="utf-8")
        except Exception:
            return None
        return log_file

    # ---- http_request ----
    def http_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[dict[str, str]] = None,
        data: Optional[str] = None,
        json_body: Optional[Any] = None,
        follow_redirects: bool = False,
        timeout: int = 20,
    ) -> dict[str, Any]:
        # 企业 session：把已维持的 cookie/header 合并进本次请求（用户传的同名键优先）。
        merged_headers, session_applied = self._apply_session(headers)

        req: httpx.Request | None = None
        try:
            with httpx.Client(verify=False, follow_redirects=follow_redirects, timeout=timeout) as client:
                req = client.build_request(
                    method.upper(), url, headers=merged_headers, content=data, json=json_body
                )
                resp = client.send(req, stream=True)
                body, truncated = self._read_limited_response(resp)
        except Exception as e:
            return {"ok": False, "error": f"HTTP 请求异常: {e}", "url": url}

        # 企业 session：自动吸收响应 Set-Cookie，后续请求自动续上登录态。
        session_updated = self._absorb_set_cookie(resp) if self.enterprise else []

        # 原始请求行（取证/格式参考）。响应报文不再单独回传：状态码 + response_headers +
        # body 已结构化提供，raw_response 会与它们 100% 重复，是当轮就纯冗余的双份大文本。
        # 模型 submit_finding 时按 prompt 规范从 body 自行裁剪取证，不依赖这份 raw_response。
        raw_req = self._raw_request(req, data, json_body)

        result = {
            "ok": True,
            "status_code": resp.status_code,
            "url": str(resp.url),
            "response_headers": dict(resp.headers),
            "body": _truncate(body),
            "body_len": len(body),
            "body_truncated": truncated,
            "raw_request": _truncate(raw_req, 1536),
        }
        if session_applied:
            result["session_applied"] = session_applied
        if session_updated:
            result["session_cookies_updated"] = session_updated
        return result

    # ---- 企业 session 状态管理 ----
    def _apply_session(self, headers: Optional[dict[str, str]]) -> tuple[dict[str, str], list[str]]:
        """把维持的 session cookie/header 合并进请求头。返回 (合并后headers, 应用了哪些)。

        合并规则：用户本次显式传入的头优先（不被 session 覆盖），保证可手动覆写。
        非企业模式直接原样返回，不启用 session。
        """
        if not self.enterprise:
            return (dict(headers) if headers else {}), []
        try:
            merged: dict[str, str] = {}
            applied: list[str] = []
            for k, v in self._session_headers.items():
                merged[k] = v
            if self._session_cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in self._session_cookies.items())
                merged["Cookie"] = cookie_str
                applied.append(f"Cookie({len(self._session_cookies)})")
            if self._session_headers:
                applied.append(f"headers({len(self._session_headers)})")
            # 用户本次传入的头覆盖 session（显式优先）。
            if headers:
                for k, v in headers.items():
                    merged[k] = v
            return merged, applied
        except Exception:
            return (dict(headers) if headers else {}), []

    def _absorb_set_cookie(self, resp: httpx.Response) -> list[str]:
        """从响应吸收 Set-Cookie 进 session jar（带数量上限防爆内存）。"""
        try:
            updated: list[str] = []
            for name, value in resp.cookies.items():
                if name in self._session_cookies:
                    self._session_cookies[name] = value
                    updated.append(name)
                elif len(self._session_cookies) < _SESSION_MAX_COOKIES:
                    self._session_cookies[name] = value
                    updated.append(name)
            return updated
        except Exception:
            return []

    def session_set(
        self,
        cookies: Optional[dict[str, str]] = None,
        headers: Optional[dict[str, str]] = None,
        clear: bool = False,
    ) -> dict[str, Any]:
        """worker 显式设置/查看会话态：手动登记拿到的 token/cookie，后续自动携带。"""
        if not self.enterprise:
            return {"ok": False, "blocked": True,
                    "error": "session 状态管理仅企业模式可用。",
                    "guidance": "edu 模式请在 http_request 的 headers 里手动带 Cookie/Authorization。"}
        try:
            if clear:
                self._session_cookies.clear()
                self._session_headers.clear()
            if isinstance(cookies, dict):
                for k, v in cookies.items():
                    if not isinstance(k, str):
                        continue
                    if k in self._session_cookies or len(self._session_cookies) < _SESSION_MAX_COOKIES:
                        self._session_cookies[k] = str(v)[:4096]
            if isinstance(headers, dict):
                for k, v in headers.items():
                    if not isinstance(k, str):
                        continue
                    if k in self._session_headers or len(self._session_headers) < _SESSION_MAX_HEADERS:
                        self._session_headers[k] = str(v)[:4096]
            return {
                "ok": True,
                "active_cookies": sorted(self._session_cookies.keys()),
                "active_headers": sorted(self._session_headers.keys()),
                "guidance": "已更新会话态，后续 http_request 会自动携带；继续以此据点深挖受限接口。",
            }
        except Exception as e:
            return {"ok": False, "error": f"session_set 异常: {type(e).__name__}: {e}"}

    # ---- decode_transform ----
    def decode_transform(self, value: str = "", mode: str = "auto") -> dict[str, Any]:
        """编码/解码/哈希分析（纯内存，无外部副作用）。详见 tools/decoder.py。"""
        return _decode_transform(value, mode)

    # ---- fofa_lookup（只读资产测绘，确认归属 + 探攻击面）----
    def fofa_lookup(self, query: str = "", size: int = 10) -> dict[str, Any]:
        """对 FOFA 发一次只读查询，返回命中规模和样本（host/ip/port/title/domain/org）。

        用途：① 确认目标归属（org/备案/证书）填准 owner；② 看同 IP/同域还开了
        哪些端口/服务，发现隐藏攻击面。只读查询，不对目标产生任何请求。
        """
        if not self.fofa_key:
            return {"ok": False, "error": "未配置 FOFA key，无法查询。",
                    "guidance": "跳过测绘，直接用 http_request 验证归属（看证书/页脚/备案）。"}
        q = (query or "").strip()
        if not q:
            return {"ok": False, "kind": "arg_error", "error": "query 不能为空",
                    "guidance": '传 FOFA 语法，如 ip="1.2.3.4" 或 host="example.com"。'}
        safe_size = max(1, min(int(size or 10), _FOFA_LOOKUP_MAX_SIZE))
        import base64 as _b64
        params = {
            "key": self.fofa_key,
            "qbase64": _b64.b64encode(q.encode("utf-8")).decode("ascii"),
            "fields": "host,ip,port,title,domain,org,protocol",
            "page": "1", "size": str(safe_size), "full": "false",
        }
        try:
            with httpx.Client(timeout=25) as client:
                resp = client.get(f"{self.fofa_base_url}/api/v1/search/all", params=params)
                data = resp.json()
        except Exception as e:
            return {"ok": False, "error": f"FOFA 调用失败: {type(e).__name__}: {e}",
                    "guidance": "FOFA 不可用，改用 http_request 直接验证归属。"}
        if not isinstance(data, dict):
            return {"ok": False, "error": "FOFA 返回格式异常"}
        if data.get("error"):
            return {"ok": False, "error": f"FOFA 错误: {data.get('errmsg', '')}"[:300]}
        def _cell(row: list, i: int) -> str:
            # FOFA 字段可能为 null/非字符串，统一转成安全字符串，杜绝 None[:n] 崩溃。
            return str(row[i]) if len(row) > i and row[i] is not None else ""

        sample = []
        for row in (data.get("results") or [])[:safe_size]:
            if isinstance(row, list):
                sample.append({
                    "host": _cell(row, 0),
                    "ip": _cell(row, 1),
                    "port": _cell(row, 2),
                    "title": _cell(row, 3)[:120],
                    "domain": _cell(row, 4),
                    "org": _cell(row, 5),
                    "protocol": _cell(row, 6),
                })
        return {
            "ok": True,
            "query": q,
            "size": data.get("size", 0),
            "sample": sample,
            "guidance": "据此核实 owner 归属、发现同 IP/同域其它端口与服务；测绘只读，验证仍需 http_request 实证。",
        }

    @staticmethod
    def _read_limited_response(resp: httpx.Response) -> tuple[str, bool]:
        chunks: list[bytes] = []
        total = 0
        truncated = False
        try:
            for chunk in resp.iter_bytes():
                if not chunk:
                    continue
                if total + len(chunk) > _HTTP_MAX_BYTES:
                    room = max(0, _HTTP_MAX_BYTES - total)
                    if room:
                        chunks.append(chunk[:room])
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)
        finally:
            resp.close()
        body = b"".join(chunks).decode(resp.encoding or "utf-8", "replace")
        if truncated:
            body += f"\n\n...[响应超过 {_HTTP_MAX_BYTES} 字节，已截断以保护内存]..."
        return body, truncated

    @staticmethod
    def _raw_request(req: httpx.Request, data: Optional[str], json_body: Any) -> str:
        lines = [f"{req.method} {req.url.raw_path.decode('latin-1')} HTTP/1.1"]
        lines.append(f"Host: {req.url.host}")
        for k, v in req.headers.items():
            if k.lower() == "host":
                continue
            lines.append(f"{k}: {v}")
        body = ""
        if req.content:
            try:
                body = req.content.decode("utf-8", "replace")
            except Exception:
                body = "<binary>"
        return "\n".join(lines) + "\n\n" + body

    # ---- analyze_javascript（条件开放给 worker）----
    def analyze_javascript(
        self,
        url: str = "",
        text: str = "",
        max_depth: int = 2,
        max_assets: int = 80,
    ) -> dict[str, Any]:
        """分析入口 URL 或 JS 文本，返回高价值链路和统一接口清单。"""
        try:
            safe_depth = max(0, min(int(max_depth or 2), 4))
            safe_assets = max(1, min(int(max_assets or 80), 150))
            if url:
                result = analyze_js_url(url, max_depth=safe_depth, max_assets=safe_assets)
            elif text:
                result = analyze_js_text(text[:800_000], base_url=self.target, source="worker_text")
            else:
                return {
                    "ok": False,
                    "kind": "arg_error",
                    "error": "analyze_javascript 需要 url 或 text",
                    "guidance": "传入口 URL 或已抓到的 JS 文本；不要空调用。",
                }
            return {
                "ok": True,
                "summary": result.get("summary", {}),
                "chains": result.get("chains", [])[:8],
                "endpoint_inventory": result.get("endpoint_inventory", [])[:80],
                "assets": result.get("assets", [])[:30],
                "fetch_errors": result.get("fetch_errors", [])[:20],
                "guidance": (
                    "这些只是 JS 静态线索。优先按 chains 里的 probes 用 http_request/run_shell 做真实验证；"
                    "没有实证危害不要 submit_finding。"
                ),
            }
        except Exception as e:
            return {"ok": False, "error": f"JS 分析异常: {type(e).__name__}: {e}"}

    # ---- suggest_waf_bypass（纯本地，不发网络）----
    def suggest_waf_bypass(
        self,
        payload: str,
        status_code: int | None = None,
        response_headers: Optional[dict[str, Any]] = None,
        response_body: str = "",
        context: str = "generic",
    ) -> dict[str, Any]:
        try:
            return _suggest_waf_bypass(
                payload=payload,
                status_code=status_code,
                response_headers=response_headers,
                response_body=response_body,
                context=context,
            )
        except Exception as e:
            return {"ok": False, "error": f"WAF 建议生成异常: {type(e).__name__}: {e}"}
