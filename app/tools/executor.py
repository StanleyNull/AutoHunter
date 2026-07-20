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
import sqlite3
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
# 代理服务器被标记为不健康后的冷却时间（秒）。冷却结束后重新纳入轮询候选。
# 轮询策略：每次请求后轮转到下一台健康代理，分散流量降低单 IP 被目标 WAF 封禁概率。
_PROXY_UNHEALTHY_COOLDOWN = int(os.environ.get("PROXY_UNHEALTHY_COOLDOWN", "60"))
# 连续失败多少次才标记不健康（避免单次网络抖动误杀）。
_PROXY_FAIL_THRESHOLD = 2

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


def _normalize_headers(headers: Any) -> dict[str, str]:
    """把 LLM 可能乱传的 headers 统一成 {str: str}，容错非 dict 形态，绝不抛异常。

    支持：
      - dict            → 原样（值转字符串）
      - list["K: V"]    → 逐行按第一个冒号切分
      - "K: V\\nK2: V2"  → 按行切分
      - None / 其它      → {}
    """
    if not headers:
        return {}
    if isinstance(headers, dict):
        return {str(k): str(v) for k, v in headers.items()}
    lines: list[str] = []
    if isinstance(headers, str):
        lines = headers.splitlines()
    elif isinstance(headers, (list, tuple)):
        for item in headers:
            if isinstance(item, dict):
                if "name" in item and "value" in item:
                    lines.append(f"{item['name']}: {item['value']}")
                else:
                    lines.extend(f"{k}: {v}" for k, v in item.items())
            else:
                lines.append(str(item))
    else:
        return {}
    out: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        if k:
            out[k] = v.strip()
    return out


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
        # 会话态：worker 登录/拿到 token 后自动携带到后续 http_request，
        # 解决"明明登进去了，深挖请求却忘带凭证导致越权失败"的断链问题。
        # 每个 target 独立 executor 实例、session jar 相互隔离，不会串号。
        # 全模式启用（登录后同样必须带登录态深入）。
        self._session_cookies: dict[str, str] = {}
        self._session_headers: dict[str, str] = {}
        # 工作笔记：worker 用 update_notes 工具维护，每轮注入回 messages，
        # 解决"历史压缩后忘了自己发现过什么"的连续性断裂问题。
        self._worker_notes: str = ""

        # 代理模式：本地 IP 被目标 WAF 封禁后，http_request 透明改走 SSH 代理，
        # 保留同一 worker 的上下文与会话态（cookie jar 原地延续），无需重派。
        self.proxy_mode = False
        self._proxy_config = None
        self._proxy_server_idx = 0
        # 代理服务器健康表：{server: {"failures": int, "last_fail": float, "healthy": bool}}
        # 轮询时跳过不健康的服务器（冷却期过后自动恢复），分散流量降低封禁概率。
        self._proxy_health: dict[str, dict] = {}
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
        try:
            timeout = int(timeout) if timeout else worker_config.shell_timeout
        except (TypeError, ValueError):
            timeout = worker_config.shell_timeout
        # 硬上限 + 下限：防 LLM 传超大/非法 timeout 长期占用 worker 槽位（DoS）。
        timeout = max(1, min(timeout, worker_config.shell_timeout_max))
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
        if self.proxy_mode:
            return self._http_request_via_proxy(
                url=url, method=method, headers=headers, data=data,
                json_body=json_body, follow_redirects=follow_redirects, timeout=timeout,
            )
        # LLM 可能把 headers 传成非 dict 形态（list["K: V"] / "K: V\nK2: V2" / None），
        # 直接喂给 dict()/httpx 会抛 "dictionary update sequence element..." 崩掉整个 agent。
        # 这里统一规范化成 dict，容错所有 agent 的 http_request 调用。
        headers = _normalize_headers(headers)
        # 会话保持：把已维持的 cookie/header 合并进本次请求（用户传的同名键优先）。
        merged_headers, session_applied = self._apply_session(headers)

        req: httpx.Request | None = None
        try:
            # 用持久 cookie jar 的 Client：跟随重定向时 httpx 会自动把每一跳 Set-Cookie
            # 存进 jar 并在后续跳转/同域请求里带上——这是走通 CAS/SSO 这类
            # 「302 连环跳 + 每跳发新 Cookie（lt→CASTGC→ST ticket→JSESSIONID）」登录链的关键。
            # 之前每次新建无 jar 的 Client + 只读最终 resp.cookies，会丢掉中间跳的 CASTGC/跨域
            # JSESSIONID，导致「明明账号对却始终登不进、没法进系统深挖」。
            with httpx.Client(verify=False, follow_redirects=follow_redirects, timeout=timeout) as client:
                # 先把已维持的 session cookie 灌进 client jar，重定向跳转时自动携带。
                for _ck, _cv in self._session_cookies.items():
                    try:
                        client.cookies.set(_ck, _cv)
                    except Exception:
                        pass
                req = client.build_request(
                    method.upper(), url, headers=merged_headers, content=data, json=json_body
                )
                resp = client.send(req, stream=True)
                body, truncated = self._read_limited_response(resp)
                # 吸收整条重定向链（resp.history 里每个中间 302 + 最终响应）的 Set-Cookie，
                # 而不是只读最终 resp.cookies；再兜底吸收 client.cookies jar 里的全部。
                session_updated = self._absorb_redirect_chain(resp, client)
        except Exception as e:
            return {"ok": False, "error": f"HTTP 请求异常: {e}", "url": url}

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
        # 跟随重定向时给出跳转链摘要，方便 agent 看清 CAS/SSO 登录流程走到哪、最终落在哪。
        try:
            hist = list(getattr(resp, "history", []) or [])
            if hist:
                chain = [f"{h.status_code} {h.request.method} {str(h.url)}" for h in hist]
                chain.append(f"{resp.status_code} {resp.request.method} {str(resp.url)}")
                result["redirect_chain"] = chain[:12]
                result["final_url"] = str(resp.url)
        except Exception:
            pass
        if session_applied:
            result["session_applied"] = session_applied
        if session_updated:
            result["session_cookies_updated"] = session_updated
        return result

    # ---- 代理模式（IP 封禁时透明走 SSH 代理）----
    def enable_proxy_mode(self) -> dict[str, Any]:
        """切换为代理模式：后续 http_request 自动经 SSH 代理发送。

        worker 交叉验证确认本地 IP 被目标 WAF 封禁后调用。切换后 http_request
        透明走代理，LLM 无需改用 run_shell+ssh curl，上下文与会话态原地保留。
        """
        from app.settings_service import resolve_proxy_config
        cfg = resolve_proxy_config()
        if not cfg.available:
            return {
                "ok": False,
                "error": "无可用代理服务器，无法切换代理模式",
                "guidance": "未配置 SSH 代理。调用 finish(verdict=ip_banned) 将目标标记为 IP 封禁，等待后续重测。",
            }
        self._proxy_config = cfg
        self.proxy_mode = True
        return {
            "ok": True,
            "message": "已切换到代理模式，后续 http_request 将自动通过 SSH 代理发送。"
                        "多台代理自动轮询分发，降低单 IP 被封概率。"
                        "继续用 http_request 正常测试即可，无需手动 ssh curl。",
            "proxy_servers": cfg.server_list,
            "guidance": "现在所有 http_request 自动走代理。继续正常挖掘；"
                        "若代理请求也持续失败（所有代理服务器不可达），再调用 finish(verdict=ip_banned)。",
        }

    def _http_request_via_proxy(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[dict[str, str]] = None,
        data: Optional[str] = None,
        json_body: Optional[Any] = None,
        follow_redirects: bool = False,
        timeout: int = 20,
    ) -> dict[str, Any]:
        """通过 SSH 代理发送 HTTP 请求，返回与 http_request 一致的结果结构。

        用 curl -D /dev/stderr -o /dev/stdout -w 把响应头(body 前的 stderr)和
        响应体(stdout)分离，尾部追加状态码标记。多台代理服务器按轮询+健康度策略
        自动分发：每次请求后轮转到下一台健康代理（分散流量降低单 IP 被封概率），
        某台连续失败则标记不健康并冷却跳过，全部不可达才报失败。
        """
        cfg = self._proxy_config
        if not cfg or not cfg.available:
            return {"ok": False, "error": "代理模式未启用或无可用代理", "url": url}

        headers = _normalize_headers(headers)
        merged_headers, session_applied = self._apply_session(headers)

        # 请求体序列化
        body_data: Optional[str] = None
        if data is not None:
            body_data = str(data)
        elif json_body is not None:
            import json as _json
            body_data = _json.dumps(json_body, ensure_ascii=False)
            if not any(k.lower() == "content-type" for k in merged_headers):
                merged_headers["Content-Type"] = "application/json"

        method_up = method.upper()
        servers = list(cfg.server_list)
        key_path = cfg.ssh_key_path
        last_error = ""

        # 轮询+健康度：_pick_proxy_servers 返回健康代理优先的轮序，
        # 每次成功后轮转到下一台，分散流量；连续失败的自动冷却跳过。
        for srv in self._pick_proxy_servers(servers):
            if ":" in srv.split("@")[-1]:
                user_host, port = srv.rsplit(":", 1)
            else:
                user_host, port = srv, "22"

            # 构造远程 curl 命令：头→stderr，体+状态码标记→stdout
            curl_parts = ["curl", "-s", "-S", "-k", "--connect-timeout", "8"]
            if follow_redirects:
                curl_parts.append("-L")
            curl_parts += [
                "--max-time", str(int(timeout)),
                "-D", "/dev/stderr", "-o", "/dev/stdout",
                "-w", r"\n<<<HTTP_STATUS:%{http_code}>>>",
                "-X", method_up,
            ]
            for k, v in merged_headers.items():
                curl_parts += ["-H", f"{k}: {v}"]
            if body_data is not None:
                curl_parts += ["-d", body_data]
            curl_parts.append(url)

            remote_cmd = " ".join(shlex.quote(p) for p in curl_parts)
            ssh_cmd = [
                "ssh", "-i", key_path,
                "-o", "StrictHostKeyChecking=no",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=5",
                "-p", port, user_host,
                remote_cmd,
            ]

            try:
                result = subprocess.run(
                    ssh_cmd, capture_output=True, timeout=timeout + 15,
                )
            except subprocess.TimeoutExpired:
                last_error = f"代理 {srv} 超时"
                self._mark_proxy_unhealthy(srv)
                continue
            except Exception as e:
                last_error = f"代理 {srv} 异常: {e}"
                self._mark_proxy_unhealthy(srv)
                continue

            out = (result.stdout or b"").decode("utf-8", "replace")
            err = (result.stderr or b"").decode("utf-8", "replace")

            # 解析状态码标记
            marker = "<<<HTTP_STATUS:"
            pos = out.rfind(marker)
            status_code = 0
            body_text = out
            if pos >= 0:
                end = out.find(">>>", pos)
                if end > pos:
                    code_str = out[pos + len(marker):end].strip()
                    if code_str.isdigit():
                        status_code = int(code_str)
                    body_text = out[:pos].rstrip("\n")

            if status_code == 0:
                # 连接失败（curl 未拿到任何 HTTP 响应）→ 换下一台代理
                last_error = f"代理 {srv} 连接失败: {err[:200]}"
                self._mark_proxy_unhealthy(srv)
                continue

            # 成功：标记健康 + 轮转到下一台代理（分散流量，降低单 IP 被封概率）
            self._mark_proxy_healthy(srv)
            self._proxy_server_idx = (servers.index(srv) + 1) % len(servers)

            resp_headers, redirect_chain, session_updated = self._parse_proxy_headers(err)

            # 截断响应体（与本地 http_request 一致的上限）
            truncated = False
            if len(body_text) > _HTTP_MAX_BYTES:
                body_text = (
                    body_text[:_HTTP_MAX_BYTES]
                    + f"\n\n...[响应超过 {_HTTP_MAX_BYTES} 字节，已截断以保护内存]..."
                )
                truncated = True
            body_out = _truncate(body_text)

            # 构造取证用原始请求行
            raw_req_lines = [f"{method_up} {url} HTTP/1.1"]
            for k, v in merged_headers.items():
                raw_req_lines.append(f"{k}: {v}")
            if body_data is not None:
                raw_req_lines.append("")
                raw_req_lines.append(body_data[:512])
            raw_req = "\n".join(raw_req_lines)

            result_dict: dict[str, Any] = {
                "ok": True,
                "status_code": status_code,
                "url": url,
                "response_headers": resp_headers,
                "body": body_out,
                "body_len": len(body_text),
                "body_truncated": truncated,
                "raw_request": _truncate(raw_req, 1536),
                "via_proxy": True,
                "proxy_server": srv,
            }
            if redirect_chain:
                result_dict["redirect_chain"] = redirect_chain
            if session_applied:
                result_dict["session_applied"] = session_applied
            if session_updated:
                result_dict["session_cookies_updated"] = session_updated
            return result_dict

        # 所有代理服务器都不可达
        return {
            "ok": False,
            "error": f"所有代理服务器均不可达: {last_error}",
            "url": url,
            "via_proxy": True,
            "guidance": "所有代理服务器都无法连接目标。若目标本身存活（探活服务器可达），"
                        "调用 finish(verdict=ip_banned) 等待后续重测。",
        }

    def _pick_proxy_servers(self, servers: list[str]) -> list[str]:
        """返回按轮询+健康度排序的代理服务器候选列表。

        健康的服务器优先、按当前轮转索引排列；不健康的排后（冷却期过后自动恢复）。
        全部不健康时返回全部（兜底：仍然尝试，成功则恢复健康）。
        """
        now = time.time()
        healthy: list[str] = []
        unhealthy: list[str] = []
        n = len(servers)
        for offset in range(n):
            idx = (self._proxy_server_idx + offset) % n
            srv = servers[idx]
            h = self._proxy_health.get(srv)
            if h and not h.get("healthy", True):
                # 冷却期结束 → 恢复健康
                if (now - h.get("last_fail", 0)) >= _PROXY_UNHEALTHY_COOLDOWN:
                    h["healthy"] = True
                    h["failures"] = 0
            if self._proxy_health.get(srv, {}).get("healthy", True):
                healthy.append(srv)
            else:
                unhealthy.append(srv)
        # 健康优先；全不健康时兜底尝试全部
        return healthy + unhealthy

    def _mark_proxy_healthy(self, server: str) -> None:
        """代理请求成功：重置失败计数，标记健康。"""
        h = self._proxy_health.get(server)
        if h:
            h["failures"] = 0
            h["healthy"] = True

    def _mark_proxy_unhealthy(self, server: str) -> None:
        """代理请求失败：累计失败次数，超过阈值则标记不健康（冷却期内跳过）。"""
        h = self._proxy_health.setdefault(
            server, {"failures": 0, "last_fail": 0, "healthy": True}
        )
        h["failures"] = h.get("failures", 0) + 1
        h["last_fail"] = time.time()
        if h["failures"] >= _PROXY_FAIL_THRESHOLD:
            h["healthy"] = False

    def _parse_proxy_headers(self, raw: str) -> tuple[dict[str, str], list[str], list[str]]:
        """解析 curl -D 输出的响应头流，返回 (最终响应头, 重定向状态码链, 更新的cookie名)。

        curl -D /dev/stderr 把每个响应（含重定向中间跳）的头块依次写入 stderr，
        块间以空行分隔。取最后一个块作为最终响应头；遍历所有块的 Set-Cookie 吸收进 session。
        """
        resp_headers: dict[str, str] = {}
        redirect_chain: list[str] = []
        updated: list[str] = []
        norm = raw.replace("\r\n", "\n").replace("\r", "\n")
        blocks = [b for b in norm.split("\n\n") if b.strip()]
        for block in blocks:
            lines = block.strip().split("\n")
            if not lines:
                continue
            # 状态行 HTTP/x.y CODE TEXT
            first = lines[0]
            parts = first.split(" ", 2)
            if len(parts) >= 2 and parts[0].upper().startswith("HTTP"):
                redirect_chain.append(parts[1])
            hdrs: dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    k = k.strip()
                    v = v.strip()
                    if not k:
                        continue
                    hdrs[k] = v
                    if k.lower() == "set-cookie":
                        cv = v.split(";")[0].strip()
                        if "=" in cv:
                            cn, cval = cv.split("=", 1)
                            self._put_cookie(cn.strip(), cval.strip(), updated)
            if hdrs:
                resp_headers = hdrs
        return resp_headers, redirect_chain, updated

    # ---- 会话状态管理（全模式）----
    def _apply_session(self, headers: Optional[dict[str, str]]) -> tuple[dict[str, str], list[str]]:
        """把维持的 session cookie/header 合并进请求头。返回 (合并后headers, 应用了哪些)。

        合并规则：用户本次显式传入的头优先（不被 session 覆盖），保证可手动覆写。
        会话为空时原样返回、零开销；全模式启用。
        """
        if not self._session_cookies and not self._session_headers:
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

    def _put_cookie(self, name: str, value: str, updated: list[str]) -> None:
        if name in self._session_cookies:
            self._session_cookies[name] = value
            if name not in updated:
                updated.append(name)
        elif len(self._session_cookies) < _SESSION_MAX_COOKIES:
            self._session_cookies[name] = value
            if name not in updated:
                updated.append(name)

    def _absorb_set_cookie(self, resp: httpx.Response) -> list[str]:
        """从单个响应吸收 Set-Cookie 进 session jar（带数量上限防爆内存）。"""
        try:
            updated: list[str] = []
            for name, value in resp.cookies.items():
                self._put_cookie(name, value, updated)
            return updated
        except Exception:
            return []

    def _absorb_redirect_chain(self, resp: httpx.Response, client: "httpx.Client") -> list[str]:
        """吸收整条重定向链上每一跳的 Set-Cookie（CAS/SSO 登录链的关键）。

        httpx 跟随重定向时，中间的每个 302 响应都在 resp.history 里。CAS 登录的
        CASTGC / 跨域 JSESSIONID 往往就发在这些中间跳上；只读最终 resp.cookies 会漏。
        再用 client.cookies jar 兜底（httpx 已把整条链的 cookie 归并进 jar）。
        """
        updated: list[str] = []
        try:
            for hist in list(getattr(resp, "history", []) or []):
                try:
                    for name, value in hist.cookies.items():
                        self._put_cookie(name, value, updated)
                except Exception:
                    pass
            for name, value in resp.cookies.items():
                self._put_cookie(name, value, updated)
            try:
                for ck in client.cookies.jar:
                    if ck.name and ck.value:
                        self._put_cookie(ck.name, ck.value, updated)
            except Exception:
                pass
        except Exception:
            pass
        return updated

    def session_set(
        self,
        cookies: Optional[dict[str, str]] = None,
        headers: Optional[dict[str, str]] = None,
        clear: bool = False,
    ) -> dict[str, Any]:
        """worker 显式设置/查看会话态：手动登记拿到的 token/cookie，后续自动携带。全模式可用。"""
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

    # ---- 工作笔记（跨轮持久记忆）----
    def update_notes(self, notes: str = "") -> dict[str, Any]:
        """worker 更新工作笔记。笔记每轮注入回 messages，不受历史压缩影响。"""
        self._worker_notes = (notes or "").strip()[:4000]
        return {"ok": True, "notes_len": len(self._worker_notes)}

    def session_status_block(self) -> str:
        """生成当前会话态 + 工作笔记的摘要块，供 worker 每轮注入 messages。

        这是连续性的核心：即使历史被压缩成摘要、即使过了 30 轮，worker 仍能
        '看到'自己当前持有哪些 cookie/header（登录态不断）、以及自己记录的关键
        进度（端点/凭据/已试方向/下一步计划），不会重复扫同一条路。
        """
        lines = ["# 当前状态（跨轮持久，每轮自动注入）"]
        cookies = sorted(self._session_cookies.keys()) if self._session_cookies else []
        headers = sorted(self._session_headers.keys()) if self._session_headers else []
        if cookies or headers:
            lines.append(f"- 会话态：持有 cookie {cookies}，鉴权头 {headers}（http_request 自动携带）")
        else:
            lines.append("- 会话态：暂无登录态（拿到凭证后用 session_set 登记）")
        if self._worker_notes:
            lines.append("- 工作笔记：")
            lines.append(self._worker_notes)
        else:
            lines.append("- 工作笔记：（暂无。发现端点/凭据/token/突破口后用 update_notes 记录，否则跨轮会忘）")
        return "\n".join(lines) + "\n\n"

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

    # ---- knowledge_lookup（人工知识库查阅，渐进式披露）----
    def knowledge_lookup(
        self,
        doc_id: str = "",
        vuln_found: bool = False,
        vuln_type: str = "",
    ) -> dict[str, Any]:
        """查阅人工知识库技巧文档。

        两步渐进式披露：
        - 传 doc_id → 返回该文档完整原文（第二步）
        - 不传 doc_id → 按是否发现漏洞筛选，返回标题+摘要列表（第一步）

        使用同步 sqlite3 直查（executor 运行在线程池中，WAL 模式并发安全）。
        """
        db_path = os.environ.get(
            "DB_PATH",
            str(Path(__file__).resolve().parent.parent.parent / "data" / "autohunter.db"),
        )
        try:
            conn = sqlite3.connect(db_path, timeout=5)
            conn.row_factory = sqlite3.Row

            # 第二步：获取完整原文
            if doc_id:
                row = conn.execute(
                    "SELECT id, title, summary, content, doc_type, tags, hit_count "
                    "FROM knowledge_docs WHERE id = ? AND enabled = 1",
                    (doc_id,),
                ).fetchone()
                conn.close()
                if not row:
                    return {"ok": False, "error": "文档不存在或未启用"}
                # 增加引用计数（best-effort，失败不影响读取）
                try:
                    conn2 = sqlite3.connect(db_path, timeout=5)
                    conn2.execute(
                        "UPDATE knowledge_docs SET hit_count = hit_count + 1 WHERE id = ?",
                        (doc_id,),
                    )
                    conn2.commit()
                    conn2.close()
                except Exception:
                    pass
                import json as _json
                return {
                    "ok": True,
                    "doc_id": row["id"],
                    "title": row["title"],
                    "summary": row["summary"],
                    "content": row["content"][:8000],  # 截断防 context 爆炸
                    "doc_type": row["doc_type"],
                    "tags": _json.loads(row["tags"]) if row["tags"] else [],
                    "hit_count": row["hit_count"],
                    "guidance": "这是辅助参考技巧，请结合目标实际情况独立判断，不要盲目照搬。",
                }

            # 第一步：返回筛选后的标题+摘要列表
            # vuln_found=false → 只返回 pre_vuln 文档
            # vuln_found=true  → 返回 pre_vuln + post_vuln 文档，按 vuln_type 标签匹配优先排序
            if vuln_found:
                query = (
                    "SELECT id, title, summary, doc_type, tags, hit_count "
                    "FROM knowledge_docs WHERE enabled = 1 "
                    "ORDER BY hit_count DESC LIMIT 30"
                )
            else:
                query = (
                    "SELECT id, title, summary, doc_type, tags, hit_count "
                    "FROM knowledge_docs WHERE enabled = 1 AND doc_type = 'pre_vuln' "
                    "ORDER BY hit_count DESC LIMIT 30"
                )
            rows = conn.execute(query).fetchall()
            conn.close()

            import json as _json
            docs = []
            for r in rows:
                tags = _json.loads(r["tags"]) if r["tags"] else []
                docs.append({
                    "doc_id": r["id"],
                    "title": r["title"],
                    "summary": r["summary"],
                    "doc_type": r["doc_type"],
                    "tags": tags,
                    "hit_count": r["hit_count"],
                })

            # 如果有 vuln_type，按标签匹配度排序（匹配的排前面）
            if vuln_type and docs:
                vt_lower = vuln_type.lower()
                docs.sort(
                    key=lambda d: (
                        0 if any(vt_lower in str(t).lower() for t in d.get("tags", [])) else 1,
                        -d.get("hit_count", 0),
                    )
                )

            # 收集所有可用标签（去重排序），供AI参考
            all_tags = sorted({str(t) for d in docs for t in d.get("tags", [])})

            return {
                "ok": True,
                "total": len(docs),
                "docs": docs,
                "available_tags": all_tags,
                "guidance": (
                    "以上是知识库中匹配的技巧文档摘要。选择你需要的文档，用 doc_id 参数获取完整原文。"
                    "available_tags 是当前知识库中所有可用标签，可用于判断文档覆盖范围。"
                    "知识库仅作辅助参考，请结合目标实际情况独立判断。"
                ),
            }
        except Exception as e:
            return {"ok": False, "error": f"知识库查询异常: {type(e).__name__}: {e}"}
