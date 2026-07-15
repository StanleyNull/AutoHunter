"""命令安全防护：只拦截会自毁运行环境的命令，不拦攻击类命令。

设计原则（对应设计文档 §11.1）：
- 无利用限制：攻击 payload、扫描、爆破等一律放行。
- 仅拦"自毁"：rm -rf /、关闭 redis/pg、改系统配置、关机重启等会搞垮容器/本机的操作。
"""
from __future__ import annotations

import re

# 会自毁运行环境的命令模式（大小写不敏感）。仅拦这些，不拦攻击。
_SELF_DESTRUCT_PATTERNS = [
    r"\brm\s+-rf\s+(/|/\*|~|\$HOME)\b",          # 删根目录/家目录
    r"\brm\s+-rf\s+--no-preserve-root",
    r":\(\)\s*\{\s*:\|:&\s*\}\s*;",               # fork 炸弹
    r"\bmkfs\b",                                   # 格式化
    r"\bdd\s+if=.*of=/dev/(sd|disk|nvme)",        # 覆写磁盘
    r">\s*/dev/(sd|disk|nvme)",
    r"\bshutdown\b", r"\breboot\b", r"\bhalt\b", r"\bpoweroff\b",
    r"\binit\s+0\b", r"\binit\s+6\b",
    # 关闭本机/容器内的依赖服务（会让平台自身挂掉）
    r"\b(systemctl|service)\s+(stop|disable)\s+(redis|postgres|postgresql)\b",
    r"\b(redis-cli\s+shutdown)\b",
    r"\bpg_ctl\s+stop\b",
    r"\bkillall\b", r"\bpkill\s+-9\s+-1\b",
    # 篡改系统认证/配置
    r">\s*/etc/(passwd|shadow|sudoers|hosts)\b",
    r"\bchmod\s+-R\s+000\s+/\b",
    # pip install 安装会破坏运行时的危险包（pyppeteer/selenium/undetected-chromedriver
    # 依赖无约束的旧版 websockets，会将其降级到 <13，导致 uvicorn 崩溃）
    r"\bpip3?\s+install\b.*\b(pyppeteer|selenium|undetected[_-]chromedriver)\b",
    r"\bpython3?\s+-m\s+pip\s+install\b.*\b(pyppeteer|selenium|undetected[_-]chromedriver)\b",
    # 直接修改/卸载运行时核心包（websockets/uvicorn/fastapi 等）
    r"\bpip3?\s+(install|uninstall)\b.*\b(websockets|uvicorn|fastapi|sqlalchemy|aiosqlite|greenlet)\b",
    r"\bpython3?\s+-m\s+pip\s+(install|uninstall)\b.*\b(websockets|uvicorn|fastapi|sqlalchemy|aiosqlite|greenlet)\b",
]

# 拦截 pip install 危险包时的指导信息
_DANGEROUS_PIP_MSG = (
    "禁止在容器内 pip install pyppeteer/selenium/undetected-chromedriver 等包："
    "它们会无约束拉旧版 websockets，导致 uvicorn 启动崩溃（ServerProtocol 导入失败）。"
    "如需浏览器自动化，请将 playwright 加入 requirements.txt 并重新构建镜像。"
)

_COMPILED = [re.compile(p, re.IGNORECASE) for p in _SELF_DESTRUCT_PATTERNS]

# 企业模式专属：拦截对【目标生产环境】的破坏性/不可逆操作。
# 企业是真实生产资产，证明漏洞存在即可，绝不实际造成数据/业务/服务损害。
# 仅在 src_type=enterprise 时启用；edu/靶场不受此限。
_ENTERPRISE_DANGER_PATTERNS = [
    # SQL 写/删/库结构破坏（拦截 sqlmap dump 全库 + 直接 DML/DDL）
    (r"\bsqlmap\b.*--(dump-all|dump\b|os-shell|file-write|sql-shell)",
     "禁止 sqlmap --dump/--dump-all/--os-shell/--file-write/--sql-shell：企业生产库只做存在性验证（布尔/延时/读单条），不批量拖库、不写入。"),
    (r"\b(drop|truncate)\s+(table|database)\b", "禁止 DROP/TRUNCATE：不破坏企业生产库结构。"),
    (r"\bdelete\s+from\b", "禁止 DELETE FROM：不删除企业生产数据。"),
    (r"\b(insert\s+into|update\s+\w+\s+set)\b", "禁止 INSERT/UPDATE 写操作：企业生产数据只读验证，不写入篡改。"),
    # 改密码/重置凭证（铁律：拿到只读不动）
    (r"\b(set\s+password|alter\s+user|update\s+.*\bpassword\b\s*=)", "禁止修改任何密码/凭证：企业模式只读取记录，绝不改密。"),
    (r"\bpasswd\b\s+\w+", "禁止 passwd 改密。"),
    # 持久化/落 webshell（只做无害探针，不留后门）
    (r"(weevely|antsword|behinder|冰蝎|哥斯拉|godzilla)", "禁止上传/连接 webshell 管理工具：企业模式不落持久后门。"),
    (r"\b(crontab|/etc/cron|systemctl\s+enable|nohup)\b.*(curl|wget|bash|sh\s)", "禁止植入定时任务/开机自启后门。"),
    # 大规模爆破/压测（点到为止，不伤害服务）
    (r"\bhydra\b", "禁止 hydra 大规模爆破：企业模式弱口令尝试点到为止（少量高命中组合）。"),
    (r"\bmedusa\b", "禁止 medusa 大规模爆破。"),
    (r"\b(ab|wrk|siege)\s+-", "禁止压测工具（ab/wrk/siege）：不对企业生产服务做压力/DoS。"),
    (r"-w\s+\S*(rockyou|big\.txt|10k|100k|million)", "禁止超大字典爆破：企业模式不跑大字典暴力。"),
]

_ENTERPRISE_COMPILED = [(re.compile(p, re.IGNORECASE), msg) for p, msg in _ENTERPRISE_DANGER_PATTERNS]


class CommandBlocked(Exception):
    pass


def check_command(cmd: str, enterprise: bool = False) -> None:
    """命中自毁模式则抛 CommandBlocked，否则放行。
    enterprise=True 时额外拦截对企业生产环境的破坏性/不可逆操作。"""
    for pat in _COMPILED:
        if pat.search(cmd):
            hint = ""
            low = cmd.lower()
            if "pip" in low and "install" in low:
                hint = f"\n指导：{_DANGEROUS_PIP_MSG}"
            elif "pip" in low and "uninstall" in low:
                hint = "\n指导：禁止卸载运行时核心包，会破坏容器环境。"
            raise CommandBlocked(
                f"命令被安全防护拦截（疑似自毁运行环境，非攻击限制）：匹配模式 {pat.pattern}{hint}"
            )
    if enterprise:
        for pat, msg in _ENTERPRISE_COMPILED:
            if pat.search(cmd):
                raise CommandBlocked(
                    f"企业生产环境危险操作被拦截：{msg} 请改为非破坏性的存在性验证。"
                )
