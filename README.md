<div align="center">

```
    ___         __        __  __            __
   /   | __  __/ /_____  / / / /_  ______  / /____  _____
  / /| |/ / / / __/ __ \/ / / /_/ / / / / __ \/ __/ _ \/ ___/
 / ___ / /_/ / /_/ /_/ / __  / /_/ / / / / /_/  __/ /
/_/  |_\__,_/\__/\____/_/ /_/\__,_/_/ /_/\__/\___/_/
```

**AutoHunter — AI 自主漏洞挖掘平台**

多 Agent 协同 · 24×7 自动挖洞 · 人工只做复审决策

`锁定 · 侦察 · 出洞`

Powered By **StanleyNull** ·  · License: CC BY-NC 4.0

</div>

---

## 这是什么

AutoHunter 是一个**多 Agent 协同的自动化漏洞挖掘系统**。你把一台机器交给它当作 7×24 小时不停歇的挖洞平台，自己只做「人工复审员」：

```
Collector（搜集）  →  Worker（1:1 真实挖洞）  →  Reviewer（AI 初审去垃圾）  →  人工复审 → 待提交
     ↑ FOFA/手动录目标        ↑ LLM + 真实工具链（nmap/nuclei/sqlmap/httpx/JS 分析…）
```

- **Collector**：从 FOFA 持续产出目标，探活、预筛、评分、归属标注后入队。
- **Worker**：每个目标一个 Worker，LLM 自主侦察 + 调用真实工具挖洞，出洞即提交。
- **Reviewer**：极理性 AI 初审，过滤半成品/误报，只把够格的洞送到人工面前。
- **控制台**：实时看板一眼看清每个 Worker 在干什么、目标优先级、事件流；结果区高效复审、编辑、标记提交。

> ⚠️ **仅限对已获明确书面授权的目标使用。** 本工具遵循 CC BY-NC 4.0，禁止商用。滥用后果自负。

---

## 一键部署（推荐）

> 前置：一台 Linux 服务器（2C4G 起步，磁盘 ≥ 20G），已装 [Docker](https://docs.docker.com/engine/install/) + Docker Compose v2。

```bash
# 1. 拉取代码
git clone <your-repo-url> autohunter && cd autohunter

# 2. 运行引导脚本（带字符画，交互式采集必填参数，自动生成 .env、构建并启动）
bash scripts/install.sh
```

脚本会：检查 Docker 环境 → 引导你填 **LLM API Key**（必填）、**FOFA Key**（推荐）→ 自动生成高强度访问令牌 → 构建镜像并启动 → 打印访问地址和令牌。

> 首次构建会编译前端 + 安装挖洞工具（nmap / nuclei / sqlmap / httpx / whatweb 等），约 5–15 分钟，请耐心等待。

---

## 手动部署

```bash
cp .env.example .env
# 编辑 .env：至少填 LLM_API_KEY；建议填 FOFA_KEY 和 AUTOHUNTER_API_TOKEN
vim .env

docker compose up -d --build
docker compose logs -f autohunter   # 看启动日志
```

启动后访问 `http://<服务器IP>:18800/`，用你在 `.env` 里设置的 `AUTOHUNTER_API_TOKEN` 登录。

---

## 必填 / 推荐配置

| 变量 | 必填 | 说明 | 获取方式 |
|------|:---:|------|---------|
| `LLM_API_KEY` | ✅ **必填** | 大模型 API Key，平台核心 | [DeepSeek](https://platform.deepseek.com/) / OpenAI / 通义 / Kimi 等 |
| `LLM_BASE_URL` | 默认 DeepSeek | OpenAI 兼容接口地址（需含 `/v1`） | 默认 `https://api.deepseek.com/v1` |
| `LLM_MODEL` | 默认 deepseek-chat | 模型名 | 按模型商填 |
| `FOFA_KEY` | ⭐ 推荐 | 资产测绘，用于自动搜集目标 | [FOFA 个人中心](https://fofa.info/) |
| `AUTOHUNTER_API_TOKEN` | ⭐ 强烈建议 | 控制台全权限访问令牌，**不设则任何人可访问** | `install.sh` 自动生成，或自填随机串 |
| `AUTOHUNTER_HOST_PORT` | 默认 18800 | 对外访问端口 | 按需 |

> 其余全部参数（Worker 预算、并发、超时、WAF 等）都有合理默认值，见 `.env.example` 内注释，按需微调即可。
> 也支持**不填 `.env`、直接在控制台「设置」页填 LLM/FOFA Key**——设置会存进数据库，优先级高于 `.env`。

---

## 常用运维命令

```bash
docker compose logs -f autohunter     # 实时日志
docker compose restart autohunter     # 重启
docker compose down                    # 停止（数据保留在 volume）
docker compose up -d --build           # 更新代码后重建
```

数据持久化在 Docker volume：`ah_data`（SQLite 数据库 + 漏洞证据）、`ah_work`（Worker 临时工作区）。**升级/重启不丢数据。**

---

## 注意事项 / 避坑

- **授权边界**：只测你有权限的目标。FOFA 语法要收窄归属（域名 / 证书 / org），别让 Worker 打到范围外资产。
- **访问控制**：公网部署**务必设 `AUTOHUNTER_API_TOKEN`**，否则控制台和挖洞能力对全网裸奔。内置应用层 WAF 默认开启，但令牌是第一道门。
- **成本控制**：Worker 靠 LLM 驱动，目标越多 token 消耗越大。可用 `.env` 里的 `WORKER_MAX_ROUNDS` / `*_BUDGET_CAP` 收紧预算，或降低任务并发。
- **资源**：每个并发 Worker 会跑真实工具子进程。小内存机器请调小 `AUTOHUNTER_AGENT_THREAD_POOL_SIZE` 和任务并发数。
- **网络**：服务器需能访问 LLM API 和目标网络。若走代理，给 Docker/容器配好出网。
- **重启恢复**：`AUTOHUNTER_RESTORE_ON_STARTUP=1` 时重启会自动续跑之前 running 的任务；受限机器可设 `0`，只起 Web/API。

---

## 技术栈

- 后端：Python 3.12 · FastAPI · SQLAlchemy(SQLite) · asyncio
- 前端：Vue 3 · Vite
- 模型：任意 OpenAI 兼容接口（DeepSeek / OpenAI / 通义 / Kimi …）
- 工具链（容器内置）：nmap · nuclei · sqlmap · httpx · whatweb · curl/wget/jq 等

---

## 许可协议

本项目采用 **[CC BY-NC 4.0](./LICENSE)**（署名-非商业性使用）：

- ✅ 可自由使用、修改、二次分发
- ✅ **必须保留原作者署名**：`Powered By StanleyNull ()`
- ❌ **禁止任何商业用途**

---

<div align="center">

**Powered By StanleyNull** · 

*仅供授权安全测试与研究 · 请遵守当地法律法规*

</div>
