<div align="center">

<img src="assets/banner.png" alt="AutoHunter" width="880">

多 Agent 协同 · 24×7 自动挖洞 · 人工只做复审决策

`锁定 · 侦察 · 出洞`

Powered By **StanleyNull** · QQ 754276250 · License: CC BY-NC 4.0

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

## 各平台环境准备

AutoHunter 全程基于 **Docker + Docker Compose v2** 运行，任意装得上 Docker 的系统都能跑。下面按平台给出准备步骤，装好 Docker 后统一走 [一键部署](#一键部署推荐) 或 [手动部署](#手动部署)。

<details open>
<summary><b>🐧 Linux 服务器（推荐，Ubuntu / Debian / CentOS）</b></summary>

生产环境首选。2C4G 起步，磁盘 ≥ 20G。

```bash
# 1. 安装 Docker（官方一键脚本，适配主流发行版）
curl -fsSL https://get.docker.com | sh
sudo systemctl enable --now docker

# 2. 把当前用户加入 docker 组（免 sudo，重登生效）
sudo usermod -aG docker $USER && newgrp docker

# 3. 验证
docker version && docker compose version

# 4. 拉代码 + 部署
git clone https://github.com/StanleyNull/AutoHunter.git autohunter && cd autohunter
bash scripts/install.sh
```

**开放端口**（默认 18800）：

```bash
# Ubuntu/Debian(ufw)
sudo ufw allow 18800/tcp
# CentOS/RHEL(firewalld)
sudo firewall-cmd --permanent --add-port=18800/tcp && sudo firewall-cmd --reload
```

> 云服务器还需在厂商**安全组**里放行 18800（或你自定义的 `AUTOHUNTER_HOST_PORT`）。

**SSH 断开后仍要运行**：容器由 Docker 守护，`docker compose up -d` 已是后台运行，关掉 SSH 不影响。可选设开机自启见下方 [服务器长期运行](#服务器长期运行--开机自启)。

</details>

<details>
<summary><b>🪟 Windows（Docker Desktop + WSL2）</b></summary>

适合本地跑 / 自用。Windows 10/11 均可。

1. **装 WSL2**（管理员 PowerShell）：
   ```powershell
   wsl --install
   ```
   装完重启。

2. **装 [Docker Desktop](https://www.docker.com/products/docker-desktop/)**：安装时勾选 “Use WSL 2 based engine”，启动后在 Settings → Resources → WSL Integration 打开集成。

3. **拉代码 + 部署**（在 PowerShell 或 WSL 终端里）：
   ```powershell
   git clone https://github.com/StanleyNull/AutoHunter.git autohunter
   cd autohunter
   bash scripts/install.sh
   ```
   > `install.sh` 是 bash 脚本，在 **WSL / Git Bash** 里跑最顺。若只用 PowerShell，也可走 [手动部署](#手动部署)：`copy .env.example .env`，编辑后 `docker compose up -d --build`。

4. 浏览器访问 `http://localhost:18800/`。

> 💡 Windows 下代码放在 **WSL 文件系统内**（如 `~/autohunter`）比放在 `C:\` 挂载盘性能好很多。

</details>

<details>
<summary><b>🍎 macOS（Docker Desktop）</b></summary>

1. 装 [Docker Desktop for Mac](https://www.docker.com/products/docker-desktop/)（Apple Silicon / Intel 均支持），启动它。
2. 部署：
   ```bash
   git clone https://github.com/StanleyNull/AutoHunter.git autohunter && cd autohunter
   bash scripts/install.sh
   ```
3. 访问 `http://localhost:18800/`。

</details>

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

## 创建任务：配置怎么填

登录控制台 → 「新建挖掘任务」，各字段含义如下：

| 字段 | 填什么 | 说明 |
|------|--------|------|
| **任务名称** | 随便起，方便自己区分 | 如 `edu批量挖掘-2026` |
| **任务模式** | `EduSRC` / `企业SRC` | 决定评分口径和审核标准，教育资产选 EduSRC |
| **漏洞类型** | 逗号分隔 | 默认 `sql_injection,rce,unauthorized_access,idor,file_upload,captcha_bypass`，一般不用改 |
| **目标来源** | `FOFA 自动搜` / `手动清单` / `两者` / `单站协作` | 想让它自己找目标就选 FOFA |
| **搜集方式** | `自动判断` / `FOFA 语法` / `自然语言意图` | 见下方说明 |
| **FOFA 语法 / 搜集意图** | 你的查询语句或大白话 | 见下方示例 |
| **手动目标清单** | 每行一个 URL | 选了「手动/两者/单站」时填 |

### 两种搜集方式

**① 我自己会写 FOFA 语法** → 搜集方式选 `FOFA 语法`，直接把语句粘进去。例如挖教育网（CERNET）下带「管理」后台的资产：

```text
body="管理" && org="China Education and Research Network Center"
```

**② 不会写语法，只想说要找什么** → 搜集方式选 `自然语言意图`，用大白话描述，搜集 Agent 会自动翻译成 FOFA 语法并逐轮演化。例如：

```text
找全国高校的统一身份认证登录系统
找某集团的 OA / CRM / ERP / API 网关 / 运维后台资产
```

> 留空「搜集方式」= **自动判断**：写得像语法就当语法，否则当意图，新手直接用这个即可。

### FOFA 语法速查（常用字段）

| 字段 | 含义 | 示例 |
|------|------|------|
| `title=` | 网页标题 | `title="后台管理"` |
| `body=` | 网页正文包含 | `body="管理"` |
| `domain=` | 域名 | `domain=".edu.cn"` |
| `host=` | 主机名 | `host="admin.example.com"` |
| `org=` | 所属机构（归属收窄利器） | `org="China Education and Research Network Center"` |
| `cert=` / `cert.subject.org=` | 证书信息 | `cert.subject.org="某某大学"` |
| `port=` / `country=` | 端口 / 国家 | `port="8080" && country="CN"` |

组合逻辑：`&&`（且）、`||`（或）、`!=`（非）。**语句越精确、归属越收窄，Worker 越不会打到范围外资产。**

### 高级选项（可留空，用服务端默认）

展开「高级」可**按任务单独覆盖**：模型 `base_url`/`api_key`/模型名、Worker 提示词版本、FOFA key、FOFA 最大页数、Worker 并发数。不填就继承「设置」页的全局默认。

> ⚠️ **务必收窄授权范围**：只搜你有权限测试的资产。`org` / `domain` / `cert` 是最有效的归属过滤手段。

---

## 必填 / 推荐配置

| 变量 | 必填 | 说明 | 获取方式 |
|------|:---:|------|---------|
| `LLM_API_KEY` | ✅ **必填** | 大模型 API Key，平台核心 | [DeepSeek](https://platform.deepseek.com/) / OpenAI / 通义 / Kimi 等 |
| `LLM_BASE_URL` | 默认 DeepSeek | OpenAI 兼容接口地址（需含 `/v1`） | 默认 `https://api.deepseek.com/v1` |
| `LLM_MODEL` | 默认 deepseek-chat | 模型名 | 按模型商填 |
| `FOFA_KEY` | ⭐ 推荐 | 资产测绘，用于自动搜集目标 | [FOFA 个人中心](https://fofa.info/) |
| `FOFA_BASE_URL` | 可选，默认官方地址 | 自定义 FOFA API 端点（私有部署/镜像/代理网关） | 默认 `https://fofa.info` |
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

## 服务器长期运行 / 开机自启

`docker compose up -d` 启动的容器默认已配置 `restart: unless-stopped`——**容器崩溃或服务器重启后会自动拉起**，一般无需额外操作。

若想让整套服务随系统开机、并托管给 systemd 管理，可加一个 unit：

```bash
sudo tee /etc/systemd/system/autohunter.service >/dev/null <<EOF
[Unit]
Description=AutoHunter
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$(pwd)          # 指向 autohunter 目录
ExecStart=/usr/bin/docker compose up -d --build
ExecStop=/usr/bin/docker compose down

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now autohunter
sudo systemctl status autohunter
```

**（可选）反向代理 + HTTPS**：生产环境建议前面挂一层 Nginx/Caddy，做域名 + TLS，再把 `AUTOHUNTER_HOST_PORT` 只绑到 `127.0.0.1` 不对公网直接暴露。Caddy 示例（自动签发证书）：

```caddyfile
hunt.example.com {
    reverse_proxy 127.0.0.1:18800
}
```

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
- ✅ **必须保留原作者署名**：`Powered By StanleyNull (QQ: 754276250)`
- ❌ **禁止任何商业用途**

---

<div align="center">

**Powered By StanleyNull** · QQ 754276250

*仅供授权安全测试与研究 · 请遵守当地法律法规*

</div>
