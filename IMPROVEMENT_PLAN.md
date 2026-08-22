# AutoHunter 挖洞能力提升 · 深度分析与下阶段计划

> 目标：持续提升**实际出洞命中率与命中质量**（不是度量指标）。
> 约束：每次改动单独 git 提交、提交信息语义化、代码注释不含阶段性标签（如 A1/C1）。

---

## 一、深度分析：瓶颈不在提示词，在"攻击面供给"

### 已夯实的能力（无需再动）
- **挖洞方法论成熟**：`app/agents/prompts.py` 的 `WORKER_SYSTEM_PROMPT_LEGACY` 铁律一~四明确优先逻辑洞 / IDOR / 鉴权绕过 / 扒 JS / 参数试探，黑盒为主场。
- **收敛保护健全**：`worker.py:497-800` 的 function-calling 循环带轮次上限、no_tool 自淘汰、软催收、失败自纠偏，不会空转到死。
- **强制侦察基线**（上轮 task1，`bce39d5`）：`worker.py:212-325` 先于 LLM 轮次做确定性入口测绘。
- **据点深度放开**（task2，`dcd2158`）：据点目标轮次放宽至 180/120。
- **经验回流**（task3，`883aa7c`）：攻击链模板库 + accepted 沉淀。
- **分级 + 降过杀**（task4，`07e53fe`）：强/弱模型按难度选档，低中危有证据误杀改 deepen。
- **选靶不漏好目标**：`scorer.py` 只降权不淘汰；`prefilter.py` 保守放行（拿不准就放行）。
- **去重稳健**：`dedup.py` 类型归一化 + 软匹配，不会把真洞误判成重复而丢。

### 真正限制出洞率的瓶颈（带代码证据）

**瓶颈 1 — 攻击面地图太薄（最核心）**
`worker.py:212-325` 的 `_run_mandatory_recon` 只做：首页指纹 + `robots/sitemap` + 固定 `_RECON_PROBE_PATHS`（51-58，约 30 条目录级路径）+ **仅当首页有 JS 信号时**跑一次 `analyze_javascript(url=base, max_depth=1, max_assets=60)`（296-314）。
- 不爬首页链接、不解析 `sitemap.xml` 内的 URL、不深扒 SPA 的 JS chunk（真实 API 面在 chunk 里）、不做参数级探测。
- 后果：复杂洞（IDOR、隐藏后台 API、业务逻辑端点）往往藏在落地页/固定清单之外的端点。Worker 要把宝贵轮次花在"**找面**"而不是"**打穿**"。这是最大杠杆。

**瓶颈 2 — 选靶探测结果未回流 worker**
`scorer.py:91-111` 的 `_probe_endpoints` 在打分时已探出 `actuator/swagger/druid/nacos/.git/.env` 等暴露端点，但（148-158）只进了 `priority_reason` 文本用于排序，**没有结构化回传给 worker**。Worker 又从零重新探一遍 → 重复发包 + 浪费轮次。

**瓶颈 3 — 鉴权差异化方法缺失（最高价值类直通缺口）**
按方法论，IDOR / 未授权访问 / 垂直越权是**最高价值类**，但坐实它们需要"匿名 vs 登录 vs 他人账号"三态响应差异对比。Worker 有 session 工具（`SESSION_TOOL_SCHEMAS`），但：
- prompt/attack_chain 里没有编码这套"三态对比"打法；
- 没有确定性辅助把"对暴露端点自动跑 unauth vs authed diff"喂给 worker。
这是直接抬升 accepted 率的最短路。

**瓶颈 4 — 经验库冷启动（与 task3 衔接）**
`attack_chain_templates.py` 模板库初始为空，前 N 个目标拿不到任何历史打法提示，要等回流攒够才生效。需要预置通用种子。

**瓶颈 5 — 中危复现缺口（与 task4 衔接）**
task4 把"低/中危有完整证据"的误杀改判 `deepen`，但目前复现验证仅覆盖 critical/high；中危有强证据时没轻量复现，进人工复审的洞质量仍有提升空间。

**瓶颈 6 — 被动情报未进 recon**
`fofa_lookup` 只是 worker 的可选工具（`worker.py:1077-1086`），确定性 recon 完全没用。配置 key 时可由系统前置查一次同域/同组织资产补充攻击面。

---

## 二、下阶段计划（按 ROI 排序，每个可单独提交 + 单测 + 无阶段标签）

### P0 — 最高杠杆、低风险、确定性
**计划 1：选靶信号回流 + Recon 2.0 攻击面地图**
- `scorer._probe_endpoints` 命中列表结构化进 `target_meta["exposed_endpoints"]` → 编排层透传 → worker recon 直接采用（去掉重复发包）。
- recon 增补：① `sitemap.xml` 内 URL 全解析入面；② 抓取首页全部 `<script src>` 后跑 `analyze_javascript` 提取**全量**接口（突破 `max_depth=1` 限制）；③ 轻量参数级探测（常见参数名 `id/file/url/redirect/token/page` → 对应漏洞类提示）。
- 收益：worker 轮次从"发现面"转移到"打穿"，命中率直接上升。
- 测试：`test_recon_surface_map`（sitemap 解析、JS 接口提取、参数探测、选靶回流接线）。

**计划 2：被动情报接入 recon（fofa 确定性前置）**
- 仅当配置 `fofa_key` 时，recon 阶段确定性查一次该域/同组织资产与标题/路径，补充攻击面；无 key 静默跳过。低风险、可降级。

### P1 — 高杠杆、中等工作量
**计划 3：鉴权差异化方法论 + 确定性辅助（最高价值类直通）**
- 在 attack_chain 块/prompt 编码"匿名 vs 登录 vs 他人账号"三态对比打法。
- 编排层/worker 对暴露的高价值端点自动跑 `unauth vs authed` 响应 diff，把差异直接喂 worker（401/403 端点→尝试绕过；200 端点→看是否匿名可拿数据）。直接抬升 IDOR/未授权/垂直越权的 accepted 率。

**计划 4：攻击链模板库冷启动种子**
- 预置 8–12 条**通用、不绑定具体商业产品**的成功打法：未授权 actuator→heapdump→提 DB 密码、Swagger 未授权→接口遍历、IDOR 参数试探、SSRF→内网探测、文件上传 HTML→存储 XSS、登录参数覆盖、默认/硬编码密钥伪造签名、GraphQL introspection 等。让经验库开箱有货。

### P2 — 中等杠杆、更大工作量
**计划 5：中危轻量复现（task4 闭环）**：复现验证扩展到中危有强证据时轻量复现。
**计划 6：降过杀端到端闭环**：确认 deepen 救援的洞真被重新派 worker 补证，而非只在状态间挪动。

### P3 — 探索性
**计划 7：参数级漏洞字典探测**（常见漏洞参数 → payload 直通）。
**计划 8：业务流状态机映射辅助**（register→login→order→pay→refund 流程理解，攻业务逻辑缺陷）。

---

## 三、落地顺序与提交策略
1. 先 **P0 计划 1**（最大 ROI、低风险、纯确定性、已测 recon 模块），单独 commit。
2. 每个计划：独立 commit（语义化 message），配单测，注释不含阶段标签。
3. 每完成一计划跑联动回归（复用上轮 5 个测试文件 + 新增测试），保证与已交付四项不冲突。

## 四、建议起点
从 **计划 1（选靶信号回流 + Recon 2.0）** 开始：它不动挖洞逻辑、只在"供给攻击面"上做加法，风险最低却对命中率提升最直接，且能顺便把 scorer 已探到的暴露端点利用起来（一石二鸟）。
