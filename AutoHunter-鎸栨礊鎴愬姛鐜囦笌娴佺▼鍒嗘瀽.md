# AutoHunter 挖洞成功率与工作流分析

> 分析对象：`AutoHunter`（多 Agent 协同自动化漏洞挖掘平台）  
> 代码版本：仓库根 `app/` 与嵌套 `AutoHunter-main/app/` 为同一项目两份副本（内容存在差异，根目录为较新工作副本）  
> 分析范围：Collector → Worker → Reviewer → 人工复审 → 通杀 Hunter 全流水线

---

## 0. 一句话结论

AutoHunter 的"挖洞成功率"**不是一个被系统度量的指标，而是 LLM 推理质量的函数**。它把传统人工渗透测试里"侦察—利用—验证—报告"的全过程压进了一个 LLM function-calling 循环，并用大量工程护栏（收敛、预筛、低分跳过、极理性 Reviewer）去压住"假阳性爆炸"和"token 黑洞"。结果是：**上限取决于你喂的模型和资产质量，下限被护栏兜住，但代价是会系统性漏掉"难挖但真实"的洞**。

---

## 1. 流水线全景

```
FOFA/Quake/Hunter/...  ──►  Collector（搜集+探活+打分+归属）
                                  │  prefilter 机械预筛（敏感/死链/CDN/纯静态跳过）
                                  ▼
                          Target 队列（priority_score 排序）
                                  │  orchestrator 按并发派发
                                  ▼
                        Worker（1 目标 1 Agent，LLM 自主侦察 + 工具链）
                                  │  submit_finding → Reviewer
                                  ▼
                        Reviewer（极理性初审 + 高危复现）
                                  ├─ accepted ──► 人工复审 ──► 通杀 Hunter（一打一片）
                                  ├─ deepen   ──► 回炉深挖（同一 target 拉回队首，上限 2 次）
                                  └─ ignored  ──► 丢弃
```

核心代码位置：

- `app/agents/worker.py`（1311 行）— 挖洞主循环
- `app/agents/reviewer.py`（536 行）— 初审
- `app/agents/scorer.py` — 目标优先级打分（纯关键词规则）
- `app/agents/prefilter.py` — 机械预筛
- `app/orchestrator.py`（~2700 行）— 调度、收敛、低成功率跳过、回炉
- `app/agents/killsweep.py` — 通杀扩散

---

## 2. 挖洞成功率的真正决定因素

### 2.1 模型能力（第一决定因素，占比最大）

Worker 是**纯 LLM 驱动**的 function-calling 循环（`worker.py:270` 起的主 `while rounds < max_rounds`）。它能否挖到洞，几乎完全取决于：

- 模型会不会调工具（`worker.py:380-425` 的 `no_tool_rounds` 逻辑）；
- 模型能否形成"假设→验证"的攻击链推理，而不是原地绕圈。

代码里对此有**明确兜底**：连续 6 轮不调工具 → 判定为"哑模型"，直接 `auto_finish(no_vuln)` 并提示换模型（`worker.py:397-422`）；如果模型全程零工具还会自动切"提示词模拟工具调用"自愈一次（`worker.py:386-396`）。  
**含义**：用不支持 tool calling 的廉价模型 = 命中率趋近 0，系统会自我淘汰。

### 2.2 工具链可用性（第二因素）

真实发包靠容器内 `nmap/nuclei/sqlmap/httpx/whatweb`（`executor.py`）。Worker 用 `run_shell` 调用它们。但代码对**泛扫做了硬性封堵**：

- 禁止宽端口 nmap、禁止无模板 nuclei、禁止无参数 sqlmap、禁止泛目录爆破（`worker.py:1088-1131` `_low_value_shell_reason`）。  
  这意味着"广度扫描型"打法被削弱，**更依赖 LLM 先形成精准假设再验证**——对模型推理要求更高。

### 2.3 目标质量（第三因素）

- **搜集**：依赖 FOFA 等测绘引擎的关键词/语法，归属靠 `org`/`domain`/`cert` 收窄；
- **预筛**（`prefilter.py`）：确定性地跳过敏感域名（.gov/.mil/军政）、CDN/对象存储、死链、纯静态托管；
- **打分**（`scorer.py`）：**纯关键词规则**（admin_backend +3、pure_frontend -4 等），HIGH≥5。

打分是**机械的关键词匹配，不看业务上下文**，会误判大量"标题朴素但后台脆弱"的高校系统为低分（被排到队尾甚至被低成功率机制跳过）。

### 2.4 预算与收敛（双刃剑）

- Edu 模式 90/45 轮、企业模式 110/60 轮（`worker_config.rounds_for`，`worker.py:269`）：轮数即"思考深度上限"，复杂利用链容易被截断；
- 收尾保护：`no_tool_rounds>=6`、连续失败 8 次、网络失败 3 次自动收尾（`worker.py:481-504`）；
- 过早结束拦截：发现 JS/API 信号却没审计、工具动作不足就 finish(no_vuln) 会被驳回（`worker.py:920-962`）。  
  **含义**：护栏压住了空转和 token 浪费，但也**提高了"该挖深却提前收尾"的假阴性**。

### 2.5 Reviewer 的"过杀"风险（隐性杀手）

Reviewer（`reviewer.py`）被设计成"极理性、只认实锤"，并有一整套 `ignored` 规则：反射 XSS、短信轰炸、公开接口、图床/CDN、疑似被黑等都直接丢弃（`_REVIEW_NEVER_DEEPEN_MARKERS`、`_maybe_reject_*`）。虽然代码用 `ignored→deepen` 启发式（`reviewer.py:80-192`）抢救"入口真实但没打穿"的线索，**但大量"弱但真实"的中低危洞仍会被判 ignored**。这是成功率被压低的第二大内因（仅次于模型）。

### 2.6 一个关键事实：系统并不度量成功率

全仓库 grep `成功率 / success_rate / hit_rate / 命中率` **没有任何计算与持久化指标**，只有 `Target.verdict`（found/no_vuln/error/timeout/skip\_*）的终态记录（`db/models.py:95`）。所谓"低成功率"是一个**启发式规则**——按 `priority_score` 阈值 + 低分特征标记，把低分目标在派发前跳过（`orchestrator.py:1098-1121` `_low_success_skip_reason`），**并非基于真实历史命中统计**。

> 也就是说：你无法在控制台看到一个"挖洞成功率 %"的数字。只能从"已采纳漏洞数 / 已派发目标数"反推，而这个分母里还混入了大量被预筛/低分机制提前剔除的目标。

---

## 3. 工作流不足（Deficiencies）

| #   | 不足                   | 证据位置                                                       | 影响                                                                 |
| --- | -------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------ |
| D1  | **成功率不可量化**          | 无 success_rate 指标；仅 verdict 分布                             | 无法科学调参、无法 A/B 对比模型、无法知道钱花得值不值                                      |
| D2  | **低分跳过放大假阴性**        | `orchestrator.py:1098-1121` 按 `priority_score<=阈值` + 关键词跳过 | 关键词打分不准 → 真有洞的高校后台被当"低成功率"跳过，永不派 worker                            |
| D3  | **收敛护栏导致提前收尾**       | `worker.py:481-504, 920-962`                               | 复杂利用链（多步、需登录态维护）易被截断为 no_vuln                                      |
| D4  | **Reviewer 过杀中低危**   | `reviewer.py:48-54, 195-234`                               | 真实但"弱"的洞被 ignored，整体命中率被压低                                         |
| D5  | **no_vuln 默认不重试**    | `orchestrator.py:1123-1141` 默认不重试                          | 模型第一次没挖到 ≠ 真没洞，但默认不再给机会（仅凭证/高价值入口例外）                               |
| D6  | **回炉深挖上限仅 2 次**      | `deepen.py:13` `DEEPEN_CAP_DEFAULT=2`                      | 多步链（指纹→登录→越权→读数据）2 轮内打不穿就被归档                                       |
| D7  | **双 LLM 成本 + 仅高危复现** | `reviewer.py:369-412` 仅 critical/high 复现                   | 中危洞无人复现、信度只到 likely；且每洞多一次 LLM 调用                                  |
| D8  | **LLM 单点推理风险**       | `worker.py` 全靠 LLM 决策                                      | 幻觉可能走偏、漏关键入口；无"确定性攻击剧本"兜底                                          |
| D9  | **对抗 WAF/风控弱**       | 仅 `suggest_waf_bypass` 工具建议                                | 真实目标有 WAF/限频/IP 封锁时，Worker 易被拦且无自动换路/降速/代理轮换                       |
| D10 | **SQLite 单写瓶颈**      | `requirements.txt` SQLAlchemy+aiosqlite                    | 高并发 worker 实时落库（finding_submitted 实时写，`orchestrator.py:1852`）可能成瓶颈 |
| D11 | **反馈闭环浅**            | 情报库 + playbook_router 复用                                   | 人工"采纳/打回"的结论没有回流成 prompt 改进或模型微调，系统不会"越挖越聪明"                       |
| D12 | **成本不可预测**           | 轮数×工具调用×并发                                                 | 目标越多 token 越贵，无"单洞成本"和"预算封顶即停"的硬约束                                 |



---

## 4. 改进建议（对应上表）

**量化层（先止血 D1）**

- 新增 `metrics` 表/视图：按 (task, src_type, model, engine) 维度统计 `派发数 / found数 / accepted数 / ignored数 / no_vuln数 / error数`，算出**真实命中率 = accepted / 派发数**和**采纳率 = accepted / submit数**。控制台加一张看板。
- 把"低成功率跳过"从静态阈值改为**基于真实历史命中**的动态决策（D2）。

**目标质量层（D2/D3）**

- 打分引入 LLM：对"标题朴素"的目标用一次轻量 LLM 判断"是否有后台/登录/API 迹象"，替代纯关键词（scorer 可保留作初筛，LLM 作复核）。
- 对"疑似但没挖穿"的目标，放宽 no_vuln 重试：同目标换不同模型/换打法再挖 1 轮（D5），并把 deepen 上限提到 3~4（D6）。

**挖掘深度层（D3/D8）**

- 引入"确定性攻击剧本"作为 LLM 的兜底：对已知指纹（如 Druid/Nacos/Actuator/Swagger）直接跑标准化验证链，不完全依赖 LLM 临场发挥（D8）。
- 把 deep 路线（Actuator/Nacos/API）的硬上限从 30 放宽，并允许"跨轮会话态"保持更久（已有 `resume_context`，可强化）。

**初审层（D4/D7）**

- Reviewer 对"中危且证据完整"的洞也跑一次轻量复现（不限于高危），提升采纳率与信度。
- 把人工"打回/采纳"作为标签回流，定期用这些样本做 prompt 修订或训练一个轻量分类器辅助 Reviewer（D11）。

**对抗与稳健层（D9/D10）**

- 加 WAF/限频感知：检测到 403/WAF 特征时自动降速、轮换 UA、切换代理出口，而非只给文字建议。
- SQLite 高并发下改用连接池 + 批量落库，或评估 Postgres（D10）。

**成本层（D12）**

- 增加"单目标预算封顶""单洞成本统计""日预算熔断"硬开关，避免失控烧钱。

---

## 5. 成功率估计（基于设计的推断，非实测）

由于项目不度量成功率，只能定性推断：

- **单目标挖到"可提交洞"（submit_finding）的概率**：高度依赖模型。用 DeepSeek/GPT-4o 级模型 + 高质量 edu 后台目标，乐观估计 10%~30% 的目标会产生至少一个 finding；用弱模型接近 0%。
- **最终"被人工采纳"的概率（真实成功率）**：受 Reviewer 过杀 + 低分跳过双重压制，实际采纳率大概率明显低于 submit 率，**中低危漏洞召回率偏低**是结构性问题。
- **通杀 Hunter**：对已采纳洞做 2~4 个同款验证（`killsweep.py`），是"乘数"，能把单个洞放大成一批，但对指纹识别准确性依赖高。

> 一句话：**AutoHunter 把"挖洞"从人海战术变成了"模型质量 × 资产质量 × 工程护栏"的乘积。想提成功率，优先换更强的模型 + 收窄授权范围内的高价值资产 + 把 Reviewer 过杀和提前收尾这两道"内耗"降下来；想可持续，先把成功率量化出来。**

---

## 6. 备注：与项目定位的偏差

README 自述为 **Demo 级别**（`README.md:153` "本项目为 Demo 级别，作者抛砖引玉"）。因此 D1/D10/D11 这类"生产级"短板属于合理范围；但 D2（低分跳过误杀）、D4（Reviewer 过杀）、D3（提前收尾）这三项**直接吃掉挖洞成功率**，即便在 Demo 阶段也建议优先修。
