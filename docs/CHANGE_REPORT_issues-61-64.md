# 变更报告：issues #61–#64 修复 + 终端用户视角缺陷修复

- 分支：`fix-issues-61-64-hard-targets-and-endpoint-pool`
- 关联 issue：[#61](https://github.com/StanleyNull/AutoHunter/issues/61)、[#62](https://github.com/StanleyNull/AutoHunter/issues/62)、[#63](https://github.com/StanleyNull/AutoHunter/issues/63)、[#64](https://github.com/StanleyNull/AutoHunter/issues/64)
- 测试基线（改动前）：`Ran 275 tests`，`failures=3 errors=5`
- 改动后：`Ran 304 tests`，仅 `test_llm_endpoint_hardening` 因缺少 `pytest` 无法导入（改动前就存在，见 §5）

---

## 一、逐 issue 复现条件 / 根本原因 / 修复方案

### #61 硬骨头库删除功能（防止误删）

**复现条件**
1. 任务跑出若干 `dead` / `skipped` 目标，打开「全局硬骨头库」；
2. 想清掉一条误入库的目标（比如上一轮因为模型抽风被打死的）——界面上只有「置顶」，没有任何删除入口；
3. 直接打后端也没有对应路由：`DELETE /api/assets/{id}` 返回 `405`。库里只会越堆越多，无法回捞清理。

**根本原因**
`app/api/assets.py` 是「硬骨头库写操作」路由，但只实现了置顶（`PATCH /batch/top`、`PATCH /{id}/top`），从未提供删除；前端 `HardTargetsView.vue` 也只有置顶按钮。库的设计初衷是「只进不出」，缺一个受控的清理出口。

**修复方案**
- 新增 `DELETE /api/assets/{target_id}` 与 `POST /api/assets/batch/delete`。
- 因为是**物理删除**、不可撤销，加了三道闸：
  1. 只允许删除硬骨头库内的终态目标（`dead` / `skipped`）。正在排队/挖掘的目标返回 `409`，并提示「请到任务看板里删除/跳过」——避免把在跑的资产误删。
  2. 目标上仍挂着有效漏洞（`status != superseded`）时拒绝删除，返回 `409` 并给出条数。因为 `Target.findings` 配了 `cascade="all, delete-orphan"`，删目标会连带删洞；这里把「顺手删掉已确认的洞」挡在门外。`superseded` 是深挖让位的旧线索，随目标一起清掉无副作用。
  3. 每次删除写一条 `TaskEvent(kind="target_deleted", level="warn")`，事后可从活动流追溯。
- 批量删除逐条独立校验：不合条件的那条只记进 `failed[{id, reason}]`，不拖累整批。
- 前端：行内新增「删除」按钮 + 全选后的「批量删除」，统一走二次确认弹窗，弹窗里写明「删的是什么、不可撤销、有洞会被拒」。

**影响范围**：`app/api/assets.py`、`frontend/src/api.js`、`frontend/src/views/HardTargetsView.vue`、`frontend/src/style.css`。仅新增接口与入口，不改动既有置顶行为。

**验证**：`tests/test_hard_target_actions.py::HardTargetDeleteTests`（含路由级冒烟 `HardTargetRouteTests`）覆盖：正常删除落库+审计事件、库外目标 409、挂洞 409、`superseded` 不拦、批量部分成功。

---

### #62 硬骨头库添加深挖功能

**复现条件**
1. 硬骨头库里有一条「其实是好资产、只是上一轮没打穿」的目标；
2. 想让它带一句定向指令重新回炉——库里没有任何入口；只能去任务看板的漏洞详情里对 finding 做「继续深挖」，而这类目标往往根本没有 finding 可挂。

**根本原因**
深挖回炉的实现分散在两处：`app/agents/deepen.py::apply_deepen`（AI 审核打回 + 人工复审共用）与 `POST /api/results/{finding_id}/deepen`（人工入口）。**两个入口都以 `Finding` 为锚点**，而硬骨头库操作的是 `Target`。`Target` 上其实早就有 `deepen_context` / `deepen_count` 字段，只是没有面向 target 的入口。

**修复方案**
- 新增 `POST /api/assets/{target_id}/deepen`，直接复用 `deepen.py` 的语义与上限：`clamp_deepen_cap` / `deepen_cap_for` 读任务级「深挖次数」，`deepen_count >= cap` 拒绝，`cap == 0`（任务关闭回炉）拒绝。
- 成功后写回目标：`deepen_context{source: "user"}`、`deepen_count += 1`、`status = queued`、`verdict/dead_reason/last_error` 清空、`retry_count = 0`、`priority_score += 100`、`priority_reason = "[人工深挖#n] …"`，并写 `TaskEvent(kind="target_deepen")`。
- 返回体里的 `queued_now` 告诉前端「任务在跑，会立刻被派发」还是「任务没在跑，等下次启动」。
- 前端：行内「深挖」按钮 + 指令输入弹窗（指令为空不给提交），提交后刷新列表并 toast 出当次深挖序号。

**影响范围**：同 #61 的四个文件。不改动 `apply_deepen` 与 finding 侧深挖路径。

**验证**：`tests/test_hard_target_actions.py::HardTargetDeepenTests` 覆盖：回炉字段全量断言、空指令 400、运行中目标 409、超上限 409、任务关闭回炉 409、任务未运行时 `queued_now=False`。

---

### #63 非挖掘目标问题不进硬骨头（如 llm 或网络问题）

**复现条件**
1. 模型端点额度/网络/鉴权出问题，任务持续跑；
2. 一批目标被逐个「挖」过一遍，全部以 `dead` 收进硬骨头库，`dead_reason` 写的是 `LLM 持续异常：临时错误回队已达上限 5 次，模型服务可能不稳定`；
3. 用户复盘时看到一堆「硬骨头」，误以为这些站真的打不动——实际上它们连一次有效的模型对话都没跑到。这些目标也不会被自动重试，等于被永久误杀。

**根本原因**
`TaskRunner._persist_worker_result()` 里所有失败路径最终都写 `status = "dead"`，没有区分「目标本身打不穿」和「端侧基础设施挂了」：

- `transient_exhausted`（临时 LLM 错误回队超上限）→ `dead` + `LLM 持续异常…`；
- `verdict == "timeout"` 且重试到顶 → `dead` + `超时×重试仍无果`；
- 兜底 `else`（`verdict == "error"`）→ `dead` + 原始错误，而 `auth` / `invalid_request` 这类配置错根本没进「临时错误」集合，第一次就落 `dead`；
- worker 自动收敛文案「连续 3 次网络/超时失败，目标当前不可稳定验证」走 `no_vuln` 出口，命中 `auto_converged` 判定后被写成 `dead` + 该文案。

确认「基础设施」归因的唯一可靠信号是 worker 原样带出的 `failure_kind`（来自 `LLMError.kind`），其次是收敛文案里的明确措辞。

**修复方案**
- 新增 `TaskRunner._is_infra_failure(result)`：`failure_kind ∈ {provider_cooldown, rate_limit, timeout, network, upstream, unknown, blocked, invalid_request, auth, model_behavior, tool_argument}`，或收敛文案命中 `网络/超时失败` / `目标当前不可稳定验证`（后者无 `failure_kind`，只能按文本兜底），即判定为基础设施问题。
- 基础设施失败**复用既有的临时错误回队通道**（不消耗 `retry_count`，回队上限 `MAX_TRANSIENT_LLM_REQUEUE`）；回队预算耗尽后进入**新终态 `stalled`**，而不是 `dead`。
- 新增 `stalled` 状态：**不在硬骨头库**（硬骨头库仍只聚合 `dead`/`skipped`）、不计入「已完成」统计、不消耗重试次数、不参与同款簇冷却判定；`TaskStats` 新增 `stalled` 计数。
- 确保它们不会变成「黑洞状态」，三条放行路径：
  1. `recover()`（任务重启）时把 `stalled` 放回队列 —— 对应「用户修好模型配置后重启任务」；
  2. `_tick()` 周期性（默认 300s，`STALLED_RELEASE_INTERVAL`）放行，前提是端点池里**确实还有可用端点**（`_pool_has_usable_endpoint` 看健康快照，全池 `cooldown`/`failed` 时跳过，避免白跑）；
  3. `_pop_queued()` 观察到全池冷却节流刚解除、以及某轮 worker 真的出了结论（证明端点已恢复）时立即放行。
- 收集器的 `seen` 集合按 host 全量取，`stalled` 目标不会被重新收集成重复行。

**影响范围**：`app/orchestrator.py`（判定、终态、放行）、`app/api/dto.py`（`TaskStats.stalled`）、`app/api/tasks.py`（统计与 `list_hosts` rollup）。**没有数据库 schema 变更**：`Target.status` 是已有的字符串列，`stalled` 只是新增取值。

**验证**：`InfraFailureClassificationTests`（含 `_is_infra_failure` 逐 kind 断言、`stalled` 不进硬骨头库查询的源码断言）+ `InfraFailurePersistenceTests`（首次回队不置 dead、预算耗尽转 stalled、`auth` 配置错不落硬骨头、worker 网络收敛不落硬骨头、**反例**：目标真的确认无洞时仍然照旧落 `dead`）+ `PoolUsableEndpointTests` / `StalledReleaseTriggerTests`。

---

### #64 （端点池）api 错误后切换其他 api 端点而并非反复报 error

**复现条件**
1. 在设置里配好「端点池」（2 个以上可用端点）；
2. 让池中第一个端点持续失败（例如限流/网关 5xx/网络不通）；
3. 观察：同一个失败端点被**反复重试**，每次还带 1 秒退避，然后才切到下一个端点。`LLMError` 事件流里同一个 `base_url` 连续出现。

**根本原因**（有据可查的回归）
`tests/test_llm_provider_pool.py::test_pool_mode_does_not_retry_bad_endpoint_before_failover` 这个用例在改动前就是**红的**——它断言的正是「池模式下不先重试坏端点，直接 failover」。用 `git log -S` 追到：

```
8f6506a fix: LLM 软重试续挖、漏洞模型归因，并恢复检查更新入口
-        max_retries = 0 if self.pool_mode else _MAX_RETRIES
+        max_retries = _POOL_SAME_PROVIDER_RETRIES if self.pool_mode else _MAX_RETRIES
+_POOL_SAME_PROVIDER_RETRIES = int(os.environ.get("LLM_POOL_SAME_PROVIDER_RETRIES", "1"))
```

池模式原本是「同端点 0 次重试、直接切下一个」，`8f6506a` 把它改成默认 1 次，于是每次端点报错都会先在原地 `time.sleep(min(2**0, 8))` 后重试一次，再走 failover——这就是用户看到的「反复报 error 而不切换」。

**修复方案**
把 `LLM_POOL_SAME_PROVIDER_RETRIES` 的默认值改回 `0`，并保留该环境变量作为逃生阀（确实需要在同端点重试的部署可显式设成 `1` 或更大）。同时在常量处写明理由，避免再被改回去。

**影响范围**：`app/llm/client.py` 一个常量。单端点（`pool_mode=False`）行为完全不变，仍走 `LLM_MAX_RETRIES`；池化时一次 `chat()` 内每个端点最多打一次，失败即切下一个。

**验证**：回归用例 `test_pool_mode_does_not_retry_bad_endpoint_before_failover` 由红转绿；`test_llm_provider_pool.py` 34 个用例全绿。

---

## 二、终端用户视角审查发现的缺陷

| # | 现象 | 根因 | 修复 |
|---|---|---|---|
| A1 | 任何接口报错都会把 FastAPI 的原始 JSON（`{"detail":"…"}`）弹到 `alert()` 里，用户看到的是 `409 {"detail":"该目标…"}` | `frontend/src/api.js` 的 4 处错误抛出都直接拼 `${status} ${text}` | 新增 `readableError()`：优先取 `detail` / `message` / `error`（数组形式按 `msg` 拼接），取不到才回退到 `status + 原文`；4 处统一改用 |
| A2 | 搜索/筛选出 0 条结果后，每次点「刷新」都先闪一遍骨架屏 | `load()` 用 `if (!rows.length) initialLoading = true` 判断，空列表被当成「首次加载」 | 增加独立的 `loaded` 标志位，只有真正的首次加载才显示骨架 |
| A3 | 新增的 `target_stalled` / `stalled_released` / `target_deepen` / `target_deleted` 事件在活动流里**完全看不到** | 前端 `BoardView.vue` 的 `IMPORTANT_KINDS` / `LOG_INFO_IMPORTANT`（实时流 + 历史回放）和后端 `tasks.py` 的 `_STREAM_IMPORTANT_KINDS` 都是显式白名单，新 kind 不在其中会被静默丢弃 | 三处白名单同步补上这四个 kind。对 #63 尤其关键：`stalled` 目标不在硬骨头库里，活动流是它唯一的显性出口 |
| A4 | 主机聚合接口会把「仅因 LLM/网络停摆」的主机 `rollup` 成 `skipped`（前端会显示成「低分跳过」），属于把非目标问题误报成资产问题 | `app/api/tasks.py::list_hosts` 的 rollup 分支只有 scanning/queued/done/dead/else→skipped | 增加 `stalled` 分支，单独归类 |
| A5 | 测试套件长期是红的（`failures=3 errors=5`），真实回归被淹没——#64 那个回归就是这么漏掉的 | 三处 `Worker.__new__(Worker)` 夹具在 `Worker` 增加 `src_rules` 后没同步；`Worker(...)` 真实构造在无 API Key 环境下直接抛 `RuntimeError`；`executor` 夹具缺 `export_resume_state`；`session.get` 返回的 `SimpleNamespace` 缺 `model_config_json` | 补齐夹具（3 个文件共 4 处），无需改产品代码 |
| A6 | `test_task_model_probe` 两个用例断言「换了端点/协议就直接拒绝探测」，与现行为不符 | 后来加入了「再兜底系统设置里同身份的 Key」逻辑，探测会继续但不是用旧 Key | 把断言改成**真正的安全属性**：探测仍会发起，但 `api_key` 必须为空、且报文里不得出现旧 Key 明文 |

---

## 三、影响范围汇总

| 文件 | 改动 |
|---|---|
| `app/api/assets.py` | 新增删除（单个/批量）与深挖回炉接口；抽出 `_clean_ids` / `_live_finding_count` / `_reject_not_hard_bone` |
| `app/orchestrator.py` | 新增 `_INFRA_FAILURE_KINDS` / `_INFRA_SUMMARY_MARKERS` / `STALLED_RELEASE_INTERVAL` 等常量；新增 `_is_infra_failure` / `_park_target_for_infra` / `_release_stalled_targets` / `_pool_has_usable_endpoint` / `_maybe_release_stalled`；改写 `_persist_worker_result` 的终态分支与日志；`recover()` / `_tick()` / `_pop_queued()` 接入放行 |
| `app/llm/client.py` | `LLM_POOL_SAME_PROVIDER_RETRIES` 默认 `1 → 0` |
| `app/api/dto.py` | `TaskStats` 新增 `stalled` |
| `app/api/tasks.py` | `_compute_stats` 统计 `stalled`；`list_hosts` rollup 增加 `stalled`；`_STREAM_IMPORTANT_KINDS` 补 4 个 kind |
| `frontend/src/api.js` | `readableError()`；新增 `assetDelete` / `assetBatchDelete` / `assetDeepen` |
| `frontend/src/views/HardTargetsView.vue` | 删除/批量删除/深挖入口 + 两个确认弹窗；`loaded` 标志修骨架屏闪烁 |
| `frontend/src/views/BoardView.vue` | 活动流两处白名单补 kind；`totalTargets` 计入 `stalled` |
| `frontend/src/style.css` | 行内操作区、危险按钮、弹窗样式（含窄屏适配） |
| `tests/test_hard_target_actions.py` | 新增 29 个用例 |
| `tests/test_agent_visibility.py`、`test_llm_cooldown_flow.py`、`test_worker_llm_soft_retry.py`、`test_task_model_probe.py` | 修陈旧夹具与断言 |

---

## 四、验证方式

### 1. 单元测试

```
python -m unittest discover -s tests
```

- 改动前：`Ran 275 tests … FAILED (failures=3, errors=5)`
- 改动后：`Ran 304 tests … FAILED (errors=1)`，唯一剩余错误是 `test_llm_endpoint_hardening` 需要 `pytest`（环境未装，改动前同样导入失败，见 §5）。

新增 29 个用例集中在 `tests/test_hard_target_actions.py`，覆盖 issue 的行为断言、拒绝路径、路由方法/URL 冒烟，以及 #63 的**反例保护**（目标真的确认无洞时仍必须落 `dead`）。

### 2. 变异验证（确认测试真的能变红）

把修复逐条改回缺陷状态，跑对应测试，确认失败：

| 改回的内容 | 结果 |
|---|---|
| `LLM_POOL_SAME_PROVIDER_RETRIES` 默认值 `0 → 1` | RED：`test_pool_mode_does_not_retry_bad_endpoint_before_failover` |
| `_park_target_for_infra` 里 `status = "stalled"` 改回 `"dead"` | RED：`test_llm_outage_requeues_first_then_stalls` 等 3 例 |
| 删掉 `delete_asset` 里的 `_reject_not_hard_bone(tgt)` | RED：`test_refuses_target_outside_hard_bone_library` |

### 3. 前端构建

```
cd frontend && npm run build
```

`vite build` 通过（47 modules transformed，产物写入 `web/dist/`）。

### 4. 未做的验证（如实说明）

- **没有**在真实 LLM 端点池上做端到端故障切换压测，也没有在真实站点上跑完整任务验证 #63 的放行节奏；上述结论来自单测与代码路径分析。
- **没有**做浏览器人工交互验证（删除/深挖弹窗的实际观感、窄屏布局）；只保证构建通过。
- `STALLED_RELEASE_INTERVAL`（300s）与 `MAX_INFRA_REQUEUE` 的取值是按现有同类常量（`QUEUE_TRANSIENT_PREFILTER_COOLDOWN=900`、`MAX_TRANSIENT_LLM_REQUEUE=5`）取的，**没有**实测调优。

---

## 五、兼容性、风险与遗留

**兼容性**
- 无数据库 schema 变更：`stalled` 是 `targets.status` 这个既有字符串列的新取值。老数据、老前端（不认识 `stalled`）只会把它当未知状态显示，不会崩。
- `stats.stalled` 是 DTO 新增字段，旧客户端忽略即可。
- `LLM_POOL_SAME_PROVIDER_RETRIES` 默认值变化是**行为变更**：池化时一次 `chat()` 内每个端点最多打一次。想恢复旧行为设 `LLM_POOL_SAME_PROVIDER_RETRIES=1`。

**风险**
- 删除接口是物理删除，无法撤销；因此用「仅限硬骨头库内终态目标 + 有洞就拒 + 二次确认 + 审计事件」四重约束兜底。
- #63 让基础设施失败的目标不再落 `dead`，因此「任务看起来永远跑不完」的可能性上升；这是刻意的取舍（对应 issue 诉求），并且由一个独立的 `stalled` 状态 + 三条放行路径 + 活动流可见性控制住了。

**已知遗留**
1. `tests/test_llm_endpoint_hardening.py` 依赖 `pytest`，而 `requirements.txt` 里没有测试依赖，用 `unittest` 跑必然会 import error。改动前就存在，本 PR 未处理（要么补一个测试依赖文件，要么把它改成 `unittest`）。**本次没有修改该文件**。
2. #63 的归因依赖 worker 传出的 `failure_kind` 与收敛文案。若将来新增失败类型而没带 `failure_kind`、文案也不含现有标记，就会退回旧的 `dead` 行为——`_INFRA_FAILURE_KINDS` / `_INFRA_SUMMARY_MARKERS` 需要随之维护。

---

## 六、手动验收建议

1. 造一条 `dead` 目标（或直接改库），打开「全局硬骨头库」→ 点「删除」→ 确认弹窗 → 列表少一条，任务活动流出现 `target_deleted`。
2. 对另一条 `dead` 目标点「深挖」→ 填指令 → 提交；目标从库里消失、任务看板出现 `target_deepen`，目标状态变 `queued` 且优先级明显升高。
3. 故意把 LLM Key 改错、启动任务：目标应在回队若干次后变成 `stalled`（**不出现**在硬骨头库），活动流能看到 `target_stalled`；把 Key 改回来后点一次「启动」或等一个放行周期，目标自动回到队列。
4. 配两个端点，把第一个端点地址改错：`llm_error` 事件里应看到立刻切到第二个端点，而不是同一个 `base_url` 连报两次。
