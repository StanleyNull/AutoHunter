<script setup>
import { reactive, ref, onMounted } from "vue";
import { api } from "../api.js";

const loading = ref(true);
const saving = ref(false);
const toastMsg = ref("");
const meta = ref({ updated_at: null });

// 连通性测试状态
const testing = reactive({ llm: false, ssh: false });
const testResult = reactive({ llm: null, ssh: null });

// 引擎连通性测试状态
const engineTesting = reactive({});
const engineTestResult = reactive({});

// 工作目录管理状态
const workdirLoading = ref(false);
const workdirCleaning = ref(false);
const workdirStats = ref(null);
const workdirResult = ref(null);
const cleanupRetentionDays = ref(7);
const cleanupDryRun = ref(true);

async function runTest(type) {
  testing[type] = true;
  testResult[type] = null;
  try {
    const fn = { llm: api.testLLM, ssh: api.testSSH }[type];
    const res = await fn();
    testResult[type] = res;
  } catch (e) {
    testResult[type] = { ok: false, message: String(e.message || e).replace(/^\d+\s*/, "") };
  } finally {
    testing[type] = false;
  }
}

async function runEngineTest(engineName) {
  engineTesting[engineName] = true;
  engineTestResult[engineName] = null;
  try {
    const res = await api.testEngine(engineName);
    engineTestResult[engineName] = res;
  } catch (e) {
    engineTestResult[engineName] = { ok: false, message: String(e.message || e).replace(/^\d+\s*/, "") };
  } finally {
    engineTesting[engineName] = false;
  }
}

// ---- 一键更新 ----
const updateState = reactive({
  checking: false,
  info: null,       // check_update 返回
  updating: false,
  restarting: false,
  error: "",
  supported: true,   // 后端是否注册了 update 路由（原版不注册 → 隐藏整个区块）
});

async function checkUpdate() {
  updateState.checking = true;
  updateState.error = "";
  updateState.info = null;
  try {
    updateState.info = await api.checkUpdate();
    if (updateState.info?.error && /非 git|无法/.test(updateState.info.error)) {
      updateState.supported = false;
    }
  } catch (e) {
    const msg = String(e.message || e);
    if (/404|not found/i.test(msg)) { updateState.supported = false; }
    else { updateState.error = msg.replace(/^\d+\s*/, ""); }
  } finally {
    updateState.checking = false;
  }
}

async function runUpdate() {
  if (!confirm("确认更新？服务会自动重启，进行中的任务会优雅暂停。")) return;
  updateState.updating = true;
  updateState.error = "";
  try {
    const r = await api.runUpdate();
    if (r.ok) {
      updateState.restarting = true;
      pollHealth();
    } else {
      updateState.error = r.error || "更新失败";
      if (r.command) updateState.info = { ...updateState.info, rebuild_command: r.command };
    }
  } catch (e) {
    updateState.error = String(e.message || e).replace(/^\d+\s*/, "");
  } finally {
    updateState.updating = false;
  }
}

function pollHealth() {
  let attempts = 0;
  const timer = setInterval(async () => {
    attempts++;
    try {
      const r = await fetch("/health");
      if (r.ok) {
        clearInterval(timer);
        updateState.restarting = false;
        toast("更新完成，服务已重启 🎉");
        updateState.info = null;
        load();
      }
    } catch {}
    if (attempts > 60) { clearInterval(timer); updateState.restarting = false; updateState.error = "重启超时，请手动刷新页面"; }
  }, 3000);
}

const form = reactive({
  base_url: "",
  api_key: "",
  model: "",
  temperature: 0.3,
  api_key_set: false,
  max_pages: 20,
  page_size: 100,
  default_intent_mode: "",
  default_engine: "",
  concurrency: 3,
  skip_score_threshold: -10,
  worker_prompt_version: "legacy",
  proxy_ssh_servers: "",
  proxy_ssh_key_path: "",
  proxy_probe_servers: "",
});

// 引擎配置：{ [engineName]: { key: "", base_url: "", key_set: false } }
const engineForm = reactive({});
// 后端返回的可用引擎列表
const availableEngines = ref([]);

// 模型计价配置：[{model, input, output, cache_hit}]
const pricingEntries = ref([]);

function toast(m) {
  toastMsg.value = m;
  setTimeout(() => (toastMsg.value = ""), 2600);
}

async function load() {
  loading.value = true;
  try {
    const s = await api.getSettings();
    meta.value = { updated_at: s.updated_at };
    form.base_url = s.llm?.base_url || "";
    form.model = s.llm?.model || "";
    form.temperature = s.llm?.temperature ?? 0.3;
    form.api_key = "";
    form.api_key_set = s.llm?.api_key_set;
    form.max_pages = s.fofa?.max_pages ?? 20;
    form.page_size = s.fofa?.page_size ?? 100;
    form.default_intent_mode = s.fofa?.default_intent_mode || "";
    form.default_engine = s.defaults?.engine || "";
    form.concurrency = s.defaults?.concurrency ?? 3;
    form.skip_score_threshold = s.defaults?.skip_score_threshold ?? -10;
    form.worker_prompt_version = s.defaults?.worker_prompt_version || "legacy";
    form.proxy_ssh_servers = s.proxy?.ssh_servers || "";
    form.proxy_ssh_key_path = s.proxy?.ssh_key_path || "";
    form.proxy_probe_servers = s.proxy?.probe_servers || "";
    // 加载引擎配置
    const engines = s.engines || {};
    const engineList = s.available_engines || [];
    availableEngines.value = engineList;
    for (const eng of engineList) {
      const name = eng.name;
      const ecfg = engines[name] || {};
      engineForm[name] = {
        key: "",
        base_url: ecfg.base_url || "",
        key_set: !!ecfg.key_set,
      };
    }
    // 加载模型计价
    const pricing = s.pricing || {};
    pricingEntries.value = Object.entries(pricing).map(([model, cfg]) => ({
      model,
      input: cfg.input ?? "",
      output: cfg.output ?? "",
      cache_hit: cfg.cache_hit ?? "",
    }));
    // 如果当前模型不在计价列表中，自动添加一行
    if (form.model && !pricingEntries.value.some(e => e.model === form.model)) {
      pricingEntries.value.unshift({ model: form.model, input: "", output: "", cache_hit: "" });
    }
  } finally {
    loading.value = false;
  }
}

async function save() {
  saving.value = true;
  try {
    const body = {
      llm: {
        base_url: form.base_url,
        model: form.model,
        temperature: Number(form.temperature),
      },
      fofa: {
        max_pages: Number(form.max_pages),
        page_size: Number(form.page_size),
        default_intent_mode: form.default_intent_mode,
      },
      defaults: {
        concurrency: Number(form.concurrency),
        skip_score_threshold: Number(form.skip_score_threshold),
        worker_prompt_version: form.worker_prompt_version,
        engine: form.default_engine,
      },
      proxy: {
        ssh_servers: form.proxy_ssh_servers,
        ssh_key_path: form.proxy_ssh_key_path,
        probe_servers: form.proxy_probe_servers,
      },
    };
    if (form.api_key.trim()) body.llm.api_key = form.api_key.trim();
    // 构建引擎配置
    const enginesBody = {};
    for (const eng of availableEngines.value) {
      const name = eng.name;
      const ef = engineForm[name];
      if (!ef) continue;
      const cfg = {};
      if (ef.key.trim()) cfg.key = ef.key.trim();
      if (ef.base_url.trim()) cfg.base_url = ef.base_url.trim();
      if (Object.keys(cfg).length) enginesBody[name] = cfg;
    }
    if (Object.keys(enginesBody).length) body.engines = enginesBody;
    // 构建计价配置（过滤掉模型名为空的行）
    const pricingBody = {};
    for (const e of pricingEntries.value) {
      const model = (e.model || "").trim();
      if (!model) continue;
      const cfg = {};
      if (e.input !== "" && e.input !== null) cfg.input = Number(e.input);
      if (e.output !== "" && e.output !== null) cfg.output = Number(e.output);
      if (e.cache_hit !== "" && e.cache_hit !== null) cfg.cache_hit = Number(e.cache_hit);
      if (Object.keys(cfg).length) pricingBody[model] = cfg;
    }
    if (Object.keys(pricingBody).length) body.pricing = pricingBody;
    const s = await api.updateSettings(body);
    meta.value = { updated_at: s.updated_at };
    form.api_key = "";
    form.api_key_set = s.llm?.api_key_set;
    // 更新引擎 key_set 状态
    const engines = s.engines || {};
    for (const eng of availableEngines.value) {
      const name = eng.name;
      if (engineForm[name]) {
        engineForm[name].key = "";
        engineForm[name].key_set = !!(engines[name]?.key_set);
        if (engines[name]?.base_url !== undefined) {
          engineForm[name].base_url = engines[name].base_url || "";
        }
      }
    }
    toast("系统配置已保存");
  } catch (e) {
    toast(String(e.message || e).replace(/^\d+\s*/, ""));
  } finally {
    saving.value = false;
  }
}

onMounted(() => {
  load();
  loadWorkdirStats();
  // 探测后端是否支持更新 API（原版不注册 → supported=false → 隐藏区块）
  checkUpdate();
});

async function loadWorkdirStats() {
  workdirLoading.value = true;
  try {
    workdirStats.value = await api.workdirStats();
    if (workdirStats.value) {
      cleanupRetentionDays.value = workdirStats.value.retention_days || 7;
    }
  } catch (e) {
    toast(String(e.message || e).replace(/^\d+\s*/, ""));
  } finally {
    workdirLoading.value = false;
  }
}

async function runCleanup() {
  workdirCleaning.value = true;
  workdirResult.value = null;
  try {
    const res = await api.workdirCleanup(cleanupRetentionDays.value, cleanupDryRun.value);
    workdirResult.value = res;
    const prefix = res.dry_run ? "模拟清理" : "清理";
    toast(`${prefix}完成：删除 ${res.deleted_dirs} 个目录，释放 ${res.freed_human}`);
    if (!res.dry_run) {
      await loadWorkdirStats();
    }
  } catch (e) {
    toast(String(e.message || e).replace(/^\d+\s*/, ""));
  } finally {
    workdirCleaning.value = false;
  }
}

function addPricingRow() {
  pricingEntries.value.push({ model: "", input: "", output: "", cache_hit: "" });
}
function removePricingRow(idx) {
  pricingEntries.value.splice(idx, 1);
}
</script>

<template>
  <section class="view settings-view">
    <header class="page-head">
      <h2>系统配置</h2>
      <p class="page-sub">
        全局默认 LLM / 搜索引擎 / 调度参数。新建任务留空时会使用此处配置；任务内填写可单独覆盖。
        <span v-if="meta.updated_at" class="settings-updated">上次保存 {{ meta.updated_at?.slice(0, 19).replace("T", " ") }}</span>
      </p>
    </header>

    <div v-if="loading" class="empty">加载中…</div>
    <div v-else class="settings-layout">
      <aside class="settings-summary" aria-label="当前系统配置摘要">
        <div class="settings-summary-head">
          <span>ACTIVE PROFILE</span>
          <b>全局默认</b>
        </div>
        <div class="settings-health">
          <div>
            <span>LLM</span>
            <b>{{ form.model || "未设置模型" }}</b>
          </div>
          <i :class="{ on: form.api_key_set }">{{ form.api_key_set ? "key set" : "no key" }}</i>
        </div>
        <div v-for="eng in availableEngines" :key="eng.name" class="settings-health">
          <div>
            <span>{{ eng.display_name }}</span>
            <b>{{ form.default_engine === eng.name ? "默认" : "" }}</b>
          </div>
          <i :class="{ on: engineForm[eng.name]?.key_set }">{{ engineForm[eng.name]?.key_set ? "key set" : "no key" }}</i>
        </div>
        <dl class="settings-facts">
          <div>
            <dt>任务默认并发</dt>
            <dd>{{ form.concurrency }}</dd>
          </div>
          <div>
            <dt>低分跳过阈值</dt>
            <dd>{{ form.skip_score_threshold }}</dd>
          </div>
          <div>
            <dt>Worker 提示词</dt>
            <dd>{{ form.worker_prompt_version }}</dd>
          </div>
        </dl>
        <p class="settings-note">
          此处是运行期默认值。任务创建时若在高级区单独填写，则按任务配置覆盖。
        </p>
      </aside>

      <form class="form settings-form" @submit.prevent="save">
        <fieldset class="settings-block">
          <legend>
            <span>AI / LLM</span>
            <small>Worker、Reviewer、报告助手共用的默认模型通道</small>
          </legend>
          <div class="settings-grid">
            <label class="full">base_url
              <input v-model="form.base_url" placeholder="https://api.deepseek.com/v1" />
            </label>
            <p class="field-hint full">OpenAI 兼容接口地址（官方或自建均可），路径需要包含 <code>/v1</code>。</p>
            <label class="full">api_key
              <input v-model="form.api_key" type="password"
                :placeholder="form.api_key_set ? '已配置，留空不修改' : 'sk-...'" />
            </label>
            <label>模型名 <input v-model="form.model" placeholder="deepseek-v4-flash" /></label>
            <label>temperature
              <input v-model="form.temperature" type="number" step="0.1" min="0" max="2" />
            </label>
          </div>
          <div class="settings-test">
            <button type="button" class="test-btn" :disabled="testing.llm" @click="runTest('llm')">
              {{ testing.llm ? "测试中…" : "测试连通" }}
            </button>
            <span v-if="testResult.llm" class="test-result" :class="testResult.llm.ok ? 'ok' : 'fail'">
              {{ testResult.llm.ok ? "✓" : "✗" }} {{ testResult.llm.message }}
            </span>
          </div>
        </fieldset>

        <fieldset class="settings-block">
          <legend>
            <span>搜索引擎</span>
            <small>Collector 使用的测绘引擎 API 密钥</small>
          </legend>
          <div v-for="eng in availableEngines" :key="eng.name" class="engine-config-item">
            <div class="engine-config-head">
              <span class="engine-config-name">{{ eng.display_name }}</span>
              <i :class="{ on: engineForm[eng.name]?.key_set }">{{ engineForm[eng.name]?.key_set ? "key set" : "no key" }}</i>
            </div>
            <div class="settings-grid">
              <label class="full">API Key
                <input v-model="engineForm[eng.name].key" type="password"
                  :placeholder="engineForm[eng.name]?.key_set ? '已配置，留空不修改' : `${eng.display_name} Key`" />
              </label>
              <label class="full">API 端点
                <input v-model="engineForm[eng.name].base_url"
                  :placeholder="`留空使用默认地址`" />
              </label>
            </div>
            <div class="settings-test">
              <button type="button" class="test-btn" :disabled="engineTesting[eng.name]"
                @click="runEngineTest(eng.name)">
                {{ engineTesting[eng.name] ? "测试中…" : "测试连通" }}
              </button>
              <span v-if="engineTestResult[eng.name]" class="test-result"
                :class="engineTestResult[eng.name].ok ? 'ok' : 'fail'">
                {{ engineTestResult[eng.name].ok ? "✓" : "✗" }} {{ engineTestResult[eng.name].message }}
              </span>
            </div>
          </div>
        </fieldset>

        <fieldset class="settings-block">
          <legend>
            <span>Collector 默认参数</span>
            <small>资产搜集的分页与默认引擎</small>
          </legend>
          <div class="settings-grid">
            <label>默认搜索引擎
              <select v-model="form.default_engine">
                <option value="">自动（FOFA）</option>
                <option v-for="eng in availableEngines" :key="eng.name" :value="eng.name">
                  {{ eng.display_name }}
                </option>
              </select>
            </label>
            <label>默认最大页数 <input v-model="form.max_pages" type="number" min="1" /></label>
            <label>每页条数 <input v-model="form.page_size" type="number" min="1" /></label>
            <label class="full">默认搜集方式
              <select v-model="form.default_intent_mode">
                <option value="">自动判断</option>
                <option value="syntax">FOFA 语法</option>
                <option value="intent">自然语言意图</option>
              </select>
            </label>
          </div>
          <p class="field-hint full">新建任务时默认使用的搜索引擎和分页参数，可在任务高级配置中单独覆盖。</p>
        </fieldset>

        <fieldset class="settings-block">
          <legend>
            <span>调度默认</span>
            <small>新任务创建时的保守默认值</small>
          </legend>
          <div class="settings-grid">
            <label>新建任务默认并发 <input v-model="form.concurrency" type="number" min="1" max="32" /></label>
            <label>低分跳过阈值
              <input v-model="form.skip_score_threshold" type="number" step="1" />
            </label>
            <label class="full">Worker 提示词版本
              <select v-model="form.worker_prompt_version">
                <option value="legacy">legacy（旧版 23/25 风格）</option>
                <option value="current">current（当前省 token 版）</option>
                <option value="modern">modern（当前完整版）</option>
              </select>
            </label>
            <p class="field-hint full">Collector 评分低于此值的目标直接跳过，避免 worker 消耗在垃圾资产上。</p>
          </div>
        </fieldset>

        <fieldset class="settings-block">
          <legend>
            <span>模型计价</span>
            <small>按百万 Token 计费（元），用于日历成本统计</small>
          </legend>
          <div class="pricing-table">
            <div class="pricing-row pricing-header">
              <span>模型名</span>
              <span>输入 (元/M)</span>
              <span>输出 (元/M)</span>
              <span>缓存命中 (元/M)</span>
              <span></span>
            </div>
            <div v-for="(e, idx) in pricingEntries" :key="idx" class="pricing-row">
              <input v-model="e.model" placeholder="模型名" class="pricing-input" />
              <input v-model="e.input" type="number" step="0.01" min="0" placeholder="0" class="pricing-input" />
              <input v-model="e.output" type="number" step="0.01" min="0" placeholder="0" class="pricing-input" />
              <input v-model="e.cache_hit" type="number" step="0.01" min="0" placeholder="0" class="pricing-input" />
              <button type="button" class="pricing-del" @click="removePricingRow(idx)" title="删除">×</button>
            </div>
          </div>
          <button type="button" class="test-btn" @click="addPricingRow">+ 添加模型</button>
          <p class="field-hint full">成本 = (输入Token - 缓存命中) × 输入价 + 输出Token × 输出价 + 缓存命中 × 缓存价，单位均为元/百万Token。留空表示该模型不计费。</p>
        </fieldset>

        <fieldset class="settings-block">
          <legend>
            <span>SSH 代理池</span>
            <small>WAF 封 IP 时交叉检测 + 失败目标重测</small>
          </legend>
          <div class="settings-grid">
            <label class="full">测试服务器（一行一个）
              <textarea v-model="form.proxy_ssh_servers" rows="3"
                placeholder="root@1.2.3.4:22&#10;root@5.6.7.8:22"></textarea>
            </label>
            <p class="field-hint full">用于代理测试的免密 SSH 服务器，格式 <code>user@host:port</code>，一行一个。留空则关闭代理功能。</p>
            <label class="full">专用探活服务器（一行一个）
              <textarea v-model="form.proxy_probe_servers" rows="3"
                placeholder="root@9.10.11.12:22&#10;root@13.14.15.16:22"></textarea>
            </label>
            <p class="field-hint full">仅用于失败目标重测时探活交叉验证，不参与测试，避免 IP 被封。留空则回退到测试服务器探活。</p>
            <label class="full">SSH 私钥路径（容器内）
              <input v-model="form.proxy_ssh_key_path" placeholder="/root/.ssh/id_ed25519" />
            </label>
            <p class="field-hint full">容器内私钥路径。私钥文件需先通过 docker-compose 挂载进容器（一次性配置）。</p>
          </div>
          <div class="settings-test">
            <button type="button" class="test-btn" :disabled="testing.ssh" @click="runTest('ssh')">
              {{ testing.ssh ? "测试中…" : "测试连通" }}
            </button>
            <span v-if="testResult.ssh" class="test-result" :class="testResult.ssh.ok ? 'ok' : 'fail'">
              {{ testResult.ssh.ok ? "✓" : "✗" }} {{ testResult.ssh.message }}
            </span>
          </div>
        </fieldset>

        <fieldset class="settings-block">
          <legend>
            <span>工作目录管理</span>
            <small>Worker / Escalate 等 agent 产生的临时文件磁盘占用与清理</small>
          </legend>
          <div v-if="workdirLoading" class="field-hint">加载中…</div>
          <div v-else-if="workdirStats" class="workdir-panel">
            <div class="workdir-stats-grid">
              <div class="workdir-stat-item">
                <span class="workdir-stat-label">磁盘占用</span>
                <b class="workdir-stat-value">{{ workdirStats.total_size_human }}</b>
              </div>
              <div class="workdir-stat-item">
                <span class="workdir-stat-label">目标目录数</span>
                <b class="workdir-stat-value">{{ workdirStats.total_dirs }}</b>
              </div>
              <div class="workdir-stat-item">
                <span class="workdir-stat-label">自动清理</span>
                <b class="workdir-stat-value" :class="workdirStats.auto_cleanup_enabled ? 'on' : 'off'">
                  {{ workdirStats.auto_cleanup_enabled ? `已开启（${workdirStats.retention_days}天）` : '已关闭' }}
                </b>
              </div>
              <div v-if="workdirStats.oldest_dir" class="workdir-stat-item">
                <span class="workdir-stat-label">最旧目录</span>
                <b class="workdir-stat-value small">{{ workdirStats.oldest_dir.age_days }}天前</b>
              </div>
            </div>
            <p class="field-hint">工作路径：<code>{{ workdirStats.work_root }}</code></p>
            <p v-if="workdirStats.auto_cleanup_enabled" class="field-hint">
              系统将自动清理超过 {{ workdirStats.retention_days }} 天未修改的工作目录（每 6 小时检查一次）。
            </p>

            <div class="workdir-cleanup-controls">
              <label class="workdir-retention-label">
                清理保留天数
                <input v-model.number="cleanupRetentionDays" type="number" min="0" max="365" />
              </label>
              <label class="workdir-dryrun-label">
                <input type="checkbox" v-model="cleanupDryRun" />
                模拟运行（不实际删除）
              </label>
              <button type="button" class="test-btn" :disabled="workdirCleaning" @click="runCleanup">
                {{ workdirCleaning ? "清理中…" : (cleanupDryRun ? "模拟清理" : "执行清理") }}
              </button>
              <button type="button" class="test-btn" @click="loadWorkdirStats" :disabled="workdirLoading">
                刷新统计
              </button>
            </div>

            <div v-if="workdirResult" class="workdir-result">
              <div class="workdir-result-summary">
                <span>{{ workdirResult.dry_run ? "模拟清理" : "清理" }}完成</span>
                <span>扫描 {{ workdirResult.scanned_dirs }} 个目录</span>
                <span>删除 {{ workdirResult.deleted_dirs }} 个</span>
                <span v-if="workdirResult.failed_dirs">失败 {{ workdirResult.failed_dirs }} 个</span>
                <span>释放 {{ workdirResult.freed_human }}</span>
              </div>
              <details v-if="workdirResult.deleted?.length" class="workdir-result-details">
                <summary>已清理目录（{{ workdirResult.deleted.length }}）</summary>
                <div class="workdir-result-list">
                  <div v-for="d in workdirResult.deleted.slice(0, 100)" :key="d.name" class="workdir-result-item">
                    <span class="workdir-item-name">{{ d.name }}</span>
                    <span class="workdir-item-age">{{ d.age_days }}天</span>
                    <span class="workdir-item-size">{{ d.size_human }}</span>
                  </div>
                  <p v-if="workdirResult.deleted.length > 100" class="field-hint">
                    仅显示前 100 条，共 {{ workdirResult.deleted.length }} 条
                  </p>
                </div>
              </details>
              <details v-if="workdirResult.failed?.length" class="workdir-result-details">
                <summary>失败目录（{{ workdirResult.failed.length }}）</summary>
                <div class="workdir-result-list">
                  <div v-for="d in workdirResult.failed" :key="d.name" class="workdir-result-item">
                    <span class="workdir-item-name">{{ d.name }}</span>
                    <span class="workdir-item-age">{{ d.error }}</span>
                  </div>
                </div>
              </details>
            </div>
          </div>
        </fieldset>

        <div class="settings-actions">
          <button type="submit" class="primary" :disabled="saving">{{ saving ? "保存中…" : "保存配置" }}</button>
          <span>密钥输入框留空时不会覆盖已有值。</span>
        </div>
      </form>
    </div>

    <!-- 一键更新（后端未注册 update 路由时自动隐藏，如原版 rsync 部署） -->
    <section v-if="updateState.supported" class="settings-block update-section">
      <legend>
        <span>版本更新</span>
        <small>从 GitHub 拉取最新代码并自动重启</small>
      </legend>
      <div v-if="updateState.restarting" class="update-restarting">
        <div class="update-spinner"></div>
        <p>服务正在重启，自动重连中…</p>
      </div>
      <div v-else class="update-body">
        <button class="btn-check" @click="checkUpdate" :disabled="updateState.checking">
          {{ updateState.checking ? "检测中…" : "检查更新" }}
        </button>
        <div v-if="updateState.error" class="update-error">{{ updateState.error }}</div>
        <div v-if="updateState.info?.update_available" class="update-info">
          <div class="update-version">
            <span class="version-old">{{ updateState.info.current_commit }}</span>
            <span class="version-arrow">→</span>
            <span class="version-new">{{ updateState.info.latest_commit }}</span>
            <span class="update-badge">落后 {{ updateState.info.commits_behind }} 个提交</span>
          </div>
          <div class="update-latest-msg">{{ updateState.info.latest_message }}</div>
          <details class="update-files">
            <summary>变更文件 ({{ updateState.info.changed_files?.length || 0 }})</summary>
            <ul>
              <li v-for="f in updateState.info.changed_files" :key="f">{{ f }}</li>
            </ul>
          </details>
          <div v-if="updateState.info.hot_updateable" class="update-actions">
            <button class="primary" @click="runUpdate" :disabled="updateState.updating">
              {{ updateState.updating ? "更新中…" : "一键更新并重启" }}
            </button>
            <span class="update-hint">仅后端代码变更，可热更新（git pull + 自动重启）</span>
          </div>
          <div v-else class="update-actions rebuild">
            <p class="update-warn">⚠ 本次更新包含前端/Dockerfile 变更，需在服务器执行完整重建：</p>
            <code class="rebuild-cmd">{{ updateState.info.rebuild_command || 'git pull && docker compose up -d --build' }}</code>
          </div>
        </div>
        <div v-else-if="updateState.info && !updateState.info.update_available && !updateState.info.error" class="update-uptodate">
          ✓ 已是最新版本（{{ updateState.info.current_commit }}）
        </div>
      </div>
    </section>

    <div v-if="toastMsg" class="toast settings-toast">{{ toastMsg }}</div>
  </section>
</template>
