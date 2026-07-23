<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import { api } from "../api.js";

const loading = ref(true);
const saving = ref(false);
const testingLlm = ref(false);
const toastMsg = ref("");
const meta = ref({ updated_at: null });
const llmMode = ref("single");
const llmTest = ref(null);
const singleModels = ref([]);
const singleModelsLoading = ref(false);
const singleModelsError = ref("");
let healthPoll = null;

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
  key_ref: "",
  model: "",
  protocol: "openai_chat",
  temperature: 0.3,
  api_key_set: false,
  llm_provider_count: 0,
  llm_providers: [],
  fofa_key: "",
  fofa_key_set: false,
  fofa_base_url: "",
  max_pages: 20,
  page_size: 100,
  default_intent_mode: "",
  concurrency: 3,
  skip_score_threshold: -10,
  worker_prompt_version: "legacy",
});

function toast(m) {
  toastMsg.value = m;
  setTimeout(() => (toastMsg.value = ""), 2600);
}

function newLlmProvider() {
  return {
    name: `llm-${form.llm_providers.length + 1}`,
    base_url: form.base_url || "https://api.deepseek.com/v1",
    api_key: "",
    api_key_set: false,
    api_key_masked: "",
    key_ref: "",
    health_ref: "",
    model: form.model || "deepseek-chat",
    protocol: form.protocol || "openai_chat",
    temperature: Number(form.temperature ?? 0.3),
    weight: 1,
    enabled: true,
    testing: false,
    models: [],
    modelsLoading: false,
    modelsError: "",
    health: {},
  };
}

const selectedLlmProvider = ref(0);
const selectedLlm = computed(() => form.llm_providers[selectedLlmProvider.value] || null);

function normalizeLlmProtocol(protocol) {
  return ["auto", "openai_chat", "anthropic_messages"].includes(protocol) ? protocol : "auto";
}

function loadLlmProviders(items = []) {
  form.llm_providers = items.map((provider, idx) => ({
    name: provider.name || `llm-${idx + 1}`,
    base_url: provider.base_url || "",
    api_key: "",
    api_key_set: !!provider.api_key_set,
    api_key_masked: provider.api_key_masked || "",
    key_ref: provider.key_ref || "",
    health_ref: provider.health_ref || "",
    model: provider.model || "",
    protocol: normalizeLlmProtocol(provider.protocol),
    temperature: provider.temperature ?? form.temperature ?? 0.3,
    weight: provider.weight ?? 1,
    enabled: provider.enabled !== false,
    testing: false,
    models: [],
    modelsLoading: false,
    modelsError: "",
    health: provider.health || {},
  }));
  selectedLlmProvider.value = form.llm_providers.length ? 0 : -1;
}

function providerHealthClass(provider) {
  const status = provider.health?.status || "";
  if (["ok", "failed", "cooldown", "half_open"].includes(status)) {
    return status.replace("_", "-");
  }
  return "unknown";
}

function providerHealthText(provider) {
  const status = provider.health?.status || "";
  if (status === "ok") return "健康";
  if (status === "failed") return "失效";
  if (status === "cooldown") return "冷却中";
  if (status === "half_open") return "探测中";
  return "未检测";
}

function providerHealthTitle(provider) {
  const health = provider.health || {};
  if (!health.last_seen) return "暂无运行时健康记录";
  const parts = [health.last_seen];
  if (health.consecutive_failures) parts.push(`连续失败 ${health.consecutive_failures} 次`);
  if (health.cooldown_until) parts.push(`冷却到 ${health.cooldown_until}`);
  if (health.last_error) parts.push(health.last_error);
  return parts.join("；");
}

function addLlmProvider() {
  form.llm_providers.push(newLlmProvider());
  selectedLlmProvider.value = form.llm_providers.length - 1;
  llmTest.value = null;
}

function removeLlmProvider(idx) {
  form.llm_providers.splice(idx, 1);
  if (!form.llm_providers.length) selectedLlmProvider.value = -1;
  else selectedLlmProvider.value = Math.min(idx, form.llm_providers.length - 1);
  llmTest.value = null;
}

function moveLlmProvider(idx, delta) {
  const next = idx + delta;
  if (next < 0 || next >= form.llm_providers.length) return;
  const [provider] = form.llm_providers.splice(idx, 1);
  form.llm_providers.splice(next, 0, provider);
  if (selectedLlmProvider.value === idx) selectedLlmProvider.value = next;
  else if (selectedLlmProvider.value === next) selectedLlmProvider.value = idx;
}

function buildLlmProvider(provider) {
  return {
    name: String(provider.name || "").trim(),
    base_url: String(provider.base_url || "").trim(),
    api_key: String(provider.api_key || "").trim(),
    key_ref: provider.key_ref || "",
    model: String(provider.model || "").trim(),
    protocol: normalizeLlmProtocol(provider.protocol),
    temperature: Number(provider.temperature ?? form.temperature ?? 0.3),
    weight: Math.max(1, Math.min(100, Number(provider.weight || 1))),
    enabled: provider.enabled !== false,
  };
}

function buildLlmProviders() {
  return form.llm_providers.map(buildLlmProvider);
}

function invalidateSingleKey() {
  form.key_ref = "";
  form.api_key_set = false;
  singleModels.value = [];
  singleModelsError.value = "";
  llmTest.value = null;
}

function invalidateProviderKey(provider) {
  if (!provider) return;
  provider.key_ref = "";
  provider.api_key_set = false;
  provider.api_key_masked = "";
  provider.health_ref = "";
  provider.health = {};
  provider.models = [];
  provider.modelsError = "";
  llmTest.value = null;
}

function validateLlmProviders() {
  if (llmMode.value !== "pool") {
    if (!String(form.base_url || "").trim() || !String(form.model || "").trim()
      || (!String(form.api_key || "").trim() && !form.key_ref)) {
      throw new Error("单端点配置缺少 base_url、api_key 或模型");
    }
    return;
  }
  if (!form.llm_providers.length) throw new Error("端点池至少需要一个端点");
  for (const [idx, provider] of buildLlmProviders().entries()) {
    if (!provider.name || !provider.base_url || !provider.model || (!provider.api_key && !provider.key_ref)) {
      throw new Error(`LLM 端点 #${idx + 1} 缺少名称、base_url、api_key 或模型`);
    }
  }
  if (!form.llm_providers.some((provider) => provider.enabled !== false)) {
    throw new Error("端点池至少需要启用一个端点");
  }
}

function resultText(item) {
  if (!item) return "";
  const parts = [];
  if (item.protocol) parts.push(item.protocol);
  if (item.model) parts.push(item.model);
  if (item.latency_ms) parts.push(`${item.latency_ms}ms`);
  if (item.ok && item.reply) parts.push(`reply: ${item.reply}`);
  if (!item.ok && item.error) parts.push(item.error);
  return parts.join(" · ");
}

function applyLlmHealthResults(results = []) {
  for (const item of results) {
    const provider = form.llm_providers.find((row) =>
      (row.name && item.name && row.name === item.name)
      || (row.base_url === item.base_url && row.model === item.model)
    );
    if (!provider) continue;
    provider.health = {
      status: item.ok ? "ok" : "failed",
      last_seen: new Date().toISOString(),
      last_error: item.ok ? "" : (item.error || "测试失败"),
    };
  }
}

async function refreshProviderHealth() {
  if (llmMode.value !== "pool" || !form.llm_providers.length) return;
  const res = await api.providerHealth();
  const byRef = new Map((res.providers || []).map((item) => [item.health_ref, item.health || {}]));
  for (const provider of form.llm_providers) {
    if (provider.health_ref && byRef.has(provider.health_ref)) {
      provider.health = byRef.get(provider.health_ref);
    }
  }
}

async function loadSingleModels() {
  singleModelsLoading.value = true;
  singleModelsError.value = "";
  try {
    const res = await api.listModels({
      base_url: form.base_url,
      api_key: form.api_key.trim(),
      key_ref: form.key_ref,
      model: form.model,
      protocol: form.protocol,
    });
    if (res?.ok && res.models?.length) {
      singleModels.value = res.models;
      if (!form.model || !singleModels.value.includes(form.model)) form.model = singleModels.value[0];
      toast(`已获取 ${res.models.length} 个模型`);
    } else {
      singleModels.value = [];
      singleModelsError.value = res?.error || "未获取到模型列表";
      toast("获取模型失败");
    }
  } catch (e) {
    singleModels.value = [];
    singleModelsError.value = String(e.message || e).replace(/^\d+\s*/, "");
    toast("获取模型失败");
  } finally {
    singleModelsLoading.value = false;
  }
}

async function loadProviderModels(idx) {
  const provider = form.llm_providers[idx];
  if (!provider) return;
  provider.modelsLoading = true;
  provider.modelsError = "";
  try {
    const res = await api.listModels({
      base_url: provider.base_url,
      api_key: String(provider.api_key || "").trim(),
      protocol: provider.protocol,
      key_ref: provider.key_ref,
      model: provider.model,
    });
    if (res?.ok && res.models?.length) {
      provider.models = res.models;
      if (!provider.model || !provider.models.includes(provider.model)) provider.model = provider.models[0];
      toast(`已获取 ${res.models.length} 个模型`);
    } else {
      provider.models = [];
      provider.modelsError = res?.error || "未获取到模型列表";
      toast(`端点 #${idx + 1} 获取模型失败`);
    }
  } catch (e) {
    provider.models = [];
    provider.modelsError = String(e.message || e).replace(/^\d+\s*/, "");
    toast(`端点 #${idx + 1} 获取模型失败`);
  } finally {
    provider.modelsLoading = false;
  }
}

async function testSingleLlm() {
  testingLlm.value = true;
  llmTest.value = null;
  try {
    const res = await api.testLLM({
      base_url: form.base_url,
      api_key: form.api_key.trim(),
      key_ref: form.key_ref,
      model: form.model,
      protocol: form.protocol,
      temperature: Number(form.temperature),
    });
    llmTest.value = res;
    toast(res.ok ? "LLM 测试通过" : "LLM 测试失败");
  } catch (e) {
    llmTest.value = { ok: false, results: [], error: String(e.message || e).replace(/^\d+\s*/, "") };
    toast("LLM 测试失败");
  } finally {
    testingLlm.value = false;
  }
}

async function testLlmProvider(idx) {
  const provider = form.llm_providers[idx];
  if (!provider) return;
  provider.testing = true;
  llmTest.value = null;
  try {
    const payload = buildLlmProvider(provider);
    if (!payload.base_url || !payload.model || (!payload.api_key && !payload.key_ref)) {
      throw new Error(`LLM 端点 #${idx + 1} 配置不完整`);
    }
    const res = await api.testLLM({ providers: [payload] });
    llmTest.value = res;
    applyLlmHealthResults(res.results || []);
    toast(res.ok ? `端点 #${idx + 1} 测试通过` : `端点 #${idx + 1} 测试失败`);
  } catch (e) {
    llmTest.value = { ok: false, results: [], error: String(e.message || e).replace(/^\d+\s*/, "") };
    toast(`端点 #${idx + 1} 测试失败`);
  } finally {
    provider.testing = false;
  }
}

async function load() {
  loading.value = true;
  try {
    const s = await api.getSettings();
    meta.value = { updated_at: s.updated_at };
    form.base_url = s.llm?.base_url || "";
    form.model = s.llm?.model || "";
    form.protocol = normalizeLlmProtocol(s.llm?.protocol);
    form.temperature = s.llm?.temperature ?? 0.3;
    form.api_key = "";
    form.key_ref = s.llm?.key_ref || "";
    form.api_key_set = s.llm?.api_key_set;
    llmMode.value = s.llm?.mode === "pool" ? "pool" : "single";
    form.llm_provider_count = s.llm?.provider_count || 0;
    loadLlmProviders(s.llm?.providers || []);
    form.fofa_key = "";
    form.fofa_key_set = s.fofa?.key_set;
    form.fofa_base_url = s.fofa?.base_url || "";
    form.max_pages = s.fofa?.max_pages ?? 20;
    form.page_size = s.fofa?.page_size ?? 100;
    form.default_intent_mode = s.fofa?.default_intent_mode || "";
    form.concurrency = s.defaults?.concurrency ?? 3;
    form.skip_score_threshold = s.defaults?.skip_score_threshold ?? -10;
    form.worker_prompt_version = s.defaults?.worker_prompt_version || "legacy";
  } finally {
    loading.value = false;
  }
}

async function save() {
  saving.value = true;
  try {
    validateLlmProviders();
    const body = {
      llm: {
        mode: llmMode.value,
        base_url: form.base_url,
        model: form.model,
        protocol: form.protocol,
        temperature: Number(form.temperature),
        providers: buildLlmProviders(),
      },
      fofa: {
        base_url: form.fofa_base_url,
        max_pages: Number(form.max_pages),
        page_size: Number(form.page_size),
        default_intent_mode: form.default_intent_mode,
      },
      defaults: {
        concurrency: Number(form.concurrency),
        skip_score_threshold: Number(form.skip_score_threshold),
        worker_prompt_version: form.worker_prompt_version,
      },
    };
    if (form.api_key.trim()) body.llm.api_key = form.api_key.trim();
    if (form.fofa_key.trim()) body.fofa.key = form.fofa_key.trim();
    const s = await api.updateSettings(body);
    meta.value = { updated_at: s.updated_at };
    form.api_key = "";
    form.fofa_key = "";
    form.api_key_set = s.llm?.api_key_set;
    form.key_ref = s.llm?.key_ref || "";
    llmMode.value = s.llm?.mode === "pool" ? "pool" : "single";
    form.protocol = normalizeLlmProtocol(s.llm?.protocol);
    form.llm_provider_count = s.llm?.provider_count || 0;
    loadLlmProviders(s.llm?.providers || []);
    form.fofa_key_set = s.fofa?.key_set;
    toast("系统配置已保存");
  } catch (e) {
    toast(String(e.message || e).replace(/^\d+\s*/, ""));
  } finally {
    saving.value = false;
  }
}

onMounted(async () => {
  await load();
  refreshProviderHealth().catch(() => {});
  healthPoll = setInterval(() => refreshProviderHealth().catch(() => {}), 10000);
  // 探测后端是否支持更新 API（原版不注册 → supported=false → 隐藏区块）
  checkUpdate();
});
onUnmounted(() => clearInterval(healthPoll));
</script>

<template>
  <section class="view settings-view">
    <header class="page-head">
      <h2>系统配置</h2>
      <p class="page-sub">
        全局默认 LLM / FOFA / 调度参数。新建任务留空时会使用此处配置；任务内填写可单独覆盖。
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
            <b>{{ llmMode === "pool" ? `${form.llm_providers.length} 个端点` : (form.model || "未设置模型") }}</b>
          </div>
          <i :class="{ on: llmMode === 'pool' ? form.llm_providers.some((p) => p.enabled !== false) : form.api_key_set }">
            {{ llmMode === "pool" ? "pool" : (form.api_key_set ? "key set" : "no key") }}
          </i>
        </div>
        <div class="settings-health">
          <div>
            <span>FOFA</span>
            <b>{{ form.max_pages }} 页 · {{ form.page_size }} / 页</b>
          </div>
          <i :class="{ on: form.fofa_key_set }">{{ form.fofa_key_set ? "key set" : "no key" }}</i>
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
          <div class="llm-mode-switch" role="tablist" aria-label="LLM 调用模式">
            <button
              type="button"
              role="tab"
              :aria-selected="llmMode === 'single'"
              :class="{ active: llmMode === 'single' }"
              @click="llmMode = 'single'; llmTest = null"
            >单端点</button>
            <button
              type="button"
              role="tab"
              :aria-selected="llmMode === 'pool'"
              :class="{ active: llmMode === 'pool' }"
              @click="llmMode = 'pool'; llmTest = null"
            >端点池</button>
          </div>

          <div v-if="llmMode === 'single'" class="settings-grid llm-config-pane">
            <label class="full">base_url
              <input v-model="form.base_url" required placeholder="https://api.deepseek.com/v1" @input="invalidateSingleKey" />
            </label>
            <label class="full">api_key
              <input v-model="form.api_key" type="password"
                :required="!form.key_ref"
                :placeholder="form.api_key_set ? '已配置，留空不修改' : 'sk-...'" />
            </label>
            <label>协议
              <select v-model="form.protocol" @change="invalidateSingleKey">
                <option value="auto">自动判断</option>
                <option value="openai_chat">OpenAI Chat</option>
                <option value="anthropic_messages">Anthropic Messages</option>
              </select>
            </label>
            <label>temperature
              <input v-model="form.temperature" type="number" step="0.1" min="0" max="2" />
            </label>
            <label class="full">模型名
              <div class="model-picker">
                <input v-model="form.model" required list="single-llm-models" placeholder="deepseek-chat" />
                <datalist id="single-llm-models">
                  <option v-for="model in singleModels" :key="model" :value="model" />
                </datalist>
                <button type="button" :disabled="singleModelsLoading" @click="loadSingleModels">
                  {{ singleModelsLoading ? "查询中…" : "查询模型" }}
                </button>
              </div>
              <small v-if="singleModelsError" class="model-hint">{{ singleModelsError }}</small>
            </label>
            <div class="settings-test full">
              <button type="button" :disabled="testingLlm" @click="testSingleLlm">
                {{ testingLlm ? "测试中…" : "测试连接" }}
              </button>
            </div>
          </div>

          <div v-else class="llm-pool-pane">
            <div class="llm-pool-toolbar">
              <div>
                <b>端点列表</b>
                <span>{{ form.llm_providers.length }} 个</span>
              </div>
              <button type="button" @click="addLlmProvider">+ 添加端点</button>
            </div>

            <div v-if="!form.llm_providers.length" class="provider-empty">
              <span>端点池为空</span>
              <button type="button" @click="addLlmProvider">+ 添加端点</button>
            </div>

            <div v-else class="provider-selector" role="listbox" aria-label="LLM 端点列表">
              <button
                v-for="(provider, idx) in form.llm_providers"
                :key="`${idx}:${provider.name}:${provider.base_url}:${provider.protocol}:${provider.key_ref || 'new'}`"
                type="button"
                role="option"
                :aria-selected="selectedLlmProvider === idx"
                class="provider-selector-row"
                :class="[{ active: selectedLlmProvider === idx, disabled: provider.enabled === false }, `health-${providerHealthClass(provider)}`]"
                @click="selectedLlmProvider = idx"
              >
                <span class="provider-dot" :class="providerHealthClass(provider)"></span>
                <b>{{ provider.name || `llm-${idx + 1}` }}</b>
                <small>{{ provider.model || "未设置模型" }}</small>
                <em>{{ provider.protocol === "auto" ? "Auto" : provider.protocol === "anthropic_messages" ? "Anthropic" : "OpenAI" }}</em>
                <i>权重 {{ provider.weight || 1 }}</i>
              </button>
            </div>

            <div v-if="selectedLlm" class="provider-detail">
              <div class="provider-detail-head">
                <div>
                  <span>端点 {{ selectedLlmProvider + 1 }}</span>
                  <strong class="provider-health" :class="providerHealthClass(selectedLlm)" :title="providerHealthTitle(selectedLlm)">
                    {{ providerHealthText(selectedLlm) }}
                  </strong>
                </div>
                <div class="provider-head-actions">
                  <button type="button" title="上移" aria-label="上移端点" :disabled="selectedLlmProvider === 0" @click="moveLlmProvider(selectedLlmProvider, -1)">↑</button>
                  <button type="button" title="下移" aria-label="下移端点" :disabled="selectedLlmProvider === form.llm_providers.length - 1" @click="moveLlmProvider(selectedLlmProvider, 1)">↓</button>
                  <label class="provider-enabled">
                    <input v-model="selectedLlm.enabled" type="checkbox" />
                    启用
                  </label>
                  <button type="button" class="danger" title="删除" aria-label="删除端点" @click="removeLlmProvider(selectedLlmProvider)">×</button>
                </div>
              </div>

              <div class="provider-fields">
                <label>名称 <input v-model="selectedLlm.name" placeholder="primary" /></label>
                <label>协议
                  <select v-model="selectedLlm.protocol" @change="invalidateProviderKey(selectedLlm)">
                    <option value="auto">自动判断</option>
                    <option value="openai_chat">OpenAI Chat</option>
                    <option value="anthropic_messages">Anthropic Messages</option>
                  </select>
                </label>
                <label class="wide">base_url
                  <input v-model="selectedLlm.base_url" placeholder="https://api.deepseek.com/v1" @input="invalidateProviderKey(selectedLlm)" />
                </label>
                <label>api_key
                  <input
                    v-model="selectedLlm.api_key"
                    type="password"
                    :required="!selectedLlm.key_ref"
                    :placeholder="selectedLlm.api_key_set ? `${selectedLlm.api_key_masked}，留空不修改` : 'sk-...'"
                  />
                </label>
                <label>temperature
                  <input v-model="selectedLlm.temperature" type="number" step="0.1" min="0" max="2" />
                </label>
                <label>权重
                  <input v-model="selectedLlm.weight" type="number" min="1" max="100" />
                </label>
                <label class="wide">模型名
                  <div class="model-picker">
                    <input
                      v-model="selectedLlm.model"
                      :list="`llm-provider-models-${selectedLlmProvider}`"
                      placeholder="deepseek-chat"
                    />
                    <datalist :id="`llm-provider-models-${selectedLlmProvider}`">
                      <option v-for="model in selectedLlm.models" :key="model" :value="model" />
                    </datalist>
                    <button type="button" :disabled="selectedLlm.modelsLoading" @click="loadProviderModels(selectedLlmProvider)">
                      {{ selectedLlm.modelsLoading ? "查询中…" : "查询模型" }}
                    </button>
                  </div>
                  <small v-if="selectedLlm.modelsError" class="model-hint">{{ selectedLlm.modelsError }}</small>
                </label>
                <div class="provider-test wide">
                  <button type="button" :disabled="selectedLlm.testing" @click="testLlmProvider(selectedLlmProvider)">
                    {{ selectedLlm.testing ? "测试中…" : "测试当前端点" }}
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div v-if="llmTest" class="settings-test-result" :class="{ ok: llmTest.ok }">
            <b>{{ llmTest.ok ? "LLM 可用" : "LLM 不可用" }}</b>
            <p v-if="llmTest.error">{{ llmTest.error }}</p>
            <ul v-if="llmTest.results?.length">
              <li v-for="item in llmTest.results" :key="`${item.name}-${item.base_url}`" :class="{ ok: item.ok }">
                <strong>{{ item.ok ? "通过" : "失败" }} · {{ item.name || "single" }}</strong>
                <small>{{ resultText(item) }}</small>
              </li>
            </ul>
          </div>
        </fieldset>

        <fieldset class="settings-block">
          <legend>
            <span>FOFA</span>
            <small>Collector 默认资产搜集参数</small>
          </legend>
          <div class="settings-grid">
            <label class="full">FOFA key
              <input v-model="form.fofa_key" type="password"
                :placeholder="form.fofa_key_set ? '已配置，留空不修改' : 'FOFA API Key'" />
            </label>
            <label class="full">API 端点
              <input v-model="form.fofa_base_url" placeholder="https://fofa.info" />
            </label>
            <p class="field-hint full">自定义 FOFA 兼容端点（私有部署/镜像/代理网关），留空用官方地址。</p>
            <label>默认最大页数 <input v-model="form.max_pages" type="number" min="1" /></label>
            <label>每页条数 <input v-model="form.page_size" type="number" min="1" /></label>
            <label class="full">默认搜集方式
              <select v-model="form.default_intent_mode">
                <option value="">自动判断</option>
                <option value="syntax">查询语法（FOFA 或引擎原生均可）</option>
                <option value="intent">自然语言意图</option>
              </select>
            </label>
          </div>
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
