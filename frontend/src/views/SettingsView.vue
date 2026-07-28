<script setup>
import { computed, nextTick, onMounted, onUnmounted, reactive, ref, watch } from "vue";
import { api } from "../api.js";
import LlmModelPicker from "../components/LlmModelPicker.vue";

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
/** 自动保存状态：idle | pending | saving | saved | error | incomplete */
const autoSaveStatus = ref("idle");
const autoSaveError = ref("");
let autoSaveTimer = null;
let suppressAutoSave = false; // load / 保存回写期间屏蔽 watch
let dirtyDuringSave = false; // 保存飞行中又有改动 → finally 后补一次调度
let healthPoll = null;
let restartPoll = null;   // pollHealth 的重启轮询计时器（组件卸载时清理，防泄漏）

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
    // 非 git / 网络失败：区块仍显示，把原因和手动更新指引给用户看
    // 以前用 /非 git|无法/ 直接 supported=false，导致「检查更新整块消失」
  } catch (e) {
    const msg = String(e.message || e);
    // 仅原版未注册 update 路由（404）时隐藏；发布版始终保留入口
    if (/^\s*404\b|not found/i.test(msg)) {
      updateState.supported = false;
    } else {
      updateState.error = msg.replace(/^\d+\s*/, "");
    }
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
  clearInterval(restartPoll);
  restartPoll = setInterval(async () => {
    attempts++;
    try {
      const r = await fetch("/health");
      if (r.ok) {
        clearInterval(restartPoll);
        updateState.restarting = false;
        toast("更新完成，服务已重启 🎉");
        updateState.info = null;
        load();
      }
    } catch {}
    if (attempts > 60) { clearInterval(restartPoll); updateState.restarting = false; updateState.error = "重启超时，请手动刷新页面"; }
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
  llm_providers: [],
  fofa_key: "",
  fofa_key_set: false,
  fofa_base_url: "",
  max_pages: 20,
  page_size: 100,
  default_intent_mode: "",
  default_engine: "fofa",
  engines: {},
  available_engines: [],
  concurrency: 3,
  skip_score_threshold: -10,
  worker_prompt_version: "legacy",
});

const engineKeysSetCount = computed(() =>
  Object.values(form.engines || {}).filter((e) => e && e.key_set).length
);

function toast(m) {
  toastMsg.value = m;
  setTimeout(() => (toastMsg.value = ""), 2600);
}

let _providerUidSeq = 1;
function nextProviderUid() {
  return `llm-uid-${_providerUidSeq++}`;
}

function newLlmProvider() {
  return {
    _uid: nextProviderUid(),
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

function loadLlmProviders(items = [], { resetSelection = true } = {}) {
  form.llm_providers = items.map((provider, idx) => ({
    _uid: provider._uid || nextProviderUid(),
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
  if (resetSelection) {
    selectedLlmProvider.value = form.llm_providers.length ? 0 : -1;
  } else if (!form.llm_providers.length) {
    selectedLlmProvider.value = -1;
  } else {
    selectedLlmProvider.value = Math.min(
      Math.max(selectedLlmProvider.value, 0),
      form.llm_providers.length - 1,
    );
  }
}

/** 保存成功后就地合并服务端回写，禁止整表替换（否则选中端点会跳回第 1 个，正在编辑的内容也丢）。 */
function mergeProvidersAfterSave(saved = [], clearedKeyIndexes = []) {
  const cleared = new Set(clearedKeyIndexes);
  for (let i = 0; i < form.llm_providers.length; i++) {
    const local = form.llm_providers[i];
    const remote = saved[i];
    if (!remote) continue;
    if (cleared.has(i)) local.api_key = "";
    local.api_key_set = !!remote.api_key_set;
    local.api_key_masked = remote.api_key_masked || local.api_key_masked || "";
    local.key_ref = remote.key_ref || local.key_ref || "";
    local.health_ref = remote.health_ref || local.health_ref || "";
    if (remote.health) local.health = remote.health;
  }
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
  const provider = form.llm_providers[idx];
  if (!provider) return;
  const label = provider.name || provider.model || `端点 #${idx + 1}`;
  if (!confirm(`确认删除模型端点「${label}」？`)) return;
  form.llm_providers.splice(idx, 1);
  if (!form.llm_providers.length) {
    selectedLlmProvider.value = -1;
  } else if (selectedLlmProvider.value > idx) {
    selectedLlmProvider.value -= 1;
  } else if (selectedLlmProvider.value === idx) {
    selectedLlmProvider.value = Math.min(idx, form.llm_providers.length - 1);
  }
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
  if (item.ok && item.tool_calling) {
    const tc = {
      yes: "工具调用 ✓",
      no: "工具调用 ✗ 不支持原生 function calling（系统会自动用提示词模拟兜底；如仍异常可设 AUTOHUNTER_TOOL_COMPAT=prompt）",
      unknown: "工具调用 ? 未检测到（若挖洞全程不调用工具，可设 AUTOHUNTER_TOOL_COMPAT=prompt 强制模拟）",
    };
    parts.push(tc[item.tool_calling] || "");
  }
  if (!item.ok && item.error) parts.push(item.error);
  return parts.filter(Boolean).join(" · ");
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
  suppressAutoSave = true;
  try {
    for (const provider of form.llm_providers) {
      if (provider.health_ref && byRef.has(provider.health_ref)) {
        provider.health = byRef.get(provider.health_ref);
      }
    }
  } finally {
    await nextTick();
    suppressAutoSave = false;
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
  // 用 _uid 锚定：请求期间用户若主动换端点，结束时不抢回选中态
  const keepUid = provider._uid;
  const keepSelected = selectedLlmProvider.value;
  suppressAutoSave = true;
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
    const nowUid = form.llm_providers[selectedLlmProvider.value]?._uid;
    // 仅当选中仍是发起查询的端点、或被副作用冲掉时，才按 uid 纠正索引
    if (nowUid === keepUid || selectedLlmProvider.value === keepSelected) {
      const found = form.llm_providers.findIndex((p) => p._uid === keepUid);
      if (found >= 0) selectedLlmProvider.value = found;
    }
    suppressAutoSave = false;
    scheduleAutoSave(); // 可能自动选中了模型
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
  suppressAutoSave = true;
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
    await nextTick();
    suppressAutoSave = false;
  }
}

async function load() {
  clearTimeout(autoSaveTimer);
  autoSaveTimer = null;
  dirtyDuringSave = false;
  loading.value = true;
  suppressAutoSave = true;
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
    loadLlmProviders(s.llm?.providers || []);
    form.fofa_key = "";
    form.fofa_key_set = s.fofa?.key_set;
    form.fofa_base_url = s.fofa?.base_url || "";
    form.max_pages = s.fofa?.max_pages ?? 20;
    form.page_size = s.fofa?.page_size ?? 100;
    form.default_intent_mode = s.fofa?.default_intent_mode || "";
    form.default_engine = s.defaults?.engine || "fofa";
    form.available_engines = s.available_engines || [];
    const engView = s.engines || {};
    const nextEngines = {};
    for (const meta of form.available_engines) {
      const name = meta.name;
      const cur = engView[name] || {};
      nextEngines[name] = {
        display_name: meta.display_name || cur.display_name || name,
        key: "",
        key_set: !!cur.key_set,
        base_url: cur.base_url || "",
      };
    }
    if (nextEngines.fofa && !nextEngines.fofa.key_set && s.fofa?.key_set) {
      nextEngines.fofa.key_set = true;
    }
    if (nextEngines.fofa && !nextEngines.fofa.base_url && s.fofa?.base_url) {
      nextEngines.fofa.base_url = s.fofa.base_url;
    }
    form.engines = nextEngines;
    form.concurrency = s.defaults?.concurrency ?? 3;
    form.skip_score_threshold = s.defaults?.skip_score_threshold ?? -10;
    form.worker_prompt_version = s.defaults?.worker_prompt_version || "legacy";
    autoSaveStatus.value = "idle";
    autoSaveError.value = "";
  } finally {
    loading.value = false;
    await nextTick();
    suppressAutoSave = false;
  }
}

function secretReady(value) {
  // 密钥输入中途不自动提交（避免 "sk-" 半成品写进 DB）；留空=不覆盖
  const v = String(value || "").trim();
  return v.length >= 8;
}

function scheduleAutoSave() {
  if (loading.value) return;
  if (saving.value) {
    // 飞行中改动（含 suppressAutoSave=true 的回写窗口）：标记脏，finally 再调度
    dirtyDuringSave = true;
    autoSaveStatus.value = "pending";
    return;
  }
  if (suppressAutoSave) return;
  autoSaveStatus.value = "pending";
  autoSaveError.value = "";
  clearTimeout(autoSaveTimer);
  // 端点详情输入中拉长防抖，避免打字过程中频繁落库抢焦点/冲选中态
  const typingPool = typeof document !== "undefined"
    && !!document.activeElement?.closest?.(".provider-detail, .provider-fields, .llm-pool-pane .model-picker");
  autoSaveTimer = setTimeout(() => {
    save({ silent: true }).catch(() => {});
  }, typingPool ? 2500 : 1200);
}

async function save({ silent = false } = {}) {
  if (saving.value || loading.value) return;
  // 配置不完整时：静默跳过自动保存，手动保存仍提示
  try {
    validateLlmProviders();
  } catch (e) {
    autoSaveStatus.value = "incomplete";
    autoSaveError.value = String(e.message || e);
    if (!silent) toast(autoSaveError.value);
    return;
  }

  saving.value = true;
  dirtyDuringSave = false;
  autoSaveStatus.value = "saving";
  autoSaveError.value = "";
  const clearedKeyIndexes = [];
  try {
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
        max_pages: Number(form.max_pages),
        page_size: Number(form.page_size),
        default_intent_mode: form.default_intent_mode,
      },
      engines: {},
      defaults: {
        concurrency: Number(form.concurrency),
        skip_score_threshold: Number(form.skip_score_threshold),
        worker_prompt_version: form.worker_prompt_version,
        engine: form.default_engine || "fofa",
      },
    };
    if (secretReady(form.api_key)) body.llm.api_key = form.api_key.trim();
    for (const [name, eng] of Object.entries(form.engines || {})) {
      const patch = { base_url: eng.base_url || "" };
      if (secretReady(eng.key)) patch.key = eng.key.trim();
      body.engines[name] = patch;
    }
    const fofaEng = form.engines?.fofa;
    if (fofaEng) {
      body.fofa.base_url = fofaEng.base_url || "";
      if (secretReady(fofaEng.key)) body.fofa.key = fofaEng.key.trim();
    }
    // 端点池密钥：半成品不提交，靠 key_ref 让后端保留原值
    if (llmMode.value === "pool") {
      body.llm.providers = body.llm.providers.map((provider, idx) => {
        if (secretReady(provider.api_key)) {
          clearedKeyIndexes.push(idx);
          return provider;
        }
        return { ...provider, api_key: "" };
      });
    }

    suppressAutoSave = true;
    const s = await api.updateSettings(body);
    meta.value = { updated_at: s.updated_at };
    form.api_key = "";
    form.fofa_key = "";
    form.api_key_set = s.llm?.api_key_set;
    form.key_ref = s.llm?.key_ref || "";
    llmMode.value = s.llm?.mode === "pool" ? "pool" : "single";
    form.protocol = normalizeLlmProtocol(s.llm?.protocol);
    form.fofa_key_set = s.fofa?.key_set;
    const engView = s.engines || {};
    for (const name of Object.keys(form.engines || {})) {
      const cur = engView[name] || {};
      form.engines[name].key = "";
      form.engines[name].key_set = !!cur.key_set || (name === "fofa" && !!s.fofa?.key_set);
      form.engines[name].base_url = cur.base_url || (name === "fofa" ? (s.fofa?.base_url || "") : "") || form.engines[name].base_url || "";
      if (cur.display_name) form.engines[name].display_name = cur.display_name;
    }
    form.default_engine = s.defaults?.engine || form.default_engine;
    // 关键：禁止 loadLlmProviders 整表替换；就地合并，不强制改写选中索引（用户飞行中换端点不被抢回）
    if (llmMode.value === "pool") {
      mergeProvidersAfterSave(s.llm?.providers || [], clearedKeyIndexes);
      if (form.llm_providers.length && selectedLlmProvider.value >= form.llm_providers.length) {
        selectedLlmProvider.value = form.llm_providers.length - 1;
      }
    }
    autoSaveStatus.value = dirtyDuringSave ? "pending" : "saved";
    if (!silent) toast("系统配置已保存");
  } catch (e) {
    const msg = String(e.message || e).replace(/^\d+\s*/, "");
    autoSaveStatus.value = "error";
    autoSaveError.value = msg;
    toast(msg);
  } finally {
    saving.value = false;
    await nextTick();
    suppressAutoSave = false;
    if (dirtyDuringSave) {
      dirtyDuringSave = false;
      scheduleAutoSave();
    }
  }
}

watch([form, llmMode], () => scheduleAutoSave(), { deep: true });

const autoSaveLabel = computed(() => {
  if (autoSaveStatus.value === "pending") return "将自动保存…";
  if (autoSaveStatus.value === "saving") return "自动保存中…";
  if (autoSaveStatus.value === "saved") {
    const t = meta.value.updated_at?.slice(11, 19) || "";
    return t ? `已自动保存 ${t}` : "已自动保存";
  }
  if (autoSaveStatus.value === "incomplete") return autoSaveError.value || "完善配置后将自动保存";
  if (autoSaveStatus.value === "error") return autoSaveError.value || "自动保存失败";
  return "改动后约 1 秒自动保存";
});

onMounted(async () => {
  await load();
  refreshProviderHealth().catch(() => {});
  healthPoll = setInterval(() => refreshProviderHealth().catch(() => {}), 10000);
  // 探测后端是否支持更新 API（原版不注册 → supported=false → 隐藏区块）
  checkUpdate();
});
onUnmounted(() => {
  clearInterval(healthPoll);
  clearInterval(restartPoll);
  clearTimeout(autoSaveTimer);
});
</script>

<template>
  <section class="view settings-view">
    <header class="page-head">
      <h2>系统配置</h2>
      <p class="page-sub">
        全局默认 LLM / 资产测绘引擎 / 调度参数。改动后约 1 秒自动保存；新建任务留空时会使用此处配置，任务内填写可单独覆盖。
        <span v-if="meta.updated_at" class="settings-updated">上次保存 {{ meta.updated_at?.slice(0, 19).replace("T", " ") }}</span>
      </p>
    </header>

    <!-- 骨架屏：镜像真实的「摘要侧栏 + 配置块」两栏布局，与加载后的结构对齐（不再是一行“加载中…”）。 -->
    <div v-if="loading" class="settings-layout settings-skeleton" aria-hidden="true">
      <aside class="settings-summary skeleton-panel">
        <div class="skeleton-block lg" style="height:16px;width:58%"></div>
        <div class="skeleton-line" style="margin-top:16px"></div>
        <div class="skeleton-line"></div>
        <div class="skeleton-line"></div>
        <div class="skeleton-line" style="width:68%"></div>
      </aside>
      <div class="settings-form">
        <div v-for="i in 3" :key="i" class="settings-block skeleton-panel">
          <div class="skeleton-block lg" style="height:15px;width:38%;margin-bottom:16px"></div>
          <div class="skeleton-line"></div>
          <div class="skeleton-line"></div>
          <div class="skeleton-line" style="width:84%"></div>
          <div class="skeleton-row" style="margin-top:14px">
            <div class="skeleton-chip"></div>
            <div class="skeleton-chip wide"></div>
          </div>
        </div>
      </div>
    </div>
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
            <span>测绘</span>
            <b>{{ form.default_engine || "fofa" }} · {{ form.max_pages }} 页</b>
          </div>
          <i :class="{ on: engineKeysSetCount > 0 }">{{ engineKeysSetCount > 0 ? `${engineKeysSetCount} key` : "no key" }}</i>
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
              <LlmModelPicker
                v-model="form.model"
                :models="singleModels"
                :loading="singleModelsLoading"
                :error="singleModelsError"
                required
                @refresh="loadSingleModels"
              />
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
                :key="provider._uid || idx"
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
                  <LlmModelPicker
                    v-model="selectedLlm.model"
                    :models="selectedLlm.models"
                    :loading="selectedLlm.modelsLoading"
                    :error="selectedLlm.modelsError"
                    required
                    @refresh="loadProviderModels(selectedLlmProvider)"
                  />
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
            <span>资产测绘</span>
            <small>多引擎搜集默认；创建任务可选引擎，Key 在此统一配置</small>
          </legend>
          <div class="settings-grid">
            <label class="full">默认搜索引擎
              <select v-model="form.default_engine">
                <option v-for="eng in form.available_engines" :key="eng.name" :value="eng.name">
                  {{ eng.display_name || eng.name }}
                </option>
              </select>
            </label>
            <p class="field-hint full">新建任务「搜索引擎」留空时使用此项。任务里仍可临时换引擎。</p>
            <label>默认最大页数 <input v-model="form.max_pages" type="number" min="1" /></label>
            <label>每页条数 <input v-model="form.page_size" type="number" min="1" /></label>
            <label class="full">默认搜集方式
              <select v-model="form.default_intent_mode">
                <option value="">自动判断</option>
                <option value="syntax">查询语法（FOFA 语法或当前引擎原生均可）</option>
                <option value="intent">自然语言意图</option>
              </select>
            </label>
            <p class="field-hint full">分页与搜集方式对当前选用的测绘引擎生效，不限于 FOFA。</p>
          </div>

          <div class="engine-keys">
            <h4 class="engine-keys-title">各引擎 API Key</h4>
            <p class="field-hint">按需配置；未配 Key 的引擎在任务里选中时无法搜资产。密钥留空表示不修改。</p>
            <div v-for="eng in form.available_engines" :key="eng.name" class="engine-key-card">
              <div class="engine-key-head">
                <strong>{{ form.engines[eng.name]?.display_name || eng.display_name || eng.name }}</strong>
                <i :class="{ on: form.engines[eng.name]?.key_set }">
                  {{ form.engines[eng.name]?.key_set ? "已配置" : "未配置" }}
                </i>
              </div>
              <div class="settings-grid" v-if="form.engines[eng.name]">
                <label class="full">API Key
                  <input v-model="form.engines[eng.name].key" type="password"
                    :placeholder="form.engines[eng.name]?.key_set ? '已配置，留空不修改' : `${eng.display_name || eng.name} API Key`" />
                </label>
                <label class="full">API 端点（可选）
                  <input v-model="form.engines[eng.name].base_url"
                    :placeholder="eng.name === 'fofa' ? 'https://fofa.info' : '留空用官方默认'" />
                </label>
              </div>
            </div>
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
            <p class="field-hint full">Collector 评分低于此值的目标直接跳过，避免 worker 消耗在垃圾资产上。</p>
          </div>
        </fieldset>

        <div class="settings-actions">
          <button type="submit" class="primary" :disabled="saving">
            {{ saving ? "保存中…" : "立即保存" }}
          </button>
          <span class="autosave-status" :class="autoSaveStatus">{{ autoSaveLabel }}</span>
          <span class="settings-actions-hint">密钥留空不覆盖；输入完成后会随自动保存写入。</span>
        </div>
      </form>
    </div>

    <!-- 一键更新（仅原版未注册 update 路由时隐藏；发布版即使非 git 也保留入口） -->
    <section v-if="updateState.supported" class="settings-block update-section">
      <legend>
        <span>版本更新</span>
        <small>检查 GitHub 最新代码；git 部署可一键热更，镜像部署给出手动指引</small>
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
        <div v-if="updateState.info?.error" class="update-error">
          <p>{{ updateState.info.error }}</p>
          <p v-if="updateState.info.hint" class="update-hint">{{ updateState.info.hint }}</p>
          <a
            class="update-link"
            :href="updateState.info.releases_url || 'https://github.com/StanleyNull/AutoHunter'"
            target="_blank"
            rel="noopener"
          >打开 GitHub 仓库 / Releases</a>
        </div>
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
