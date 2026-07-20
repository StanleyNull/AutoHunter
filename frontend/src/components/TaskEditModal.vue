<script setup>
import { computed, reactive, ref, watch } from "vue";
import { api } from "../api.js";

const props = defineProps({
  open: Boolean,
  task: Object,
});
const emit = defineEmits(["close", "saved"]);

const models = ref([]);            // 拉取到的可用模型列表
const modelsLoading = ref(false);
const modelsError = ref("");
const useCustomModel = ref(false); // 列表外手输模式

async function loadModels() {
  modelsLoading.value = true;
  modelsError.value = "";
  try {
    const res = await api.listModels(form.base_url || undefined, form.api_key || undefined);
    if (res?.ok && res.models?.length) {
      models.value = res.models;
      // 当前模型不在列表里 → 默认进入手输模式，避免选错
      useCustomModel.value = !!form.model && !models.value.includes(form.model);
    } else {
      models.value = [];
      modelsError.value = res?.error || "未获取到模型列表";
      useCustomModel.value = true;
    }
  } catch (e) {
    models.value = [];
    modelsError.value = "拉取失败，可手动输入模型名";
    useCustomModel.value = true;
  } finally {
    modelsLoading.value = false;
  }
}

const form = reactive({
  name: "",
  src_type: "edusrc",
  vuln_types: "",
  target_source: "fofa",
  engine: "",
  fofa_query: "",
  intent_mode: "",
  manual_targets: "",
  src_rules: "",
  base_url: "",
  api_key: "",
  model: "",
  prompt_version: "legacy",
  fofa_key: "",
  fofa_base_url: "",
  max_pages: 20,
  page_size: 100,
  concurrency: 3,
  skip_site_recon: false,
});
const authBindings = ref([{ target: "*", raw: "", username: "", password: "", cookie: "", authorization: "", login_url: "", note: "" }]);
const original = reactive({
  base_url: "",
  model: "",
  prompt_version: "legacy",
  intent_mode: "",
  fofa_base_url: "",
  max_pages: 20,
  page_size: 100,
});
const isSiteMode = computed(() => form.target_source === "site");
const isFofaMode = computed(() => form.target_source === "fofa");
const showAuthBindings = computed(() => !isFofaMode.value);
const manualTargetLines = computed(() =>
  form.manual_targets.split("\n").map((s) => s.trim()).filter(Boolean)
);
const bindingOptions = computed(() => {
  const opts = [{ value: "*", label: "*（全部目标默认）" }];
  for (const line of manualTargetLines.value) {
    opts.push({ value: line, label: line });
  }
  return opts;
});
function emptyBinding() {
  return { target: "*", raw: "", username: "", password: "", cookie: "", authorization: "", login_url: "", note: "" };
}
function addBinding() {
  authBindings.value.push(emptyBinding());
}
function removeBinding(i) {
  authBindings.value.splice(i, 1);
  if (!authBindings.value.length) authBindings.value.push(emptyBinding());
}
function exportAuthBindings() {
  return authBindings.value
    .map((b) => ({
      target: (b.target || "*").trim() || "*",
      username: (b.username || "").trim(),
      password: (b.password || "").trim(),
      cookie: (b.cookie || "").trim(),
      authorization: (b.authorization || "").trim(),
      login_url: (b.login_url || "").trim(),
      raw: (b.raw || "").trim(),
      note: (b.note || "").trim(),
    }))
    .filter((b) => b.username || b.password || b.cookie || b.authorization || b.raw);
}
function loadAuthBindings(task) {
  const rows = Array.isArray(task?.auth_bindings) ? task.auth_bindings : [];
  if (!rows.length) {
    authBindings.value = [emptyBinding()];
    return;
  }
  authBindings.value = rows.map((b) => ({
    target: b.target || "*",
    raw: b.raw || "",
    username: b.username || "",
    password: b.password || "",
    cookie: b.cookie || "",
    authorization: b.authorization || "",
    login_url: b.login_url || "",
    note: b.note || "",
  }));
}

function fill(task) {
  if (!task) return;
  const modelCfg = task.model_config_data || {};
  const fofaCfg = task.fofa_config || {};
  form.name = task.name || "";
  form.src_type = task.src_type || "edusrc";
  form.vuln_types = (task.vuln_types || []).join(",");
  form.target_source = task.target_source || "fofa";
  form.engine = task.engine || "";
  form.fofa_query = task.fofa_query || "";
  form.intent_mode = fofaCfg.intent_mode || "";
  form.manual_targets = (task.manual_targets || []).join("\n");
  form.src_rules = task.src_rules || "";
  form.base_url = modelCfg.base_url || "";
  form.api_key = "";
  form.model = modelCfg.model || "";
  form.prompt_version = modelCfg.prompt_version || "legacy";
  form.fofa_key = "";
  form.fofa_base_url = fofaCfg.base_url || "";
  form.max_pages = fofaCfg.max_pages ?? 20;
  form.page_size = fofaCfg.page_size ?? 100;
  form.skip_site_recon = !!fofaCfg.skip_site_recon;
  form.concurrency = task.concurrency || 3;
  loadAuthBindings(task);
  original.base_url = form.base_url;
  original.model = form.model;
  original.prompt_version = form.prompt_version;
  original.intent_mode = form.intent_mode;
  original.fofa_base_url = form.fofa_base_url;
  original.max_pages = Number(form.max_pages);
  original.page_size = Number(form.page_size);
  // 重置模型列表状态（打开弹窗时 watch 会随即自动 loadModels 拉好列表）
  models.value = [];
  modelsError.value = "";
  useCustomModel.value = false;
}

watch(() => props.task, fill, { immediate: true });
watch(() => props.open, (open) => {
  if (open) {
    fill(props.task);
    loadModels();  // 打开即自动拉好可用模型列表，默认下拉选择
  }
});

async function save() {
  const modelConfig = {};
  if (form.base_url !== original.base_url) modelConfig.base_url = form.base_url;
  if (form.model !== original.model) modelConfig.model = form.model;
  if (form.prompt_version !== original.prompt_version) modelConfig.prompt_version = form.prompt_version;
  if (form.api_key.trim()) modelConfig.api_key = form.api_key.trim();

  const maxPages = parseInt(form.max_pages) || 20;
  const pageSize = parseInt(form.page_size) || 100;
  const fofaConfig = {};
  if (maxPages !== original.max_pages) fofaConfig.max_pages = maxPages;
  if (pageSize !== original.page_size) fofaConfig.page_size = pageSize;
  if (form.intent_mode !== original.intent_mode) fofaConfig.intent_mode = form.intent_mode;
  if (form.fofa_key.trim()) fofaConfig.key = form.fofa_key.trim();
  if (form.fofa_base_url !== original.fofa_base_url) fofaConfig.base_url = form.fofa_base_url;
  // 单站模式：总是显式带上开关值，支持从 true 改回 false。
  if (isSiteMode.value) fofaConfig.skip_site_recon = !!form.skip_site_recon;

  const updated = await api.updateTask(props.task.id, {
    name: form.name,
    src_type: form.src_type,
    vuln_types: form.vuln_types.split(",").map((s) => s.trim()).filter(Boolean),
    target_source: form.target_source,
    engine: form.engine,
    fofa_query: form.fofa_query,
    manual_targets: form.manual_targets.split("\n").map((s) => s.trim()).filter(Boolean),
    auth_bindings: showAuthBindings.value ? exportAuthBindings() : [],
    src_rules: form.src_rules,
    concurrency: parseInt(form.concurrency) || 3,
    model_config_data: modelConfig,
    fofa_config: fofaConfig,
  });
  emit("saved", updated);
}
</script>

<template>
  <div v-if="open" class="task-edit-backdrop" @click.self="emit('close')">
    <form class="task-edit-modal" @submit.prevent="save">
      <header>
        <div>
          <h3>编辑任务参数</h3>
          <p>运行中的任务会在下一轮调度读取新参数；密钥留空则保留原值。</p>
        </div>
        <button type="button" class="icon-btn" @click="emit('close')">×</button>
      </header>

      <div class="settings-grid">
        <label>任务名称 <input v-model="form.name" required /></label>
        <label>worker 并发 <input v-model="form.concurrency" type="number" min="1" max="20" /></label>
        <label>任务模式
          <select v-model="form.src_type">
            <option value="edusrc">EduSRC（教育行业）</option>
            <option value="enterprise">企业SRC</option>
          </select>
        </label>
        <label>目标来源
          <select v-model="form.target_source">
            <option value="fofa">FOFA 自动搜</option>
            <option value="manual">手动清单</option>
            <option value="both">两者</option>
            <option value="site">单站协作</option>
          </select>
        </label>
        <label v-if="!isSiteMode">搜索引擎
          <select v-model="form.engine">
            <option value="">默认引擎</option>
            <option value="fofa">FOFA</option>
            <option value="quake">360 Quake</option>
            <option value="hunter">Hunter (鹰图)</option>
            <option value="zoomeye">ZoomEye</option>
            <option value="shodan">Shodan</option>
            <option value="censys">Censys</option>
          </select>
        </label>
        <label v-if="!isSiteMode">搜集方式
          <select v-model="form.intent_mode">
            <option value="">自动判断</option>
            <option value="syntax">FOFA 语法</option>
            <option value="intent">自然语言意图</option>
          </select>
        </label>
      </div>

      <label>漏洞类型（逗号分隔） <input v-model="form.vuln_types" /></label>
      <label v-if="!isSiteMode">FOFA 语法 / 搜集意图 <input v-model="form.fofa_query" /></label>
      <label v-else>目标相关信息 / 协作重点
        <textarea v-model="form.fofa_query" rows="4" placeholder="可写重点方向、后台位置等协作备注。登录凭据请填下方「登录凭据区」。"></textarea>
      </label>
      <label>{{ isSiteMode ? "主目标 URL（每行一个，会自动拆成多条协作路线）" : "手动目标清单（每行一个）" }}
        <textarea v-model="form.manual_targets" rows="3"></textarea>
      </label>

      <section v-if="showAuthBindings" class="auth-bindings">
        <div class="auth-bindings-head">
          <strong>登录凭据（按目标绑定，可选）</strong>
          <button type="button" class="linkish" @click="addBinding">+ 添加一条</button>
        </div>
        <p class="field-hint">不填不影响挖掘。填了会强制尝试并在看板反馈成败。</p>
        <div v-for="(b, i) in authBindings" :key="i" class="auth-binding-row">
          <div class="auth-binding-top">
            <label>绑定目标
              <select v-model="b.target">
                <option v-for="opt in bindingOptions" :key="opt.value" :value="opt.value">{{ opt.label }}</option>
              </select>
            </label>
            <button type="button" class="icon-btn" title="删除" @click="removeBinding(i)">×</button>
          </div>
          <label>快捷粘贴
            <textarea v-model="b.raw" rows="2" placeholder="Cookie: ... / Bearer ... / 账号+密码"></textarea>
          </label>
          <details>
            <summary>结构化字段</summary>
            <div class="auth-grid">
              <label>账号 <input v-model="b.username" autocomplete="off" /></label>
              <label>密码 <input v-model="b.password" type="password" autocomplete="new-password" /></label>
              <label class="span2">Cookie <input v-model="b.cookie" /></label>
              <label class="span2">Authorization <input v-model="b.authorization" /></label>
              <label class="span2">登录 URL <input v-model="b.login_url" /></label>
            </div>
          </details>
        </div>
      </section>

      <label v-if="isSiteMode" class="check-line">
        <input type="checkbox" v-model="form.skip_site_recon" />
        跳过入口盘点侦察（省 token）
      </label>
      <p v-if="isSiteMode" class="field-hint">
        跳过泛扒首页/API 文档的「入口盘点」路线。已给登录凭据时推荐开启：Agent 直接登录进系统挖，
        不浪费 token 泛侦察（前端 JS/密钥侦察仍保留）。
      </p>

      <details open>
        <summary>高级：模型 / FOFA</summary>
        <div class="settings-grid">
          <label>模型 base_url <input v-model="form.base_url" placeholder="https://api.deepseek.com/v1" /></label>
          <label class="model-field">
            模型名
            <div class="model-picker">
              <select v-if="models.length && !useCustomModel" v-model="form.model">
                <option v-for="m in models" :key="m" :value="m">{{ m }}</option>
              </select>
              <input v-else v-model="form.model" placeholder="deepseek-chat" />
              <button type="button" class="ghost-btn" :disabled="modelsLoading" @click="loadModels" title="改了 base_url/api_key 后可重新拉取">
                {{ modelsLoading ? "拉取中…" : "刷新" }}
              </button>
              <button
                v-if="models.length"
                type="button"
                class="ghost-btn"
                @click="useCustomModel = !useCustomModel"
              >
                {{ useCustomModel ? "选列表" : "手动输入" }}
              </button>
            </div>
            <small v-if="modelsError" class="model-hint">{{ modelsError }}</small>
            <small v-else-if="models.length" class="model-hint">已获取 {{ models.length }} 个可用模型</small>
          </label>
          <label>Worker 提示词
            <select v-model="form.prompt_version">
              <option value="current">current（当前省 token 版）</option>
              <option value="legacy">legacy（旧版 23/25 风格）</option>
              <option value="modern">modern（当前完整版）</option>
            </select>
          </label>
          <label>模型 api_key <input v-model="form.api_key" type="password" placeholder="留空保留原值" /></label>
          <label v-if="!isSiteMode">FOFA key <input v-model="form.fofa_key" type="password" placeholder="留空保留原值" /></label>
          <label v-if="!isSiteMode">FOFA API 端点 <input v-model="form.fofa_base_url" placeholder="https://fofa.info" /></label>
          <label v-if="!isSiteMode">FOFA 最大页数 <input v-model="form.max_pages" type="number" min="1" max="200" /></label>
          <label v-if="!isSiteMode">FOFA page_size <input v-model="form.page_size" type="number" min="1" max="1000" /></label>
        </div>
      </details>

      <label>SRC 规则
        <textarea v-model="form.src_rules" rows="3"></textarea>
      </label>

      <footer>
        <button type="button" @click="emit('close')">取消</button>
        <button type="submit" class="primary">保存参数</button>
      </footer>
    </form>
  </div>
</template>

<style scoped>
.model-field {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.model-picker {
  display: flex;
  gap: 6px;
  align-items: center;
}
.model-picker select,
.model-picker input {
  flex: 1;
  min-width: 0;
}
.ghost-btn {
  flex: 0 0 auto;
  padding: 6px 10px;
  font-size: 12px;
  border: 1px solid var(--border, #d0d5dd);
  background: transparent;
  border-radius: 6px;
  cursor: pointer;
  white-space: nowrap;
}
.ghost-btn:disabled {
  opacity: 0.5;
  cursor: default;
}
.model-hint {
  color: var(--muted, #98a2b3);
  font-size: 11px;
}
</style>
