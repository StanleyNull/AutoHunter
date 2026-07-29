<script setup>
import { computed, reactive, ref, watch } from "vue";
import { api } from "../api.js";
import { useAuthBindings, emptyBinding } from "../composables/useAuthBindings.js";
import LlmModelPicker from "./LlmModelPicker.vue";
import LlmPoolEditor from "./LlmPoolEditor.vue";

const props = defineProps({
  open: Boolean,
  task: Object,
});
const emit = defineEmits(["close", "saved"]);

const models = ref([]);
const modelsLoading = ref(false);
const modelsError = ref("");
const taskProviders = ref([]);
const poolEditor = ref(null);
// inherit | single | pool
const modelMode = ref("inherit");

async function loadModels() {
  if (!props.task?.id || modelMode.value !== "single") return;
  modelsLoading.value = true;
  modelsError.value = "";
  try {
    const res = await api.taskModels(props.task.id, {
      base_url: form.base_url || undefined,
      api_key: form.api_key || undefined,
      key_ref: form.key_ref || undefined,
      protocol: form.protocol,
    });
    if (res?.ok && res.models?.length) {
      models.value = res.models;
      if (!form.model || !models.value.includes(form.model)) form.model = models.value[0];
    } else {
      models.value = [];
      modelsError.value = res?.error || "未获取到模型列表";
    }
  } catch (e) {
    models.value = [];
    modelsError.value = "拉取失败，可手动输入模型名";
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
  key_ref: "",
  model: "",
  protocol: "auto",
  prompt_version: "legacy",
  fofa_key: "",
  fofa_base_url: "",
  max_pages: 20,
  page_size: 100,
  concurrency: 3,
  skip_site_recon: false,
});
const { authBindings, addBinding, removeBinding, exportAuthBindings, bindingOptions } =
  useAuthBindings(() => form.manual_targets);
const saving = ref(false);
const original = reactive({
  base_url: "",
  model: "",
  protocol: "auto",
  prompt_version: "legacy",
  intent_mode: "",
  fofa_base_url: "",
  max_pages: 20,
  page_size: 100,
});
const isSiteMode = computed(() => form.target_source === "site");
const isFofaMode = computed(() => form.target_source === "fofa");
const engineIsFofa = computed(() => !form.engine || form.engine === "fofa");

const showAuthBindings = computed(() => !isFofaMode.value);

function invalidateModelKey() {
  form.key_ref = "";
  models.value = [];
  modelsError.value = "";
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
  form.key_ref = modelCfg.key_ref || "";
  form.model = modelCfg.model || "";
  form.protocol = modelCfg.protocol || "auto";
  form.prompt_version = modelCfg.prompt_version || "legacy";
  form.fofa_key = "";
  form.fofa_base_url = fofaCfg.base_url || "";
  form.max_pages = fofaCfg.max_pages ?? 20;
  form.page_size = fofaCfg.page_size ?? 100;
  form.skip_site_recon = !!fofaCfg.skip_site_recon;
  form.concurrency = task.concurrency || 3;
  loadAuthBindings(task);

  const providers = Array.isArray(modelCfg.providers) ? modelCfg.providers : [];
  taskProviders.value = providers.map((p, idx) => ({
    name: p.name || `llm-${idx + 1}`,
    base_url: p.base_url || "",
    api_key: "",
    api_key_set: !!p.api_key_set,
    api_key_masked: p.api_key_masked || "",
    key_ref: p.key_ref || "",
    model: p.model || "",
    protocol: p.protocol || "auto",
    temperature: p.temperature ?? 0.3,
    weight: p.weight ?? 1,
    enabled: p.enabled !== false,
    models: [],
    modelsLoading: false,
    modelsError: "",
  }));

  if (modelCfg.inherit_global !== false && !providers.length) {
    modelMode.value = "inherit";
  } else if (providers.length || modelCfg.mode === "pool") {
    modelMode.value = "pool";
  } else {
    modelMode.value = "single";
  }

  original.base_url = form.base_url;
  original.model = form.model;
  original.protocol = form.protocol;
  original.prompt_version = form.prompt_version;
  original.intent_mode = form.intent_mode;
  original.fofa_base_url = form.fofa_base_url;
  original.max_pages = Number(form.max_pages);
  original.page_size = Number(form.page_size);
  models.value = [];
  modelsError.value = "";
}

watch(() => props.task, fill, { immediate: true });
watch(() => props.open, (open) => {
  if (open) {
    fill(props.task);
    if (modelMode.value === "single") loadModels();
  }
});
watch(modelMode, (mode) => {
  if (mode === "single" && props.open) loadModels();
  if (mode === "pool" && !taskProviders.value.length) {
    taskProviders.value = [{
      name: "llm-1",
      base_url: form.base_url || "https://api.deepseek.com/v1",
      api_key: "",
      api_key_set: false,
      api_key_masked: "",
      key_ref: "",
      model: form.model || "deepseek-chat",
      protocol: form.protocol || "auto",
      temperature: 0.3,
      weight: 1,
      enabled: true,
      models: [],
      modelsLoading: false,
      modelsError: "",
    }];
  }
});

async function save() {
  if (modelMode.value === "single" && !form.api_key.trim() && !form.key_ref) return;
  if (modelMode.value === "pool") {
    const rows = poolEditor.value?.exportProviders?.() || [];
    if (!rows.length || rows.some((p) => !p.base_url || !p.model || (!p.api_key && !p.key_ref))) {
      alert("端点池每个端点都需要 base_url / 模型 / api_key（已保存的可留空保留）");
      return;
    }
  }
  if (saving.value) return;
  saving.value = true;
  try {
  let modelConfig;
  if (modelMode.value === "inherit") {
    modelConfig = { inherit_global: true };
  } else if (modelMode.value === "pool") {
    modelConfig = {
      inherit_global: false,
      providers: poolEditor.value?.exportProviders?.() || [],
    };
  } else {
    modelConfig = {
      inherit_global: false,
      base_url: form.base_url,
      model: form.model,
      protocol: form.protocol,
    };
    if (form.api_key.trim()) modelConfig.api_key = form.api_key.trim();
  }
  if (form.prompt_version !== original.prompt_version) modelConfig.prompt_version = form.prompt_version;

  const maxPages = parseInt(form.max_pages) || 20;
  const pageSize = parseInt(form.page_size) || 100;
  const fofaConfig = {};
  if (maxPages !== original.max_pages) fofaConfig.max_pages = maxPages;
  if (pageSize !== original.page_size) fofaConfig.page_size = pageSize;
  if (form.intent_mode !== original.intent_mode) fofaConfig.intent_mode = form.intent_mode;
  if (form.fofa_key.trim()) fofaConfig.key = form.fofa_key.trim();
  if (form.fofa_base_url !== original.fofa_base_url) fofaConfig.base_url = form.fofa_base_url;
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
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <div v-if="open" class="task-edit-backdrop">
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
            <option value="fofa">测绘引擎自动搜</option>
            <option value="manual">手动清单</option>
            <option value="both">测绘 + 手动</option>
            <option value="site">单站协作</option>
          </select>
        </label>
        <label v-if="!isSiteMode">搜索引擎
          <select v-model="form.engine">
            <option value="">系统默认引擎</option>
            <option value="fofa">FOFA</option>
            <option value="quake">360 Quake</option>
            <option value="hunter">Hunter (鹰图)</option>
            <option value="zoomeye">ZoomEye</option>
            <option value="shodan">Shodan</option>
            <option value="censys">Censys</option>
          </select>
        </label>
        <p v-if="!isSiteMode" class="field-hint">各引擎 API Key 在「设置 → 资产测绘」配置。</p>
        <label v-if="!isSiteMode">搜集方式
          <select v-model="form.intent_mode">
            <option value="">自动判断</option>
            <option value="syntax">查询语法（FOFA 或引擎原生均可）</option>
            <option value="intent">自然语言意图</option>
          </select>
        </label>
      </div>

      <label>漏洞类型（逗号分隔） <input v-model="form.vuln_types" /></label>
      <label v-if="!isSiteMode">查询语法 / 搜集意图 <input v-model="form.fofa_query" /></label>
      <p v-if="!isSiteMode && form.intent_mode !== 'intent'" class="field-hint">
        FOFA 语法会自动翻译到当前引擎；直接写该引擎原生语法则原样透传。
      </p>
      <label v-else>目标相关信息 / 协作重点
        <textarea v-model="form.fofa_query" rows="4" placeholder="可写重点方向、后台位置等协作备注。登录凭据请填下方「登录凭据区」。"></textarea>
      </label>
      <label>{{ isSiteMode ? "主目标 URL（每行一个，会自动拆成多条协作路线）" : "手动目标清单（每行一个，可粘贴杂乱资产表）" }}
        <textarea v-model="form.manual_targets" rows="8" placeholder="支持行尾备注、括号 IP、裸域名；保存时自动清理，入队时查泄露凭据"></textarea>
      </label>
      <p class="field-hint">
        保存时自动清理备注/补协议/去重；搜集入队时会按根域补充泄露凭据。
      </p>

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
        <summary>高级：模型 / 测绘分页</summary>
        <div class="llm-mode-switch" role="tablist" aria-label="任务模型方案">
          <button type="button" role="tab" :aria-selected="modelMode === 'inherit'" :class="{ active: modelMode === 'inherit' }" @click="modelMode = 'inherit'">跟随系统</button>
          <button type="button" role="tab" :aria-selected="modelMode === 'single'" :class="{ active: modelMode === 'single' }" @click="modelMode = 'single'">单端点</button>
          <button type="button" role="tab" :aria-selected="modelMode === 'pool'" :class="{ active: modelMode === 'pool' }" @click="modelMode = 'pool'">端点池</button>
        </div>

        <div v-if="modelMode === 'single'" class="settings-grid">
          <label>模型 base_url <input v-model="form.base_url" required placeholder="https://api.deepseek.com/v1" @input="invalidateModelKey" /></label>
          <label class="model-field">
            模型名
            <LlmModelPicker
              v-model="form.model"
              :models="models"
              :loading="modelsLoading"
              :error="modelsError"
              required
              refresh-label="刷新"
              @refresh="loadModels"
            />
          </label>
          <label>模型协议
            <select v-model="form.protocol" @change="invalidateModelKey">
              <option value="auto">自动识别</option>
              <option value="openai_chat">OpenAI Chat Completions</option>
              <option value="anthropic_messages">Anthropic Messages</option>
            </select>
          </label>
          <label>模型 api_key <input v-model="form.api_key" :required="!form.key_ref" type="password" :placeholder="form.key_ref ? '已配置，留空保留原值' : 'sk-...'" /></label>
        </div>

        <LlmPoolEditor
          v-else-if="modelMode === 'pool'"
          ref="poolEditor"
          v-model="taskProviders"
          :task-id="task?.id || ''"
          :defaults="{ base_url: form.base_url, model: form.model, protocol: form.protocol }"
        />

        <div class="settings-grid" style="margin-top: 12px">
          <label v-if="!isSiteMode">搜集最大页数 <input v-model="form.max_pages" type="number" min="1" max="200" /></label>
          <label v-if="!isSiteMode">每页条数 <input v-model="form.page_size" type="number" min="1" max="1000" /></label>
          <p v-if="!isSiteMode" class="field-hint full">分页对当前选用的测绘引擎生效（不限于 FOFA）。</p>
          <template v-if="!isSiteMode && engineIsFofa">
            <label>FOFA Key（任务级覆盖） <input v-model="form.fofa_key" type="password" placeholder="留空保留原值" /></label>
            <label>FOFA API 端点 <input v-model="form.fofa_base_url" placeholder="https://fofa.info" /></label>
            <p class="field-hint full">仅 FOFA 支持任务级 Key/端点覆盖；其它引擎请改系统设置。</p>
          </template>
        </div>
      </details>

      <label>SRC 规则
        <textarea v-model="form.src_rules" rows="3"></textarea>
      </label>

      <footer>
        <button type="button" @click="emit('close')">取消</button>
        <button type="submit" class="primary" :disabled="saving">{{ saving ? "保存中…" : "保存参数" }}</button>
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
</style>
