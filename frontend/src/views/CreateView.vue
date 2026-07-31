<script setup>
import { computed, reactive, ref, watch, onMounted } from "vue";
import { useRouter } from "vue-router";
import { api } from "../api.js";
import { useAuthBindings } from "../composables/useAuthBindings.js";
import LlmModelPicker from "../components/LlmModelPicker.vue";
import LlmPoolEditor from "../components/LlmPoolEditor.vue";

const router = useRouter();
const adv = ref(false);
const form = reactive({
  name: "",
  src_type: "edusrc",
  vuln_types: "sql_injection,rce,unauthorized_access,idor,file_upload,captcha_bypass,backdoor_compromised",
  target_source: "fofa",
  engine: "",
  fofa_query: "",
  intent_mode: "",
  manual_targets: "",
  src_rules: "",
  // inherit | single | pool
  model_mode: "inherit",
  base_url: "", api_key: "", key_ref: "", model: "", protocol: "auto", prompt_version: "legacy",
  fofa_key: "", fofa_base_url: "", max_pages: 20, concurrency: 3,
  skip_site_recon: false,
  skip_recon_touched: false,   // 用户是否手动调过这个开关（调过就不再自动跟随凭据）
});
const taskProviders = ref([]);
const singleModels = ref([]);
const singleModelsLoading = ref(false);
const singleModelsError = ref("");
const poolEditor = ref(null);
const { authBindings, addBinding, removeBinding, exportAuthBindings, bindingOptions } =
  useAuthBindings(() => form.manual_targets);
const submitting = ref(false);

const inherited = reactive({
  base_url: "",
  model: "",
  protocol: "auto",
  llm_provider_count: 0,
  llm_mode: "single",
  prompt_version: "legacy",
  fofa_base_url: "",
  max_pages: 20,
  intent_mode: "",
  concurrency: 3,
});
const isSiteMode = computed(() => form.target_source === "site");
const isFofaMode = computed(() => form.target_source === "fofa");
const engineIsFofa = computed(() => !form.engine || form.engine === "fofa");
const engineLabel = computed(() => {
  const map = { fofa: "FOFA", quake: "360 Quake", hunter: "Hunter", zoomeye: "ZoomEye", shodan: "Shodan", censys: "Censys" };
  return map[form.engine] || (form.engine ? form.engine : "系统默认引擎");
});

const manualTargetsPlaceholder = computed(() =>
  isSiteMode.value
    ? "https://target.example.com/\nhttps://target.example.com/admin 后台"
    : "www.example.edu.cn\nhttps://a.example.edu.cn/path?x=1\nhttps://b.example.edu.cn/ 港澳台\n(203.0.113.10)"
);
// 凭据区只对「用户自己指定目标」有意义：手动 / 两者 / 单站。纯 FOFA 自动搜不展示。
const showAuthBindings = computed(() => !isFofaMode.value);

function invalidateModelKey() {
  form.key_ref = "";
  singleModels.value = [];
  singleModelsError.value = "";
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
    } else {
      singleModels.value = [];
      singleModelsError.value = res?.error || "未获取到模型列表";
    }
  } catch (e) {
    singleModels.value = [];
    singleModelsError.value = String(e.message || e).replace(/^\d+\s*/, "");
  } finally {
    singleModelsLoading.value = false;
  }
}

function ensurePoolSeed() {
  if (taskProviders.value.length) return;
  taskProviders.value = [{
    name: "llm-1",
    base_url: form.base_url || inherited.base_url || "https://api.deepseek.com/v1",
    api_key: "",
    api_key_set: false,
    api_key_masked: "",
    key_ref: "",
    model: form.model || inherited.model || "deepseek-chat",
    protocol: form.protocol || inherited.protocol || "auto",
    temperature: 0.3,
    weight: 1,
    enabled: true,
    models: [],
    modelsLoading: false,
    modelsError: "",
  }];
}

watch(() => form.model_mode, (mode) => {
  if (mode === "pool") ensurePoolSeed();
});

// 粗略识别用户是否在方向说明或凭据区给了登录凭据。
const looksHasCreds = computed(() => {
  const t = (form.fofa_query || "");
  if (/(账号|帐号|账户|用户名|user(name)?|密码|pass(word|wd)?|cookie|token|authorization|bearer|jsessionid|session|登录态|凭据|凭证)/i.test(t)) {
    return true;
  }
  return exportAuthBindings().length > 0;
});
watch([() => form.fofa_query, isSiteMode, authBindings], () => {
  if (isSiteMode.value && !form.skip_recon_touched) {
    form.skip_site_recon = looksHasCreds.value;
  }
});

async function submit() {
  if (form.model_mode === "single" && !form.api_key.trim() && !form.key_ref) return;
  if (form.model_mode === "pool") {
    const rows = poolEditor.value?.exportProviders?.() || taskProviders.value;
    if (!rows.length || rows.some((p) => !p.base_url || !p.model || (!p.api_key && !p.key_ref))) {
      alert("端点池每个端点都需要名称/base_url/模型/api_key");
      return;
    }
  }
  if (submitting.value) return;   // 防抖：慢网络/双击不重复建任务
  submitting.value = true;
  try {
  let modelConfig;
  if (form.model_mode === "inherit") {
    modelConfig = { inherit_global: true };
  } else if (form.model_mode === "pool") {
    const rows = poolEditor.value?.exportProviders?.() || taskProviders.value;
    modelConfig = { inherit_global: false, providers: rows };
  } else {
    modelConfig = {
      inherit_global: false,
      base_url: form.base_url,
      model: form.model,
      protocol: form.protocol,
    };
    if (form.api_key.trim()) modelConfig.api_key = form.api_key.trim();
  }
  if (form.prompt_version !== inherited.prompt_version) modelConfig.prompt_version = form.prompt_version;

  const maxPages = parseInt(form.max_pages) || 20;
  const fofaConfig = {};
  if (form.fofa_key.trim()) fofaConfig.key = form.fofa_key.trim();
  if (form.fofa_base_url && form.fofa_base_url !== inherited.fofa_base_url) fofaConfig.base_url = form.fofa_base_url;
  fofaConfig.max_pages = maxPages;  // 始终写入，避免任务配置缺省时掉回硬编码 20
  if (form.intent_mode !== inherited.intent_mode) fofaConfig.intent_mode = form.intent_mode;
  if (isSiteMode.value && form.skip_site_recon) fofaConfig.skip_site_recon = true;

  const body = {
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
  };
  const task = await api.createTask(body);
  router.push(`/task/${task.id}`);
  } finally {
    submitting.value = false;
  }
}

onMounted(async () => {
  try {
    const s = await api.getSettings();
    if (!form.base_url) form.base_url = s.llm?.base_url || "";
    if (!form.model) form.model = s.llm?.model || "";
    form.protocol = s.llm?.protocol || form.protocol;
    form.key_ref = s.llm?.key_ref || "";
    form.prompt_version = s.defaults?.worker_prompt_version || form.prompt_version;
    form.max_pages = s.fofa?.max_pages ?? form.max_pages;
    if (!form.intent_mode) form.intent_mode = s.fofa?.default_intent_mode || "";
    if (!form.fofa_base_url) form.fofa_base_url = s.fofa?.base_url || "";
    form.concurrency = s.defaults?.concurrency ?? form.concurrency;
    inherited.base_url = form.base_url;
    inherited.model = form.model;
    inherited.protocol = form.protocol;
    inherited.llm_provider_count = s.llm?.provider_count || 0;
    inherited.llm_mode = s.llm?.mode || "single";
    inherited.prompt_version = form.prompt_version;
    inherited.fofa_base_url = form.fofa_base_url;
    inherited.max_pages = Number(form.max_pages);
    inherited.intent_mode = form.intent_mode;
    inherited.concurrency = Number(form.concurrency);
  } catch {}
});
</script>

<template>
  <section class="view">
    <header class="page-head">
      <h2>新建挖掘任务</h2>
      <p class="page-sub">配置目标来源与模型，创建后自动进入指挥台</p>
    </header>
    <form class="form" @submit.prevent="submit">
      <label>任务名称 <input v-model="form.name" required :placeholder="form.src_type === 'enterprise' ? '企业SRC批量挖掘-2026' : 'edu批量挖掘-2026'" /></label>
      <label>任务模式
        <select v-model="form.src_type">
          <option value="edusrc">EduSRC（教育行业，保留原规则）</option>
          <option value="enterprise">企业SRC（企业资产/业务口径）</option>
        </select>
      </label>
      <label>漏洞类型（逗号分隔） <input v-model="form.vuln_types" /></label>
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
      <p v-if="!isSiteMode" class="field-hint">
        当前选用：{{ engineLabel }}。各引擎 API Key 在「设置 → 资产测绘」配置；未配 Key 的引擎搜不到资产。
      </p>
      <label v-if="!isSiteMode">搜集方式
        <select v-model="form.intent_mode">
          <option value="">自动判断（写得像语法就当语法，否则当意图）</option>
          <option value="syntax">查询语法（FOFA 或当前引擎原生均可）</option>
          <option value="intent">自然语言意图（让搜集 Agent 翻译成语法并逐轮演化）</option>
        </select>
      </label>
      <label v-if="!isSiteMode">
        {{ form.intent_mode === "intent" ? "搜集意图（用大白话说要找什么）" : "查询语法 / 搜集意图" }}
        <input v-model="form.fofa_query"
          :placeholder="form.src_type === 'enterprise'
            ? (form.intent_mode === 'intent' ? '例：找某集团 OA/CRM/ERP/API/运维后台资产' : 'domain=&quot;example.com&quot; || cert=&quot;示例集团&quot; || org=&quot;示例集团&quot;')
            : (form.intent_mode === 'intent' ? '例：找全国高校的统一身份认证登录系统' : 'title=&quot;统一身份认证&quot; && domain=&quot;.edu.cn&quot;')" />
      </label>
      <p v-if="!isSiteMode && form.intent_mode !== 'intent'" class="field-hint">
        两种写法都可用：① <strong>FOFA 语法</strong>（换引擎会自动翻译）；② <strong>当前引擎原生语法</strong>（识别后原样请求，不二次翻译）。
        例 Quake：<code>title:"登录" AND domain:"edu.cn"</code>；Hunter：<code>web.title="登录" && domain.suffix="edu.cn"</code>。
      </p>
      <label v-else>目标相关信息 / 协作重点
        <textarea v-model="form.fofa_query" rows="4" placeholder="可写：重点方向、后台位置等协作备注。登录凭据请填下方「登录凭据区」。&#10;例：后台在 /admin，重点测 API、越权、上传。"></textarea>
      </label>
      <label v-if="!isFofaMode">{{ isSiteMode ? "主目标 URL（每行一个，会自动拆成多条协作路线）" : "手动目标清单（每行一个，可直接粘贴杂乱资产表）" }}
        <textarea v-model="form.manual_targets" rows="8" :placeholder="manualTargetsPlaceholder"></textarea>
      </label>
      <p v-if="!isFofaMode" class="field-hint">
        入库前自动清理：去掉行尾中文备注、单独成行的括号 IP 会入队、裸域名补协议、保留路径/查询串并去重。
        入队时会按根域查询泄露凭据，挂到目标上供 worker 使用。
      </p>

      <section v-if="showAuthBindings" class="auth-bindings">
        <div class="auth-bindings-head">
          <strong>登录凭据（按目标绑定，可选）</strong>
          <button type="button" class="linkish" @click="addBinding">+ 添加一条</button>
        </div>
        <p class="field-hint">
          不填则完全不影响挖掘。填了会<strong>强制尝试</strong>：Cookie/Token 直接注入会话，账密自动走登录；
          成败在看板目标卡徽章 + 活动流里反馈。绑定 <code>*</code> 表示该任务下匹配到的目标都用。
        </p>
        <div v-for="(b, i) in authBindings" :key="i" class="auth-binding-row">
          <div class="auth-binding-top">
            <label>绑定目标
              <select v-model="b.target">
                <option v-for="opt in bindingOptions" :key="opt.value" :value="opt.value">{{ opt.label }}</option>
              </select>
            </label>
            <button type="button" class="icon-btn" title="删除" @click="removeBinding(i)">×</button>
          </div>
          <label>快捷粘贴（系统自动分辨 Cookie / Bearer / 账密）
            <textarea v-model="b.raw" rows="2" placeholder="例：Cookie: JSESSIONID=xxx&#10;或 Authorization: Bearer eyJ...&#10;或 账号: test  密码: Test@123"></textarea>
          </label>
          <details>
            <summary>展开填结构化字段</summary>
            <div class="auth-grid">
              <label>账号 <input v-model="b.username" autocomplete="off" /></label>
              <label>密码 <input v-model="b.password" type="password" autocomplete="new-password" /></label>
              <label class="span2">Cookie 串 <input v-model="b.cookie" placeholder="JSESSIONID=...; other=..." /></label>
              <label class="span2">Authorization <input v-model="b.authorization" placeholder="Bearer eyJ..." /></label>
              <label class="span2">登录 URL（可选） <input v-model="b.login_url" placeholder="https://host/login" /></label>
            </div>
          </details>
        </div>
      </section>

      <label v-if="isSiteMode" class="check-line">
        <input type="checkbox" v-model="form.skip_site_recon" @change="form.skip_recon_touched = true" />
        跳过入口盘点侦察（省 token）
      </label>
      <p v-if="isSiteMode" class="field-hint">
        默认会先派一条「入口盘点」路线泛扒首页/robots/API 文档摸清全站入口。<strong>已给登录凭据时不必这样</strong>——
        Agent 可直接登录进系统，从内部功能发现入口，泛侦察纯属浪费 token。勾选后跳过它（前端 JS/密钥侦察仍保留）。
        检测到你填了账号密码/Cookie 会自动勾上，可手动取消。
      </p>
      <p v-if="isSiteMode && looksHasCreds && !(exportAuthBindings().length)" class="field-hint warn-hint">
        协作备注里像有凭据，但「登录凭据区」为空——请挪到凭据区，才能强制尝试并在看板反馈。
      </p>
      <details :open="adv">
        <summary @click="adv = !adv">高级：模型 / 测绘分页 / 并发（留空用服务端默认）</summary>
        <p class="field-hint">
          当前系统方案：{{ inherited.llm_mode === "pool" ? inherited.llm_provider_count + " 个模型端点" : "单模型" }}。
          「跟随系统」时，系统配置变更会在任务下一轮调用时生效；也可为本任务单独选单端点或端点池。
        </p>
        <div class="llm-mode-switch" role="tablist" aria-label="任务模型方案">
          <button type="button" role="tab" :aria-selected="form.model_mode === 'inherit'" :class="{ active: form.model_mode === 'inherit' }" @click="form.model_mode = 'inherit'">跟随系统</button>
          <button type="button" role="tab" :aria-selected="form.model_mode === 'single'" :class="{ active: form.model_mode === 'single' }" @click="form.model_mode = 'single'">单端点</button>
          <button type="button" role="tab" :aria-selected="form.model_mode === 'pool'" :class="{ active: form.model_mode === 'pool' }" @click="form.model_mode = 'pool'">端点池</button>
        </div>

        <template v-if="form.model_mode === 'single'">
          <label>模型 base_url <input v-model="form.base_url" required placeholder="https://api.deepseek.com/v1" @input="invalidateModelKey" /></label>
          <label>模型 api_key <input v-model="form.api_key" :required="!form.key_ref" type="password" :placeholder="form.key_ref ? '已配置，留空复用' : 'sk-...'" /></label>
          <label>模型名
            <LlmModelPicker
              v-model="form.model"
              :models="singleModels"
              :loading="singleModelsLoading"
              :error="singleModelsError"
              required
              @refresh="loadSingleModels"
            />
          </label>
          <label>模型协议
            <select v-model="form.protocol" @change="invalidateModelKey">
              <option value="auto">自动识别</option>
              <option value="openai_chat">OpenAI Chat Completions</option>
              <option value="anthropic_messages">Anthropic Messages</option>
            </select>
          </label>
        </template>

        <LlmPoolEditor
          v-else-if="form.model_mode === 'pool'"
          ref="poolEditor"
          v-model="taskProviders"
          :defaults="{ base_url: form.base_url || inherited.base_url, model: form.model || inherited.model, protocol: form.protocol || inherited.protocol }"
        />

        <label v-if="!isSiteMode">搜集最大页数 <input v-model="form.max_pages" type="number" /></label>
        <p v-if="!isSiteMode" class="field-hint">对当前选用的测绘引擎生效（不限于 FOFA）。</p>
        <template v-if="!isSiteMode && engineIsFofa">
          <label>FOFA Key（任务级覆盖，可选） <input v-model="form.fofa_key" type="password" placeholder="留空用系统设置" /></label>
          <label>FOFA API 端点（可选） <input v-model="form.fofa_base_url" placeholder="https://fofa.info" /></label>
          <p class="field-hint">仅当本任务使用 FOFA 时生效。Quake / Hunter 等引擎请到系统设置配 Key，暂不支持任务级覆盖。</p>
        </template>
        <p v-else-if="!isSiteMode" class="field-hint">
          当前引擎不是 FOFA：Key 请用系统设置里的「各引擎 API Key」，高级区不再重复填。
        </p>
        <label>worker 并发 <input v-model="form.concurrency" type="number" /></label>
      </details>
      <label>SRC 规则（审核用，可留空，审核 agent 已内置{{ form.src_type === 'enterprise' ? '企业SRC' : 'edusrc' }}标准）
        <textarea v-model="form.src_rules" rows="3"></textarea>
      </label>
      <button type="submit" class="primary" :disabled="submitting">{{ submitting ? "创建中…" : "创建任务" }}</button>
    </form>
  </section>
</template>
