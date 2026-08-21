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
  fofa_key: "", fofa_base_url: "", max_pages: 20, concurrency: 3, deepen_cap: 2,
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
const VULN_OPTIONS = [
  { id: "sql_injection", label: "SQL 注入" },
  { id: "rce", label: "命令执行" },
  { id: "unauthorized_access", label: "未授权" },
  { id: "idor", label: "水平越权" },
  { id: "file_upload", label: "文件上传" },
  { id: "captcha_bypass", label: "验证码绕过" },
  { id: "backdoor_compromised", label: "已控后门" },
];
const SOURCE_OPTIONS = [
  { id: "fofa", title: "测绘搜资产", desc: "用引擎按语法或意图拉一批站" },
  { id: "manual", title: "手动清单", desc: "自己贴域名 / URL，清理后入队" },
  { id: "both", title: "测绘 + 手动", desc: "搜到的和你贴的一起打" },
  { id: "site", title: "单站深挖", desc: "少数 URL 协作，可带登录凭据" },
];
const ENGINE_OPTIONS = [
  { id: "", label: "系统默认" },
  { id: "fofa", label: "FOFA" },
  { id: "quake", label: "Quake" },
  { id: "hunter", label: "Hunter" },
  { id: "zoomeye", label: "ZoomEye" },
  { id: "shodan", label: "Shodan" },
  { id: "censys", label: "Censys" },
];

const isSiteMode = computed(() => form.target_source === "site");
const isFofaMode = computed(() => form.target_source === "fofa");
const engineIsFofa = computed(() => !form.engine || form.engine === "fofa");
const engineLabel = computed(() => {
  const map = { fofa: "FOFA", quake: "360 Quake", hunter: "Hunter", zoomeye: "ZoomEye", shodan: "Shodan", censys: "Censys" };
  return map[form.engine] || (form.engine ? form.engine : "系统默认引擎");
});
const vulnSelected = computed(() => new Set(form.vuln_types.split(",").map((s) => s.trim()).filter(Boolean)));
function hasVuln(id) { return vulnSelected.value.has(id); }
function toggleVuln(id) {
  const known = VULN_OPTIONS.map((o) => o.id);
  const next = new Set(vulnSelected.value);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  const ordered = known.filter((k) => next.has(k));
  const extra = [...next].filter((k) => !known.includes(k));
  form.vuln_types = [...ordered, ...extra].join(",");
}
const manualCount = computed(() =>
  form.manual_targets.split("\n").map((s) => s.trim()).filter(Boolean).length
);
const recapSource = computed(() => SOURCE_OPTIONS.find((s) => s.id === form.target_source)?.title || "未选");
const recapModel = computed(() => {
  if (form.model_mode === "pool") return "任务端点池";
  if (form.model_mode === "single") return form.model || "单端点";
  return inherited.llm_mode === "pool" ? `跟随系统 · ${inherited.llm_provider_count} 端点` : "跟随系统";
});
const recapLine = computed(() => {
  const bits = [
    form.src_type === "enterprise" ? "企业 SRC" : "EduSRC",
    recapSource.value,
    isSiteMode.value ? null : engineLabel.value,
    `${vulnSelected.value.size} 类漏洞`,
  ].filter(Boolean);
  if (!isFofaMode.value && manualCount.value) bits.push(`${manualCount.value} 条手动目标`);
  return bits.join(" · ");
});
const missingHint = computed(() => {
  if (!form.name.trim()) return "还差任务名称";
  if (form.model_mode === "single" && !form.api_key.trim() && !form.key_ref) return "单端点还缺 API Key";
  if ((form.target_source === "manual" || form.target_source === "site") && !manualCount.value) return "还没贴目标清单";
  if ((form.target_source === "fofa" || form.target_source === "both") && !form.fofa_query.trim()) return "还没写搜集条件";
  if (!vulnSelected.value.size) return "至少选一类漏洞";
  return "";
});
const engineKey = computed(() => form.engine || "fofa");
const queryPlaceholder = computed(() => {
  if (form.intent_mode === "intent") {
    return form.src_type === "enterprise"
      ? "例：找某集团 OA/CRM/ERP/API/运维后台资产"
      : "例：找全国高校的统一身份认证登录系统";
  }
  const samples = {
    fofa: form.src_type === "enterprise"
      ? 'domain="example.com" || cert="示例集团" || org="示例集团"'
      : 'title="统一身份认证" && domain=".edu.cn"',
    quake: 'title:"统一身份认证" AND domain:"edu.cn"',
    hunter: 'ip.isp="中国教育网"&&header.status_code="200"',
    zoomeye: 'title="统一身份认证" && country="CN"',
    shodan: 'http.title:"login" hostname:edu.cn',
    censys: 'host.services.http.response.html_title:"Login" and host.dns.names: edu.cn',
  };
  return samples[engineKey.value] || samples.fofa;
});
const queryHintSample = computed(() => {
  const samples = {
    fofa: 'title="统一身份认证" && domain=".edu.cn"',
    quake: 'title:"登录" AND domain:"edu.cn"',
    hunter: 'ip.isp="中国教育网"&&header.status_code="200"',
    zoomeye: 'title="login" && country="CN"',
    shodan: 'http.title:"nginx" port:443',
    censys: 'host.dns.names: edu.cn',
  };
  return samples[engineKey.value] || samples.fofa;
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
  if (!vulnSelected.value.size) {
    alert("至少选一类漏洞");
    return;
  }
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
    deepen_cap: Math.max(0, Math.min(parseInt(form.deepen_cap) || 0, 10)),
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
    form.deepen_cap = s.defaults?.deepen_cap ?? form.deepen_cap;
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
    inherited.deepen_cap = Number(form.deepen_cap);
  } catch {}
});
</script>

<template>
  <section class="view create-view">
    <header class="page-head">
      <div>
        <h2>新建任务</h2>
        <p class="page-sub">先选口径和目标从哪来，填完创建，直接进指挥台开打</p>
      </div>
    </header>

    <form class="create-layout form" @submit.prevent="submit">
      <div class="create-main">
        <section class="create-block">
          <header class="create-block-head">
            <b>任务</b>
            <small>名称给自己看；口径决定审核红线</small>
          </header>
          <div class="create-grid">
            <label>任务名称
              <input v-model="form.name" required :placeholder="form.src_type === 'enterprise' ? '企业 SRC 批量挖掘' : 'EduSRC 批量挖掘'" />
            </label>
            <div class="create-field">
              <span>SRC 口径</span>
              <div class="llm-mode-switch create-seg" role="radiogroup" aria-label="SRC 口径">
                <button type="button" role="radio" :aria-checked="form.src_type === 'edusrc'" :class="{ active: form.src_type === 'edusrc' }" @click="form.src_type = 'edusrc'">EduSRC</button>
                <button type="button" role="radio" :aria-checked="form.src_type === 'enterprise'" :class="{ active: form.src_type === 'enterprise' }" @click="form.src_type = 'enterprise'">企业 SRC</button>
              </div>
            </div>
          </div>
          <div class="create-field">
            <span>要挖的漏洞</span>
            <div class="create-chips" role="group" aria-label="漏洞类型">
              <button
                v-for="opt in VULN_OPTIONS"
                :key="opt.id"
                type="button"
                :class="{ on: hasVuln(opt.id) }"
                :aria-pressed="hasVuln(opt.id)"
                @click="toggleVuln(opt.id)"
              >{{ opt.label }}</button>
            </div>
            <p class="create-mini">点一下开关。默认全开，收窄范围能更快对准。</p>
          </div>
        </section>

        <section class="create-block">
          <header class="create-block-head">
            <b>目标从哪来</b>
            <small>这一步决定下面要填什么</small>
          </header>
          <div class="create-source" role="radiogroup" aria-label="目标来源">
            <button
              v-for="opt in SOURCE_OPTIONS"
              :key="opt.id"
              type="button"
              role="radio"
              :aria-checked="form.target_source === opt.id"
              :class="{ on: form.target_source === opt.id }"
              @click="form.target_source = opt.id"
            >
              <b>{{ opt.title }}</b>
              <small>{{ opt.desc }}</small>
            </button>
          </div>

          <template v-if="!isSiteMode">
            <div class="create-field">
              <span>搜索引擎</span>
              <div class="create-chips" role="radiogroup" aria-label="搜索引擎">
                <button
                  v-for="opt in ENGINE_OPTIONS"
                  :key="opt.id || 'default'"
                  type="button"
                  role="radio"
                  :aria-checked="form.engine === opt.id"
                  :class="{ on: form.engine === opt.id }"
                  @click="form.engine = opt.id"
                >{{ opt.label }}</button>
              </div>
              <p class="create-mini">Key 在「设置 → 资产测绘」。没配 Key 的引擎搜不到资产。</p>
            </div>
            <div class="create-field">
              <span>怎么写条件</span>
              <div class="llm-mode-switch create-seg" role="radiogroup" aria-label="搜集方式">
                <button type="button" role="radio" :aria-checked="form.intent_mode === ''" :class="{ active: form.intent_mode === '' }" @click="form.intent_mode = ''">自动判断</button>
                <button type="button" role="radio" :aria-checked="form.intent_mode === 'syntax'" :class="{ active: form.intent_mode === 'syntax' }" @click="form.intent_mode = 'syntax'">查询语法</button>
                <button type="button" role="radio" :aria-checked="form.intent_mode === 'intent'" :class="{ active: form.intent_mode === 'intent' }" @click="form.intent_mode = 'intent'">大白话意图</button>
              </div>
            </div>
            <label>
              {{ form.intent_mode === "intent" ? "要找什么（大白话）" : "查询语法" }}
              <textarea v-model="form.fofa_query" rows="3" :placeholder="queryPlaceholder"></textarea>
            </label>
            <p v-if="form.intent_mode !== 'intent'" class="field-hint">
              按当前引擎官网语法原样请求，不会改写成别的引擎。示例 <code>{{ queryHintSample }}</code>
            </p>
            <p v-else class="create-mini">搜集 Agent 会把意图翻成语法，并按结果逐轮演化。</p>
          </template>
          <label v-else>协作重点
            <textarea v-model="form.fofa_query" rows="4" placeholder="后台位置、重点方向。登录凭据请填下面「登录凭据」。&#10;例：后台在 /admin，重点测 API、越权、上传。"></textarea>
          </label>
        </section>

        <section v-if="!isFofaMode" class="create-block">
          <header class="create-block-head">
            <b>{{ isSiteMode ? "主目标 URL" : "手动目标清单" }}</b>
            <small>{{ isSiteMode ? "每行一个，会拆成多条协作路线" : "每行一个，可直接粘贴杂乱资产表" }}</small>
          </header>
          <label class="create-sr-only" for="manual-targets">目标清单</label>
          <textarea id="manual-targets" v-model="form.manual_targets" rows="8" :placeholder="manualTargetsPlaceholder"></textarea>
          <p class="create-mini">
            自动去掉行尾中文备注、括号 IP 入队、裸域名补协议、去重。入队时按根域挂泄露凭据。
            <template v-if="manualCount">已识别 {{ manualCount }} 条。</template>
          </p>

          <section v-if="showAuthBindings" class="auth-bindings">
            <div class="auth-bindings-head">
              <strong>登录凭据（可选）</strong>
              <button type="button" class="linkish" @click="addBinding">+ 添加一条</button>
            </div>
            <p class="create-mini">
              不填不影响挖掘。填了会强制尝试：Cookie / Token 注入会话，账密走登录。绑定 <code>*</code> 表示本任务都用。
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
              <label>快捷粘贴（自动分辨 Cookie / Bearer / 账密）
                <textarea v-model="b.raw" rows="2" placeholder="Cookie: JSESSIONID=xxx&#10;Authorization: Bearer eyJ...&#10;账号: test  密码: Test@123"></textarea>
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
          <p v-if="isSiteMode" class="create-mini">
            默认先泛扒首页 / robots / API 文档。已给登录凭据时可跳过——Agent 能从内部功能发现入口。填了账密或 Cookie 会自动勾上。
          </p>
          <p v-if="isSiteMode && looksHasCreds && !(exportAuthBindings().length)" class="field-hint warn-hint">
            协作备注里像有凭据，但凭据区是空的。挪到凭据区才能强制尝试并在看板反馈。
          </p>
        </section>

        <section class="create-block">
          <header class="create-block-head">
            <b>本任务额外规则</b>
            <small>叠在内置 {{ form.src_type === "enterprise" ? "企业 SRC" : "EduSRC" }} 标准上，不能放宽红线</small>
          </header>
          <label class="create-sr-only" for="src-rules">SRC 规则</label>
          <textarea id="src-rules" v-model="form.src_rules" rows="3" placeholder="例：本校不收弱口令；重点收越权与未授权。"></textarea>
        </section>

        <details class="create-block create-adv" :open="adv" @toggle="adv = $event.target.open">
          <summary>高级：模型、测绘分页、并发</summary>
          <p class="create-mini">
            当前系统是{{ inherited.llm_mode === "pool" ? inherited.llm_provider_count + " 个模型端点" : "单模型" }}。
            「跟随系统」时，设置页改完下一轮生效。
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

          <div class="create-grid">
            <label v-if="!isSiteMode">搜集最大页数 <input v-model="form.max_pages" type="number" /></label>
            <label>worker 并发 <input v-model="form.concurrency" type="number" min="1" max="32" /></label>
            <label>深挖次数 <input v-model="form.deepen_cap" type="number" min="0" max="10" /></label>
          </div>
          <p v-if="!isSiteMode" class="create-mini">页数对当前测绘引擎生效。</p>
          <template v-if="!isSiteMode && engineIsFofa">
            <label>FOFA Key（本任务覆盖，可选） <input v-model="form.fofa_key" type="password" placeholder="留空用系统设置" /></label>
            <label>FOFA API 端点（可选） <input v-model="form.fofa_base_url" placeholder="https://fofa.info" /></label>
            <p class="create-mini">仅 FOFA 生效。Quake / Hunter 等到设置页配 Key。</p>
          </template>
          <p v-else-if="!isSiteMode" class="create-mini">当前不是 FOFA：Key 用设置页「各引擎 API Key」。</p>
          <p class="create-mini">深挖次数是同一目标被打回的上限（人工 + AI 审核 + 自动），0 表示关闭回炉。</p>
        </details>
      </div>

      <aside class="create-aside">
        <div class="create-recap">
          <span>即将创建</span>
          <b>{{ form.name.trim() || "未命名任务" }}</b>
          <dl>
            <div><dt>口径</dt><dd>{{ form.src_type === "enterprise" ? "企业 SRC" : "EduSRC" }}</dd></div>
            <div><dt>来源</dt><dd>{{ recapSource }}</dd></div>
            <div v-if="!isSiteMode"><dt>引擎</dt><dd>{{ engineLabel }}</dd></div>
            <div><dt>漏洞</dt><dd>{{ vulnSelected.size }} 类</dd></div>
            <div v-if="!isFofaMode"><dt>清单</dt><dd>{{ manualCount }} 条</dd></div>
            <div><dt>模型</dt><dd>{{ recapModel }}</dd></div>
            <div><dt>并发</dt><dd>{{ form.concurrency }}</dd></div>
          </dl>
          <p v-if="missingHint" class="create-missing">{{ missingHint }}</p>
          <button type="submit" class="primary" :disabled="submitting">{{ submitting ? "创建中…" : "创建任务" }}</button>
        </div>
      </aside>

      <div class="create-dock">
        <p>{{ recapLine }}</p>
        <button type="submit" class="primary" :disabled="submitting">{{ submitting ? "创建中…" : "创建" }}</button>
      </div>
    </form>
  </section>
</template>
