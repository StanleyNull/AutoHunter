<script setup>
import { computed, reactive, ref, watch, onMounted } from "vue";
import { useRouter } from "vue-router";
import { api } from "../api.js";

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
  cas_sso_config: "",
  base_url: "", api_key: "", model: "", prompt_version: "legacy",
  fofa_key: "", fofa_base_url: "", max_pages: 20, concurrency: 3,
  enable_worker_fofa_lookup: true, enable_killsweep_fofa_search: true,
  skip_site_recon: false,
  skip_recon_touched: false,   // 用户是否手动调过这个开关（调过就不再自动跟随凭据）
});
const inherited = reactive({
  base_url: "",
  model: "",
  prompt_version: "legacy",
  fofa_base_url: "",
  max_pages: 20,
  intent_mode: "",
  concurrency: 3,
});
const isSiteMode = computed(() => form.target_source === "site");
const isFofaMode = computed(() => form.target_source === "fofa");

// 粗略识别用户是否在方向说明里给了登录凭据（账号密码 / Cookie / Token）。
// 命中即默认帮用户勾上「跳过入口盘点」——有凭据可直接登录进系统，泛侦察费 token。
const looksHasCreds = computed(() => {
  const t = (form.fofa_query || "");
  return /(账号|帐号|账户|用户名|user(name)?|密码|pass(word|wd)?|cookie|token|authorization|bearer|jsessionid|session|登录态|凭据|凭证)/i.test(t);
});
watch([() => form.fofa_query, isSiteMode], () => {
  // 只在用户没手动调过开关时，才自动跟随「是否检测到凭据」。
  if (isSiteMode.value && !form.skip_recon_touched) {
    form.skip_site_recon = looksHasCreds.value;
  }
});

async function submit() {
  const modelConfig = {};
  if (form.api_key.trim()) modelConfig.api_key = form.api_key.trim();
  if (form.base_url && form.base_url !== inherited.base_url) modelConfig.base_url = form.base_url;
  if (form.model && form.model !== inherited.model) modelConfig.model = form.model;
  if (form.prompt_version !== inherited.prompt_version) modelConfig.prompt_version = form.prompt_version;

  const maxPages = parseInt(form.max_pages) || 20;
  const fofaConfig = {};
  if (form.fofa_key.trim()) fofaConfig.key = form.fofa_key.trim();
  if (form.fofa_base_url && form.fofa_base_url !== inherited.fofa_base_url) fofaConfig.base_url = form.fofa_base_url;
  if (maxPages !== inherited.max_pages) fofaConfig.max_pages = maxPages;
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
    src_rules: form.src_rules,
    cas_sso_config: form.cas_sso_config,
    concurrency: parseInt(form.concurrency) || 3,
    enable_worker_fofa_lookup: form.enable_worker_fofa_lookup,
    enable_killsweep_fofa_search: form.enable_killsweep_fofa_search,
    model_config_data: modelConfig,
    fofa_config: fofaConfig,
  };
  const task = await api.createTask(body);
  router.push(`/task/${task.id}`);
}

onMounted(async () => {
  try {
    const s = await api.getSettings();
    if (!form.base_url) form.base_url = s.llm?.base_url || "";
    if (!form.model) form.model = s.llm?.model || "";
    form.prompt_version = s.defaults?.worker_prompt_version || form.prompt_version;
    form.max_pages = s.fofa?.max_pages ?? form.max_pages;
    if (!form.intent_mode) form.intent_mode = s.fofa?.default_intent_mode || "";
    if (!form.fofa_base_url) form.fofa_base_url = s.fofa?.base_url || "";
    form.concurrency = s.defaults?.concurrency ?? form.concurrency;
    inherited.base_url = form.base_url;
    inherited.model = form.model;
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
          <option value="">自动判断（写得像语法就当语法，否则当意图）</option>
          <option value="syntax">FOFA 语法（我自己写好了）</option>
          <option value="intent">自然语言意图（让搜集 Agent 翻译成语法并逐轮演化）</option>
        </select>
      </label>
      <label v-if="!isSiteMode">
        {{ form.intent_mode === "intent" ? "搜集意图（用大白话说要找什么）" : "FOFA 语法 / 搜集意图" }}
        <input v-model="form.fofa_query"
          :placeholder="form.src_type === 'enterprise'
            ? (form.intent_mode === 'intent' ? '例：找某集团 OA/CRM/ERP/API/运维后台资产' : 'domain=&quot;example.com&quot; || cert=&quot;示例集团&quot; || org=&quot;示例集团&quot;')
            : (form.intent_mode === 'intent' ? '例：找全国高校的统一身份认证登录系统' : 'title=&quot;统一身份认证&quot; && domain=&quot;.edu.cn&quot;')" />
      </label>
      <label v-else>目标相关信息 / 协作重点 / 已有凭据
        <textarea v-model="form.fofa_query" rows="4" placeholder="可写：重点方向、后台位置、以及【已有的登录凭据】。给了凭据 Agent 会先在前台测，再登录进系统内部深挖（越权/敏感数据/上传/写操作）。&#10;例：后台在 /admin，重点测 API、越权、上传。&#10;已有账号：test / Test@123&#10;或登录态：Cookie: JSESSIONID=xxxx（或 Authorization: Bearer xxxx）"></textarea>
      </label>
      <label v-if="!isFofaMode">{{ isSiteMode ? "主目标 URL（每行一个，会自动拆成多条协作路线）" : "手动目标清单（每行一个）" }}
        <textarea v-model="form.manual_targets" rows="3" :placeholder="isSiteMode ? 'https://target.example.com/' : 'http://211.84.165.243/'"></textarea>
      </label>
      <label v-if="isSiteMode" class="check-line">
        <input type="checkbox" v-model="form.skip_site_recon" @change="form.skip_recon_touched = true" />
        跳过入口盘点侦察（省 token）
      </label>
      <p v-if="isSiteMode" class="field-hint">
        默认会先派一条「入口盘点」路线泛扒首页/robots/API 文档摸清全站入口。<strong>已给登录凭据时不必这样</strong>——
        Agent 可直接登录进系统，从内部功能发现入口，泛侦察纯属浪费 token。勾选后跳过它（前端 JS/密钥侦察仍保留）。
        检测到你填了账号密码/Cookie 会自动勾上，可手动取消。
      </p>
      <details :open="adv">
        <summary @click="adv = !adv">高级：模型 / FOFA / 并发（留空用服务端默认）</summary>
        <label>模型 base_url <input v-model="form.base_url" placeholder="https://api.deepseek.com/v1" /></label>
        <label>模型 api_key <input v-model="form.api_key" type="password" /></label>
        <label>模型名 <input v-model="form.model" placeholder="deepseek-chat" /></label>
        <label>Worker 提示词
          <select v-model="form.prompt_version">
            <option value="current">current（当前省 token 版）</option>
            <option value="legacy">legacy（旧版 23/25 风格）</option>
            <option value="modern">modern（当前完整版）</option>
          </select>
        </label>
        <label v-if="!isSiteMode">FOFA key <input v-model="form.fofa_key" type="password" /></label>
        <label v-if="!isSiteMode">FOFA API 端点 <input v-model="form.fofa_base_url" placeholder="https://fofa.info" /></label>
        <label v-if="!isSiteMode">FOFA 最大页数 <input v-model="form.max_pages" type="number" /></label>
        <label>worker 并发 <input v-model="form.concurrency" type="number" /></label>
      </details>
      <details>
        <summary>测绘工具开关</summary>
        <label class="checkbox-row"><input type="checkbox" v-model="form.enable_worker_fofa_lookup" /> Worker 挖掘时 fofa_lookup（确认归属/探攻击面）</label>
        <label class="checkbox-row"><input type="checkbox" v-model="form.enable_killsweep_fofa_search" /> 通杀分析时 fofa_search（圈定同款系统+统计规模）</label>
        <p class="hint">关闭后可避免 Worker/通杀 Agent 自主调用 FOFA 消耗点数（手动清单模式尤其有用）</p>
      </details>
      <label>SRC 规则（审核用，可留空，审核 agent 已内置{{ form.src_type === 'enterprise' ? '企业SRC' : 'edusrc' }}标准）
        <textarea v-model="form.src_rules" rows="3"></textarea>
      </label>
      <label>CAS SSO 统一认证凭证（任务级，可留空）
        <textarea v-model="form.cas_sso_config" rows="4" placeholder="填写后，本任务每个 Worker 在测试前都会收到这些凭证，可用于需要登录的目标。&#10;例：&#10;登录入口：https://cas.xxx.edu.cn/cas/login&#10;账号：2023xxxx&#10;密码：xxxxxx&#10;或 Cookie/Token：CASTGC=TGT-xxxx"></textarea>
      </label>
      <button type="submit" class="primary">创建任务</button>
    </form>
  </section>
</template>
