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
});
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

function fill(task) {
  if (!task) return;
  const modelCfg = task.model_config_data || {};
  const fofaCfg = task.fofa_config || {};
  form.name = task.name || "";
  form.src_type = task.src_type || "edusrc";
  form.vuln_types = (task.vuln_types || []).join(",");
  form.target_source = task.target_source || "fofa";
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
  form.concurrency = task.concurrency || 3;
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

  const updated = await api.updateTask(props.task.id, {
    name: form.name,
    src_type: form.src_type,
    vuln_types: form.vuln_types.split(",").map((s) => s.trim()).filter(Boolean),
    target_source: form.target_source,
    fofa_query: form.fofa_query,
    manual_targets: form.manual_targets.split("\n").map((s) => s.trim()).filter(Boolean),
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
        <textarea v-model="form.fofa_query" rows="4"></textarea>
      </label>
      <label>{{ isSiteMode ? "主目标 URL（每行一个，会自动拆成多条协作路线）" : "手动目标清单（每行一个）" }}
        <textarea v-model="form.manual_targets" rows="3"></textarea>
      </label>

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
