<script setup>
import { computed, ref, watch } from "vue";
import { api } from "../api.js";
import LlmModelPicker from "./LlmModelPicker.vue";

const props = defineProps({
  modelValue: { type: Array, default: () => [] },
  disabled: { type: Boolean, default: false },
  /** 编辑已有任务时传入，查询模型走任务级密钥解析 */
  taskId: { type: String, default: "" },
  /** 新建端点时的默认值 */
  defaults: {
    type: Object,
    default: () => ({
      base_url: "https://api.deepseek.com/v1",
      model: "deepseek-chat",
      protocol: "auto",
      temperature: 0.3,
    }),
  },
});
const emit = defineEmits(["update:modelValue"]);

const selected = ref(0);
const toastMsg = ref("");
let _uidSeq = 1;
function nextUid() {
  return `pool-uid-${_uidSeq++}`;
}

function toast(m) {
  toastMsg.value = m;
  setTimeout(() => { toastMsg.value = ""; }, 2200);
}

function normalizeProtocol(protocol) {
  return ["auto", "openai_chat", "anthropic_messages"].includes(protocol) ? protocol : "auto";
}

function ensureUid(row) {
  if (row && !row._uid) row._uid = nextUid();
  return row;
}

function normalizeRow(provider = {}, idx = 0) {
  return {
    _uid: provider._uid || nextUid(),
    name: provider.name || `llm-${idx + 1}`,
    base_url: provider.base_url || "",
    api_key: provider.api_key || "",
    api_key_set: !!provider.api_key_set,
    api_key_masked: provider.api_key_masked || "",
    key_ref: provider.key_ref || "",
    model: provider.model || "",
    protocol: normalizeProtocol(provider.protocol),
    temperature: provider.temperature ?? props.defaults.temperature ?? 0.3,
    weight: provider.weight ?? 1,
    enabled: provider.enabled !== false,
    models: Array.isArray(provider.models) ? provider.models : [],
    modelsLoading: !!provider.modelsLoading,
    modelsError: provider.modelsError || "",
  };
}

const providers = computed({
  get: () => props.modelValue || [],
  set: (v) => emit("update:modelValue", v),
});

watch(
  () => providers.value.length,
  (n) => {
    if (!n) selected.value = -1;
    else if (selected.value < 0 || selected.value >= n) selected.value = 0;
  },
  { immediate: true },
);

// 给外来数据补稳定 uid，避免 key 抖动
watch(
  () => props.modelValue,
  (rows) => {
    if (!Array.isArray(rows)) return;
    let changed = false;
    for (const row of rows) {
      if (row && !row._uid) {
        row._uid = nextUid();
        changed = true;
      }
    }
    if (changed) emit("update:modelValue", rows.slice());
  },
  { immediate: true, deep: false },
);

const current = computed(() => providers.value[selected.value] || null);

/** 结构变更（增删移）时整表规范化；字段编辑走 patchCurrent，避免整表重建冲掉焦点/选中。 */
function replaceAll(mutator) {
  const next = providers.value.map((row, idx) => normalizeRow(row, idx));
  mutator(next);
  providers.value = next;
}

function addProvider() {
  replaceAll((rows) => {
    rows.push(normalizeRow({
      name: `llm-${rows.length + 1}`,
      base_url: props.defaults.base_url || "https://api.deepseek.com/v1",
      model: props.defaults.model || "deepseek-chat",
      protocol: props.defaults.protocol || "auto",
      temperature: props.defaults.temperature ?? 0.3,
      weight: 1,
      enabled: true,
    }, rows.length));
    selected.value = rows.length - 1;
  });
}

function removeProvider(idx) {
  const provider = providers.value[idx];
  if (!provider) return;
  const label = provider.name || provider.model || `端点 #${idx + 1}`;
  if (!confirm(`确认删除模型端点「${label}」？`)) return;
  replaceAll((rows) => {
    rows.splice(idx, 1);
    if (!rows.length) selected.value = -1;
    else if (selected.value > idx) selected.value -= 1;
    else if (selected.value === idx) selected.value = Math.min(idx, rows.length - 1);
  });
}

function moveProvider(idx, delta) {
  const next = idx + delta;
  if (next < 0 || next >= providers.value.length) return;
  replaceAll((rows) => {
    const [row] = rows.splice(idx, 1);
    rows.splice(next, 0, row);
    selected.value = next;
  });
}

function patchCurrent(patch) {
  if (!current.value || selected.value < 0) return;
  patchAt(selected.value, patch);
}

function invalidateKey() {
  patchCurrent({
    key_ref: "",
    api_key_set: false,
    api_key_masked: "",
    models: [],
    modelsError: "",
  });
}

function onBaseUrlInput(value) {
  patchCurrent({
    base_url: value,
    key_ref: "",
    api_key_set: false,
    api_key_masked: "",
    models: [],
    modelsError: "",
  });
}

function onProtocolChange(value) {
  patchCurrent({
    protocol: value,
    key_ref: "",
    api_key_set: false,
    api_key_masked: "",
    models: [],
    modelsError: "",
  });
}

function patchAt(idx, patch) {
  if (idx < 0 || idx >= providers.value.length) return;
  const row = providers.value[idx];
  if (!row) return;
  // 就地改字段，只浅拷贝数组触发父级更新；避免每键新建对象导致输入框丢光标
  Object.assign(ensureUid(row), patch);
  providers.value = providers.value.slice();
}

async function loadModels(idx) {
  const provider = providers.value[idx];
  if (!provider) return;
  const keepUid = provider._uid;
  const keepSelected = selected.value;
  patchAt(idx, { modelsLoading: true, modelsError: "" });
  const payload = {
    base_url: provider.base_url,
    api_key: String(provider.api_key || "").trim(),
    protocol: provider.protocol,
    key_ref: provider.key_ref,
    model: provider.model,
  };
  try {
    // 任务编辑：走 /tasks/{id}/models，才能解析任务端点池里的 key_ref
    // 新建任务/系统配置：走 /settings/models
    const res = props.taskId
      ? await api.taskModels(props.taskId, payload)
      : await api.listModels(payload);
    if (res?.ok && res.models?.length) {
      const model = (!provider.model || !res.models.includes(provider.model))
        ? res.models[0]
        : provider.model;
      patchAt(idx, { models: res.models, modelsLoading: false, model });
      toast(`已获取 ${res.models.length} 个模型`);
    } else {
      patchAt(idx, {
        models: [],
        modelsError: res?.error || "未获取到模型列表",
        modelsLoading: false,
      });
      toast(`端点 #${idx + 1} 获取模型失败`);
    }
  } catch (e) {
    patchAt(idx, {
      models: [],
      modelsError: String(e.message || e).replace(/^\d+\s*/, ""),
      modelsLoading: false,
    });
    toast(`端点 #${idx + 1} 获取模型失败`);
  } finally {
    const nowUid = providers.value[selected.value]?._uid;
    if (nowUid === keepUid || selected.value === keepSelected) {
      const found = providers.value.findIndex((p) => p._uid === keepUid);
      if (found >= 0) selected.value = found;
    }
  }
}

/** 导出给父组件提交用的干净 payload */
function exportProviders() {
  return (providers.value || []).map((p, idx) => ({
    name: String(p.name || `llm-${idx + 1}`).trim(),
    base_url: String(p.base_url || "").trim(),
    api_key: String(p.api_key || "").trim(),
    key_ref: p.key_ref || "",
    model: String(p.model || "").trim(),
    protocol: normalizeProtocol(p.protocol),
    temperature: Number(p.temperature ?? 0.3),
    weight: Math.max(1, Math.min(100, Number(p.weight || 1))),
    enabled: p.enabled !== false,
  }));
}

defineExpose({ exportProviders, addProvider });
</script>

<template>
  <div class="llm-pool-pane" :class="{ disabled }">
    <div class="llm-pool-toolbar">
      <div>
        <b>端点列表</b>
        <span>{{ providers.length }} 个</span>
      </div>
      <button type="button" :disabled="disabled" @click="addProvider">+ 添加端点</button>
    </div>

    <div v-if="!providers.length" class="provider-empty">
      <span>端点池为空，至少添加一个端点</span>
      <button type="button" :disabled="disabled" @click="addProvider">+ 添加端点</button>
    </div>

    <div v-else class="provider-selector" role="listbox" aria-label="LLM 端点列表">
      <button
        v-for="(provider, idx) in providers"
        :key="provider._uid || idx"
        type="button"
        role="option"
        :aria-selected="selected === idx"
        class="provider-selector-row"
        :class="[{ active: selected === idx, disabled: provider.enabled === false }]"
        :disabled="disabled"
        @click="selected = idx"
      >
        <span class="provider-dot unknown"></span>
        <b>{{ provider.name || `llm-${idx + 1}` }}</b>
        <small>{{ provider.model || "未设置模型" }}</small>
        <em>{{ provider.protocol === "auto" ? "Auto" : provider.protocol === "anthropic_messages" ? "Anthropic" : "OpenAI" }}</em>
        <i>权重 {{ provider.weight || 1 }}</i>
      </button>
    </div>

    <div v-if="current" class="provider-detail">
      <div class="provider-detail-head">
        <div>
          <span>端点 {{ selected + 1 }}</span>
        </div>
        <div class="provider-head-actions">
          <button type="button" title="上移" :disabled="disabled || selected === 0" @click="moveProvider(selected, -1)">↑</button>
          <button type="button" title="下移" :disabled="disabled || selected === providers.length - 1" @click="moveProvider(selected, 1)">↓</button>
          <label class="provider-enabled">
            <input
              type="checkbox"
              :checked="current.enabled !== false"
              :disabled="disabled"
              @change="patchCurrent({ enabled: $event.target.checked })"
            />
            启用
          </label>
          <button type="button" class="danger" :disabled="disabled" @click="removeProvider(selected)">×</button>
        </div>
      </div>

      <div class="provider-fields">
        <label>名称
          <input :value="current.name" :disabled="disabled" placeholder="primary" @input="patchCurrent({ name: $event.target.value })" />
        </label>
        <label>协议
          <select
            :value="current.protocol"
            :disabled="disabled"
            @change="onProtocolChange($event.target.value)"
          >
            <option value="auto">自动判断</option>
            <option value="openai_chat">OpenAI Chat</option>
            <option value="anthropic_messages">Anthropic Messages</option>
          </select>
        </label>
        <label class="wide">base_url
          <input
            :value="current.base_url"
            :disabled="disabled"
            placeholder="https://api.deepseek.com/v1"
            @input="onBaseUrlInput($event.target.value)"
          />
        </label>
        <label>api_key
          <input
            :value="current.api_key"
            type="password"
            :disabled="disabled"
            :required="!current.key_ref"
            :placeholder="current.api_key_set ? `${current.api_key_masked || '已配置'}，留空不修改` : 'sk-...'"
            @input="patchCurrent({ api_key: $event.target.value })"
          />
        </label>
        <label>temperature
          <input
            type="number" step="0.1" min="0" max="2"
            :value="current.temperature"
            :disabled="disabled"
            @input="patchCurrent({ temperature: $event.target.value })"
          />
        </label>
        <label>权重
          <input
            type="number" min="1" max="100"
            :value="current.weight"
            :disabled="disabled"
            @input="patchCurrent({ weight: $event.target.value })"
          />
        </label>
        <label class="wide">模型名
          <LlmModelPicker
            :model-value="current.model"
            :models="current.models"
            :loading="current.modelsLoading"
            :disabled="disabled"
            :error="current.modelsError"
            @update:model-value="patchCurrent({ model: $event })"
            @refresh="loadModels(selected)"
          />
        </label>
      </div>
    </div>
    <p v-if="toastMsg" class="model-hint">{{ toastMsg }}</p>
  </div>
</template>
