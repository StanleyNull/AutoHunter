<script setup>
import { computed, ref, watch } from "vue";

const props = defineProps({
  modelValue: { type: String, default: "" },
  models: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
  disabled: { type: Boolean, default: false },
  required: { type: Boolean, default: false },
  placeholder: { type: String, default: "deepseek-chat" },
  error: { type: String, default: "" },
  hint: { type: String, default: "" },
  refreshLabel: { type: String, default: "查询模型" },
});

const emit = defineEmits(["update:modelValue", "refresh"]);

const useCustom = ref(false);

const list = computed(() => (props.models || []).filter(Boolean));
const inList = computed(() => !!props.modelValue && list.value.includes(props.modelValue));

watch(
  () => [list.value.join("\0"), props.modelValue],
  () => {
    if (!list.value.length) {
      useCustom.value = true;
      return;
    }
    // 有列表且当前值在列表中 → 默认下拉；不在列表 → 手输，避免误选
    useCustom.value = !!props.modelValue && !inList.value;
  },
  { immediate: true },
);

function setValue(v) {
  emit("update:modelValue", v);
}
</script>

<template>
  <div class="model-picker-wrap">
    <div class="model-picker">
      <select
        v-if="list.length && !useCustom"
        :value="modelValue"
        :disabled="disabled"
        :required="required"
        @change="setValue($event.target.value)"
      >
        <option v-if="!inList" value="" disabled>请选择模型</option>
        <option v-for="m in list" :key="m" :value="m">{{ m }}</option>
      </select>
      <input
        v-else
        :value="modelValue"
        :disabled="disabled"
        :required="required"
        :placeholder="placeholder"
        @input="setValue($event.target.value)"
      />
      <button type="button" class="ghost-btn" :disabled="loading || disabled" @click="emit('refresh')">
        {{ loading ? "查询中…" : refreshLabel }}
      </button>
      <button
        v-if="list.length"
        type="button"
        class="ghost-btn"
        :disabled="disabled"
        @click="useCustom = !useCustom"
      >
        {{ useCustom ? "选列表" : "手动输入" }}
      </button>
    </div>
    <small v-if="error" class="model-hint">{{ error }}</small>
    <small v-else-if="hint" class="model-hint">{{ hint }}</small>
    <small v-else-if="list.length" class="model-hint">已获取 {{ list.length }} 个可用模型，可下拉选择</small>
  </div>
</template>
