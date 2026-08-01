<script setup>
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from "vue";
import { useRouter } from "vue-router";
import { authRoleRef } from "../api.js";

const emit = defineEmits(["close", "toggle-theme"]);
const router = useRouter();
const query = ref("");
const selectedIndex = ref(0);
const inputRef = ref(null);

const allCommands = computed(() => {
  const isFull = authRoleRef.value === "full";
  const isObserver = authRoleRef.value === "observer";
  const cmds = [
    { id: "tasks",    label: "任务列表",   sub: "查看所有挖掘任务",      icon: "≡", path: "/" },
    { id: "analytics",label: "分析仪表盘", sub: "漏洞统计与可视化",      icon: "◎", path: "/analytics" },
    { id: "hard",     label: "硬骨头库",   sub: "全局难突破目标库",      icon: "◈", path: "/hard-targets" },
  ];
  if (!isObserver) {
    cmds.push(
      { id: "vulns",  label: "全局漏洞库", sub: "跨任务漏洞汇总归档",    icon: "⚑", path: "/vulns" },
      { id: "intel",  label: "情报库",     sub: "沉淀的攻击情报",        icon: "◆", path: "/intel" },
      { id: "logs",   label: "运行异常",   sub: "系统错误与异常日志",    icon: "!", path: "/runtime-logs" },
    );
  }
  if (isFull) {
    cmds.push(
      { id: "create",   label: "新建任务", sub: "创建一个挖掘任务",      icon: "+", path: "/create" },
      { id: "settings", label: "系统设置", sub: "LLM / 引擎 / 令牌配置", icon: "⚙", path: "/settings" },
    );
  }
  cmds.push({ id: "theme", label: "切换主题", sub: "在暗色和亮色之间切换", icon: "◑", action: "toggle-theme" });
  return cmds;
});

const filtered = computed(() => {
  const q = query.value.trim().toLowerCase();
  if (!q) return allCommands.value;
  return allCommands.value.filter(
    (c) => c.label.toLowerCase().includes(q) || c.sub.toLowerCase().includes(q),
  );
});

watch(query, () => { selectedIndex.value = 0; });

function select(cmd) {
  if (!cmd) return;
  if (cmd.action === "toggle-theme") {
    emit("toggle-theme");
  } else if (cmd.path) {
    router.push(cmd.path);
  }
  emit("close");
}

function onKeydown(e) {
  if (e.key === "ArrowDown") {
    e.preventDefault();
    selectedIndex.value = Math.min(selectedIndex.value + 1, filtered.value.length - 1);
  } else if (e.key === "ArrowUp") {
    e.preventDefault();
    selectedIndex.value = Math.max(selectedIndex.value - 1, 0);
  } else if (e.key === "Enter") {
    e.preventDefault();
    select(filtered.value[selectedIndex.value]);
  } else if (e.key === "Escape") {
    emit("close");
  }
}

onMounted(() => nextTick(() => inputRef.value?.focus()));
</script>

<template>
  <div class="cmd-backdrop" @click.self="$emit('close')"
    role="dialog" aria-modal="true" aria-label="命令面板">
    <div class="cmd-panel">
      <div class="cmd-input-wrap">
        <span class="cmd-search-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none"
            stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"/>
            <path d="m21 21-4.35-4.35"/>
          </svg>
        </span>
        <input
          ref="inputRef"
          v-model="query"
          class="cmd-input"
          placeholder="搜索命令或跳转页面…"
          autocomplete="off"
          spellcheck="false"
          @keydown="onKeydown"
        />
        <kbd class="cmd-esc-hint">ESC</kbd>
      </div>

      <ul class="cmd-list" role="listbox" aria-label="命令列表">
        <li v-if="filtered.length === 0" class="cmd-empty">无匹配结果</li>
        <li
          v-for="(cmd, i) in filtered"
          :key="cmd.id"
          class="cmd-item"
          :class="{ selected: i === selectedIndex }"
          role="option"
          :aria-selected="i === selectedIndex"
          @click="select(cmd)"
          @mouseover="selectedIndex = i"
        >
          <span class="cmd-icon" aria-hidden="true">{{ cmd.icon }}</span>
          <span class="cmd-info">
            <b class="cmd-label">{{ cmd.label }}</b>
            <small class="cmd-sub">{{ cmd.sub }}</small>
          </span>
          <kbd v-if="i === selectedIndex" class="cmd-return" aria-hidden="true">↵</kbd>
        </li>
      </ul>

      <div class="cmd-footer" aria-hidden="true">
        <span><kbd>↑↓</kbd> 导航</span>
        <span><kbd>↵</kbd> 确认</span>
        <span><kbd>Esc</kbd> 关闭</span>
      </div>
    </div>
  </div>
</template>
