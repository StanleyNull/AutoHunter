<script setup>
import { ref, onMounted, computed } from "vue";
import { api } from "../api.js";

const vulnStats = ref({ total: 0, submitted: 0, ready: 0, by_severity: {} });
const tasks = ref([]);
const loading = ref(true);

async function load() {
  loading.value = true;
  try {
    const [stats, taskList] = await Promise.all([
      api.vulnStats().catch(() => ({ total: 0, submitted: 0, ready: 0, by_severity: {} })),
      api.listTasks().catch(() => []),
    ]);
    vulnStats.value = stats;
    tasks.value = Array.isArray(taskList) ? taskList : [];
  } finally {
    loading.value = false;
  }
}

const SEV_CONFIG = [
  { key: "critical", label: "严重", color: "var(--danger)" },
  { key: "high",     label: "高危", color: "var(--danger)" },
  { key: "medium",   label: "中危", color: "var(--warn)" },
  { key: "low",      label: "低危", color: "var(--info)" },
  { key: "info",     label: "信息", color: "var(--ok)" },
];

const sevData = computed(() => {
  const bySev = vulnStats.value.by_severity || {};
  return SEV_CONFIG.map((s) => ({ ...s, count: bySev[s.key] || 0 })).filter((s) => s.count > 0);
});

const sevMax = computed(() => Math.max(...sevData.value.map((s) => s.count), 1));

const STATUS_LABEL = {
  running: "运行中", idle: "空闲", paused: "已暂停",
  stopped: "已停止", created: "未启动",
};

const taskStats = computed(() => {
  const counts = {};
  for (const t of tasks.value) counts[t.status] = (counts[t.status] || 0) + 1;
  return Object.entries(counts).map(([status, count]) => ({
    status, count, label: STATUS_LABEL[status] || status,
  }));
});

const runningCount = computed(() => tasks.value.filter((t) => t.status === "running").length);

onMounted(load);
</script>

<template>
  <section class="view analytics-view" :class="{ 'is-refreshing': loading }">
    <div v-if="loading" class="view-progress" aria-hidden="true"><i></i></div>

    <header class="page-head split">
      <div>
        <h2>分析仪表盘</h2>
        <p class="page-sub">跨任务漏洞与运行状态的整体视角</p>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <router-link class="head-action" to="/">返回任务</router-link>
        <button class="head-action" @click="load" :disabled="loading" style="border:1px solid var(--border)">
          {{ loading ? "刷新中…" : "刷新" }}
        </button>
      </div>
    </header>

    <!-- KPI 卡片 -->
    <div class="an-kpi-grid">
      <div class="an-kpi-card">
        <span class="an-kpi-label">过审漏洞</span>
        <b class="an-kpi-val">{{ vulnStats.total }}</b>
      </div>
      <div class="an-kpi-card ok">
        <span class="an-kpi-label">已提交</span>
        <b class="an-kpi-val">{{ vulnStats.submitted }}</b>
      </div>
      <div class="an-kpi-card warn">
        <span class="an-kpi-label">待提交</span>
        <b class="an-kpi-val">{{ vulnStats.ready }}</b>
      </div>
      <div class="an-kpi-card">
        <span class="an-kpi-label">总任务数</span>
        <b class="an-kpi-val">{{ tasks.length }}</b>
      </div>
      <div class="an-kpi-card info">
        <span class="an-kpi-label">运行中</span>
        <b class="an-kpi-val">{{ runningCount }}</b>
      </div>
    </div>

    <!-- 漏洞等级分布 -->
    <div class="an-section">
      <p class="an-section-title">漏洞等级分布</p>
      <div v-if="loading && !sevData.length" class="an-sev-chart">
        <div v-for="n in 4" :key="n" class="an-sev-row">
          <span class="sk-bar" style="width:40px;height:12px;border-radius:4px"></span>
          <div class="an-sev-bar-wrap"><div class="an-sev-bar skeleton-pulse" style="width:60%;background:var(--surface-3)"></div></div>
          <span class="sk-bar" style="width:24px;height:12px;border-radius:4px"></span>
        </div>
      </div>
      <div v-else-if="sevData.length === 0" class="empty sm">暂无漏洞数据</div>
      <div v-else class="an-sev-chart">
        <div v-for="s in sevData" :key="s.key" class="an-sev-row">
          <span class="an-sev-label">{{ s.label }}</span>
          <div class="an-sev-bar-wrap">
            <div class="an-sev-bar" :style="{ width: (s.count / sevMax * 100) + '%', background: s.color }"></div>
          </div>
          <span class="an-sev-count">{{ s.count }}</span>
        </div>
      </div>
    </div>

    <!-- 任务状态分布 -->
    <div class="an-section">
      <p class="an-section-title">任务状态分布</p>
      <div v-if="tasks.length === 0" class="empty sm">暂无任务</div>
      <div v-else class="an-task-pills">
        <div v-for="ts in taskStats" :key="ts.status" class="an-task-pill" :class="ts.status">
          <b>{{ ts.count }}</b>
          <span>{{ ts.label }}</span>
        </div>
      </div>
    </div>
  </section>
</template>
