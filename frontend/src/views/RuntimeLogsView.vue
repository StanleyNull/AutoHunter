<script setup>
import { computed, onMounted, ref, watch } from "vue";
import { api } from "../api.js";

const stats = ref({ total: 0, errors: 0, warns: 0, by_agent: {} });
const rows = ref([]);
const initialLoading = ref(true);
const refreshing = ref(false);
const level = ref("all");
const agent = ref("all");
const searchDraft = ref("");
const searchText = ref("");
const total = ref(0);
const page = ref(0);
const pageSize = 100;
const hasMore = ref(false);
let searchTimer = null;

const agentOptions = computed(() => {
  const names = Object.keys(stats.value.by_agent || {}).sort();
  return ["all", ...names];
});

async function loadStats() {
  try { stats.value = await api.runtimeLogStats(); } catch { /* keep */ }
}

async function loadList() {
  if (!rows.value.length) initialLoading.value = true;
  else refreshing.value = true;
  try {
    const res = await api.runtimeLogs(level.value, agent.value, searchText.value, {
      limit: pageSize,
      offset: page.value * pageSize,
    });
    rows.value = Array.isArray(res) ? res : (res.items || []);
    total.value = Array.isArray(res) ? rows.value.length : (res.total || 0);
    hasMore.value = !Array.isArray(res) && !!res.has_more;
  } finally {
    initialLoading.value = false;
    refreshing.value = false;
  }
}

async function reload() {
  page.value = 0;
  await Promise.all([loadStats(), loadList()]);
}

function nextPage() {
  if (!hasMore.value || refreshing.value) return;
  page.value += 1;
  loadList();
}

function prevPage() {
  if (page.value <= 0 || refreshing.value) return;
  page.value -= 1;
  loadList();
}

function fmtTime(iso) {
  if (!iso) return "-";
  const s = String(iso).trim();
  // 后端存 UTC naive 时间（无 Z/偏移），需显式按 UTC 解析再转本地显示。
  const hasTz = /[zZ]|[+-]\d{2}:\d{2}$/.test(s);
  const d = new Date(hasTz ? s : `${s}Z`);
  if (Number.isNaN(d.getTime())) return s.slice(0, 19).replace("T", " ");
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function agentLabel(a) {
  if (a === "all") return "全部 agent";
  return a || "unknown";
}

function payloadText(payload) {
  try { return JSON.stringify(payload || {}, null, 2); }
  catch { return String(payload || ""); }
}

watch([level, agent], reload);
watch(searchDraft, (v) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    searchText.value = v.trim();
    page.value = 0;
    loadList();
  }, 180);
});

onMounted(reload);
</script>

<template>
  <section class="view runtime-logs-view" :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !initialLoading" class="view-progress" aria-hidden="true"><i></i></div>

    <header class="page-head split">
      <div>
        <h2>全局运行异常 <span class="intel-chip">RUNTIME</span></h2>
        <p class="page-sub">集中查看跨任务 LLM / reviewer / worker / orchestrator 异常与安全收敛事件。</p>
      </div>
      <router-link class="head-action" to="/">返回任务</router-link>
    </header>

    <div class="intel-dash">
      <div class="dash-card hero">
        <span class="dash-k">异常事件</span>
        <b class="dash-v">{{ stats.total }}</b>
        <span class="dash-sub">Error {{ stats.errors }} · Warn {{ stats.warns }}</span>
      </div>
      <div class="dash-card danger">
        <span class="dash-icon">!</span>
        <b class="dash-v">{{ stats.errors }}</b>
        <span class="dash-k">错误</span>
      </div>
      <div class="dash-card warn">
        <span class="dash-icon">⚠</span>
        <b class="dash-v">{{ stats.warns }}</b>
        <span class="dash-k">警告</span>
      </div>
      <div class="dash-card info">
        <span class="dash-icon">∑</span>
        <b class="dash-v">{{ Object.keys(stats.by_agent || {}).length }}</b>
        <span class="dash-k">Agent 来源</span>
      </div>
    </div>

    <div class="intel-toolbar">
      <div class="kind-tabs">
        <button v-for="l in ['all','error','warn','info']" :key="l" type="button"
                class="kind-tab" :class="{ on: level === l }" @click="level = l">
          {{ l === 'all' ? '全部' : l.toUpperCase() }}
        </button>
      </div>
      <div class="search-box">
        <span>⌕</span>
        <input v-model="searchDraft" placeholder="搜索 任务 / agent / kind / 错误详情" />
      </div>
      <select v-model="agent">
        <option v-for="a in agentOptions" :key="a" :value="a">{{ agentLabel(a) }}</option>
      </select>
      <button class="btn-ghost" @click="reload" :disabled="refreshing">{{ refreshing ? "刷新中…" : "刷新" }}</button>
    </div>

    <div v-if="initialLoading" class="intel-grid">
      <div v-for="n in 8" :key="n" class="intel-row skeleton-hard"></div>
    </div>
    <div v-else-if="!rows.length" class="empty">
      暂无异常
      <span class="hint">当前筛选条件下没有运行异常事件</span>
    </div>
    <div v-else class="intel-grid runtime-grid">
      <article v-for="row in rows" :key="row.id" class="intel-row runtime-row" :class="row.level">
        <span class="ir-kind" :class="row.level">
          <i>{{ row.level === 'error' ? '!' : row.level === 'warn' ? '⚠' : '·' }}</i>{{ row.level || 'info' }}
        </span>
        <div class="ir-main">
          <b class="ir-primary">{{ row.kind || 'event' }} · {{ row.agent || 'unknown' }}</b>
          <small class="ir-secondary">{{ row.message }}</small>
          <span class="ir-key">任务：{{ row.task_name || row.task_id || '-' }}</span>
          <details v-if="row.payload && Object.keys(row.payload).length" class="runtime-payload">
            <summary>payload</summary>
            <pre>{{ payloadText(row.payload) }}</pre>
          </details>
        </div>
        <div class="ir-side">
          <span class="ir-conf likely">{{ row.task_status || 'unknown' }}</span>
          <small class="ir-src">{{ row.task_id }}</small>
          <time>{{ fmtTime(row.ts) }}</time>
        </div>
      </article>
    </div>

    <div v-if="!initialLoading && total > pageSize" class="hard-pager">
      <button type="button" @click="prevPage" :disabled="page <= 0 || refreshing">上一页</button>
      <span>第 {{ page + 1 }} 页 · {{ page * pageSize + 1 }}-{{ page * pageSize + rows.length }} / {{ total }}</span>
      <button type="button" @click="nextPage" :disabled="!hasMore || refreshing">下一页</button>
    </div>
  </section>
</template>
