<script setup>
import { computed, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { api } from "../api.js";

const router = useRouter();
const stats = ref({ total: 0, submitted: 0, ready: 0, by_severity: {} });
const rows = ref([]);
const initialLoading = ref(true);
const refreshing = ref(false);
const submitted = ref("all");
const severity = ref("");
const searchDraft = ref("");
const searchText = ref("");
const total = ref(0);
const page = ref(0);
const pageSize = 100;
const hasMore = ref(false);
let searchTimer = null;

const SUBMIT_TABS = [
  { id: "all", label: "全部" },
  { id: "yes", label: "已提交" },
  { id: "no", label: "待提交" },
];

const SEV_META = {
  critical: { label: "严重", hue: "danger" },
  high: { label: "高危", hue: "danger" },
  medium: { label: "中危", hue: "warn" },
  low: { label: "低危", hue: "info" },
  info: { label: "信息", hue: "ok" },
};

const severityOptions = computed(() => Object.keys(stats.value.by_severity || {}));

async function loadStats() {
  try { stats.value = await api.vulnStats(); } catch { /* keep */ }
}

async function loadList() {
  if (!rows.value.length) initialLoading.value = true;
  else refreshing.value = true;
  try {
    const res = await api.vulns(submitted.value, severity.value, searchText.value, {
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

function sevMeta(s) {
  return SEV_META[(s || "").toLowerCase()] || { label: s || "未定级", hue: "ok" };
}

function fmtTime(iso) {
  if (!iso) return "-";
  return iso.slice(0, 19).replace("T", " ");
}

function openVuln(row) {
  router.push(`/task/${row.task_id}`);
}

watch([submitted, severity], reload);
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
  <section class="view intel-view" :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !initialLoading" class="view-progress" aria-hidden="true"><i></i></div>

    <header class="page-head split">
      <div>
        <h2>全局漏洞库 <span class="intel-chip">VULN</span></h2>
        <p class="page-sub">跨任务汇总通过人工审核的漏洞——含已提交 SRC 与待提交两类，用于统一归档与复盘。</p>
      </div>
      <router-link class="head-action" to="/">返回任务</router-link>
    </header>

    <div class="intel-dash">
      <div class="dash-card hero">
        <span class="dash-k">过审漏洞</span>
        <b class="dash-v">{{ stats.total }}</b>
        <span class="dash-sub">已提交 {{ stats.submitted }} · 待提交 {{ stats.ready }}</span>
      </div>
      <div class="dash-card ok">
        <span class="dash-icon">✓</span>
        <b class="dash-v">{{ stats.submitted }}</b>
        <span class="dash-k">已提交</span>
      </div>
      <div class="dash-card warn">
        <span class="dash-icon">◷</span>
        <b class="dash-v">{{ stats.ready }}</b>
        <span class="dash-k">待提交</span>
      </div>
      <div class="dash-card info">
        <span class="dash-icon">∑</span>
        <b class="dash-v">{{ severityOptions.length }}</b>
        <span class="dash-k">等级分布</span>
      </div>
    </div>

    <div class="intel-toolbar">
      <div class="kind-tabs">
        <button v-for="t in SUBMIT_TABS" :key="t.id" type="button"
                class="kind-tab" :class="{ on: submitted === t.id }" @click="submitted = t.id">
          {{ t.label }}
        </button>
      </div>
      <div class="search-box">
        <span>⌕</span>
        <input v-model="searchDraft" placeholder="搜索 标题 / 类型 / URL / 归属 / 任务" />
      </div>
      <select v-model="severity">
        <option value="">全部等级</option>
        <option v-for="s in severityOptions" :key="s" :value="s">{{ sevMeta(s).label }}</option>
      </select>
      <button class="btn-ghost" @click="reload" :disabled="refreshing">{{ refreshing ? "刷新中…" : "刷新" }}</button>
    </div>

    <div v-if="initialLoading" class="intel-grid">
      <div v-for="n in 8" :key="n" class="intel-row skeleton-hard"></div>
    </div>
    <div v-else-if="!rows.length" class="empty">
      漏洞库暂无记录
      <span class="hint">人工审核通过的漏洞会自动汇总到这里</span>
    </div>
    <div v-else class="intel-grid">
      <article v-for="row in rows" :key="row.id" class="intel-row" :class="sevMeta(row.effective_severity).hue"
               role="button" tabindex="0" @click="openVuln(row)" @keyup.enter="openVuln(row)">
        <span class="ir-kind" :class="sevMeta(row.effective_severity).hue">
          <i>⚑</i>{{ sevMeta(row.effective_severity).label }}
        </span>
        <div class="ir-main">
          <b class="ir-primary">{{ row.title }}</b>
          <small class="ir-secondary">{{ row.vuln_type }} · {{ row.target_url }}</small>
          <span class="ir-key">归属：{{ row.owner || "待确认" }} · 任务：{{ row.task_name || row.task_id }}</span>
          <div v-if="(row.kill_chain || []).length" class="vuln-chain" @click.stop>
            <div class="vc-flow">
              <span class="vc-label">攻击链路</span>
              <template v-for="(s, i) in row.kill_chain" :key="i">
                <span class="vc-node">{{ s.method }}</span>
                <span v-if="i < row.kill_chain.length - 1" class="vc-arrow">→</span>
              </template>
            </div>
            <ol class="vc-steps">
              <li v-for="(s, i) in row.kill_chain" :key="'d' + i">
                <b>{{ s.method }}</b><span v-if="s.detail"> — {{ s.detail }}</span>
              </li>
            </ol>
          </div>
        </div>
        <div class="ir-side">
          <span class="ir-conf" :class="row.submitted ? 'verified' : 'likely'">
            {{ row.submitted ? "✓ 已提交" : "◷ 待提交" }}
          </span>
          <span class="ir-hit" v-if="row.confidence">{{ row.confidence }}</span>
          <time>{{ fmtTime(row.user_reviewed_at || row.created_at) }}</time>
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
