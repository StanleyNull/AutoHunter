<script setup>
import { computed, nextTick, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { api } from "../api.js";
import { createChangeTracker } from "../motion/changeTracker.js";
import { highlightChanged } from "../motion/presets.js";
import { useMotion } from "../motion/useMotion.js";

const router = useRouter();
const rows = ref([]);
const initialLoading = ref(true);
const refreshing = ref(false);
const hasLoaded = ref(false);
const status = ref("all");
const searchDraft = ref("");
const searchText = ref("");
const total = ref(0);
const page = ref(0);
const pageSize = 100;
const hasMore = ref(false);
let searchTimer = null;
const pageRoot = ref(null);
const motion = useMotion();
const tracker = createChangeTracker({
  getId: (row) => String(row?.id ?? ""),
  getSignature: (row) => `${row.status}|${row.hit_count}|${row.updated_at}|${row.retry_count}|${row.priority_score}`,
});
let motionSeeded = false;

function resetRowMotion() {
  tracker.reset();
  motionSeeded = false;
}

async function trackRows() {
  if (!motionSeeded) {
    tracker.seed(rows.value);
    motionSeeded = true;
    return;
  }

  const changedIds = tracker.diff(rows.value);
  if (!changedIds.size) return;
  await nextTick();
  const changedElements = [...(pageRoot.value?.querySelectorAll('[data-motion-area="hard-targets"][data-motion-id]') || [])]
    .filter((element) => changedIds.has(element.dataset.motionId));
  highlightChanged(changedElements, motion);
}

const STATUS_LABEL = {
  dead: "硬骨头",
  skipped: "已跳过",
};

async function load() {
  if (!hasLoaded.value) initialLoading.value = true;
  else refreshing.value = true;
  try {
    const res = await api.hardTargets(status.value, searchText.value, {
      limit: pageSize,
      offset: page.value * pageSize,
    });
    rows.value = Array.isArray(res) ? res : (res.items || []);
    await trackRows();
    total.value = Array.isArray(res) ? rows.value.length : (res.total || 0);
    hasMore.value = !Array.isArray(res) && !!res.has_more;
  } finally {
    initialLoading.value = false;
    refreshing.value = false;
    hasLoaded.value = true;
  }
}

function resetAndLoad() {
  page.value = 0;
  resetRowMotion();
  load();
}

function nextPage() {
  if (!hasMore.value || refreshing.value) return;
  page.value += 1;
  resetRowMotion();
  load();
}

function prevPage() {
  if (page.value <= 0 || refreshing.value) return;
  page.value -= 1;
  resetRowMotion();
  load();
}

function reasonOf(row) {
  return row.dead_reason || row.last_error || row.priority_reason || "无记录";
}

function fmtTime(iso) {
  if (!iso) return "-";
  return iso.slice(0, 19).replace("T", " ");
}

function openTask(row) {
  router.push(`/task/${row.task_id}`);
}

const counts = computed(() => ({
  all: total.value,
  dead: rows.value.filter((r) => r.status === "dead").length,
  skipped: rows.value.filter((r) => r.status === "skipped").length,
}));

watch(searchDraft, (v) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    searchText.value = v.trim();
    resetAndLoad();
  }, 160);
});

onMounted(load);
</script>

<template>
  <section ref="pageRoot" class="view hard-view" data-motion-page :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !initialLoading" class="view-progress" aria-hidden="true"><i></i></div>
    <header class="page-head split" data-motion-enter>
      <div>
        <h2>全局硬骨头库</h2>
        <p class="page-sub">跨任务聚合 dead / skipped 目标，用于回捞、复盘和判断收敛质量。</p>
      </div>
      <router-link class="head-action" to="/">返回任务</router-link>
    </header>

    <div class="hard-toolbar" data-motion-enter>
      <div class="search-box">
        <span>⌕</span>
        <input v-model="searchDraft" placeholder="搜索任务 / 单位 / URL / 原因 / org" />
      </div>
      <select v-model="status" @change="resetAndLoad">
        <option value="all">全部状态</option>
        <option value="dead">只看硬骨头</option>
        <option value="skipped">只看跳过</option>
      </select>
      <button @click="load" :disabled="refreshing">{{ refreshing ? "刷新中…" : "刷新" }}</button>
    </div>

    <div class="hard-stats" data-motion-enter>
      <span><b>{{ counts.all }}</b>总命中</span>
      <span><b>{{ rows.length }}</b>本页</span>
      <span><b>{{ page + 1 }}</b>页码</span>
    </div>

    <div v-if="initialLoading" class="hard-list">
      <div v-for="n in 6" :key="n" class="hard-row skeleton-hard"></div>
    </div>
    <div v-else-if="!rows.length" class="empty">暂无硬骨头记录</div>
    <div v-else class="hard-list">
      <button v-for="row in rows" :key="row.id" class="hard-row" type="button"
              data-motion-enter data-motion-area="hard-targets" :data-motion-id="row.id" @click="openTask(row)">
        <span class="hard-status" :class="row.status">{{ STATUS_LABEL[row.status] || row.status }}</span>
        <span class="hard-main">
          <b>{{ row.host || row.url }}</b>
          <small>{{ row.task_name }} · {{ row.school || row.org || row.title || "归属待确认" }}</small>
          <em>{{ reasonOf(row) }}</em>
        </span>
        <span class="hard-meta">
          <b>重试 {{ row.retry_count }}</b>
          <small>优先级 {{ Number(row.priority_score || 0).toFixed(1) }}</small>
          <time>{{ fmtTime(row.updated_at || row.created_at) }}</time>
        </span>
      </button>
    </div>

    <div v-if="!initialLoading && total > pageSize" class="hard-pager">
      <button type="button" @click="prevPage" :disabled="page <= 0 || refreshing">上一页</button>
      <span>第 {{ page + 1 }} 页 · {{ page * pageSize + 1 }}-{{ page * pageSize + rows.length }} / {{ total }}</span>
      <button type="button" @click="nextPage" :disabled="!hasMore || refreshing">下一页</button>
    </div>
  </section>
</template>
