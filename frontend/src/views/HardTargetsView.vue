<script setup>
import { computed, onActivated, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { api, canWrite } from "../api.js";

defineOptions({ name: "HardTargetsView" });

const router = useRouter();
const rows = ref([]);
const initialLoading = ref(true);
const refreshing = ref(false);
const status = ref("all");
const searchDraft = ref("");
const searchText = ref("");
const total = ref(0);
const page = ref(0);
const pageSize = 100;
const hasMore = ref(false);
let searchTimer = null;

// 置顶功能：仅 full 令牌可写；selected 为本页已勾选的资产 id 集合。
const writable = computed(() => canWrite());
const selected = ref(new Set());
const toggling = ref(new Set());
const batchToggling = ref(false);
const toastMsg = ref("");

function toast(m, ms = 2400) {
  toastMsg.value = m;
  setTimeout(() => { if (toastMsg.value === m) toastMsg.value = ""; }, ms);
}

const STATUS_LABEL = {
  dead: "硬骨头",
  skipped: "已跳过",
};

const selectedCount = computed(() => selected.value.size);
const pageIds = computed(() => rows.value.map((r) => r.id));
const allChecked = computed(() =>
  pageIds.value.length > 0 && pageIds.value.every((id) => selected.value.has(id)));
const someChecked = computed(() =>
  pageIds.value.some((id) => selected.value.has(id)));

async function load() {
  if (!rows.value.length) initialLoading.value = true;
  else refreshing.value = true;
  try {
    const res = await api.hardTargets(status.value, searchText.value, {
      limit: pageSize,
      offset: page.value * pageSize,
    });
    rows.value = Array.isArray(res) ? res : (res.items || []);
    total.value = Array.isArray(res) ? rows.value.length : (res.total || 0);
    hasMore.value = !Array.isArray(res) && !!res.has_more;
    // 翻页/重载后清空勾选：跨页勾选意义不大且易误操作。
    selected.value = new Set();
  } finally {
    initialLoading.value = false;
    refreshing.value = false;
  }
}

function resetAndLoad() {
  page.value = 0;
  load();
}

function nextPage() {
  if (!hasMore.value || refreshing.value) return;
  page.value += 1;
  load();
}

function prevPage() {
  if (page.value <= 0 || refreshing.value) return;
  page.value -= 1;
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

// ===== 置顶交互 =====
function toggleRowChecked(row, checked) {
  const next = new Set(selected.value);
  if (checked) next.add(row.id);
  else next.delete(row.id);
  selected.value = next;
}

function toggleAllChecked(checked) {
  const next = new Set(selected.value);
  if (checked) pageIds.value.forEach((id) => next.add(id));
  else pageIds.value.forEach((id) => next.delete(id));
  selected.value = next;
}

// 单条置顶/取消置顶：异步无刷新更新列表状态。
async function toggleTop(row) {
  if (!writable.value || toggling.value.has(row.id)) return;
  const next = !row.is_top;
  toggling.value = new Set(toggling.value).add(row.id);
  try {
    await api.assetTop(row.id, next);
    row.is_top = next;
    toast(next ? "已置顶" : "已取消置顶");
  } catch (e) {
    alert(`操作失败：${e?.message || e}`);
  } finally {
    const s = new Set(toggling.value);
    s.delete(row.id);
    toggling.value = s;
  }
}

// 批量置顶/取消置顶：确认对话框显示选中数量，加载中禁用按钮。
async function batchTop(isTop) {
  if (!writable.value || batchToggling.value) return;
  const ids = Array.from(selected.value);
  if (!ids.length) return;
  const verb = isTop ? "置顶" : "取消置顶";
  if (!confirm(`确认${verb}选中的 ${ids.length} 条资产？`)) return;
  batchToggling.value = true;
  try {
    const res = await api.assetBatchTop(ids, isTop);
    const ok = res?.success_count ?? 0;
    const failed = res?.failed_ids || [];
    const idSet = new Set(ids);
    rows.value.forEach((r) => { if (idSet.has(r.id)) r.is_top = isTop; });
    if (failed.length) {
      alert(`成功${verb} ${ok} 条，失败 ${failed.length} 条（记录可能已不存在）`);
    } else {
      toast(`成功${verb} ${ok} 条`);
    }
  } catch (e) {
    alert(`批量操作失败：${e?.message || e}`);
  } finally {
    batchToggling.value = false;
  }
}

watch(searchDraft, (v) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    searchText.value = v.trim();
    resetAndLoad();
  }, 160);
});

onMounted(load);
onActivated(() => {
  if (rows.value.length) load();
});
</script>

<template>
  <section class="view hard-view" :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !initialLoading" class="view-progress" aria-hidden="true"><i></i></div>
    <header class="page-head split">
      <div>
        <h2>全局硬骨头库</h2>
        <p class="page-sub">跨任务聚合 dead / skipped 目标，用于回捞、复盘和判断收敛质量。</p>
      </div>
      <router-link class="head-action" to="/">返回任务</router-link>
    </header>

    <div class="hard-toolbar">
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

    <div v-if="writable && rows.length" class="pin-batch-bar">
      <label class="pin-sel-all">
        <input type="checkbox" :checked="allChecked" :indeterminate.prop="someChecked && !allChecked"
               @change="toggleAllChecked($event.target.checked)" />
        <span>全选本页</span>
      </label>
      <span class="pin-sel-count">已选 {{ selectedCount }} 项</span>
      <button class="btn-pin" type="button" @click="batchTop(true)"
              :disabled="!selectedCount || batchToggling">
        {{ batchToggling ? "处理中…" : "批量置顶" }}
      </button>
      <button class="btn-ghost" type="button" @click="batchTop(false)"
              :disabled="!selectedCount || batchToggling">
        {{ batchToggling ? "处理中…" : "批量取消置顶" }}
      </button>
    </div>

    <div class="hard-stats">
      <span><b>{{ counts.all }}</b>总命中</span>
      <span><b>{{ rows.length }}</b>本页</span>
      <span><b>{{ page + 1 }}</b>页码</span>
    </div>

    <div v-if="initialLoading" class="hard-list">
      <div v-for="n in 6" :key="n" class="hard-row skeleton-hard"></div>
    </div>
    <div v-else-if="!rows.length" class="empty">暂无硬骨头记录</div>
    <div v-else class="hard-list">
      <div v-for="row in rows" :key="row.id" class="hard-row pin-row"
           :class="{ pinned: row.is_top }"
           role="button" tabindex="0" @click="openTask(row)" @keyup.enter="openTask(row)">
        <span v-if="row.is_top" class="pin-mark" title="已置顶">★</span>
        <input v-if="writable" type="checkbox" class="row-check"
               :checked="selected.has(row.id)"
               @click.stop @change="toggleRowChecked(row, $event.target.checked)" />
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
        <button v-if="writable" class="ir-top" type="button"
                :class="{ on: row.is_top }"
                :disabled="toggling.has(row.id)"
                :title="row.is_top ? '取消置顶' : '置顶'"
                @click.stop="toggleTop(row)">
          {{ toggling.has(row.id) ? "…" : (row.is_top ? "取消置顶" : "置顶") }}
        </button>
      </div>
    </div>

    <div v-if="!initialLoading && total > pageSize" class="hard-pager">
      <button type="button" @click="prevPage" :disabled="page <= 0 || refreshing">上一页</button>
      <span>第 {{ page + 1 }} 页 · {{ page * pageSize + 1 }}-{{ page * pageSize + rows.length }} / {{ total }}</span>
      <button type="button" @click="nextPage" :disabled="!hasMore || refreshing">下一页</button>
    </div>

    <div v-if="toastMsg" class="toast">{{ toastMsg }}</div>
  </section>
</template>
