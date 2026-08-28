<script setup>
import { computed, onActivated, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { api, canWrite } from "../api.js";
import { fmtLocalTime } from "../format.js";

defineOptions({ name: "VulnsView" });

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

// 置顶功能：仅 full 令牌可写；selected 为本页已勾选的漏洞 id 集合。
const writable = computed(() => canWrite());
const selected = ref(new Set());
const toggling = ref(new Set());    // 单条置顶进行中的 id（按钮 loading）
const batchToggling = ref(false);  // 批量置顶进行中
const toastMsg = ref("");

function toast(m, ms = 2400) {
  toastMsg.value = m;
  setTimeout(() => { if (toastMsg.value === m) toastMsg.value = ""; }, ms);
}

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
const selectedCount = computed(() => selected.value.size);
const pageIds = computed(() => rows.value.map((r) => r.id));
const allChecked = computed(() =>
  pageIds.value.length > 0 && pageIds.value.every((id) => selected.value.has(id)));
const someChecked = computed(() =>
  pageIds.value.some((id) => selected.value.has(id)));

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
    // 翻页/重载后清空勾选：跨页勾选意义不大且易误操作。
    selected.value = new Set();
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

function openVuln(row) {
  router.push(`/task/${row.task_id}`);
}

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
  if (!writable.value) return;
  if (toggling.value.has(row.id)) return;
  const next = !row.is_top;
  toggling.value = new Set(toggling.value).add(row.id);
  try {
    await api.vulnTop(row.id, next);
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
  if (!confirm(`确认${verb}选中的 ${ids.length} 条漏洞？`)) return;
  batchToggling.value = true;
  try {
    const res = await api.vulnBatchTop(ids, isTop);
    const ok = res?.success_count ?? 0;
    const failed = res?.failed_ids || [];
    // 同步本页勾选项的 is_top 状态
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
onActivated(() => {
  if (rows.value.length) reload();
});
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

    <div v-if="initialLoading" class="intel-grid">
      <div v-for="n in 8" :key="n" class="intel-row skeleton-hard"></div>
    </div>
    <div v-else-if="!rows.length" class="empty">
      漏洞库暂无记录
      <span class="hint">人工审核通过的漏洞会自动汇总到这里</span>
    </div>
    <div v-else class="intel-grid">
      <article v-for="row in rows" :key="row.id" class="intel-row pin-row"
               :class="[sevMeta(row.effective_severity).hue, { pinned: row.is_top }]"
               role="button" tabindex="0" @click="openVuln(row)" @keyup.enter="openVuln(row)">
        <span v-if="row.is_top" class="pin-mark" title="已置顶">★</span>
        <input v-if="writable" type="checkbox" class="row-check"
               :checked="selected.has(row.id)"
               @click.stop @change="toggleRowChecked(row, $event.target.checked)" />
        <span class="ir-kind" :class="sevMeta(row.effective_severity).hue">
          <i>⚑</i>{{ sevMeta(row.effective_severity).label }}
        </span>
        <div class="ir-main">
          <b class="ir-primary">{{ row.title }}</b>
          <small class="ir-secondary">{{ row.vuln_type }} · {{ row.target_url }}<template v-if="row.llm_model"> · {{ row.llm_model }}</template></small>
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
          <time>{{ fmtLocalTime(row.user_reviewed_at || row.created_at) }}</time>
        </div>
        <button v-if="writable" class="ir-top" type="button"
                :class="{ on: row.is_top }"
                :disabled="toggling.has(row.id)"
                :title="row.is_top ? '取消置顶' : '置顶'"
                @click.stop="toggleTop(row)">
          {{ toggling.has(row.id) ? "…" : (row.is_top ? "取消置顶" : "置顶") }}
        </button>
      </article>
    </div>

    <div v-if="!initialLoading && total > pageSize" class="hard-pager">
      <button type="button" @click="prevPage" :disabled="page <= 0 || refreshing">上一页</button>
      <span>第 {{ page + 1 }} 页 · {{ page * pageSize + 1 }}-{{ page * pageSize + rows.length }} / {{ total }}</span>
      <button type="button" @click="nextPage" :disabled="!hasMore || refreshing">下一页</button>
    </div>

    <div v-if="toastMsg" class="toast">{{ toastMsg }}</div>
  </section>
</template>
