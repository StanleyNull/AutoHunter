<script setup>
import { computed, onActivated, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { api, canWrite } from "../api.js";

defineOptions({ name: "HardTargetsView" });

const router = useRouter();
const rows = ref([]);
const initialLoading = ref(true);
const loaded = ref(false);      // 已加载过一次后，空列表不再反复显示骨架屏
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

// 删除（#61）：二次确认弹窗，确认前只展示将要删除的目标，不会真的动手。
const deleting = ref(new Set());
const batchDeleting = ref(false);
const confirmDelete = ref(null);   // { ids: string[], label: string }
// 深挖（#62）：带指令回炉，指令为空不给提交。
const deepenRow = ref(null);
const deepenDraft = ref("");
const deepening = ref(false);

function toast(m, ms = 2400) {
  toastMsg.value = m;
  setTimeout(() => { if (toastMsg.value === m) toastMsg.value = ""; }, ms);
}

const STATUS_LABEL = {
  dead: "硬骨头",
  skipped: "已跳过",
  stalled: "停摆待重试",
};

const selectedCount = computed(() => selected.value.size);
const pageIds = computed(() => rows.value.map((r) => r.id));
const allChecked = computed(() =>
  pageIds.value.length > 0 && pageIds.value.every((id) => selected.value.has(id)));
const someChecked = computed(() =>
  pageIds.value.some((id) => selected.value.has(id)));

async function load() {
  if (!loaded.value) initialLoading.value = true;
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
    loaded.value = true;
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

// ===== 删除（#61）=====
// 删除是物理删除、不可撤销，所以统一走弹窗二次确认，并在弹窗里写清后果。
function askDelete(row) {
  if (!writable.value || deleting.value.has(row.id)) return;
  confirmDelete.value = { ids: [row.id], label: row.host || row.url || row.id };
}

function askBatchDelete() {
  if (!writable.value || !selectedCount.value) return;
  confirmDelete.value = { ids: Array.from(selected.value), label: `${selectedCount.value} 条资产` };
}

async function doDelete() {
  const payload = confirmDelete.value;
  if (!payload || !payload.ids.length) return;
  const single = payload.ids.length === 1;
  if (!single) batchDeleting.value = true;
  else deleting.value = new Set(deleting.value).add(payload.ids[0]);
  try {
    if (single) {
      await api.assetDelete(payload.ids[0]);
      rows.value = rows.value.filter((r) => r.id !== payload.ids[0]);
      total.value = Math.max(0, total.value - 1);
      toast("已删除 1 条");
    } else {
      const res = await api.assetBatchDelete(payload.ids);
      const ok = res?.success_count ?? 0;
      const failed = res?.failed || [];
      const okSet = new Set(payload.ids.filter((id) => !failed.some((f) => f.id === id)));
      rows.value = rows.value.filter((r) => !okSet.has(r.id));
      total.value = Math.max(0, total.value - okSet.size);
      if (failed.length) {
        const first = failed[0]?.reason || "该目标当前不允许删除";
        alert(`成功删除 ${ok} 条，${failed.length} 条未删除（${first}）`);
      } else {
        toast(`成功删除 ${ok} 条`);
      }
    }
    confirmDelete.value = null;
    await load();
  } catch (e) {
    alert(`删除失败：${e?.message || e}`);
  } finally {
    batchDeleting.value = false;
    const s = new Set(deleting.value);
    payload.ids.forEach((id) => s.delete(id));
    deleting.value = s;
  }
}

// ===== 深挖回炉（#62）=====
function openDeepen(row) {
  if (!writable.value) return;
  deepenRow.value = row;
  deepenDraft.value = "";
}

async function submitDeepen() {
  const row = deepenRow.value;
  const directive = deepenDraft.value.trim();
  if (!row || !directive || deepening.value) return;
  deepening.value = true;
  try {
    const res = await api.assetDeepen(row.id, directive);
    deepenRow.value = null;
    deepenDraft.value = "";
    toast(res?.message || `已回炉重挖（第 ${res?.deepen_count ?? "?"} 次深挖）`);
    await load();
  } catch (e) {
    alert(`深挖失败：${e?.message || e}`);
  } finally {
    deepening.value = false;
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
      <button class="btn-danger" type="button" @click="askBatchDelete"
              :disabled="!selectedCount || batchDeleting">
        {{ batchDeleting ? "删除中…" : "批量删除" }}
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
        <span v-if="writable" class="hard-actions" @click.stop>
          <button class="ir-act" type="button" :disabled="deepening"
                  title="带定向指令把该目标重新塞回挖掘队列"
                  @click="openDeepen(row)">深挖</button>
          <button class="ir-top" type="button"
                  :class="{ on: row.is_top }"
                  :disabled="toggling.has(row.id)"
                  :title="row.is_top ? '取消置顶' : '置顶'"
                  @click="toggleTop(row)">
            {{ toggling.has(row.id) ? "…" : (row.is_top ? "取消置顶" : "置顶") }}
          </button>
          <button class="ir-del" type="button" :disabled="deleting.has(row.id)"
                  title="从硬骨头库彻底删除该目标记录"
                  @click="askDelete(row)">
            {{ deleting.has(row.id) ? "…" : "删除" }}
          </button>
        </span>
      </div>
    </div>

    <div v-if="!initialLoading && total > pageSize" class="hard-pager">
      <button type="button" @click="prevPage" :disabled="page <= 0 || refreshing">上一页</button>
      <span>第 {{ page + 1 }} 页 · {{ page * pageSize + 1 }}-{{ page * pageSize + rows.length }} / {{ total }}</span>
      <button type="button" @click="nextPage" :disabled="!hasMore || refreshing">下一页</button>
    </div>

    <!-- 删除二次确认：把「删的是什么 / 后果是什么」写清楚，避免误删（#61） -->
    <div v-if="confirmDelete" class="hard-modal-mask" @click.self="confirmDelete = null">
      <div class="hard-modal">
        <h3>确认删除？</h3>
        <p class="modal-line">即将从硬骨头库删除 <b>{{ confirmDelete.label }}</b>（共 {{ confirmDelete.ids.length }} 条）。</p>
        <p class="modal-warn">删除是物理删除、不可撤销：目标记录会从库里移除，之后不会再出现在硬骨头库里。</p>
        <p class="modal-note">已挖到的漏洞不会被删——若该目标还挂着有效漏洞，后端会拒绝删除并提示你先去漏洞库处理。</p>
        <div class="modal-actions">
          <button class="btn-ghost" type="button" :disabled="batchDeleting" @click="confirmDelete = null">取消</button>
          <button class="btn-danger" type="button" :disabled="batchDeleting" @click="doDelete">
            {{ batchDeleting ? "删除中…" : "确认删除" }}
          </button>
        </div>
      </div>
    </div>

    <!-- 深挖回炉：必须写清这一轮要去打穿什么（#62） -->
    <div v-if="deepenRow" class="hard-modal-mask" @click.self="deepenRow = null">
      <div class="hard-modal">
        <h3>打回深挖回炉</h3>
        <p class="modal-line">目标：<b>{{ deepenRow.host || deepenRow.url }}</b></p>
        <p class="modal-note">
          上次结论：{{ reasonOf(deepenRow) }}。该目标会带着你的指令重新入队并插到队首，
          占用一次该任务的深挖次数。
        </p>
        <label class="modal-field">
          <span>深挖指令（告诉 worker 这一轮去把什么打穿）</span>
          <textarea v-model="deepenDraft" rows="3"
                    placeholder="例如：重点打后台 /uploads 目录的上传点，先拿一个可写 shell 再提权"></textarea>
        </label>
        <div class="modal-actions">
          <button class="btn-ghost" type="button" :disabled="deepening" @click="deepenRow = null">取消</button>
          <button class="btn-pin" type="button" :disabled="!deepenDraft.trim() || deepening" @click="submitDeepen">
            {{ deepening ? "提交中…" : "确认回炉" }}
          </button>
        </div>
      </div>
    </div>

    <div v-if="toastMsg" class="toast">{{ toastMsg }}</div>
  </section>
</template>
