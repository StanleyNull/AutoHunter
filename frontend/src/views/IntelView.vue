<script setup>
import { computed, onMounted, ref, watch } from "vue";
import { api, canWrite } from "../api.js";

const stats = ref({ total: 0, by_kind: {}, verified: 0, reused: 0 });
const rows = ref([]);
const initialLoading = ref(true);
const refreshing = ref(false);
const kind = ref("all");
const confidence = ref("all");
const searchDraft = ref("");
const searchText = ref("");
const curator = ref(null);
const curatorLoading = ref(false);
const curatorApplying = ref(false);
let searchTimer = null;
const writable = computed(() => canWrite());

const KIND_META = {
  cred: { label: "凭证", icon: "🔑", hue: "danger" },
  fingerprint: { label: "打法", icon: "🎯", hue: "info" },
  endpoint: { label: "端点", icon: "🧭", hue: "warn" },
  profile: { label: "画像", icon: "🪪", hue: "ok" },
};

const KIND_TABS = [
  { id: "all", label: "全部" },
  { id: "cred", label: "凭证" },
  { id: "fingerprint", label: "打法" },
  { id: "endpoint", label: "端点" },
  { id: "profile", label: "画像" },
];

async function loadStats() {
  try { stats.value = await api.intelStats(); } catch { /* keep */ }
}

async function loadList() {
  if (!rows.value.length) initialLoading.value = true;
  else refreshing.value = true;
  try {
    rows.value = await api.intelList(kind.value, confidence.value, searchText.value, 800);
  } finally {
    initialLoading.value = false;
    refreshing.value = false;
  }
}

async function reload() {
  await Promise.all([loadStats(), loadList(), previewCurator()]);
}

function fmtTime(iso) {
  if (!iso) return "-";
  return iso.slice(0, 19).replace("T", " ");
}

function primaryText(row) {
  const p = row.payload || {};
  if (row.kind === "cred") return `${p.username || "?"} : ${p.password || "?"}`;
  if (row.kind === "endpoint") return p.path || row.summary || "-";
  if (row.kind === "fingerprint") return p.tactic || row.summary || "-";
  if (row.kind === "profile") return `${p.key || ""}：${p.value || ""}`;
  return row.summary || "-";
}

function secondaryText(row) {
  const p = row.payload || {};
  if (row.kind === "endpoint" && p.vuln_type) return p.vuln_type;
  if (row.kind === "fingerprint" && p.vuln_type) return p.vuln_type;
  return row.summary || "";
}

async function removeOne(row) {
  if (!writable.value) return;
  if (!confirm(`确认删除这条情报？\n${row.match_key} · ${primaryText(row)}`)) return;
  await api.deleteIntel(row.id);
  await reload();
}

async function clearKind() {
  if (!writable.value) return;
  const label = kind.value === "all" ? "全部" : (KIND_META[kind.value]?.label || kind.value);
  if (!confirm(`确认清空【${label}】情报？此操作不可恢复。`)) return;
  await api.clearIntel(kind.value);
  await reload();
}

async function previewCurator() {
  curatorLoading.value = true;
  try {
    curator.value = await api.previewIntelCurate(1000);
  } catch {
    curator.value = null;
  } finally {
    curatorLoading.value = false;
  }
}

async function applyCurator() {
  if (!writable.value) return;
  const flagged = curator.value?.flagged || 0;
  if (!flagged) return;
  if (!confirm(`Intel Curator 发现 ${flagged} 条低价值候选。\n将只清理未验证且未复用的明显垃圾，确认执行？`)) return;
  curatorApplying.value = true;
  try {
    const res = await api.applyIntelCurate(1000);
    const kept = res?.kept_hot || 0;
    alert(`已清理 ${res?.deleted || 0} 条垃圾情报` + (kept ? `，保留 ${kept} 条高频复用项（hit≥3）需人工确认` : ""));
    curator.value = res;
    await reload();
  } finally {
    curatorApplying.value = false;
  }
}

watch([kind, confidence], reload);
watch(searchDraft, (v) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    searchText.value = v.trim();
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
        <h2>全局情报库 <span class="intel-chip">INTEL</span></h2>
        <p class="page-sub">跨任务沉淀的可复用作战情报——凭证 / 打法 / 端点 / 画像，由 worker 自动回写并复用。</p>
      </div>
      <router-link class="head-action" to="/">返回任务</router-link>
    </header>

    <!-- 高级总览仪表 -->
    <div class="intel-dash">
      <div class="dash-card hero">
        <span class="dash-k">情报总量</span>
        <b class="dash-v">{{ stats.total }}</b>
        <span class="dash-sub">已验证 {{ stats.verified }} · 被复用 {{ stats.reused }}</span>
      </div>
      <div v-for="k in ['cred','fingerprint','endpoint','profile']" :key="k"
           class="dash-card" :class="KIND_META[k].hue"
           :data-active="kind === k"
           @click="kind = (kind === k ? 'all' : k)">
        <span class="dash-icon">{{ KIND_META[k].icon }}</span>
        <b class="dash-v">{{ stats.by_kind[k] || 0 }}</b>
        <span class="dash-k">{{ KIND_META[k].label }}</span>
      </div>
    </div>

    <!-- 工具条 -->
    <div class="intel-toolbar">
      <div class="kind-tabs">
        <button v-for="t in KIND_TABS" :key="t.id" type="button"
                class="kind-tab" :class="{ on: kind === t.id }" @click="kind = t.id">
          {{ t.label }}
        </button>
      </div>
      <div class="search-box">
        <span>⌕</span>
        <input v-model="searchDraft" placeholder="搜索 域名 / 账号 / 路径 / 来源 / 内容" />
      </div>
      <select v-model="confidence">
        <option value="all">全部可信度</option>
        <option value="verified">仅已验证</option>
        <option value="likely">仅疑似</option>
      </select>
      <button class="btn-ghost" @click="reload" :disabled="refreshing">{{ refreshing ? "刷新中…" : "刷新" }}</button>
      <button v-if="writable" class="btn-danger" @click="clearKind">清空当前类</button>
    </div>

    <div class="curator-card">
      <div>
        <b>Intel Curator</b>
        <span>
          {{ curatorLoading ? "维护检查中…" : `候选垃圾 ${curator?.flagged || 0} 条，已检查 ${curator?.examined || 0} 条` }}
        </span>
      </div>
      <div class="curator-actions">
        <button class="btn-ghost" @click="previewCurator" :disabled="curatorLoading">重新检查</button>
        <button v-if="writable" class="btn-danger" @click="applyCurator" :disabled="curatorApplying || !(curator?.flagged)">
          {{ curatorApplying ? "清理中…" : "维护清理" }}
        </button>
      </div>
      <small v-if="curator?.items?.length" class="curator-reason">
        示例：{{ curator.items[0].kind }} · {{ curator.items[0].match_key }} · {{ curator.items[0].reasons?.join("、") }}
      </small>
    </div>

    <!-- 数据网格 -->
    <div v-if="initialLoading" class="intel-grid">
      <div v-for="n in 8" :key="n" class="intel-row skeleton-hard"></div>
    </div>
    <div v-else-if="!rows.length" class="empty">
      情报库暂无记录
      <span class="hint">worker 出洞 / 撞库成功后会自动沉淀，越挖越聪明</span>
    </div>
    <div v-else class="intel-grid">
      <article v-for="row in rows" :key="row.id" class="intel-row" :class="KIND_META[row.kind]?.hue">
        <span class="ir-kind" :class="KIND_META[row.kind]?.hue">
          <i>{{ KIND_META[row.kind]?.icon }}</i>{{ KIND_META[row.kind]?.label || row.kind }}
        </span>
        <div class="ir-main">
          <b class="ir-primary">{{ primaryText(row) }}</b>
          <small class="ir-secondary" v-if="secondaryText(row)">{{ secondaryText(row) }}</small>
          <span class="ir-key">作用域：{{ row.match_key }}</span>
        </div>
        <div class="ir-side">
          <span class="ir-conf" :class="row.confidence">
            {{ row.confidence === 'verified' ? '✓ 已验证' : '· 疑似' }}
          </span>
          <span class="ir-hit" v-if="row.hit_count > 1" title="被复用次数">×{{ row.hit_count }} 复用</span>
          <small class="ir-src">{{ row.source_host || '未知来源' }}</small>
          <time>{{ fmtTime(row.last_seen) }}</time>
        </div>
        <button v-if="writable" class="ir-del" type="button" title="删除" @click="removeOne(row)">✕</button>
      </article>
    </div>
  </section>
</template>
