<script setup>
import { ref, onMounted, onUnmounted, computed, watch } from "vue";
import { useRouter } from "vue-router";
import { api, authReadyRef, authRequiredRef, authRoleRef, loadAuthRole, verifyToken } from "../api.js";
import TaskEditModal from "../components/TaskEditModal.vue";

const tasks = ref([]);
const initialLoading = ref(true);
const refreshing = ref(false);
const editOpen = ref(false);
const editingTask = ref(null);
const writable = computed(() => authRoleRef.value === "full");
const router = useRouter();
let pollTimer = null;

const STATUS_LABEL = {
  running: "运行中",
  idle: "空闲",
  paused: "已暂停",
  stopped: "已停止",
  created: "未启动",
};
function taskModeLabel(t) {
  return t?.src_type === "enterprise" ? "企业SRC" : "EduSRC";
}
function engineLabel(engine) {
  return {
    fofa: "FOFA",
    quake: "360 Quake",
    hunter: "Hunter",
    zoomeye: "ZoomEye",
    shodan: "Shodan",
    censys: "Censys",
  }[engine] || engine || "";
}
function targetSourceLabel(t) {
  const source = t?.target_source;
  const eng = engineLabel(t?.engine);
  if (source === "manual") return "手动清单";
  if (source === "site") return "单站协作";
  if (source === "both") return eng ? `${eng}+手动` : "测绘+手动";
  if (source === "fofa") return eng || "测绘搜集";
  return source || "-";
}
function taskScopeText(t) {
  if (t?.target_source === "site") {
    return t.fofa_query || t.manual_targets?.[0] || "单站协作";
  }
  return t?.fofa_query || "手动清单";
}

const hasRunning = computed(() => tasks.value.some((t) => t.status === "running"));
const runningCount = computed(() => tasks.value.filter((t) => t.status === "running").length);

function openSearch() {
  window.dispatchEvent(new CustomEvent("autohunter-open-search"));
}

function syncPoller() {
  clearInterval(pollTimer);
  pollTimer = null;
  // 有运行中任务时加快刷新；否则慢轮询，仍能感知远端状态变化。
  const ms = hasRunning.value ? 5000 : 15000;
  pollTimer = setInterval(() => load({ background: true }), ms);
}

async function load(opts = {}) {
  const background = !!opts.background;
  if (!tasks.value.length) initialLoading.value = true;
  else if (!background) refreshing.value = true;
  try { tasks.value = await api.listTasks(); }
  finally {
    initialLoading.value = false;
    refreshing.value = false;
    syncPoller();
  }
}
async function openEdit(task) {
  try {
    editingTask.value = await api.getTask(task.id);
    editOpen.value = true;
  } catch (e) {
    // 用可见的 alert 反馈；delError 只在删除确认弹窗内渲染，编辑失败时不可见。
    alert(`加载任务失败：${e?.message || e}`);
  }
}
// ===== 删除任务：二次确认 + 输入 full 令牌校验 =====
const delTarget = ref(null);       // 待删除的任务对象（弹窗打开时非空）
const delToken = ref("");          // 用户输入的 full 令牌
const delError = ref("");
const deleting = ref(false);

function askDelete(task) {
  delTarget.value = task;
  delToken.value = "";
  delError.value = "";
}
function cancelDelete() {
  if (deleting.value) return;
  delTarget.value = null;
  delToken.value = "";
  delError.value = "";
}
async function confirmDelete() {
  if (!delTarget.value || deleting.value) return;
  const task = delTarget.value;
  // 仅当服务端开启鉴权时，才要求再次输入 full 令牌做二次校验。
  if (authRequiredRef.value) {
    if (!delToken.value.trim()) {
      delError.value = "请输入 full 权限令牌以确认删除";
      return;
    }
    deleting.value = true;
    delError.value = "";
    const role = await verifyToken(delToken.value);
    if (role !== "full") {
      deleting.value = false;
      delError.value = role === "none" ? "令牌无效" : "该令牌不是 full 权限，无法删除";
      return;
    }
  } else {
    deleting.value = true;
  }
  try {
    await api.deleteTask(task.id, delToken.value);
    tasks.value = tasks.value.filter((t) => t.id !== task.id);
    delTarget.value = null;
    delToken.value = "";
  } catch (e) {
    delError.value = `删除失败：${e.message || e}`;
  } finally {
    deleting.value = false;
  }
}
function closeEdit() {
  editOpen.value = false;
  editingTask.value = null;
}
function onSaved() {
  closeEdit();
  load();
}
onMounted(async () => {
  if (!authReadyRef.value) await loadAuthRole();
  await load();
});
onUnmounted(() => {
  clearInterval(pollTimer);
  pollTimer = null;
});
watch(authReadyRef, (ready) => {
  if (ready) load();
});
watch(hasRunning, () => syncPoller());
</script>

<template>
  <section class="view tasks-view" :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !initialLoading" class="view-progress" aria-hidden="true"><i></i></div>

    <!-- ══ HERO：居中搜索入口 ══ -->
    <div class="tasks-hero">
      <div class="tasks-hero-brand">
        <span class="tasks-hero-logo" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <circle cx="12" cy="12" r="4"/>
            <line x1="12" y1="2" x2="12" y2="6"/>
            <line x1="12" y1="18" x2="12" y2="22"/>
            <line x1="2" y1="12" x2="6" y2="12"/>
            <line x1="18" y1="12" x2="22" y2="12"/>
          </svg>
        </span>
        <h1 class="tasks-hero-title">AutoHunter</h1>
        <p class="tasks-hero-sub">SRC · 24×7 全自动漏洞挖掘平台</p>
      </div>

      <!-- 大型居中搜索栏 -->
      <button type="button" class="tasks-search-bar" @click="openSearch" aria-label="打开搜索">
        <svg class="tasks-search-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
        </svg>
        <span class="tasks-search-placeholder">搜索任务、命令、漏洞…</span>
        <kbd class="tasks-search-kbd">⌘ K</kbd>
      </button>

      <!-- 实时统计小药丸 -->
      <div class="tasks-hero-stats" v-if="!initialLoading">
        <span v-if="runningCount > 0" class="stat-pill stat-pill-running">
          <span class="stat-live-dot" aria-hidden="true"></span>
          <b>{{ runningCount }}</b> 运行中
        </span>
        <span class="stat-pill">
          共 <b>{{ tasks.length }}</b> 个任务
        </span>
      </div>

      <!-- 快捷操作 -->
      <div class="tasks-hero-actions">
        <router-link v-if="authRoleRef === 'full'" class="hero-btn-primary" to="/create">
          <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M8 2v12M2 8h12"/></svg>
          新建任务
        </router-link>
        <router-link class="hero-btn-ghost" to="/analytics">分析仪表盘</router-link>
        <router-link v-if="authRoleRef !== 'observer'" class="hero-btn-ghost" to="/vulns">漏洞库</router-link>
        <router-link class="hero-btn-ghost" to="/hard-targets">硬骨头</router-link>
        <router-link v-if="authRoleRef !== 'observer'" class="hero-btn-ghost" to="/intel">情报库</router-link>
      </div>
    </div>

    <!-- ══ 任务列表区段 ══ -->
    <div class="tasks-list-section">
      <div v-if="tasks.length || !initialLoading" class="tasks-list-head">
        <span class="tasks-list-label">最近任务</span>
        <span v-if="tasks.length" class="tasks-list-count">{{ tasks.length }} 个</span>
      </div>
      <div v-if="initialLoading" class="task-list">
      <div v-for="n in 4" :key="n" class="task-card skeleton-task" aria-hidden="true">
        <div class="task-card-main">
          <div class="tc-title"><span class="sk-bar sk-title"></span></div>
          <div class="task-card-meta">
            <span class="sk-bar sk-badge"></span>
            <span class="sk-bar sk-meta"></span>
          </div>
          <div class="task-query sk-query-wrap">
            <span class="sk-bar sk-query"></span>
            <span class="sk-bar sk-query short"></span>
          </div>
        </div>
        <div class="task-card-side">
          <span class="sk-bar sk-time"></span>
          <div class="task-actions">
            <span class="sk-bar sk-action"></span>
            <span class="sk-bar sk-action"></span>
          </div>
        </div>
      </div>
    </div>
    <div v-else-if="!tasks.length" class="empty">
      还没有任务
      <span class="hint">点顶栏「新建」创建第一个挖掘任务</span>
    </div>
    <div v-else class="task-list">
      <div v-for="t in tasks" :key="t.id" class="task-card" :class="{ live: t.status === 'running' }"
        @click="router.push(`/task/${t.id}`)">
        <div class="task-card-main">
          <div class="tc-title">
            <span v-if="t.status === 'running'" class="pulse"></span>
            <b>{{ t.name }}</b>
          </div>
          <span v-if="t.pending_user_review > 0" class="review-dot"
                :title="`${t.pending_user_review} 个漏洞待复审`">{{ t.pending_user_review }}</span>
          <div class="task-card-meta">
            <span class="badge" :class="t.status">{{ STATUS_LABEL[t.status] || t.status }}</span>
            <span class="meta">{{ taskModeLabel(t) }} · {{ targetSourceLabel(t) }} · 并发 {{ t.concurrency }}</span>
          </div>
          <div class="meta task-query">{{ taskScopeText(t) }}</div>
        </div>
        <div class="task-card-side">
          <time class="meta task-time">{{ t.created_at.slice(0, 19).replace("T", " ") }}</time>
          <div v-if="writable" class="task-actions">
            <button class="mini-action" type="button" @click.stop="openEdit(t)">编辑参数</button>
            <button class="mini-action danger" type="button" @click.stop="askDelete(t)">删除</button>
          </div>
          <span class="task-chevron" aria-hidden="true">›</span>
        </div>
      </div>
    </div>
    <TaskEditModal :open="editOpen" :task="editingTask" @close="closeEdit" @saved="onSaved" />

    <div v-if="delTarget" class="modal-mask" @click.self="cancelDelete">
      <div class="modal-card del-modal" role="dialog" aria-modal="true">
        <h3 class="del-title">删除任务</h3>
        <p class="del-desc">
          即将删除任务 <b>「{{ delTarget.name }}」</b>。
        </p>
        <p class="del-warn">
          此操作会一并删除该任务的<b>全部目标、漏洞、审核与通杀记录</b>，且<b>不可恢复</b>。
          （全局情报库不受影响）
        </p>
        <label v-if="authRequiredRef" class="del-field">
          <span>请输入 <b>full 权限令牌</b>以确认</span>
          <input v-model="delToken" type="password" autocomplete="off"
            placeholder="full 访问令牌" @keyup.enter="confirmDelete" />
        </label>
        <p v-if="delError" class="del-error">{{ delError }}</p>
        <div class="del-actions">
          <button class="mini-action" type="button" :disabled="deleting" @click="cancelDelete">取消</button>
          <button class="mini-action danger" type="button" :disabled="deleting" @click="confirmDelete">
            {{ deleting ? "删除中…" : "确认删除" }}
          </button>
        </div>
      </div>
    </div>
    </div>
  </section>
</template>