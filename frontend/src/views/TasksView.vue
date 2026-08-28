<script setup>
import { ref, onActivated, onDeactivated, onMounted, onUnmounted, computed, watch } from "vue";
import { useRouter } from "vue-router";
import { api, authReadyRef, authRequiredRef, authRoleRef, loadAuthRole, verifyToken } from "../api.js";
import TaskEditModal from "../components/TaskEditModal.vue";

defineOptions({ name: "TasksView" });

const tasks = ref([]);
const initialLoading = ref(true);
const refreshing = ref(false);
const editOpen = ref(false);
const editingTask = ref(null);
const writable = computed(() => authRoleRef.value === "full");
const router = useRouter();

// ===== 任务置顶：选中态 / 操作中态 / 批量栏 =====
const selected = ref(new Set());       // 勾选的任务 id
const toggling = ref(new Set());       // 正在置顶/取消置顶中的任务 id（按钮禁用）
const pageIds = computed(() => tasks.value.map((t) => t.id));
const allChecked = computed(() =>
  pageIds.value.length > 0 && pageIds.value.every((id) => selected.value.has(id))
);
const someChecked = computed(() => pageIds.value.some((id) => selected.value.has(id)));

function toast(msg, ms = 2400) {
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = msg;
  document.body.appendChild(el);
  requestAnimationFrame(() => el.classList.add("show"));
  setTimeout(() => {
    el.classList.remove("show");
    setTimeout(() => el.remove(), 260);
  }, ms);
}
function toggleRowChecked(id, checked) {
  const s = new Set(selected.value);
  if (checked) s.add(id); else s.delete(id);
  selected.value = s;   // 整体重新赋值触发响应式
}
function toggleAllChecked(checked) {
  selected.value = checked ? new Set(pageIds.value) : new Set();
}
// 单条置顶：按 id 在当前列表就地更新，无刷新。
// 注意：不能直接改传入的 t —— 任务列表有 5s 轮询，await 期间 t 可能已换成旧引用，
// 改它不会反映到渲染中的新对象；用 find 拿到当前列表里的同 id 对象再改。
async function toggleTop(t) {
  if (toggling.value.has(t.id)) return;
  const next = !t.is_top;
  toggling.value = new Set(toggling.value).add(t.id);
  try {
    await api.taskTop(t.id, next);
    const cur = tasks.value.find((x) => x.id === t.id);
    if (cur) cur.is_top = next;
    toast(next ? "已置顶" : "已取消置顶");
  } catch (e) {
    alert(`置顶失败：${e?.message || e}`);
  } finally {
    const s = new Set(toggling.value);
    s.delete(t.id);
    toggling.value = s;
  }
}
// 批量置顶：确认弹窗显示选中数量，成功后清空选择
async function batchTop(isTop) {
  const ids = [...selected.value];
  if (!ids.length) return;
  if (!confirm(`确认${isTop ? "置顶" : "取消置顶"}选中的 ${ids.length} 个任务？`)) return;
  try {
    const res = await api.taskBatchTop(ids, isTop);
    const ok = res?.success_count ?? 0;
    const fail = res?.failed_ids ?? [];
    const idSet = new Set(ids);
    tasks.value.forEach((t) => { if (idSet.has(t.id)) t.is_top = isTop; });
    toast(`成功${isTop ? "置顶" : "取消置顶"} ${ok} 个任务${fail.length ? `，${fail.length} 个失败` : ""}`);
    selected.value = new Set();
  } catch (e) {
    alert(`批量操作失败：${e?.message || e}`);
  }
}
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
onActivated(() => {
  if (tasks.value.length) load({ background: true });
  syncPoller();
});
onDeactivated(() => {
  clearInterval(pollTimer);
  pollTimer = null;
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
    <header class="page-head">
      <div>
        <h2>任务列表</h2>
        <p class="page-sub">点击进入指挥台，查看实时看板与复审队列</p>
      </div>
      <div class="head-actions">
        <router-link v-if="authRoleRef !== 'observer'" class="head-action vuln-entry" to="/vulns">
          全局漏洞库
        </router-link>
        <router-link class="head-action" to="/hard-targets">全局硬骨头库</router-link>
        <router-link v-if="authRoleRef !== 'observer'" class="head-action intel-entry" to="/intel">
          <span class="ie-dot" aria-hidden="true"></span>全局情报库
        </router-link>
        <router-link v-if="authRoleRef !== 'observer'" class="head-action" to="/runtime-logs">
          运行异常
        </router-link>
      </div>
    </header>
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
      <div v-if="writable" class="pin-batch-bar">
        <label class="pin-sel-all">
          <input type="checkbox" :checked="allChecked"
                 :indeterminate.prop="someChecked && !allChecked"
                 @change="toggleAllChecked($event.target.checked)" />
          全选本页
        </label>
        <span class="pin-sel-count">已选 {{ selected.size }} 个</span>
        <button class="btn-pin" type="button" :disabled="!someChecked" @click="batchTop(true)">批量置顶</button>
        <button class="btn-ghost" type="button" :disabled="!someChecked" @click="batchTop(false)">批量取消置顶</button>
      </div>
      <div v-for="t in tasks" :key="t.id" class="task-card"
        :class="{ live: t.status === 'running', pinned: t.is_top }"
        @click="router.push(`/task/${t.id}`)">
        <div class="task-card-main">
          <div class="tc-title">
            <input v-if="writable" class="row-check" type="checkbox" :checked="selected.has(t.id)"
                   @click.stop @change="toggleRowChecked(t.id, $event.target.checked)" />
            <span v-if="t.is_top" class="pin-mark" aria-hidden="true">★</span>
            <span v-if="t.status === 'running'" class="pulse"></span>
            <b>{{ t.name }}</b>
          </div>
          <span v-if="t.pending_user_review > 0" class="review-dot"
                :title="`${t.pending_user_review} 个漏洞待复审`">{{ t.pending_user_review }}</span>
          <div class="task-card-meta">
            <span class="badge" :class="t.status">{{ STATUS_LABEL[t.status] || t.status }}</span>
            <span class="meta">{{ taskModeLabel(t) }} · {{ targetSourceLabel(t) }} · 并发 {{ t.concurrency }} · 深挖 ×{{ t.deepen_cap ?? 2 }}</span>
          </div>
          <div class="meta task-query">{{ taskScopeText(t) }}</div>
        </div>
        <div class="task-card-side">
          <time class="meta task-time">{{ t.created_at.slice(0, 19).replace("T", " ") }}</time>
          <div v-if="writable" class="task-actions">
            <button class="mini-action pin" type="button" :class="{ on: t.is_top }"
                    :disabled="toggling.has(t.id)" @click.stop="toggleTop(t)">
              {{ toggling.has(t.id) ? "…" : (t.is_top ? "取消置顶" : "置顶") }}
            </button>
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
  </section>
</template>
