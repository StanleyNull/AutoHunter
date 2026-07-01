<script setup>
import { ref, onMounted, computed, watch } from "vue";
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
function targetSourceLabel(source) {
  return {
    fofa: "FOFA",
    manual: "手动清单",
    both: "FOFA+手动",
    site: "单站协作",
}[source] || source || "-";
}
function taskScopeText(t) {
  if (t?.target_source === "site") {
    return t.fofa_query || t.manual_targets?.[0] || "单站协作";
  }
  return t?.fofa_query || "手动清单";
}

async function load() {
  if (!tasks.value.length) initialLoading.value = true;
  else refreshing.value = true;
  try { tasks.value = await api.listTasks(); }
  finally {
    initialLoading.value = false;
    refreshing.value = false;
  }
}
async function openEdit(task) {
  editingTask.value = await api.getTask(task.id);
  editOpen.value = true;
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
watch(authReadyRef, (ready) => {
  if (ready) load();
});
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
      <div v-for="n in 4" :key="n" class="task-card skeleton-task"></div>
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
            <span class="meta">{{ taskModeLabel(t) }} · {{ targetSourceLabel(t.target_source) }} · 并发 {{ t.concurrency }}</span>
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
  </section>
</template>
