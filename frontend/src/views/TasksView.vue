<script setup>
import { ref, onMounted, computed, watch } from "vue";
import { useRouter } from "vue-router";
import { api, authReadyRef, authRoleRef, loadAuthRole } from "../api.js";
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
          <button v-if="writable" class="mini-action" type="button" @click.stop="openEdit(t)">编辑参数</button>
          <span class="task-chevron" aria-hidden="true">›</span>
        </div>
      </div>
    </div>
    <TaskEditModal :open="editOpen" :task="editingTask" @close="closeEdit" @saved="onSaved" />
  </section>
</template>
