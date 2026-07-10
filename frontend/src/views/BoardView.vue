<script setup>
import { ref, onMounted, onUnmounted, computed, watch } from "vue";
import { marked } from "marked";
import DOMPurify from "dompurify";
import { api, wsUrl, authRoleRef, authReadyRef, loadAuthRole } from "../api.js";
import { copyText } from "../clipboard.js";
import { effectiveSeverity, buildReportMd, buildReportPy, reportSlug } from "../report.js";
import ReportDrawer from "../components/ReportDrawer.vue";
import TaskEditModal from "../components/TaskEditModal.vue";

const props = defineProps({ id: String });
const task = ref(null);
const tab = ref("board");          // board | review | submit | killsweep | rejected
const boardPanel = ref("workers"); // workers | stream（手机端看板切换）
const events = ref([]);
const liveWorkers = ref([]);       // 在跑 worker 活态
const siteCollab = ref(null);      // 单站协作态势（三阶段路线流水线，仅 site 任务）
const queue = ref([]);             // 复审队列
const submitItems = ref([]);       // 待提交
const killsweepItems = ref([]);    // 通杀列
const rejectedItems = ref([]);     // 已驳回
const archivedItems = ref([]);     // AI 未采纳归档（ignored/deepen，可救回）
const expandedKillsweeps = ref(new Set());
const searchDraft = ref("");
const searchText = ref("");
const submittedFilter = ref(false);
const drawerId = ref(null);
const drawerMode = ref("view");
const toastMsg = ref("");
const editOpen = ref(false);
const invalidatingKillsweepId = ref(null);
const readonly = computed(() => authRoleRef.value !== "full");
const initialLoading = ref(false);
const refreshing = ref(false);
const loadedTaskId = ref("");
const submitHasMore = ref(false);
const submitLoading = ref(false);
const archivedHasMore = ref(false);
const archivedLoading = ref(false);
const ARCHIVED_PAGE_SIZE = 50;
const bulkWorking = ref(false);
const SUBMIT_PAGE_SIZE = 120;
const EXPORT_PAGE_SIZE = 80;
let ws = null, poll = null, boardPoll = null, searchTimer = null, poolPoll = null;
let wsReconnectTimer = null, wsReconnectAttempt = 0, wsIntentionalClose = false;
let eventRefreshTimer = null, eventRefreshPending = null;
const LIST_TABS = new Set(["review", "submit", "killsweep", "rejected", "archived"]);
// 记录哪些列表 tab 已经加载过数据：首屏只拉看板，列表按需加载；后台只刷新看过的列表。
const loadedTabs = ref(new Set());

// Target 面板状态
const targetPanelOpen = ref(false);
const targetList = ref([]);
const targetListLoading = ref(false);
const targetFilter = ref("");  // all / alive / done / dead / skipped / queued
const targetSearch = ref("");  // 搜索关键词
const filteredTargetList = computed(() => {
  const q = targetSearch.value.trim().toLowerCase();
  if (!q) return targetList.value;
  return targetList.value.filter((t) =>
    (t.host || "").toLowerCase().includes(q) ||
    (t.url || "").toLowerCase().includes(q) ||
    (t.title || "").toLowerCase().includes(q) ||
    (t.school || "").toLowerCase().includes(q) ||
    (t.org || "").toLowerCase().includes(q)
  );
});
const targetDetailData = ref(null);
const targetDetailLoading = ref(false);
const redigWorking = ref(false);
const resetWorking = ref(false);
const resetFailedWorking = ref(false);
const collectWorking = ref(false);
const showResetConfirm = ref(false);
const showResetFailedConfirm = ref(false);
const retestSummary = ref(null);
// 凭证提交表单状态
const credType = ref("password");
const credUsername = ref("");
const credPassword = ref("");
const credCookie = ref("");
const credWorking = ref(false);
// 数据库连接池状态
const poolStats = ref(null);
// 注册助手状态
const targetAssistantText = ref("");
const targetAssistantBusy = ref(false);
const targetAssistantMessages = ref([]);
const TARGET_ASSISTANT_WELCOME = "我可以回答这个目标的注册条件、阻断原因、注册流程等问题。你也可以让我再访问注册页或发请求做补充验证。";

function toast(m) { toastMsg.value = m; setTimeout(() => (toastMsg.value = ""), 2200); }

function onAuthOrTokenChange() {
  closeWs(true);
  connectWs();
  refreshAll({ background: true, includeTask: true, includeBoard: true });
}

function isListTab(t) {
  return LIST_TABS.has(t);
}

function markTabLoaded(t) {
  if (!isListTab(t)) return;
  const next = new Set(loadedTabs.value);
  next.add(t);
  loadedTabs.value = next;
}

async function loadTask() {
  const id = props.id;
  const t = await api.getTask(id);
  if (id === props.id && id === loadedTaskId.value) task.value = t;
}
async function loadQueue() {
  const id = props.id;
  const rows = await api.reviewQueue(id);
  if (id === props.id) queue.value = rows.map(withSearchCache);
}
async function loadSubmit(opts = {}) {
  const id = props.id;
  const reset = opts.reset !== false;
  const offset = reset ? 0 : submitItems.value.length;
  submitLoading.value = true;
  try {
    const res = await api.submitList(id, submittedFilter.value, undefined, {
      compact: true,
      limit: SUBMIT_PAGE_SIZE,
      offset,
    });
    const rows = Array.isArray(res) ? res : (res.items || []);
    const next = rows.map(withSearchCache);
    if (id !== props.id) return;
    submitItems.value = reset ? next : [...submitItems.value, ...next];
    submitHasMore.value = !Array.isArray(res) && !!res.has_more;
  } finally {
    submitLoading.value = false;
  }
}
async function loadKillsweeps() {
  const id = props.id;
  const rows = await api.killsweeps(id);
  if (id === props.id) killsweepItems.value = rows.map(withSearchCache);
}
async function loadRejected() {
  const id = props.id;
  const rows = await api.rejectedList(id);
  if (id === props.id) rejectedItems.value = rows.map(withSearchCache);
}
async function loadArchived(opts = {}) {
  const id = props.id;
  const reset = opts.reset !== false;
  const offset = reset ? 0 : archivedItems.value.length;
  archivedLoading.value = true;
  try {
    const res = await api.archivedList(id, undefined, {
      limit: ARCHIVED_PAGE_SIZE,
      offset,
    });
    const rows = Array.isArray(res) ? res : (res.items || []);
    const next = rows.map(withSearchCache);
    if (id !== props.id) return;
    archivedItems.value = reset ? next : [...archivedItems.value, ...next];
    archivedHasMore.value = !Array.isArray(res) && !!res.has_more;
  } finally {
    archivedLoading.value = false;
  }
}
async function loadMoreArchived() {
  if (archivedLoading.value || !archivedHasMore.value) return;
  await loadArchived({ reset: false });
}

async function refreshAll(opts = {}) {
  const background = !!opts.background;
  const includeTask = opts.includeTask !== false;
  const includeBoard = !!opts.includeBoard;
  const includeCurrent = opts.includeCurrent !== false;
  if (background) refreshing.value = true;
  try {
    const tabs = new Set([...loadedTabs.value].filter(isListTab));
    if (includeCurrent && isListTab(tab.value)) tabs.add(tab.value);
    const jobs = [];
    if (includeTask) jobs.push(loadTask());
    if (includeBoard) jobs.push(loadBoard());
    for (const t of tabs) jobs.push(loadTabData(t));
    await Promise.all(jobs);
  } finally {
    if (background) refreshing.value = false;
  }
}

async function loadTabData(t = tab.value) {
  if (t === "review") await loadQueue();
  else if (t === "submit") await loadSubmit({ reset: true });
  else if (t === "killsweep") await loadKillsweeps();
  else if (t === "rejected") await loadRejected();
  else if (t === "archived") await loadArchived();
  else return;
  markTabLoaded(t);
}

function refreshTabData() {
  if (isListTab(tab.value)) return loadTabData(tab.value);
  return Promise.resolve();
}

function shouldRefreshTab(t) {
  return tab.value === t || loadedTabs.value.has(t);
}

function scheduleEventRefresh(ev) {
  eventRefreshPending = ev;
  clearTimeout(eventRefreshTimer);
  eventRefreshTimer = setTimeout(() => {
    const pending = eventRefreshPending;
    eventRefreshPending = null;
    if (pending) refreshFromEvent(pending);
  }, 280);
}

async function refreshFromEvent(ev) {
  const k = ev.kind || "";
  const jobs = [loadBoard()];
  if ((k.includes("finding") || k.includes("review")) && shouldRefreshTab("review")) {
    jobs.push(loadTabData("review"));
  }
  if ((k.includes("finding") || k.includes("review")) && shouldRefreshTab("rejected")) {
    jobs.push(loadTabData("rejected"));
  }
  if ((k.includes("finding") || k.includes("review")) && shouldRefreshTab("archived")) {
    jobs.push(loadTabData("archived"));
  }
  if ((k.includes("submit") || k.includes("review")) && shouldRefreshTab("submit")) {
    jobs.push(loadTabData("submit"));
  }
  if (k.includes("killsweep") && shouldRefreshTab("killsweep")) {
    jobs.push(loadTabData("killsweep"));
  }
  await Promise.all(jobs);
}

function closeWs(intentional = false) {
  wsIntentionalClose = intentional;
  clearTimeout(wsReconnectTimer);
  wsReconnectTimer = null;
  if (!ws) return;
  const old = ws;
  ws = null;
  old.close();
}

function resetTaskState(full = true) {
  if (full) {
    task.value = null;
    queue.value = [];
    submitItems.value = [];
    killsweepItems.value = [];
    rejectedItems.value = [];
    archivedItems.value = [];
    archivedHasMore.value = false;
    submitHasMore.value = false;
    loadedTabs.value = new Set();
    clearSearch();
  }
  events.value = [];
  liveWorkers.value = [];
  siteCollab.value = null;
  drawerId.value = null;
  editOpen.value = false;
}

async function bootstrapTask() {
  if (!props.id) return;
  const switching = loadedTaskId.value && loadedTaskId.value !== props.id;
  if (!task.value) initialLoading.value = true;
  else if (switching) refreshing.value = true;

  closeWs(true);
  resetTaskState(!task.value || switching);
  loadedTaskId.value = props.id;

  try {
    await Promise.all([loadTask(), loadBoard()]);
    if (isListTab(tab.value)) await loadTabData(tab.value);
    wsIntentionalClose = false;
    connectWs();
  } finally {
    initialLoading.value = false;
    refreshing.value = false;
  }
}

// 实时事件：只展示稍重要的事件，过滤 HTTP/Shell/思考等高频低价值噪音。
const IMPORTANT_KINDS = new Set([
  "collector_phase",
  "finding_submitted", "finding_duplicate", "finding_invalid",
  "worker_start", "worker_finish", "worker_cancelled", "worker_auto_finish",
  "target_done", "target_requeued", "timeout", "auto_deepen", "salvage",
  "review_start", "review_done", "review_error", "review_deferred", "review_cancelled",
  "reproduce_start", "reproduce_done",
  "killsweep_start", "killsweep_done", "killsweep_error", "killsweep_dedup",
  "killsweep_invalid", "killsweep_cancelled",
  "llm_error", "quota_stop", "reclaim", "recover", "workers_cancelled",
  "tool_exception",
  "retest_start", "retest_phase2", "retest_sleep", "retest_wake", "retest_done",
  "retest_sleep_log", "retest_ip_banned", "retest_dead", "retest_recover",
]);
const NOISE_KINDS = new Set([
  "ping",
  "tool_http", "tool_shell", "tool_shell_blocked", "tool_arg_error",
  "tool_js_analyze", "tool_decode", "tool_waf_advice", "tool_fofa_lookup", "tool_session_set",
  "worker_thought", "intel_reported", "js_analyzer_enabled",
  "killsweep_fofa", "killsweep_http", "killsweep_shell",
  "refill", "cluster_cooldown_skip", "skip",
]);
const LOG_INFO_IMPORTANT = new Set([
  "target_done", "target_requeued", "timeout", "auto_deepen", "salvage",
  "review_done", "review_deferred", "review_cancelled",
  "reclaim", "recover", "workers_cancelled", "quota_stop",
  "killsweep_done", "killsweep_dedup", "killsweep_error", "killsweep_cancelled",
  "target_needs_auth",
]);

function isImportantEvent(ev) {
  const kind = ev.kind || "";
  if (kind === "ping") return false;
  if (ev.level === "error" || ev.level === "warn") return true;
  if (NOISE_KINDS.has(kind)) return false;
  if (IMPORTANT_KINDS.has(kind)) return true;
  if (kind === "duplicate_checked") return !!ev.duplicate;
  if (ev.message && LOG_INFO_IMPORTANT.has(kind)) return true;
  if (ev.message && kind === "error") return true;
  return false;
}

// 把任意事件格式化为一句人话（worker 动作事件本身没有 message）
function fmtEvent(ev) {
  if (ev.message) return ev.message;
  const d = ev;
  switch (ev.kind) {
    case "worker_start": return `开始挖掘 ${d.target || ""}${d.mode === "deepen" ? "（定向深挖）" : ""}`;
    case "collector_phase": return d.message || phaseLabel(d.phase) || "正在跑过滤器阶段";
    case "finding_submitted": return `🎯 发现漏洞 [${d.severity || ""}] ${d.title || ""}`;
    case "duplicate_checked": return d.duplicate ? `查重重复：${d.title || ""}` : null;
    case "finding_duplicate": return `重复漏洞已拦截：${d.title || ""}`;
    case "finding_invalid": return `漏洞格式校验失败，重试中`;
    case "worker_finish": return `收尾: ${d.verdict || ""}`;
    case "worker_auto_finish": return `自动收敛: ${(d.summary || d.verdict || "").slice(0, 120)}`;
    case "worker_cancelled": return `挖掘被取消: ${d.target || ""}`;
    case "review_start": return `开始审核: ${d.title || ""}`;
    case "review_done": return `审核完成: ${d.verdict || ""} · ${d.confidence || ""} · ${d.score ?? ""}`;
    case "review_error": return `审核异常: ${(d.error || "").slice(0, 120)}`;
    case "review_deferred": return `审核暂缓，稍后重试`;
    case "review_cancelled": return `审核已取消`;
    case "reproduce_start": return `复现验证: ${d.title || ""}`;
    case "reproduce_done": return `复现${d.reproduced ? "成功" : "未证实"}: ${d.title || ""}`;
    case "killsweep_start": return `通杀 Hunter 启动：${d.title || ""}`;
    case "killsweep_done": return `通杀分析完成：${d.product || ""} · ${d.is_killsweep ? "可通杀" : "不可通杀"}`;
    case "killsweep_error": return `通杀分析异常: ${(d.error || "").slice(0, 120)}`;
    case "killsweep_dedup": return `通杀分析去重：${d.product || ""}`;
    case "killsweep_invalid": return `通杀记录已标记无效：${d.product || ""}`;
    case "llm_error": return `⚠ LLM 调用失败: ${d.error || ""}`;
    case "tool_exception": return `工具异常: ${d.tool || ""} ${(d.error || "").slice(0, 80)}`;
    case "ping": return null;
    default: return ev.message || `${ev.kind || ""}`;
  }
}

function phaseStateText(state) {
  return { active: "进行中", pending: "排队中", done: "已完成", idle: "未开始" }[state] || "";
}

async function loadBoard() {
  const id = props.id;
  const b = await api.board(id);
  if (id !== props.id) return;
  liveWorkers.value = b.live_workers || [];
  siteCollab.value = b.site_collab || null;
  retestSummary.value = b.retest_summary || null;
  if (task.value) {
    if (b.task_status) task.value.status = b.task_status;
    if (b.stats) task.value.stats = b.stats;
    if (b.fofa_config) task.value.fofa_config = b.fofa_config;
    if (b.model_config_data) task.value.model_config_data = b.model_config_data;
    if (b.llm_usage) task.value.llm_usage = b.llm_usage;
        if (b.llm_usage_by_model) task.value.llm_usage_by_model = b.llm_usage_by_model;
  }
  if (!events.value.length && b.events?.length) {
    events.value = b.events
      .filter(isImportantEvent)
      .map((e) => ({ ...e, _text: fmtEvent(e) }))
      .filter((e) => e._text);
  }
}

function connectWs() {
  if (ws) {
    wsIntentionalClose = true;
    ws.close();
    ws = null;
  }
  clearTimeout(wsReconnectTimer);
  wsReconnectTimer = null;
  if (!props.id) return;
  wsIntentionalClose = false;
  ws = new WebSocket(wsUrl(props.id));
  ws.onopen = () => { wsReconnectAttempt = 0; };
  ws.onmessage = (e) => {
    const ev = JSON.parse(e.data);
    if (ev.kind === "ping") return;
    if (!isImportantEvent(ev)) return;
    if (ev.kind === "collector_phase") updateCollectorStatus(ev);
    const text = fmtEvent(ev);
    if (!text) return;
    events.value.unshift({ ...ev, _text: text });
    if (events.value.length > 200) events.value.pop();
    const k = ev.kind || "";
    if (k.includes("finding") || k.includes("review") || k.includes("target_done")
        || k.includes("target_needs") || k.includes("submit")
        || k.includes("killsweep") || k.includes("worker")
        || k.includes("retest")) {
      scheduleEventRefresh(ev);
    }
  };
  ws.onclose = () => {
    ws = null;
    if (wsIntentionalClose || !props.id) return;
    clearTimeout(wsReconnectTimer);
    const delay = Math.min(30000, 1000 * (2 ** wsReconnectAttempt));
    wsReconnectAttempt += 1;
    wsReconnectTimer = setTimeout(async () => {
      if (wsIntentionalClose || !props.id) return;
      connectWs();
      await loadBoard();
    }, delay);
  };
}

function updateCollectorStatus(ev) {
  if (!task.value) return;
  task.value.fofa_config = {
    ...(task.value.fofa_config || {}),
    collector_phase: ev.phase || "",
    collector_phase_text: ev.message || "",
    last_target_filter_total: Number(ev.survivors || 0),
    last_target_filter_evaluated: Number(ev.filter_evaluated || 0),
  };
}

async function loadPoolStats() {
  try { poolStats.value = await api.poolStats(); } catch { /* 静默 */ }
}
function syncPollers() {
  clearInterval(poll);
  clearInterval(boardPoll);
  clearInterval(poolPoll);
  const running = task.value?.status === "running";
  boardPoll = setInterval(loadBoard, running ? 2500 : 12000);
  poll = setInterval(() => refreshAll({
    background: true,
    includeTask: false,
    includeBoard: false,
  }), running ? 15000 : 30000);
  // 连接池状态：运行中 5s 刷新，空闲 30s
  loadPoolStats();
  poolPoll = setInterval(loadPoolStats, running ? 5000 : 30000);
}

onMounted(async () => {
  window.addEventListener("autohunter-auth-role", onAuthOrTokenChange);
  window.addEventListener("autohunter-token-changed", onAuthOrTokenChange);
  if (!authReadyRef.value) await loadAuthRole();
  await bootstrapTask();
  syncPollers();
});
onUnmounted(() => {
  window.removeEventListener("autohunter-auth-role", onAuthOrTokenChange);
  window.removeEventListener("autohunter-token-changed", onAuthOrTokenChange);
  closeWs(true);
  clearInterval(poll);
  clearInterval(boardPoll);
  clearInterval(poolPoll);
  clearTimeout(searchTimer);
  clearTimeout(wsReconnectTimer);
  clearTimeout(eventRefreshTimer);
});

watch(() => props.id, async (id, oldId) => {
  if (!id || id === oldId) return;
  await bootstrapTask();
  syncPollers();
});

watch(() => task.value?.status, () => {
  syncPollers();
});

watch(tab, (t) => {
  // 已加载过的 tab 直接用内存数据；未打开过的列表按需补拉一次。
  // 数据新鲜度由 WebSocket 事件后台刷新 + 后台轮询(refreshAll)保证。
  if (t === "board") return;
  if (loadedTabs.value.has(t)) return;
  loadTabData(t);
});

watch(searchDraft, (v) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { searchText.value = v; }, 120);
});

function elapsed(iso) {
  if (!iso) return "";
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m${s % 60}s`;
}

async function ctl(action) {
  await api[action](props.id);
  toast(action === "start" ? "已启动" : action === "pause" ? "已暂停" : "已停止");
  await Promise.all([loadTask(), loadBoard()]);
}

// ===== Target 面板 =====
const TARGET_STATUS_LABELS = {
  queued: "排队中", assigned: "已分配", scanning: "挖掘中",
  done: "已完成", dead: "已放弃", skipped: "已跳过",
  ip_banned: "IP封禁",
  pending_input: "待注册",
};

async function openTargetPanel() {
  targetPanelOpen.value = true;
  targetDetailData.value = null;
  await loadTargetList();
}

function closeTargetPanel() {
  targetPanelOpen.value = false;
  targetDetailData.value = null;
}

async function loadTargetList() {
  targetListLoading.value = true;
  try {
    const status = targetFilter.value === "alive" ? "alive" :
                   targetFilter.value === "all" || !targetFilter.value ? null : targetFilter.value;
    targetList.value = await api.targets(props.id, status, 500);
  } catch (e) {
    toast("加载目标列表失败");
  } finally {
    targetListLoading.value = false;
  }
}

async function openTargetDetail(tid) {
  targetDetailLoading.value = true;
  targetDetailData.value = null;
  // 重置注册助手状态
  targetAssistantText.value = "";
  targetAssistantBusy.value = false;
  try {
    targetDetailData.value = await api.targetDetail(props.id, tid);
    // 从后端恢复助手历史
    const saved = targetDetailData.value?.target?.assistant_messages;
    targetAssistantMessages.value = (saved?.length)
      ? saved
      : [{ role: "assistant", content: TARGET_ASSISTANT_WELCOME }];
  } catch (e) {
    toast("加载目标详情失败");
  } finally {
    targetDetailLoading.value = false;
  }
}

function closeTargetDetail() {
  targetDetailData.value = null;
}

async function redigTarget(tid) {
  if (redigWorking.value) return;
  redigWorking.value = true;
  try {
    const res = await api.redigTarget(props.id, tid);
    toast(res.message || "已重置入队重挖");
    // 刷新详情和列表
    await openTargetDetail(tid);
    await loadTargetList();
    await loadBoard();
  } catch (e) {
    toast(e.message || "重挖失败");
  } finally {
    redigWorking.value = false;
  }
}

async function resetProgress() {
  if (resetWorking.value) return;
  resetWorking.value = true;
  try {
    const res = await api.resetProgress(props.id);
    toast(res.message || "进度已重置");
    showResetConfirm.value = false;
    await Promise.all([loadTask(), loadBoard()]);
    if (targetPanelOpen.value) await loadTargetList();
  } catch (e) {
    toast(e.message || "重置失败");
  } finally {
    resetWorking.value = false;
  }
}

async function resetFailedTargets() {
  if (resetFailedWorking.value) return;
  resetFailedWorking.value = true;
  try {
    const res = await api.resetFailedTargets(props.id);
    toast(res.message || "操作完成");
    showResetFailedConfirm.value = false;
    await Promise.all([loadTask(), loadBoard()]);
    if (targetPanelOpen.value) await loadTargetList();
  } catch (e) {
    toast(e.message || "重置失败");
  } finally {
    resetFailedWorking.value = false;
  }
}

async function submitCredentials(tid) {
  if (credWorking.value) return;
  if (credType.value === "password" && (!credUsername.value || !credPassword.value)) {
    toast("请填写账号和密码");
    return;
  }
  if (credType.value === "cookie" && !credCookie.value) {
    toast("请填写 Cookie/Token");
    return;
  }
  credWorking.value = true;
  try {
    const data = credType.value === "password"
      ? { type: "password", username: credUsername.value, password: credPassword.value }
      : { type: "cookie", cookie: credCookie.value };
    const res = await api.provideCredentials(props.id, tid, data);
    toast(res.message || "凭证已提交，目标已重新入队");
    credUsername.value = "";
    credPassword.value = "";
    credCookie.value = "";
    await openTargetDetail(tid);
    await loadTargetList();
    await loadBoard();
  } catch (e) {
    toast(e.message || "提交凭证失败");
  } finally {
    credWorking.value = false;
  }
}

async function skipTarget(tid) {
  if (credWorking.value) return;
  if (!window.confirm("确认跳过此目标？跳过后将不再自动测试此目标。")) return;
  credWorking.value = true;
  try {
    const res = await api.skipPendingTarget(props.id, tid);
    toast(res.message || "目标已跳过");
    await openTargetDetail(tid);
    await loadTargetList();
    await loadBoard();
  } catch (e) {
    toast(e.message || "跳过失败");
  } finally {
    credWorking.value = false;
  }
}

function renderTargetAssistantMd(text) {
  return DOMPurify.sanitize(marked.parse(text || ""));
}

const TA_TOOL_LABEL = { http_request: "HTTP 请求", run_shell: "执行命令" };

function taStepLabel(ev) {
  if (ev.type === "thinking") return ev.text || "分析中…";
  if (ev.type === "tool_call") return `${TA_TOOL_LABEL[ev.tool] || ev.tool}：${ev.summary || ""}`;
  if (ev.type === "tool_result") return `↳ ${ev.summary || "完成"}`;
  return ev.text || "";
}

/** 聊天输入框 Enter 发送：跳过 IME 组合期（拼音输入法确认候选词时不触发发送）。 */
function onChatEnter(e, fn) {
  if (e.isComposing || e.keyCode === 229) return;
  e.preventDefault();
  fn();
}

async function askTargetAssistant(preset = "") {
  const text = (preset || targetAssistantText.value).trim();
  if (!text || targetAssistantBusy.value || !targetDetailData.value?.target) return;
  const tid = targetDetailData.value.target.id;
  targetAssistantText.value = "";
  targetAssistantMessages.value.push({ role: "user", content: text });
  targetAssistantBusy.value = true;

  const liveMsg = { role: "assistant", content: "", steps: [], streaming: true };
  targetAssistantMessages.value.push(liveMsg);
  const idx = targetAssistantMessages.value.length - 1;

  const update = (patch) => {
    targetAssistantMessages.value[idx] = { ...targetAssistantMessages.value[idx], ...patch };
  };
  const pushStep = (ev) => {
    const cur = targetAssistantMessages.value[idx];
    const steps = [...(cur.steps || [])];
    if (ev.type === "tool_result" && steps.length && steps[steps.length - 1].type === "tool_call") {
      steps[steps.length - 1] = { ...steps[steps.length - 1], result: taStepLabel(ev) };
    } else {
      steps.push({ type: ev.type, label: taStepLabel(ev), tool: ev.tool });
    }
    update({ steps });
  };

  try {
    await api.targetAssistantStream(props.id, tid, text, (ev) => {
      switch (ev.type) {
        case "thinking":
        case "tool_call":
        case "tool_result":
          pushStep(ev);
          break;
        case "assistant_partial":
          update({ partial: ev.text });
          break;
        case "final":
          update({ content: ev.text || "", partial: "" });
          break;
        case "done":
          update({ content: ev.answer || targetAssistantMessages.value[idx].content || "已完成。", streaming: false, partial: "" });
          break;
        default:
          break;
      }
    });
    if (targetAssistantMessages.value[idx].streaming) {
      update({ streaming: false });
    }
  } catch (e) {
    update({ content: `注册助手异常：${String(e.message || e)}`, streaming: false });
  } finally {
    targetAssistantBusy.value = false;
  }
}

async function collectTargets() {
  if (collectWorking.value) return;
  collectWorking.value = true;
  toast("正在通过证书透明度日志搜索新资产，可能需要 30-60 秒...");
  try {
    const res = await api.collectTargets(props.id);
    const added = res.added || 0;
    const candidates = res.candidates || 0;
    if (added > 0) {
      toast(`搜集完成：发现 ${candidates} 个候选，入队 ${added} 个新目标`);
    } else {
      toast(res.reason === "no_root_domains"
        ? "无法提取根域名：任务需先有目标或 FOFA 语法含域名锚点"
        : res.reason === "no_new_hosts"
        ? "未发现新资产（已有目标已覆盖全部子域名）"
        : "搜集完成，未入队新目标");
    }
    await Promise.all([loadTask(), loadBoard()]);
    if (targetPanelOpen.value) await loadTargetList();
  } catch (e) {
    toast(e.message || "搜集失败");
  } finally {
    collectWorking.value = false;
  }
}

function openEdit() {
  editOpen.value = true;
}

function closeEdit() {
  editOpen.value = false;
}

async function onTaskSaved(updated) {
  task.value = updated;
  editOpen.value = false;
  toast("任务参数已保存");
  await loadBoard();
}

function openReview(id) { drawerId.value = id; drawerMode.value = "review"; }
function openSubmit(id) { drawerId.value = id; drawerMode.value = "submit"; }
function openRejected(id) { drawerId.value = id; drawerMode.value = "rejected"; }
function openArchived(id) { drawerId.value = id; drawerMode.value = "archived"; }
async function restoreArchived(id) {
  try {
    await api.restoreArchived(id);
    toast("已恢复到复审队列");
    archivedItems.value = archivedItems.value.filter((f) => f.id !== id);
    const jobs = [];
    if (shouldRefreshTab("review")) jobs.push(loadTabData("review"));
    jobs.push(loadBoard());
    await Promise.all(jobs);
  } catch (e) {
    toast(`恢复失败：${e?.message || e}`);
  }
}
function toggleKillsweep(id) {
  const next = new Set(expandedKillsweeps.value);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  expandedKillsweeps.value = next;
}
function isKillsweepOpen(id) {
  return expandedKillsweeps.value.has(id);
}
function assetRows(k) {
  const rows = Array.isArray(k?.affected_table) ? k.affected_table : [];
  if (rows.length) return rows;
  if (k?.verified_url) {
    return [{
      school: "待确认",
      url: k.verified_url,
      host: "",
      vuln_title: k.vuln_summary || k.origin_title || "通杀验证目标",
      status: k.verified ? "verified" : "candidate",
      evidence: k.verified ? "通杀 Hunter 已验证" : "通杀 Hunter 圈定候选",
    }];
  }
  return [];
}
function assetStatusLabel(status) {
  return status === "verified" ? "已验证" : "候选";
}
function formatTokenCount(n) {
  const v = Number(n || 0);
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(2)}M`;
  if (v >= 10_000) return `${Math.round(v / 1000)}K`;
  if (v >= 1000) return `${(v / 1000).toFixed(1)}K`;
  return String(v);
}
function shortText(text, max = 80) {
  const s = String(text || "").replace(/\s+/g, " ").trim();
  return s.length > max ? `${s.slice(0, max)}…` : s;
}
async function invalidateKillsweep(k) {
  if (readonly.value || invalidatingKillsweepId.value) return;
  const name = shortText(k.product_name || k.vuln_summary || "这条通杀记录");
  if (!window.confirm(`确认把「${name}」标记为无效？\n标记后会从默认通杀列隐藏，原始记录仍保留用于审计。`)) return;
  invalidatingKillsweepId.value = k.id;
  try {
    await api.invalidateKillsweep(props.id, k.id, "人工复审判定该通杀候选无效");
    const next = new Set(expandedKillsweeps.value);
    next.delete(k.id);
    expandedKillsweeps.value = next;
    toast("已标记为无效");
    await Promise.all([loadTabData("killsweep"), loadBoard()]);
  } catch (e) {
    toast(`标记失败：${e.message || e}`);
  } finally {
    invalidatingKillsweepId.value = null;
  }
}

async function loadMoreSubmit() {
  if (submitLoading.value || !submitHasMore.value) return;
  await loadSubmit({ reset: false });
}

async function fetchAllSubmitReports() {
  const reports = [];
  let offset = 0;
  for (;;) {
    const res = await api.submitList(props.id, submittedFilter.value, undefined, {
      compact: false,
      limit: EXPORT_PAGE_SIZE,
      offset,
    });
    const rows = Array.isArray(res) ? res : (res.items || []);
    reports.push(...rows);
    if (Array.isArray(res) || !res.has_more) break;
    offset += rows.length;
    await new Promise((resolve) => requestAnimationFrame(resolve));
  }
  return reports;
}

/** 下载单个文件的通用函数 */
function downloadFile(filename, content, mime) {
  const blob = new Blob([content], { type: mime || "text/plain;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

/** 复审队列：单项下载 MD */
function downloadReviewMd(finding) {
  downloadFile(`${reportSlug(finding)}.md`, buildReportMd(finding), "text/markdown;charset=utf-8");
  toast(`已下载 ${finding.title?.slice(0, 20) || "报告"}.md`);
}
/** 复审队列：单项下载 py 脚本 */
function downloadReviewPy(finding) {
  downloadFile(`${reportSlug(finding)}.py`, buildReportPy(finding), "text/x-python;charset=utf-8");
  toast(`已下载 ${finding.title?.slice(0, 20) || "PoC"}.py`);
}

/** 复审队列：批量导出全部 MD（合并为一个文件） */
async function exportReviewAllMd() {
  if (bulkWorking.value) return;
  bulkWorking.value = true;
  try {
    toast("正在生成复审队列 Markdown...");
    // 复审队列数据已在内存中，直接使用
    const reports = queue.value;
    const md = reports.map((f) => buildReportMd(f)).join("\n\n---\n\n");
    downloadFile(`autohunter-${props.id.slice(0, 8)}-review.md`, md, "text/markdown;charset=utf-8");
    toast(`已导出 ${reports.length} 份复审报告`);
  } finally {
    bulkWorking.value = false;
  }
}

/** 复审队列：批量导出全部 py 脚本（合并为一个文件） */
async function exportReviewAllPy() {
  if (bulkWorking.value) return;
  bulkWorking.value = true;
  try {
    toast("正在生成复审队列 PoC 脚本...");
    const reports = queue.value;
    const scripts = reports.map((f, i) => {
      const sep = "# " + "=".repeat(70);
      const title = (f.review?.user_edits?.title || f.title || "").slice(0, 60);
      return `${sep}\n# [${i + 1}/${reports.length}] ${title}\n# 目标: ${f.target_url}\n# 类型: ${f.vuln_type}\n${sep}\n\n${buildReportPy(f)}`;
    }).join("\n\n\n");
    downloadFile(`autohunter-${props.id.slice(0, 8)}-review-poc.py`, scripts, "text/x-python;charset=utf-8");
    toast(`已导出 ${reports.length} 份 PoC 脚本`);
  } finally {
    bulkWorking.value = false;
  }
}

async function copyAll() {
  if (bulkWorking.value) return;
  bulkWorking.value = true;
  try {
    toast("正在生成全部 Markdown...");
    const reports = await fetchAllSubmitReports();
    const md = reports.map((f) => buildReportMd(f)).join("\n\n---\n\n");
    await copyText(md);
    toast(`已复制 ${reports.length} 份报告`);
  } catch {
    toast("复制失败，请使用导出按钮");
  } finally {
    bulkWorking.value = false;
  }
}
async function exportAll() {
  if (bulkWorking.value) return;
  bulkWorking.value = true;
  try {
    toast("正在生成 Markdown 文件...");
    const reports = await fetchAllSubmitReports();
    const md = reports.map((f) => buildReportMd(f)).join("\n\n---\n\n");
  const blob = new Blob([md], { type: "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `autohunter-${props.id.slice(0, 8)}-submit.md`;
  a.click();
    toast(`已导出 ${reports.length} 份报告`);
  } finally {
    bulkWorking.value = false;
  }
}
function edusrcReports(reports) {
  return reports.map((f) => buildEdusrcToolReport(f));
}
async function copyEdusrcAll() {
  if (bulkWorking.value) return;
  bulkWorking.value = true;
  try {
    toast("正在生成全部 EduSRC JSON...");
    const reports = await fetchAllSubmitReports();
    const text = JSON.stringify(edusrcReports(reports), null, 2);
    await copyText(text);
    toast(`已复制 ${reports.length} 份 EduSRC JSON`);
  } catch {
    toast("复制失败，请使用导出 reports.json");
  } finally {
    bulkWorking.value = false;
  }
}
async function exportEdusrcAll() {
  if (bulkWorking.value) return;
  bulkWorking.value = true;
  try {
    toast("正在生成 reports.json...");
    const reports = await fetchAllSubmitReports();
    const text = JSON.stringify(edusrcReports(reports), null, 2);
  const blob = new Blob([text], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `autohunter-${props.id.slice(0, 8)}-edusrc-reports.json`;
  a.click();
    toast(`已导出 ${reports.length} 份 EduSRC JSON`);
  } finally {
    bulkWorking.value = false;
  }
}

const AGENT_ICON = { orchestrator: "◆", collector: "🛰", worker: "⚔", reviewer: "⚖", killsweep: "◇" };
const AGENT_LABEL = { orchestrator: "主控", collector: "搜集", worker: "挖掘", reviewer: "审核", killsweep: "通杀" };

const stats = computed(() => task.value?.stats || {});
// Tab 徽标/指标卡计数：统一以 stats 为权威来源（stats 随 loadTask 在挂载时与每次实时事件刷新），
// 无需点开对应 Tab 就能显示并实时更新。当前已加载的 Tab 若数组数更大(刚增量加载更多页)则取较大值，
// 避免分页 compact 限制导致显示偏小。
const reviewCount = computed(() =>
  Math.max(stats.value.review_pending ?? 0, loadedTabs.value.has("review") ? queue.value.length : 0));
const submitCount = computed(() => {
  if (typeof stats.value.submit_ready === "number") return stats.value.submit_ready;
  if (submittedFilter.value) return 0;
  return loadedTabs.value.has("submit")
    ? submitItems.value.filter((f) => !f.review?.submitted).length
    : 0;
});
const sweepCount = computed(() =>
  Math.max(stats.value.killsweep ?? 0, loadedTabs.value.has("killsweep") ? killsweepItems.value.length : 0));
const rejectedCount = computed(() =>
  Math.max(stats.value.rejected ?? 0, loadedTabs.value.has("rejected") ? rejectedItems.value.length : 0));
const archivedCount = computed(() =>
  Math.max(stats.value.archived ?? 0, loadedTabs.value.has("archived") ? archivedItems.value.length : 0));
const totalTargets = computed(() =>
  (stats.value.queued ?? 0) + (stats.value.scanning ?? 0) +
  (stats.value.done ?? 0) + (stats.value.dead ?? 0) + (stats.value.skipped ?? 0) +
  (stats.value.pending_input ?? 0)
);
const resolvedTargets = computed(() =>
  (stats.value.done ?? 0) + (stats.value.dead ?? 0) + (stats.value.skipped ?? 0)
);
const pendingInputCount = computed(() => stats.value.pending_input ?? 0);
const progressPct = computed(() =>
  totalTargets.value ? Math.round((resolvedTargets.value / totalTargets.value) * 100) : 0
);
const collectorCfg = computed(() => task.value?.fofa_config || {});
const collectorVisible = computed(() => {
  // 搜集终态自动隐藏进度条，不再占位：
  // FOFA 入队完成（dispatch）、证书透明度搜集完成（ct_done）/ 无根域名（ct_no_domains）。
  const phase = collectorCfg.value.collector_phase;
  if (phase === "dispatch" || phase === "ct_done" || phase === "ct_no_domains") return false;
  return !!(collectorCfg.value.collector_phase || collectorCfg.value.collector_phase_text);
});
const collectorText = computed(() =>
  collectorCfg.value.collector_phase_text || phaseLabel(collectorCfg.value.collector_phase) || "正在跑过滤器阶段"
);
const collectorMeta = computed(() => {
  const total = Number(collectorCfg.value.last_target_filter_total || 0);
  const done = Number(collectorCfg.value.last_target_filter_evaluated || 0);
  if (total > 0) return `过滤器 ${done}/${total}`;
  return phaseLabel(collectorCfg.value.collector_phase);
});
const collectorPct = computed(() => {
  const phase = collectorCfg.value.collector_phase || "";
  const total = Number(collectorCfg.value.last_target_filter_total || 0);
  const done = Number(collectorCfg.value.last_target_filter_evaluated || 0);
  if (phase === "prefilter") return 18;
  if (phase === "scoring") return 38;
  if (phase === "target_filter") return 62;
  if (phase === "enrich") return total > 0 ? Math.max(72, Math.min(88, Math.round((done / total) * 100))) : 78;
  if (phase === "dispatch") return 100;
  // 证书透明度搜集（手动"搜索新Target"）阶段进度
  if (phase === "ct_start") return 8;
  if (phase === "ct_query") return 28;
  if (phase === "ct_prefilter") return 50;
  if (phase === "ct_enqueue") return 80;
  if (phase === "ct_done") return 100;
  return 25;
});
function phaseLabel(phase) {
  return ({
    prefilter: "探活预筛",
    scoring: "评分归属",
    target_filter: "正在跑过滤器阶段",
    enrich: "补充情报",
    dispatch: "入队完成",
    ct_start: "CT 日志查询中",
    ct_query: "CT 日志查询中",
    ct_prefilter: "子域名预筛",
    ct_enqueue: "评分入库",
    ct_done: "搜集完成",
    ct_no_domains: "无根域名",
  }[phase] || phase || "");
}
const runState = computed(() => {
  const s = task.value?.status || "unknown";
  const label = { running: "运行中", idle: "空闲", paused: "已暂停", stopped: "已停止", created: "未启动" }[s] || s;
  const hint = s === "running" ? "24×7 自动补队列" : s === "idle" ? "等待新目标或人工动作" : "调度已收敛";
  return { label, hint };
});
const retestCard = computed(() => {
  const rs = retestSummary.value;
  if (!rs) return null;
  const isSleep = rs.phase === "phase3_sleep" || rs.phase === "noproxy_sleep";
  const isProxy = rs.mode === "proxy";

  // 阶段标题
  let phaseTitle = "";
  if (rs.phase === "phase1") phaseTitle = "Phase 1 · 本机探活";
  else if (rs.phase === "phase2") phaseTitle = "Phase 2 · 服务器测试";
  else if (rs.phase === "phase3_sleep") phaseTitle = `Phase 3 · 休眠中（第${rs.sleep_round + 1}轮）`;
  else if (rs.phase === "noproxy_round") phaseTitle = `第${rs.sleep_round + 1}轮 · 本机探活`;
  else if (rs.phase === "noproxy_sleep") phaseTitle = `第${rs.sleep_round + 1}轮休眠中`;
  else if (rs.phase === "done") phaseTitle = "重测完成";

  // 当前动作
  let action = "";
  if (isSleep) {
    if (rs.sleep_until) {
      const d = new Date(rs.sleep_until);
      action = `预计 ${d.getMonth() + 1}月${d.getDate()}日 ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")} 唤醒`;
    }
  } else if (rs.current_target) {
    const stepLabels = { probing: "正在探活", testing: "正在测试", idle: "等待中" };
    action = `${stepLabels[rs.current_step] || rs.current_step}: ${rs.current_target.host}`;
  }

  // 进度
  const total = rs.total || 0;
  const completed = rs.completed || 0;
  const pct = total > 0 ? Math.round((completed / total) * 100) : 0;

  // 统计行
  const stats = [];
  if (total > 0) stats.push(`已完成 ${completed}/${total}`);
  if (rs.remaining > 0) stats.push(`待处理 ${rs.remaining}`);
  if (rs.unreachable_count > 0) stats.push(`不可达 ${rs.unreachable_count}`);

  // 休眠时的额外信息
  let sleepInfo = "";
  if (isSleep && rs.remaining > 0) {
    sleepInfo = `${rs.remaining} 个目标等待复测`;
  }

  return {
    phaseTitle, action, pct, completed, total,
    isSleep, isProxy, stats: stats.join(" · "),
    sleepInfo,
  };
});
const modelName = computed(() =>
  task.value?.model_config_data?.model || task.value?.llm_usage?.model || "未配置模型"
);
const tokenUsage = computed(() => task.value?.llm_usage || {});
const llmUsageByModel = computed(() => task.value?.llm_usage_by_model || []);
const totalCost = computed(() =>
  llmUsageByModel.value.reduce((sum, m) => sum + (m.cost || 0), 0)
);
// 连接池使用率与状态色
const poolPct = computed(() => {
  const p = poolStats.value;
  if (!p || !p.total_capacity) return 0;
  return Math.round((p.checkedout / p.total_capacity) * 100);
});
const poolStatus = computed(() => {
  const pct = poolPct.value;
  if (pct >= 80) return "danger";
  if (pct >= 50) return "warn";
  return "ok";
});
function formatCost(c) {
  const v = Number(c || 0);
  if (v >= 100) return `¥${v.toFixed(0)}`;
  if (v >= 1) return `¥${v.toFixed(2)}`;
  if (v > 0) return `¥${v.toFixed(4)}`;
  return "—";
}
const cacheHitRate = computed(() => {
  const u = tokenUsage.value || {};
  const hit = Number(u.cache_hit_tokens || 0);
  const miss = Number(u.cache_miss_tokens || 0);
  const base = hit + miss || Number(u.prompt_tokens || 0);
  if (!base) return null;
  return Math.round((hit / base) * 100);
});
const isEnterpriseTask = computed(() => task.value?.src_type === "enterprise");
const taskModeName = computed(() => isEnterpriseTask.value ? "企业SRC" : "EduSRC");
const targetSourceName = computed(() => (({
  fofa: "FOFA",
  manual: "手动清单",
  both: "FOFA+手动",
  site: "单站协作",
})[task.value?.target_source] || task.value?.target_source || "-"));
const engineName = computed(() => (({
  fofa: "FOFA",
  quake: "360 Quake",
  hunter: "Hunter",
  zoomeye: "ZoomEye",
  shodan: "Shodan",
  censys: "Censys",
})[task.value?.engine] || task.value?.engine || "FOFA"));
const missionScopeText = computed(() => {
  if (task.value?.target_source === "site") {
    return task.value?.fofa_query || task.value?.manual_targets?.[0] || "单站协作";
  }
  return task.value?.fofa_query || "手动清单";
});
const missionEyebrow = computed(() => {
  if (task.value?.target_source === "site") return "COOPERATIVE SINGLE-SITE OPERATION";
  return isEnterpriseTask.value ? "AUTONOMOUS ENTERPRISE SRC OPERATION" : "AUTONOMOUS EDU SRC OPERATION";
});
const searchPlaceholder = computed(() =>
  isEnterpriseTask.value
    ? "搜索漏洞：标题 / URL / 类型 / 单位 / 系统 / 报告正文 / 审核备注"
    : "搜索漏洞：标题 / URL / 类型 / 学校 / 报告正文 / 审核备注"
);
const scopeCountLabel = computed(() => isEnterpriseTask.value ? "范围" : "教育");

const searchTokens = computed(() =>
  searchText.value.trim().toLowerCase().split(/\s+/).filter(Boolean)
);
const searchEnabled = computed(() => tab.value !== "board");
function stringifyForSearch(v) {
  if (v?._searchText) return v._searchText;
  return buildSearchText(v);
}
function buildSearchText(v) {
  const parts = [];
  try { parts.push(JSON.stringify(v ?? "", null, 0)); }
  catch { parts.push(String(v ?? "")); }
  return parts.join("\n").toLowerCase();
}
function withSearchCache(v) {
  return { ...v, _searchText: buildSearchText(v) };
}
function clearSearch() {
  clearTimeout(searchTimer);
  searchDraft.value = "";
  searchText.value = "";
}
function matchSearch(item) {
  const tokens = searchTokens.value;
  if (!tokens.length) return true;
  const text = stringifyForSearch(item);
  return tokens.every((t) => text.includes(t));
}
const filteredQueue = computed(() => queue.value.filter(matchSearch));
const filteredSubmit = computed(() => submitItems.value.filter(matchSearch));
const filteredKillsweeps = computed(() => killsweepItems.value.filter(matchSearch));
const filteredRejected = computed(() => rejectedItems.value.filter(matchSearch));
const filteredArchived = computed(() => archivedItems.value.filter(matchSearch));
const visibleCount = computed(() => {
  if (tab.value === "review") return filteredQueue.value.length;
  if (tab.value === "submit") return filteredSubmit.value.length;
  if (tab.value === "killsweep") return filteredKillsweeps.value.length;
  if (tab.value === "rejected") return filteredRejected.value.length;
  if (tab.value === "archived") return filteredArchived.value.length;
  return 0;
});
const rawCount = computed(() => {
  if (tab.value === "review") return queue.value.length;
  if (tab.value === "submit") return submitItems.value.length;
  if (tab.value === "killsweep") return killsweepItems.value.length;
  if (tab.value === "rejected") return rejectedItems.value.length;
  if (tab.value === "archived") return archivedItems.value.length;
  return 0;
});
function evClass(ev) { return `ev ${ev.level || "info"}`; }
function onDrawerUpdated() {
  refreshFromEvent({ kind: "review_updated" });
}
function evTime(ev) {
  const d = parseEventTs(ev.ts);
  return d.toLocaleTimeString("zh-CN", { hour12: false });
}
function parseEventTs(ts) {
  if (!ts) return new Date();
  // 后端时间统一是东八区（带 +08:00 偏移）。带时区标识（Z/+/-）直接解析；
  // 万一是无时区的 naive 串，按 UTC 补 Z，避免被当本地时区差 8 小时。
  const hasTz = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(ts);
  return new Date(hasTz ? ts : `${ts}Z`);
}
function fmtTime(iso) {
  if (!iso) return "";
  return iso.slice(0, 19).replace("T", " ");
}
</script>

<template>
  <section class="view board-view" :class="{ 'is-refreshing': refreshing, 'is-skeleton-loading': initialLoading && !task }">
    <div v-if="refreshing && !initialLoading" class="view-progress" aria-hidden="true"><i></i></div>

    <template v-if="initialLoading && !task">
      <div class="skeleton-hero">
        <div class="skeleton-block lg"></div>
        <div class="skeleton-block md"></div>
        <div class="skeleton-row">
          <span class="skeleton-chip"></span>
          <span class="skeleton-chip"></span>
          <span class="skeleton-chip wide"></span>
        </div>
      </div>
      <div class="metric-grid skeleton-metrics">
        <div v-for="n in 7" :key="n" class="skeleton-card"></div>
      </div>
      <div class="board-grid skeleton-board">
        <div class="board-panel skeleton-panel">
          <div class="skeleton-line sm-head"></div>
          <div v-for="n in 3" :key="n" class="skeleton-worker"></div>
        </div>
      </div>
    </template>

    <template v-else-if="task">
    <div class="mission-hero">
      <div class="mission-main">
        <div class="eyebrow">{{ missionEyebrow }}</div>
        <h2>{{ task.name }} <span class="badge" :class="task.status">{{ runState.label }}</span></h2>
        <div class="mission-meta">
          <span>{{ taskModeName }}</span>
          <span>{{ targetSourceName }}</span>
          <span v-if="task.engine && task.engine !== 'fofa'" class="engine-badge">🔍 {{ engineName }}</span>
          <span>{{ missionScopeText }}</span>
          <span>并发 {{ task.concurrency }}</span>
          <span>{{ runState.hint }}</span>
        </div>
        <div v-if="retestCard" class="retest-card">
          <div class="retest-card-header">
            <span class="retest-card-title">失败目标重测</span>
            <span class="retest-card-mode">{{ retestCard.isProxy ? "有代理" : "无代理" }}</span>
            <span class="retest-card-phase">{{ retestCard.phaseTitle }}</span>
            <span v-if="!retestCard.isSleep && retestCard.total > 0" class="retest-card-pct">{{ retestCard.pct }}%</span>
          </div>
          <div v-if="!retestCard.isSleep && retestCard.total > 0" class="retest-card-bar">
            <i :style="{ width: retestCard.pct + '%' }"></i>
          </div>
          <div class="retest-card-body">
            <span v-if="retestCard.action" class="retest-card-action">{{ retestCard.action }}</span>
            <span v-if="retestCard.sleepInfo" class="retest-card-sleep">{{ retestCard.sleepInfo }}</span>
            <span v-if="retestCard.stats" class="retest-card-stats">{{ retestCard.stats }}</span>
          </div>
        </div>
        <div class="mission-runtime">
          <span class="runtime-chip">
            <i>模型</i>
            <b :title="modelName">{{ modelName }}</b>
          </span>
          <span class="runtime-chip">
            <i>Token</i>
            <b>{{ formatTokenCount(tokenUsage.total_tokens) }}</b>
            <small>输入 {{ formatTokenCount(tokenUsage.prompt_tokens) }} / 输出 {{ formatTokenCount(tokenUsage.completion_tokens) }}</small>
            <small v-if="cacheHitRate !== null">缓存命中 {{ cacheHitRate }}%（命中价约 1/10）</small>
          </span>
          <span class="runtime-chip">
            <i>请求</i>
            <b>{{ tokenUsage.requests || 0 }}</b>
          </span>
          <span v-if="llmUsageByModel.length" class="runtime-chip cost-chip">
            <i>成本</i>
            <b>{{ formatCost(totalCost) }}</b>
            <small v-for="m in llmUsageByModel" :key="m.model" class="cost-model-row">
              {{ m.model }}: {{ formatTokenCount(m.prompt_tokens) }}入/{{ formatTokenCount(m.completion_tokens) }}出 → {{ formatCost(m.cost) }}
            </small>
          </span>
          <span v-if="poolStats" class="runtime-chip pool-chip" :class="`pool-${poolStatus}`" :title="`基础${poolStats.pool_size} + 溢出${poolStats.max_overflow} = 上限${poolStats.total_capacity} | 超时${poolStats.timeout}s`">
            <i>DB池</i>
            <b>{{ poolStats.checkedout }}/{{ poolStats.total_capacity }}</b>
            <span class="pool-bar"><i :style="{ width: poolPct + '%' }"></i></span>
            <small v-if="poolStats.overflow > 0">+{{ poolStats.overflow }}溢出</small>
          </span>
        </div>
      </div>
      <div class="mission-side">
        <div class="progress-ring">
          <b>{{ progressPct }}%</b>
          <span>处置进度</span>
        </div>
        <div class="mission-actions" v-if="!readonly">
          <button @click="openEdit">编辑参数</button>
          <button class="primary" @click="ctl('start')" :disabled="task.status === 'running'">启动</button>
          <button @click="ctl('pause')" :disabled="task.status !== 'running'">暂停</button>
          <button @click="ctl('stop')">停止</button>
          <button @click="collectTargets" :disabled="collectWorking">{{ collectWorking ? "搜索中..." : "搜索新Target" }}</button>
          <button class="danger" @click="showResetConfirm = true" :disabled="task.status === 'running'">重置进度</button>
          <button @click="showResetFailedConfirm = true">重置失败目标</button>
        </div>
        <div v-else class="mission-actions readonly-hint">{{ authRoleRef === 'readonly' ? "只读模式" : "未认证" }}</div>
      </div>
      <div class="mission-progress"><i :style="{ transform: `scaleX(${progressPct / 100})` }"></i></div>
    </div>

    <!-- 单站协作态势：三阶段流水线（侦察→主题深挖→定向追打），体现同站多路线协同 -->
    <section v-if="siteCollab" class="collab-panel">
      <header class="collab-head">
        <div class="collab-title">
          <span class="collab-badge">单站协作</span>
          <b>协作态势</b>
          <small>同一目标拆成多条路线协同攻击，共享覆盖上下文、逐阶段深入</small>
        </div>
        <div class="collab-summary">
          <span><i>{{ siteCollab.totals.routes }}</i>路线</span>
          <span class="live" v-if="siteCollab.totals.running"><i>{{ siteCollab.totals.running }}</i>进行中</span>
          <span class="hit" v-if="siteCollab.totals.findings"><i>{{ siteCollab.totals.findings }}</i>已出洞</span>
        </div>
      </header>
      <div class="collab-flow">
        <div
          v-for="(p, pi) in siteCollab.phases"
          :key="p.key"
          class="collab-phase"
          :class="[`state-${p.state}`, { current: p.phase === siteCollab.current_phase }]"
        >
          <div class="phase-rail">
            <span class="phase-dot"></span>
            <span v-if="pi < siteCollab.phases.length - 1" class="phase-line"></span>
          </div>
          <div class="phase-body">
            <div class="phase-head">
              <span class="phase-step">阶段 {{ p.phase + 1 }}</span>
              <b>{{ p.label }}</b>
              <span class="phase-state-tag" :class="`st-${p.state}`">{{ phaseStateText(p.state) }}</span>
            </div>
            <p class="phase-desc">{{ p.desc }}</p>
            <div v-if="p.routes.length" class="phase-routes">
              <div
                v-for="r in p.routes"
                :key="r.source"
                class="route-chip"
                :class="`rc-${r.status}`"
                :title="r.focus"
              >
                <span class="route-status-dot"></span>
                <span class="route-label">{{ r.label }}</span>
                <span v-if="r.findings" class="route-hit">{{ r.findings }}</span>
              </div>
            </div>
            <p v-else class="phase-empty">
              {{ p.phase === 0 ? "待启动" : (p.phase === 1 ? "等侦察完成后自动派发" : "等待侦察发现具体入口") }}
            </p>
          </div>
        </div>
      </div>
    </section>

    <div v-if="collectorVisible" class="collector-stage">
      <div class="collector-stage-head">
        <b>{{ collectorText }}</b>
        <span>{{ collectorMeta }}</span>
      </div>
      <div class="collector-stage-bar">
        <i :style="{ transform: `scaleX(${collectorPct / 100})` }"></i>
      </div>
    </div>

    <TaskEditModal :open="editOpen" :task="task" @close="closeEdit" @saved="onTaskSaved" />

    <div class="metric-grid">
      <div class="metric-card clickable" @click="openTargetPanel" title="点击查看目标列表">
        <span v-if="pendingInputCount" class="metric-badge pending-badge" @click.stop="openTargetPanel(); targetFilter = 'pending_input'; loadTargetList()" title="待注册目标">{{ pendingInputCount }}</span>
        <span class="metric-k">TARGETS</span><b>{{ totalTargets }}</b><em>目标总数</em>
      </div>
      <div class="metric-card active">
        <span class="metric-k">ACTIVE</span><b>{{ stats.scanning ?? 0 }}</b><em>扫描中</em>
      </div>
      <div class="metric-card">
        <span class="metric-k">DONE</span><b>{{ stats.done ?? 0 }}</b><em>已扫</em>
      </div>
      <div class="metric-card hot">
        <span class="metric-k">FINDINGS</span><b>{{ stats.findings_total ?? 0 }}</b><em>原始发现</em>
      </div>
      <div class="metric-card warn">
        <span class="metric-k">REVIEW</span><b>{{ reviewCount }}</b><em>待复审</em>
      </div>
      <div class="metric-card ok">
        <span class="metric-k">READY</span><b>{{ submitCount }}</b><em>待提交</em>
      </div>
      <div class="metric-card sweep">
        <span class="metric-k">SWEEP</span><b>{{ sweepCount }}</b><em>通杀列</em>
      </div>
    </div>

    <div class="tabs" role="tablist">
      <button type="button" role="tab" :aria-selected="tab === 'board'" :class="{ active: tab === 'board' }" @click="tab = 'board'">
        <span class="tab-long">实时看板</span><span class="tab-short">看板</span>
      </button>
      <button type="button" role="tab" :aria-selected="tab === 'review'" :class="{ active: tab === 'review' }" @click="tab = 'review'">
        <span class="tab-long">复审队列</span><span class="tab-short">复审</span>
        <i v-if="reviewCount">{{ reviewCount }}</i>
      </button>
      <button type="button" role="tab" :aria-selected="tab === 'submit'" :class="{ active: tab === 'submit' }" @click="tab = 'submit'">
        <span class="tab-long">待提交</span><span class="tab-short">提交</span>
        <i v-if="submitCount">{{ submitCount }}</i>
      </button>
      <button type="button" role="tab" :aria-selected="tab === 'killsweep'" :class="{ active: tab === 'killsweep' }" @click="tab = 'killsweep'">
        <span class="tab-long">通杀列</span><span class="tab-short">通杀</span>
        <i v-if="sweepCount">{{ sweepCount }}</i>
      </button>
      <button type="button" role="tab" :aria-selected="tab === 'rejected'" :class="{ active: tab === 'rejected' }" @click="tab = 'rejected'">
        <span class="tab-long">已驳回</span><span class="tab-short">驳回</span>
        <i v-if="rejectedCount">{{ rejectedCount }}</i>
      </button>
      <button type="button" role="tab" :aria-selected="tab === 'archived'" :class="{ active: tab === 'archived' }" @click="tab = 'archived'">
        <span class="tab-long">AI 未采纳</span><span class="tab-short">AI 未采纳</span>
        <i v-if="archivedCount">{{ archivedCount }}</i>
      </button>
    </div>

    <div v-if="searchEnabled" class="search-strip">
      <div class="search-box">
        <span>⌕</span>
        <input v-model="searchDraft" :placeholder="searchPlaceholder" />
      </div>
      <div class="search-stat">
        <template v-if="searchTokens.length">命中 {{ visibleCount }} / {{ rawCount }}</template>
        <template v-else>共 {{ rawCount }} 条</template>
      </div>
      <button class="search-clear" :class="{ hidden: !searchDraft.trim() }" @click="clearSearch">清空</button>
    </div>

    <!-- 看板 -->
    <div v-show="tab === 'board'" class="board-grid">
      <div class="board-mobile-switch" role="tablist" aria-label="看板视图">
        <button type="button" role="tab" :aria-selected="boardPanel === 'workers'"
          :class="{ active: boardPanel === 'workers' }" @click="boardPanel = 'workers'">
          Worker <i>{{ liveWorkers.length }}</i>
        </button>
        <button type="button" role="tab" :aria-selected="boardPanel === 'stream'"
          :class="{ active: boardPanel === 'stream' }" @click="boardPanel = 'stream'">
          活动流
        </button>
      </div>
      <!-- Worker 矩阵 -->
      <div class="board-col board-panel" :class="{ 'board-panel-hidden': boardPanel !== 'workers' }">
        <div class="col-head"><span>Worker Matrix</span><small>挖掘中</small><i class="cnt">{{ liveWorkers.length }}</i></div>
        <div v-if="!liveWorkers.length" class="empty sm">暂无运行中的 worker</div>
        <div v-for="w in liveWorkers" :key="w.target_id" class="worker-card">
          <div class="wc-top">
            <span class="wc-host">{{ w.host }}</span>
            <span class="wc-meta">
              <span v-if="w.score > 0" class="wc-score" :title="w.score_reason">★{{ w.score }}</span>
              第 {{ w.round }} 轮 · {{ elapsed(w.started_at) }}
            </span>
          </div>
          <div class="wc-action">{{ w.action }}</div>
          <div class="wc-foot">
            <span class="wc-find" :class="{ hit: w.findings > 0 }">
              {{ w.findings > 0 ? `🎯 ${w.findings} 个漏洞` : "侦察中…" }}
            </span>
            <span class="wc-bar"><i :style="{ transform: `scaleX(${Math.min(1, w.round / 60)})` }"></i></span>
          </div>
        </div>
      </div>

      <!-- 活动流 -->
      <div class="board-col board-panel" :class="{ 'board-panel-hidden': boardPanel !== 'stream' }">
        <div class="col-head"><span>Activity Stream</span><small>重要事件</small></div>
        <div class="event-log">
          <div v-if="!events.length" class="empty sm">等待事件…</div>
          <div v-for="(ev, i) in events" :key="i" :class="evClass(ev)">
            <span class="ev-icon" :class="`ag-${ev.agent}`">{{ AGENT_ICON[ev.agent] || "•" }}</span>
            <span class="ev-agent" :class="`ag-${ev.agent}`">{{ AGENT_LABEL[ev.agent] || ev.agent }}</span>
            <span class="ev-msg">{{ ev._text }}</span>
            <span class="ev-time">{{ evTime(ev) }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- 复审队列 -->
    <div v-show="tab === 'review'" class="list-panel">
      <div class="list-head"><span>复审队列</span><small>AI 采纳后等待人工裁决</small></div>
      <div v-if="queue.length" class="submit-toolbar">
        <small class="muted">{{ queue.length }} 条待复审</small>
        <span class="grow"></span>
        <button @click="exportReviewAllMd" :disabled="!queue.length || bulkWorking">导出全部 .md</button>
        <button @click="exportReviewAllPy" :disabled="!queue.length || bulkWorking">导出全部 .py</button>
      </div>
      <div v-if="!queue.length" class="empty">没有待复审的漏洞（AI 采纳后会进这里）</div>
      <div v-else-if="!filteredQueue.length" class="empty">没有匹配当前关键词的复审漏洞</div>
      <div v-for="f in filteredQueue" :key="f.id" class="result-row" @click="openReview(f.id)">
        <span class="sev-pill" :class="effectiveSeverity(f)">{{ effectiveSeverity(f) }}</span>
        <div class="rr-main">
          <div class="rr-title">{{ f.title }}</div>
          <div class="meta">{{ f.vuln_type }} · {{ f.target_url }} · {{ fmtTime(f.created_at) }}</div>
        </div>
        <div class="rr-actions" @click.stop>
          <button class="rr-dl" title="下载 Markdown" @click="downloadReviewMd(f)">MD</button>
          <button class="rr-dl" title="下载 PoC 脚本" @click="downloadReviewPy(f)">PY</button>
        </div>
        <span class="score">{{ f.review?.score ?? "-" }}</span>
      </div>
    </div>

    <!-- 待提交 -->
    <div v-show="tab === 'submit'" class="list-panel">
      <div class="list-head"><span>待提交</span><small>人工通过后的 SRC 报告池</small></div>
      <div class="submit-toolbar">
        <label class="inline"><input type="checkbox" v-model="submittedFilter" @change="loadTabData('submit')" /> 只看已提交</label>
        <small v-if="submitItems.length" class="muted">已加载 {{ submitItems.length }} 条{{ submitHasMore ? "，还有更多" : "" }}</small>
        <span class="grow"></span>
        <button @click="copyAll" :disabled="!submitItems.length || bulkWorking">复制全部 Markdown</button>
        <button @click="exportAll" :disabled="!submitItems.length || bulkWorking">导出 .md</button>
        <button v-if="!isEnterpriseTask" @click="copyEdusrcAll" :disabled="!submitItems.length || bulkWorking">复制 EduSRC JSON</button>
        <button v-if="!isEnterpriseTask" @click="exportEdusrcAll" :disabled="!submitItems.length || bulkWorking">导出 reports.json</button>
      </div>
      <div v-if="!submitItems.length" class="empty">还没有通过复审的漏洞</div>
      <div v-else-if="!filteredSubmit.length" class="empty">没有匹配当前关键词的待提交漏洞</div>
      <div v-for="f in filteredSubmit" :key="f.id" class="result-row" :class="{ submitted: f.review?.submitted }" @click="openSubmit(f.id)">
        <span class="sev-pill" :class="effectiveSeverity(f)">{{ effectiveSeverity(f) }}</span>
        <div class="rr-main">
          <div class="rr-title">{{ f.title }} <span v-if="f.review?.submitted" class="tag-done">已提交</span></div>
          <div class="meta">{{ f.vuln_type }} · {{ f.target_url }}</div>
        </div>
        <span class="score">{{ f.review?.score ?? "-" }}</span>
      </div>
      <button v-if="submitHasMore" class="load-more" @click="loadMoreSubmit" :disabled="submitLoading">
        {{ submitLoading ? "加载中..." : "加载更多已提交/待提交" }}
      </button>
    </div>

    <!-- 通杀列 -->
    <div v-show="tab === 'killsweep'" class="list-panel">
      <div class="list-head"><span>通杀列</span><small>人工通过后触发，验证 1 个同款站点</small></div>
      <div v-if="!killsweepItems.length" class="empty">还没有通杀候选（人工复审通过后，通杀 Hunter 会自动分析同款系统）</div>
      <div v-else-if="!filteredKillsweeps.length" class="empty">没有匹配当前关键词的通杀记录</div>
      <div v-for="k in filteredKillsweeps" :key="k.id" class="killsweep-card" :class="{ open: isKillsweepOpen(k.id) }">
        <button class="ks-summary" type="button" :aria-expanded="isKillsweepOpen(k.id)" @click="toggleKillsweep(k.id)">
          <span class="ks-chevron">{{ isKillsweepOpen(k.id) ? "⌄" : "›" }}</span>
          <span class="ks-main">
            <span class="ks-title">{{ k.product_name || "未知产品" }}</span>
            <span class="meta">{{ k.vuln_type }} · {{ k.origin_title || k.vuln_summary || "通杀候选" }}</span>
          </span>
          <span class="ks-summary-metrics">
            <span><b>{{ assetRows(k).length }}</b>资产</span>
            <span><b>{{ isEnterpriseTask ? (k.asset_count ?? 0) : (k.edu_count ?? 0) }}</b>{{ scopeCountLabel }}</span>
            <span><b>{{ k.asset_count ?? 0 }}</b>全网</span>
          </span>
          <span class="ks-badges">
            <span class="tag-done" v-if="k.verified">已验证</span>
            <span class="sev-pill" :class="k.confidence">{{ k.confidence || "uncertain" }}</span>
          </span>
        </button>

        <div v-if="isKillsweepOpen(k.id)" class="ks-detail">
          <div class="ks-compact">
            <div>
              <span>FOFA 语法</span>
              <code>{{ k.fofa_query || "无 FOFA 语法" }}</code>
            </div>
            <div>
              <span>指纹依据</span>
              <p>{{ k.fingerprint || k.notes || "无补充依据" }}</p>
            </div>
          </div>

          <div class="ks-affected">
            <div class="ks-affected-head">
              <span>统一资产列表</span>
              <small>{{ assetRows(k).length }} 条 · 强制字段：单位/系统 / 目标 / 漏洞 / 状态 / 依据</small>
            </div>
            <div v-if="!assetRows(k).length" class="empty sm">暂无资产明细，仅保留通杀摘要。</div>
            <table v-else>
              <thead>
                <tr>
                  <th>单位</th>
                  <th>目标</th>
                  <th>通杀洞</th>
                  <th>状态</th>
                  <th>依据</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(row, idx) in assetRows(k)" :key="row.dedup_key || row.url || row.host || idx">
                  <td>{{ row.school || "待确认" }}</td>
                  <td><span class="mono">{{ row.url || row.host || "-" }}</span></td>
                  <td>{{ row.vuln_title || k.vuln_summary || k.origin_title || "-" }}</td>
                  <td><span class="asset-status" :class="{ verified: row.status === 'verified' }">{{ assetStatusLabel(row.status) }}</span></td>
                  <td>{{ row.evidence || "-" }}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div class="ks-actions" v-if="!readonly">
            <button class="ks-invalid" type="button" :disabled="invalidatingKillsweepId === k.id" @click="invalidateKillsweep(k)">
              {{ invalidatingKillsweepId === k.id ? "标记中…" : "标记为无效" }}
            </button>
            <span>误判、资产不稳定、未实际验证或通杀条件不成立时使用。</span>
          </div>
        </div>
      </div>
    </div>

    <!-- 已驳回 -->
    <div v-show="tab === 'rejected'" class="list-panel">
      <div class="list-head"><span>已驳回</span><small>沉淀不收口径，可恢复或继续深挖</small></div>
      <div v-if="!rejectedItems.length" class="empty">还没有被驳回的漏洞（复审点「不通过」会进这里，可回看与恢复）</div>
      <div v-else-if="!filteredRejected.length" class="empty">没有匹配当前关键词的驳回漏洞</div>
      <div v-for="f in filteredRejected" :key="f.id" class="result-row rejected" @click="openRejected(f.id)">
        <span class="sev-pill" :class="effectiveSeverity(f)">{{ effectiveSeverity(f) }}</span>
        <div class="rr-main">
          <div class="rr-title">{{ f.title }}</div>
          <div class="meta">{{ f.vuln_type }} · {{ f.target_url }}</div>
          <div v-if="f.review?.user_notes" class="meta rr-note">驳回备注：{{ f.review.user_notes }}</div>
        </div>
        <span class="score">{{ f.review?.score ?? "-" }}</span>
      </div>
    </div>

    <!-- AI 未采纳归档：ignored（疑似误杀）/ deepen 未升级，保留可回看纠错，一键救回复审 -->
    <div v-show="tab === 'archived'" class="list-panel">
      <div class="list-head">
        <span>AI 未采纳</span>
        <small>AI 判为非漏洞或深挖未升级的洞，保留在此防误杀，可点开查看、必要时「恢复到复审」</small>
        <small v-if="archivedItems.length" class="muted">已加载 {{ archivedItems.length }} 条{{ archivedHasMore ? "，还有更多" : "" }}</small>
      </div>
      <div v-if="!archivedItems.length" class="empty">
        暂无 AI 未采纳的漏洞（AI 审核判「非漏洞」或「深挖未升级」的洞会沉淀到这里，防止误杀）
      </div>
      <div v-else-if="!filteredArchived.length" class="empty">没有匹配当前关键词的未采纳漏洞</div>
      <div v-for="f in filteredArchived" :key="f.id" class="result-row archived" @click="openArchived(f.id)">
        <span class="sev-pill" :class="effectiveSeverity(f)">{{ effectiveSeverity(f) }}</span>
        <div class="rr-main">
          <div class="rr-title">
            <span class="arch-tag" :class="f.archive_reason">{{ f.archive_reason_text }}</span>
            {{ f.title }}
          </div>
          <div class="meta">{{ f.vuln_type }} · {{ f.target_url }} · {{ fmtTime(f.created_at) }}</div>
          <div v-if="f.ignore_reasons?.length" class="meta rr-note">AI 理由：{{ f.ignore_reasons.join("；") }}</div>
        </div>
        <div class="rr-side" @click.stop>
          <span class="score">{{ f.review?.score ?? "-" }}</span>
          <button v-if="!readonly" class="mini-action" type="button" @click="restoreArchived(f.id)">恢复到复审</button>
        </div>
      </div>
      <button v-if="archivedHasMore" class="load-more" @click="loadMoreArchived" :disabled="archivedLoading">
        {{ archivedLoading ? "加载中..." : "加载更多未采纳漏洞" }}
      </button>
    </div>

    <ReportDrawer :finding-id="drawerId" :mode="drawerMode" :src-type="task.src_type"
      @close="drawerId = null" @updated="onDrawerUpdated" @toast="toast" />

       <!-- 重置进度确认弹窗 -->
    <div v-if="showResetConfirm" class="modal-overlay" @click.self="showResetConfirm = false">
      <div class="modal-card reset-confirm">
        <h3>重置任务进度</h3>
        <p>将所有目标重置为排队中，保留已发现的漏洞作为去重屏障。<br/>
        Worker 重挖时将自动跳过已发现的漏洞，专注探索新攻击面。</p>
        <p v-if="task?.status === 'running'" class="warn-text">任务运行中，请先停止任务再重置。</p>
        <div class="modal-actions">
          <button @click="showResetConfirm = false">取消</button>
          <button class="danger" @click="resetProgress" :disabled="resetWorking || task?.status === 'running'">
            {{ resetWorking ? "重置中..." : "确认重置" }}
          </button>
        </div>
      </div>
    </div>

    <!-- 重置失败目标确认弹窗 -->
    <div v-if="showResetFailedConfirm" class="modal-overlay" @click.self="showResetFailedConfirm = false">
      <div class="modal-card reset-confirm">
        <h3>重置失败目标</h3>
        <p>仅重置因以下原因变为「硬骨头」的目标，重新入队探活：<br/>
        • 派发前探活失败（死链/连接超时/无响应）<br/>
        • Worker 连续网络超时/工具失败后系统自动收敛</p>
        <p>任务运行中也可操作，不影响正在挖掘的目标。已发现的漏洞将作为去重屏障保留。</p>
        <div class="modal-actions">
          <button @click="showResetFailedConfirm = false">取消</button>
          <button class="danger" @click="resetFailedTargets" :disabled="resetFailedWorking">
            {{ resetFailedWorking ? "重置中..." : "确认重置" }}
          </button>
        </div>
      </div>
    </div>

    <!-- Target 面板 -->
    <div v-if="targetPanelOpen" class="modal-overlay target-panel-overlay" @click.self="closeTargetPanel">
      <div class="modal-card target-panel">
        <!-- Target 列表视图 -->
        <template v-if="!targetDetailData">
          <div class="tp-header">
            <h3>目标列表 <small>{{ filteredTargetList.length }}/{{ targetList.length }} 个目标</small></h3>
            <button class="tp-close" @click="closeTargetPanel">✕</button>
          </div>
          <div class="tp-filters">
            <button v-for="s in ['', 'alive', 'queued', 'done', 'dead', 'skipped', 'pending_input']"
              :key="s"
              :class="{ active: targetFilter === s }"
              @click="targetFilter = s; loadTargetList()">
              {{ s === '' ? '全部' : s === 'alive' ? '在挖' : TARGET_STATUS_LABELS[s] || s }}
            </button>
          </div>
          <div class="tp-search">
            <span>⌕</span>
            <input v-model="targetSearch" placeholder="搜索：域名 / URL / 标题 / 学校 / 单位" />
          </div>
          <div class="tp-list">
            <div v-if="targetListLoading" class="empty sm">加载中...</div>
            <div v-else-if="!filteredTargetList.length" class="empty sm">{{ targetSearch.trim() ? '没有匹配的目标' : '暂无目标' }}</div>
            <div v-for="t in filteredTargetList" :key="t.id" class="tp-row" @click="openTargetDetail(t.id)">
              <span class="tp-status" :class="`st-${t.status}`">{{ TARGET_STATUS_LABELS[t.status] || t.status }}</span>
              <div class="tp-info">
                <div class="tp-host">{{ t.host || t.url }}</div>
                <div class="tp-meta">
                  <span v-if="t.title">{{ t.title }}</span>
                  <span v-if="t.school">{{ t.school }}</span>
                  <span v-if="t.is_edu" class="edu-tag">教育</span>
                  <span v-if="t.deepen_count">深挖×{{ t.deepen_count }}</span>
                  <span v-if="t.retry_count">重试×{{ t.retry_count }}</span>
                </div>
                <div v-if="t.dead_reason || t.last_error" class="tp-error">{{ t.dead_reason || t.last_error }}</div>
              </div>
              <span class="tp-score" v-if="t.priority_score > 0">★{{ Math.round(t.priority_score) }}</span>
            </div>
          </div>
        </template>

        <!-- Target 明细视图 -->
        <template v-else>
          <div class="tp-header">
            <button class="tp-back" @click="closeTargetDetail">← 返回列表</button>
            <h3 v-if="targetDetailData.target">
              {{ targetDetailData.target.host || targetDetailData.target.url }}
            </h3>
            <button class="tp-close" @click="closeTargetPanel">✕</button>
          </div>
          <div v-if="targetDetailLoading" class="empty sm">加载中...</div>
          <template v-else-if="targetDetailData.target">
            <div class="tp-detail-info">
              <div class="tp-detail-row">
                <span class="tp-label">状态</span>
                <span class="tp-status" :class="`st-${targetDetailData.target.status}`">
                  {{ TARGET_STATUS_LABELS[targetDetailData.target.status] || targetDetailData.target.status }}
                </span>
              </div>
              <div class="tp-detail-row" v-if="targetDetailData.target.title">
                <span class="tp-label">标题</span>
                <span>{{ targetDetailData.target.title }}</span>
              </div>
              <div class="tp-detail-row" v-if="targetDetailData.target.school">
                <span class="tp-label">归属</span>
                <span>{{ targetDetailData.target.school }}</span>
              </div>
              <div class="tp-detail-row" v-if="targetDetailData.target.org">
                <span class="tp-label">单位</span>
                <span>{{ targetDetailData.target.org }}</span>
              </div>
              <div class="tp-detail-row" v-if="targetDetailData.target.ip">
                <span class="tp-label">IP</span>
                <span>{{ targetDetailData.target.ip }}</span>
              </div>
              <div class="tp-detail-row" v-if="targetDetailData.target.dead_reason">
                <span class="tp-label">终止原因</span>
                <span class="tp-error-text">{{ targetDetailData.target.dead_reason }}</span>
              </div>
              <div class="tp-detail-row" v-if="targetDetailData.target.priority_reason">
                <span class="tp-label">优先级理由</span>
                <span class="tp-reason-text">{{ targetDetailData.target.priority_reason }}</span>
              </div>
            </div>

            <!-- AI 注册评估 + 凭证提交（仅 pending_input 状态） -->
            <div v-if="targetDetailData.target.status === 'pending_input' && targetDetailData.target.auth_assessment" class="tp-auth-section">
              <div class="tp-section-head"><span>AI 注册评估</span></div>
              <div class="tp-auth-box">
                <div class="tp-auth-row">
                  <span class="tp-label">注册可行性</span>
                  <span class="tp-auth-status" :class="`reg-${targetDetailData.target.auth_assessment.reg_status}`">
                    {{ ({registrable_verification_needed: '✅ 可注册（仅差验证码）', not_registrable: '❌ 不可注册', registrable_no_blocker: '✅ 可注册'})[targetDetailData.target.auth_assessment.reg_status] || targetDetailData.target.auth_assessment.reg_status }}
                  </span>
                </div>
                <div class="tp-auth-row" v-if="targetDetailData.target.auth_assessment.block_reason">
                  <span class="tp-label">阻断原因</span>
                  <span>{{ targetDetailData.target.auth_assessment.block_reason }}</span>
                </div>
                <div class="tp-auth-row">
                  <span class="tp-label">注册地址</span>
                  <a :href="targetDetailData.target.auth_assessment.registration_url || targetDetailData.target.url" target="_blank" class="tp-link">
                    {{ targetDetailData.target.auth_assessment.registration_url || targetDetailData.target.url }}
                    <small v-if="!targetDetailData.target.auth_assessment.registration_url" class="tp-link-hint">（目标主页，注册入口需手动寻找）</small>
                  </a>
                </div>
                <div class="tp-auth-row" v-if="targetDetailData.target.auth_assessment.evidence_request">
                  <span class="tp-label">AI 尝试证据</span>
                  <pre class="tp-auth-evidence">{{ targetDetailData.target.auth_assessment.evidence_request }}</pre>
                </div>
                <div class="tp-auth-row" v-if="targetDetailData.target.auth_assessment.what_user_needs_to_provide">
                  <span class="tp-label">需要提供</span>
                  <span>{{ targetDetailData.target.auth_assessment.what_user_needs_to_provide }}</span>
                </div>
                <div class="tp-auth-row" v-if="targetDetailData.target.auth_assessment.next_steps">
                  <span class="tp-label">下一步建议</span>
                  <span>{{ targetDetailData.target.auth_assessment.next_steps }}</span>
                </div>
              </div>

              <!-- AI 问答：进一步询问注册条件 -->
              <div class="tp-ta-section">
                <div class="tp-ta-head">
                  <div>
                    <span>注册助手</span>
                    <small>{{ readonly ? "未认证，请先换令牌" : "问注册条件、问阻断原因、问流程；也可让它访问注册页验证" }}</small>
                  </div>
                  <div v-if="!readonly" class="tp-ta-actions">
                    <button @click="askTargetAssistant('这个目标需要什么条件才能注册？帮我总结一下。')" :disabled="targetAssistantBusy">注册条件</button>
                    <button @click="askTargetAssistant('帮我看一下注册页面是否可以正常访问，注册流程是什么。')" :disabled="targetAssistantBusy">查看注册页</button>
                  </div>
                </div>
                <div class="tp-ta-log">
                  <div v-for="(m, i) in targetAssistantMessages" :key="i" class="tp-ta-msg" :class="m.role">
                    <span>{{ m.role === "user" ? "你" : "助手" }}</span>
                    <div class="tp-ta-body">
                      <ul v-if="m.steps && m.steps.length" class="tp-ta-steps">
                        <li v-for="(s, si) in m.steps" :key="si" class="tp-ta-step" :class="s.type">
                          <span class="tp-ta-step-ico">{{ s.type === "tool_call" ? "⚙" : s.type === "thinking" ? "…" : "•" }}</span>
                          <span class="tp-ta-step-txt">
                            {{ s.label }}
                            <em v-if="s.result" class="tp-ta-step-res">{{ s.result }}</em>
                          </span>
                        </li>
                      </ul>
                      <div v-if="m.streaming && m.partial && !m.content" class="tp-ta-md tp-ta-partial" v-html="renderTargetAssistantMd(m.partial)"></div>
                      <div v-if="m.content" class="tp-ta-md" v-html="renderTargetAssistantMd(m.content)"></div>
                      <div v-if="m.streaming && !m.content && !m.partial && !(m.steps && m.steps.length)" class="tp-ta-md tp-ta-pending"><p>正在分析…</p></div>
                      <span v-if="m.streaming" class="tp-ta-cursor">▍</span>
                    </div>
                  </div>
                </div>
                <div v-if="!readonly" class="tp-ta-input">
                  <textarea v-model="targetAssistantText" rows="2"
                    placeholder="例：这个网站注册需要什么条件？有没有邀请码？"
                    @keydown.enter.exact="onChatEnter($event, askTargetAssistant)"></textarea>
                  <button class="primary" @click="askTargetAssistant()" :disabled="targetAssistantBusy || !targetAssistantText.trim()">发送</button>
                </div>
              </div>

              <!-- 凭证提交表单（仅可注册的目标） -->
              <div v-if="targetDetailData.target.auth_assessment.reg_status !== 'not_registrable' && !readonly" class="tp-cred-form">
                <div class="tp-section-head"><span>提交凭证并复测</span></div>
                <div class="tp-cred-type">
                  <label><input type="radio" v-model="credType" value="password" /> 账号密码</label>
                  <label><input type="radio" v-model="credType" value="cookie" /> Cookie/Token</label>
                </div>
                <template v-if="credType === 'password'">
                  <input v-model="credUsername" placeholder="账号" class="tp-cred-input" />
                  <input v-model="credPassword" type="password" placeholder="密码" class="tp-cred-input" />
                </template>
                <template v-else>
                  <textarea v-model="credCookie" placeholder="Cookie 或 Authorization Token" class="tp-cred-input tp-cred-textarea"></textarea>
                </template>
                <div class="tp-cred-actions">
                  <button class="primary" @click="submitCredentials(targetDetailData.target.id)" :disabled="credWorking">
                    {{ credWorking ? "提交中..." : "提交凭证并复测" }}
                  </button>
                  <button @click="skipTarget(targetDetailData.target.id)" :disabled="credWorking">跳过此目标</button>
                </div>
              </div>
            </div>

            <!-- 重挖按钮 -->
            <div class="tp-redig-bar" v-if="!readonly">
              <div class="tp-redig-info">
                <span v-if="targetDetailData.target.existing_findings > 0">
                  已发现 <b>{{ targetDetailData.target.existing_findings }}</b> 个漏洞（将作为去重屏障）
                </span>
                <span v-else>该目标尚未发现漏洞</span>
              </div>
              <button class="danger" @click="redigTarget(targetDetailData.target.id)"
                :disabled="redigWorking || targetDetailData.target.status === 'scanning' || targetDetailData.target.status === 'assigned'">
                {{ redigWorking ? "重挖中..." : "重挖此目标" }}
              </button>
            </div>

            <!-- Findings 列表 -->
            <div class="tp-section-head" v-if="targetDetailData.findings?.length">
              <span>漏洞列表 ({{ targetDetailData.findings.length }})</span>
              <small>点击查看详情</small>
            </div>
            <div v-if="targetDetailData.findings?.length" class="tp-findings">
              <div v-for="f in targetDetailData.findings" :key="f.id" class="tp-finding"
                @click="drawerId = f.id; drawerMode = 'view'; targetPanelOpen = false">
                <span class="sev-pill" :class="effectiveSeverity(f)">{{ effectiveSeverity(f) }}</span>
                <div class="tp-finding-main">
                  <div class="tp-finding-title">{{ f.title }}</div>
                  <div class="tp-finding-meta">
                    {{ f.vuln_type }} · {{ f.target_url }}
                    <span v-if="f.review?.verdict"> · 审核: {{ f.review.verdict }}</span>
                  </div>
                </div>
                <span class="tp-finding-status" :class="`fs-${f.status}`">{{ f.status }}</span>
              </div>
            </div>
            <div v-else class="empty sm">该目标暂无漏洞记录</div>

            <!-- 事件历史 -->
            <div class="tp-section-head" v-if="targetDetailData.events?.length">
              <span>事件历史 ({{ targetDetailData.events.length }})</span>
            </div>
            <div v-if="targetDetailData.events?.length" class="tp-events">
              <div v-for="(e, i) in targetDetailData.events" :key="i" class="tp-event">
                <span class="tp-event-agent">{{ AGENT_LABEL[e.agent] || e.agent }}</span>
                <span class="tp-event-kind">{{ e.kind }}</span>
                <span class="tp-event-msg" v-if="e.message">{{ e.message }}</span>
                <span class="tp-event-ts">{{ fmtTime(e.ts) }}</span>
              </div>
            </div>
          </template>
        </template>
      </div>
    </div>

    <div v-if="toastMsg" class="toast">{{ toastMsg }}</div>
    </template>
  </section>
</template>
