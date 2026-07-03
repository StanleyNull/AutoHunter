<script setup>
import { ref, onMounted, onUnmounted, computed, watch } from "vue";
import { api, wsUrl, authRoleRef, authReadyRef, loadAuthRole } from "../api.js";
import { copyText } from "../clipboard.js";
import { effectiveSeverity, buildReportMd, buildEdusrcToolReport } from "../report.js";
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
let ws = null, poll = null, boardPoll = null, searchTimer = null;
let wsReconnectTimer = null, wsReconnectAttempt = 0, wsIntentionalClose = false;
let eventRefreshTimer = null, eventRefreshPending = null;
const LIST_TABS = new Set(["review", "submit", "killsweep", "rejected", "archived"]);
// 记录哪些列表 tab 已经加载过数据：首屏只拉看板，列表按需加载；后台只刷新看过的列表。
const loadedTabs = ref(new Set());

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
  if (task.value) {
    if (b.task_status) task.value.status = b.task_status;
    if (b.stats) task.value.stats = b.stats;
    if (b.fofa_config) task.value.fofa_config = b.fofa_config;
    if (b.model_config_data) task.value.model_config_data = b.model_config_data;
    if (b.llm_usage) task.value.llm_usage = b.llm_usage;
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
        || k.includes("submit") || k.includes("killsweep") || k.includes("worker")) {
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

function syncPollers() {
  clearInterval(poll);
  clearInterval(boardPoll);
  const running = task.value?.status === "running";
  boardPoll = setInterval(loadBoard, running ? 2500 : 12000);
  poll = setInterval(() => refreshAll({
    background: true,
    includeTask: false,
    includeBoard: false,
  }), running ? 15000 : 30000);
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
  (stats.value.done ?? 0) + (stats.value.dead ?? 0) + (stats.value.skipped ?? 0)
);
const resolvedTargets = computed(() =>
  (stats.value.done ?? 0) + (stats.value.dead ?? 0) + (stats.value.skipped ?? 0)
);
const progressPct = computed(() =>
  totalTargets.value ? Math.round((resolvedTargets.value / totalTargets.value) * 100) : 0
);
const collectorCfg = computed(() => task.value?.fofa_config || {});
const collectorVisible = computed(() =>
  !!(collectorCfg.value.collector_phase || collectorCfg.value.collector_phase_text)
);
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
  return 25;
});
function phaseLabel(phase) {
  return ({
    prefilter: "探活预筛",
    scoring: "评分归属",
    target_filter: "正在跑过滤器阶段",
    enrich: "补充情报",
    dispatch: "入队完成",
  }[phase] || phase || "");
}
const runState = computed(() => {
  const s = task.value?.status || "unknown";
  const label = { running: "运行中", idle: "空闲", paused: "已暂停", stopped: "已停止", created: "未启动" }[s] || s;
  const hint = s === "running" ? "24×7 自动补队列" : s === "idle" ? "等待新目标或人工动作" : "调度已收敛";
  return { label, hint };
});
const modelName = computed(() =>
  task.value?.model_config_data?.model || task.value?.llm_usage?.model || "未配置模型"
);
const tokenUsage = computed(() => task.value?.llm_usage || {});
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
  // 后端时间统一是 UTC。带时区标识（Z/+/-）直接解析；
  // 万一是无时区的 naive 串（如 2026-06-27T02:29:00），按 UTC 补 Z，避免被当本地时区差 8 小时。
  const hasTz = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(ts);
  return new Date(hasTz ? ts : `${ts}Z`);
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
          <span>{{ missionScopeText }}</span>
          <span>并发 {{ task.concurrency }}</span>
          <span>{{ runState.hint }}</span>
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
      <div class="metric-card">
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
      <div v-if="!queue.length" class="empty">没有待复审的漏洞（AI 采纳后会进这里）</div>
      <div v-else-if="!filteredQueue.length" class="empty">没有匹配当前关键词的复审漏洞</div>
      <div v-for="f in filteredQueue" :key="f.id" class="result-row" @click="openReview(f.id)">
        <span class="sev-pill" :class="effectiveSeverity(f)">{{ effectiveSeverity(f) }}</span>
        <div class="rr-main">
          <div class="rr-title">{{ f.title }}</div>
          <div class="meta">{{ f.vuln_type }} · {{ f.target_url }}</div>
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
          <div class="meta">{{ f.vuln_type }} · {{ f.target_url }}</div>
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
    <div v-if="toastMsg" class="toast">{{ toastMsg }}</div>
    </template>
  </section>
</template>
