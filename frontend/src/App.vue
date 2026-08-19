<script setup>
import { computed, ref, onMounted, onUnmounted, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import {
  applyAccessToken,
  authReadyRef,
  authRoleRef,
  cancelTokenModal,
  loadAuthRole,
  submitTokenModal,
  api,
} from "./api.js";
const route = useRoute();
const router = useRouter();

const theme = ref("light");
const showTokenModal = ref(false);
const tokenInput = ref("");
const tokenModalReason = ref("switch");
const toastMsg = ref("");
const CUSTOM_BG_KEY = "ah-custom-background-image";


const showGlobalSearch = ref(false);
const showCreateMenu = ref(false);
const showBgModal = ref(false);
const backgroundInput = ref("");
const globalSearchDraft = ref("");
const globalSearchResults = ref([]);
const globalSearchLoading = ref(false);
const navStats = ref({ running: 0, total: 0, errors: 0, warns: 0, vulns: 0, intel: 0 });
let globalSearchTimer = null;
let navStatsTimer = null;

const noticeCount = computed(() => (navStats.value.errors || 0) + (navStats.value.warns || 0));
const runningLabel = computed(() => {
  const running = navStats.value.running || 0;
  if (running > 0) return `${running} 运行中`;
  return "空闲";
});

function isRunningTask(t) {
  return ["running", "queued", "starting", "resuming"].includes(String(t?.status || "").toLowerCase());
}

async function refreshNavStats() {
  try {
    const [tasks, runtime, vuln, intel] = await Promise.allSettled([
      api.listTasks(),
      api.runtimeLogStats(),
      api.vulnStats(),
      api.intelStats(),
    ]);
    const taskItems = tasks.status === "fulfilled" && Array.isArray(tasks.value) ? tasks.value : [];
    navStats.value = {
      running: taskItems.filter(isRunningTask).length,
      total: taskItems.length,
      errors: runtime.status === "fulfilled" ? Number(runtime.value?.errors || 0) : navStats.value.errors,
      warns: runtime.status === "fulfilled" ? Number(runtime.value?.warns || 0) : navStats.value.warns,
      vulns: vuln.status === "fulfilled" ? Number(vuln.value?.total || 0) : navStats.value.vulns,
      intel: intel.status === "fulfilled" ? Number(intel.value?.total || 0) : navStats.value.intel,
    };
  } catch {
    // keep last known values
  }
}

function openGlobalSearch() {
  showCreateMenu.value = false;
  showGlobalSearch.value = true;
  setTimeout(() => document.querySelector(".global-search-input")?.focus(), 0);
}

function closeGlobalSearch() {
  showGlobalSearch.value = false;
  globalSearchDraft.value = "";
  globalSearchResults.value = [];
}

function makeResult(type, title, meta, path) {
  return { type, title: title || "-", meta: meta || "", path };
}

async function runGlobalSearch(q) {
  const text = q.trim();
  if (!text) {
    globalSearchResults.value = [];
    return;
  }
  globalSearchLoading.value = true;
  try {
    const [tasks, vulns, intel, logs] = await Promise.allSettled([
      api.listTasks(),
      api.vulns("all", "", text, { limit: 6, offset: 0 }),
      api.intelList("all", "all", text, 6),
      api.runtimeLogs("all", "all", text, { limit: 6, offset: 0 }),
    ]);
    const results = [];
    if (tasks.status === "fulfilled" && Array.isArray(tasks.value)) {
      const lower = text.toLowerCase();
      tasks.value
        .filter((t) => `${t.name || ""} ${t.fofa_query || ""} ${t.status || ""}`.toLowerCase().includes(lower))
        .slice(0, 6)
        .forEach((t) => results.push(makeResult("任务", t.name || t.id, `${t.status || "unknown"} - ${t.id}`, `/task/${t.id}`)));
    }
    const vulnItems = vulns.status === "fulfilled" ? (Array.isArray(vulns.value) ? vulns.value : (vulns.value?.items || [])) : [];
    vulnItems.slice(0, 6).forEach((v) => results.push(makeResult("漏洞", v.title, `${v.vuln_type || "-"} - ${v.target_url || ""}`, v.task_id ? `/task/${v.task_id}` : "/vulns")));
    const intelItems = intel.status === "fulfilled" && Array.isArray(intel.value) ? intel.value : [];
    intelItems.slice(0, 6).forEach((i) => results.push(makeResult("情报", i.summary || i.match_key, `${i.kind || "intel"} - ${i.match_key || ""}`, "/intel")));
    const logItems = logs.status === "fulfilled" ? (Array.isArray(logs.value) ? logs.value : (logs.value?.items || [])) : [];
    logItems.slice(0, 6).forEach((l) => results.push(makeResult("异常", l.message || l.kind, `${l.level || "info"} - ${l.agent || "unknown"}`, "/runtime-logs")));
    globalSearchResults.value = results.slice(0, 18);
  } finally {
    globalSearchLoading.value = false;
  }
}

function go(path) {
  showCreateMenu.value = false;
  closeGlobalSearch();
  router.push(path);
}

function onKeydown(e) {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
    e.preventDefault();
    openGlobalSearch();
  } else if (e.key === "Escape") {
    showCreateMenu.value = false;
    if (showBgModal.value) closeBgModal();
    if (showGlobalSearch.value) closeGlobalSearch();
  }
}

watch(globalSearchDraft, (v) => {
  clearTimeout(globalSearchTimer);
  globalSearchTimer = setTimeout(() => runGlobalSearch(v), 180);
});


function applyCustomBackground(value) {
  const clean = String(value || "").trim();
  backgroundInput.value = clean;
  if (clean) {
    document.documentElement.style.setProperty("--custom-bg-image", `url("${clean.replace(/"/g, "%22")}")`);
    document.documentElement.classList.add("custom-bg-on");
    localStorage.setItem(CUSTOM_BG_KEY, clean);
  } else {
    document.documentElement.style.removeProperty("--custom-bg-image");
    document.documentElement.classList.remove("custom-bg-on");
    localStorage.removeItem(CUSTOM_BG_KEY);
  }
}

function openBgModal() {
  showCreateMenu.value = false;
  showBgModal.value = true;
  backgroundInput.value = localStorage.getItem(CUSTOM_BG_KEY) || "";
  setTimeout(() => document.querySelector(".bg-modal-input")?.focus(), 0);
}

function closeBgModal() {
  showBgModal.value = false;
}

function saveBackground() {
  applyCustomBackground(backgroundInput.value);
  closeBgModal();
  toast(backgroundInput.value.trim() ? "已应用自定义背景" : "已恢复默认背景");
}

function clearBackground() {
  applyCustomBackground("");
  closeBgModal();
  toast("已恢复默认背景");
}

function loadBackgroundFile(e) {
  const file = e.target?.files?.[0];
  if (!file) return;
  if (!file.type.startsWith("image/")) {
    toast("请选择图片文件");
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    backgroundInput.value = String(reader.result || "");
    applyCustomBackground(backgroundInput.value);
    closeBgModal();
    toast("已应用自定义背景");
  };
  reader.readAsDataURL(file);
  e.target.value = "";
}

function applyTheme(t) {
  theme.value = t;
  document.documentElement.setAttribute("data-theme", t);
  localStorage.setItem("ah-theme", t);
}
function toggleTheme() { applyTheme(theme.value === "dark" ? "light" : "dark"); }

function toast(m, ms = 2600) {
  toastMsg.value = m;
  setTimeout(() => { if (toastMsg.value === m) toastMsg.value = ""; }, ms);
}

function openTokenDialog(reason = "switch") {
  tokenModalReason.value = reason;
  tokenInput.value = "";
  showTokenModal.value = true;
}

async function confirmToken() {
  const raw = tokenInput.value.trim();
  if (!raw) {
    toast("请输入令牌");
    return;
  }
  showTokenModal.value = false;
  tokenInput.value = "";
  submitTokenModal(raw);
  const result = await applyAccessToken(raw);
  if (result.ok) {
    toast(result.role === "full" ? "已切换为全权限令牌"
      : result.role === "observer" ? "已切换为观摩令牌" : "已切换为只读令牌");
    window.dispatchEvent(new CustomEvent("autohunter-token-changed"));
  } else {
    toast("令牌无效，请检查后重试");
  }
}

function closeTokenModal() {
  showTokenModal.value = false;
  tokenInput.value = "";
  cancelTokenModal();
}

function onOpenTokenModal(e) {
  openTokenDialog(e.detail?.reason || "auth");
}

function changeToken() {
  openTokenDialog("switch");
}

onMounted(async () => {
  applyTheme(localStorage.getItem("ah-theme") || "light");
  applyCustomBackground(localStorage.getItem(CUSTOM_BG_KEY) || "");
  window.addEventListener("autohunter-open-token-modal", onOpenTokenModal);
  window.addEventListener("keydown", onKeydown);
  await loadAuthRole();
  await refreshNavStats();
  navStatsTimer = setInterval(refreshNavStats, 15000);
});
onUnmounted(() => {
  window.removeEventListener("autohunter-open-token-modal", onOpenTokenModal);
  window.removeEventListener("keydown", onKeydown);
  clearInterval(navStatsTimer);
  clearTimeout(globalSearchTimer);
});
</script>

<template>
  <header class="topbar">
    <div class="topbar-row">
      <nav class="topbar-island" aria-label="主导航">
        <button class="island-icon nav-search-btn" type="button" title="全局搜索" aria-label="全局搜索" @click="openGlobalSearch">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
        </button>
        <router-link to="/" class="island-action nav-status" title="运行状态" aria-label="运行状态">
          <span class="status-dot" :class="{ on: navStats.running > 0 }"></span>
          <span>{{ runningLabel }}</span>
        </router-link>
        <router-link to="/runtime-logs" class="island-icon nav-notice" title="通知 / 异常" aria-label="通知 / 异常">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 7h18s-3 0-3-7"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
          <i v-if="noticeCount" class="notice-badge">{{ noticeCount > 99 ? '99+' : noticeCount }}</i>
        </router-link>
        <span class="island-divider" aria-hidden="true"></span>
        <button class="token-switch island-action" @click="changeToken" aria-label="更换访问令牌">
          <span class="tool-icon">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"
              stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <circle cx="7.5" cy="15.5" r="4.5"/>
              <path d="M10.7 12.3 21 2"/>
              <path d="m16 6 3 3"/>
              <path d="m18 4 3 3"/>
            </svg>
          </span>
          <span class="tool-label">令牌</span>
        </button>
        <button class="theme-toggle island-icon" @click="toggleTheme"
          :title="theme === 'dark' ? '切换到亮色' : '切换到暗色'"
          :aria-label="theme === 'dark' ? '切换到亮色主题' : '切换到暗色主题'">
          <svg v-if="theme === 'light'" viewBox="0 0 24 24" width="16" height="16" fill="none"
            stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="4"/>
            <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>
          </svg>
          <svg v-else viewBox="0 0 24 24" width="16" height="16" fill="none"
            stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
          </svg>
        </button>
        <button class="island-icon bg-toggle" type="button" title="自定义背景图" aria-label="自定义背景图" @click="openBgModal">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="8.5" cy="10" r="1.5"/><path d="m21 15-5-5L5 19"/></svg>
        </button>
        <a class="github-link island-icon" href="https://github.com/StanleyNull/AutoHunter"
          target="_blank" rel="noopener noreferrer"
          title="在 GitHub 上查看项目" aria-label="在 GitHub 上查看项目">
          <svg viewBox="0 0 16 16" width="18" height="18" aria-hidden="true" focusable="false">
            <path fill="currentColor" fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/>
          </svg>
        </a>
        <span class="island-divider" aria-hidden="true"></span>
        <router-link to="/" class="navbtn island-action" :class="{ active: route.path === '/' }">
          <span class="nav-icon"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="4" rx="1"/><rect x="3" y="11" width="18" height="4" rx="1"/><rect x="3" y="18" width="18" height="3" rx="1"/></svg></span>
          <span>任务</span>
        </router-link>
        <div v-if="authRoleRef === 'full'" class="quick-create-wrap">
          <button type="button" class="navbtn island-action quick-create-btn" :class="{ active: route.path === '/create' }" @click="go('/create')">
            <span class="nav-icon"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg></span>
            <span>新建</span>
          </button>
        </div>
        <router-link v-if="authRoleRef === 'full'" to="/settings" class="navbtn island-action" :class="{ active: route.path === '/settings' }">
          <span class="nav-icon"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg></span>
          <span>设置</span>
        </router-link>
      </nav>
    </div>
  </header>
  <main>
    <router-view />
  </main>

  <footer class="app-credit" aria-label="署名">
    <span>Powered By <b>StanleyNull</b></span>
    <span class="app-credit-sep">·</span>
    <span>CC BY-NC 4.0</span>
  </footer>

  <nav class="bottom-nav mobile-only-nav" aria-label="主导航">
    <router-link to="/" class="bottom-nav-item" :class="{ active: route.path === '/' }">
      <span class="bottom-nav-icon"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="4" rx="1"/><rect x="3" y="11" width="18" height="4" rx="1"/><rect x="3" y="18" width="18" height="3" rx="1"/></svg></span>
      <span class="bottom-nav-label">任务</span>
    </router-link>
    <router-link v-if="authRoleRef === 'full'" to="/create" class="bottom-nav-item" :class="{ active: route.path === '/create' }">
      <span class="bottom-nav-icon"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg></span>
      <span class="bottom-nav-label">新建</span>
    </router-link>
    <router-link v-if="authRoleRef === 'full'" to="/settings" class="bottom-nav-item" :class="{ active: route.path === '/settings' }">
      <span class="bottom-nav-icon"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg></span>
      <span class="bottom-nav-label">设置</span>
    </router-link>
    <button type="button" class="bottom-nav-item" @click="changeToken">
      <span class="bottom-nav-icon"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3 21 2"/><path d="m16 6 3 3"/><path d="m18 4 3 3"/></svg></span>
      <span class="bottom-nav-label">令牌</span>
    </button>
    <button type="button" class="bottom-nav-item" @click="toggleTheme"
      :aria-label="theme === 'dark' ? '切换到亮色主题' : '切换到暗色主题'">
      <span class="bottom-nav-icon">
        <svg v-if="theme === 'light'" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>
        <svg v-else viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
      </span>
      <span class="bottom-nav-label">主题</span>
    </button>
  </nav>

  <div v-if="showBgModal" class="bg-modal-backdrop" @click.self="closeBgModal">
    <section class="bg-modal" role="dialog" aria-label="自定义背景图">
      <header>
        <div>
          <h3>自定义背景图</h3>
          <p>粘贴图片 URL，或上传本地图片。设置会保存在当前浏览器。</p>
        </div>
        <button type="button" class="global-search-close" @click="closeBgModal">x</button>
      </header>
      <label class="bg-field">
        图片 URL
        <input v-model="backgroundInput" class="bg-modal-input" placeholder="https://example.com/background.jpg" />
      </label>
      <div class="bg-actions">
        <label class="bg-upload">
          上传图片
          <input type="file" accept="image/*" @change="loadBackgroundFile" />
        </label>
        <button type="button" @click="clearBackground">恢复默认</button>
        <button type="button" class="primary" @click="saveBackground">应用背景</button>
      </div>
    </section>
  </div>

  <div v-if="showGlobalSearch" class="global-search-backdrop" @click.self="closeGlobalSearch">
    <section class="global-search-panel" role="dialog" aria-label="全局搜索">
      <div class="global-search-head">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
        <input v-model="globalSearchDraft" class="global-search-input" placeholder="搜索任务、漏洞、情报、异常" />
        <button type="button" class="global-search-close" @click="closeGlobalSearch">x</button>
      </div>
      <div class="global-search-body">
        <p v-if="globalSearchLoading" class="global-search-empty">搜索中...</p>
        <p v-else-if="!globalSearchDraft.trim()" class="global-search-empty">输入关键词开始搜索</p>
        <p v-else-if="!globalSearchResults.length" class="global-search-empty">没有找到匹配结果</p>
        <button v-for="item in globalSearchResults" :key="`${item.type}-${item.title}-${item.meta}`" type="button" class="global-search-result" @click="go(item.path)">
          <span>{{ item.type }}</span>
          <b>{{ item.title }}</b>
          <small>{{ item.meta }}</small>
        </button>
      </div>
    </section>
  </div>

  <div v-if="showTokenModal" class="token-modal-backdrop">
    <div class="token-modal" role="dialog" aria-labelledby="token-modal-title">
      <h3 id="token-modal-title">{{ tokenModalReason === "auth" ? "输入访问令牌" : "更换访问令牌" }}</h3>
      <p class="token-modal-hint">全权限与只读令牌均可输入；手机端请在此输入，勿使用系统弹窗。</p>
      <input
        v-model="tokenInput"
        class="token-modal-input"
        type="text"
        autocomplete="off"
        placeholder="粘贴令牌"
        @keyup.enter="confirmToken"
      />
      <div class="token-modal-actions">
        <button class="ghost" @click="closeTokenModal">取消</button>
        <button class="primary" @click="confirmToken">确认</button>
      </div>
    </div>
  </div>

  <div v-if="toastMsg" class="toast app-toast">{{ toastMsg }}</div>
</template>
