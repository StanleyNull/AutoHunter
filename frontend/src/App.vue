<script setup>
import { ref, onMounted, onUnmounted } from "vue";
import { useRoute } from "vue-router";
import {
  applyAccessToken,
  authReadyRef,
  authRoleRef,
  cancelTokenModal,
  loadAuthRole,
  submitTokenModal,
} from "./api.js";
const route = useRoute();

const theme = ref("dark");
const showTokenModal = ref(false);
const tokenInput = ref("");
const tokenModalReason = ref("switch");
const toastMsg = ref("");

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
  applyTheme(localStorage.getItem("ah-theme") || "dark");
  window.addEventListener("autohunter-open-token-modal", onOpenTokenModal);
  await loadAuthRole();
});
onUnmounted(() => {
  window.removeEventListener("autohunter-open-token-modal", onOpenTokenModal);
});
</script>

<template>
  <header class="topbar">
    <div class="topbar-row">
      <div class="brand">
        <span class="logo"><i></i></span>
        <span class="brand-copy">
          <b>AutoHunter</b>
          <small class="brand-tag">SRC · 24×7</small>
        </span>
      </div>
      <div class="topbar-tools">
        <span v-if="authReadyRef && authRoleRef === 'none'" class="readonly-badge unauth-badge">未认证</span>
        <span v-else-if="authRoleRef === 'readonly'" class="readonly-badge">只读</span>
        <span v-else-if="authRoleRef === 'observer'" class="readonly-badge">观摩</span>
        <button class="token-switch" @click="changeToken" aria-label="更换访问令牌">
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
        <button class="theme-toggle" @click="toggleTheme"
          :title="theme === 'dark' ? '切换到亮色' : '切换到暗色'"
          :aria-label="theme === 'dark' ? '切换到亮色主题' : '切换到暗色主题'">
          <svg v-if="theme === 'dark'" viewBox="0 0 24 24" width="16" height="16" fill="none"
            stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="4"/>
            <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>
          </svg>
          <svg v-else viewBox="0 0 24 24" width="16" height="16" fill="none"
            stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
          </svg>
        </button>
        <a class="github-link" href="https://github.com/StanleyNull/AutoHunter"
          target="_blank" rel="noopener noreferrer"
          title="在 GitHub 上查看项目" aria-label="在 GitHub 上查看项目">
          <svg viewBox="0 0 16 16" width="18" height="18" aria-hidden="true" focusable="false">
            <path fill="currentColor" fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/>
          </svg>
        </a>
      </div>
    </div>
    <nav class="topbar-nav desktop-only-nav" aria-label="主导航">
      <router-link to="/" class="navbtn" :class="{ active: route.path === '/' }">
        <span class="nav-icon"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="4" rx="1"/><rect x="3" y="11" width="18" height="4" rx="1"/><rect x="3" y="18" width="18" height="3" rx="1"/></svg></span>
        <span>任务</span>
      </router-link>
      <router-link v-if="authRoleRef === 'full'" to="/create" class="navbtn" :class="{ active: route.path === '/create' }">
        <span class="nav-icon"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg></span>
        <span>新建</span>
      </router-link>
      <router-link v-if="authRoleRef === 'full'" to="/settings" class="navbtn" :class="{ active: route.path === '/settings' }">
        <span class="nav-icon"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg></span>
        <span>设置</span>
      </router-link>
    </nav>
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
        <svg v-if="theme === 'dark'" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>
        <svg v-else viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
      </span>
      <span class="bottom-nav-label">主题</span>
    </button>
  </nav>

  <div v-if="showTokenModal" class="token-modal-backdrop" @click.self="closeTokenModal">
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
