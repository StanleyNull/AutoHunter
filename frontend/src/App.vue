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
          <span class="tool-icon">🔑</span>
          <span class="tool-label">令牌</span>
        </button>
        <button class="theme-toggle" @click="toggleTheme"
          :title="theme === 'dark' ? '切换到亮色' : '切换到暗色'"
          :aria-label="theme === 'dark' ? '切换到亮色主题' : '切换到暗色主题'">
          {{ theme === "dark" ? "☀" : "☾" }}
        </button>
      </div>
    </div>
    <nav class="topbar-nav desktop-only-nav" aria-label="主导航">
      <router-link to="/" class="navbtn" :class="{ active: route.path === '/' }">
        <span class="nav-icon">◎</span>
        <span>任务</span>
      </router-link>
      <router-link v-if="authRoleRef === 'full'" to="/create" class="navbtn" :class="{ active: route.path === '/create' }">
        <span class="nav-icon">＋</span>
        <span>新建</span>
      </router-link>
      <router-link v-if="authRoleRef === 'full'" to="/settings" class="navbtn" :class="{ active: route.path === '/settings' }">
        <span class="nav-icon">⚙</span>
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
    <span>QQ 754276250</span>
    <span class="app-credit-sep">·</span>
    <span>CC BY-NC 4.0</span>
  </footer>

  <nav class="bottom-nav mobile-only-nav" aria-label="主导航">
    <router-link to="/" class="bottom-nav-item" :class="{ active: route.path === '/' }">
      <span class="bottom-nav-icon">◎</span>
      <span class="bottom-nav-label">任务</span>
    </router-link>
    <router-link v-if="authRoleRef === 'full'" to="/create" class="bottom-nav-item" :class="{ active: route.path === '/create' }">
      <span class="bottom-nav-icon">＋</span>
      <span class="bottom-nav-label">新建</span>
    </router-link>
    <router-link v-if="authRoleRef === 'full'" to="/settings" class="bottom-nav-item" :class="{ active: route.path === '/settings' }">
      <span class="bottom-nav-icon">⚙</span>
      <span class="bottom-nav-label">设置</span>
    </router-link>
    <button type="button" class="bottom-nav-item" @click="changeToken">
      <span class="bottom-nav-icon">🔑</span>
      <span class="bottom-nav-label">令牌</span>
    </button>
    <button type="button" class="bottom-nav-item" @click="toggleTheme"
      :aria-label="theme === 'dark' ? '切换到亮色主题' : '切换到暗色主题'">
      <span class="bottom-nav-icon">{{ theme === "dark" ? "☀" : "☾" }}</span>
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
