<script setup>
import { ref, nextTick, onMounted, computed } from "vue";
import { useRouter } from "vue-router";
import { api } from "../api.js";

const router = useRouter();
const sessions = ref([]);
const activeId = ref("");
const messages = ref([]);
const newMessage = ref("");
const sending = ref(false);
const loadingSessions = ref(true);
const loadingMessages = ref(false);
const wumiReady = ref(false);
const wumiModel = ref("");
const streamCtl = ref(null);
const streaming = ref(true);
const toastMsg = ref("");
const donateOpen = ref(false);

const activeSession = computed(() => sessions.value.find((s) => s.id === activeId.value) || null);
const chatBody = ref(null);

function toast(m) {
  toastMsg.value = m;
  setTimeout(() => (toastMsg.value = ""), 2600);
}

async function loadSessions() {
  loadingSessions.value = true;
  try { sessions.value = await api.chatSessions(); }
  catch { sessions.value = []; }
  finally { loadingSessions.value = false; }
}

async function checkWumi() {
  try {
    const s = await api.getSettings();
    wumiReady.value = !!s?.xiaoqi?.api_key_set;
    wumiModel.value = s?.xiaoqi?.model || "";
  } catch { wumiReady.value = false; }
}

function stopGen() {
  if (streamCtl.value) streamCtl.value();
}

async function selectSession(id) {
  if (!id || activeId.value === id) return;
  activeId.value = id;
  loadingMessages.value = true;
  messages.value = [];
  try { messages.value = await api.chatMessages(id); }
  catch (e) { toast(`加载消息失败：${e.message || e}`); }
  finally { loadingMessages.value = false; }
  scrollToBottom();
}

async function newSession() {
  try {
    const cs = await api.chatCreateSession("");
    sessions.value.unshift(cs);
    activeId.value = cs.id;
    messages.value = [];
    scrollToBottom();
  } catch (e) {
    toast(`新建会话失败：${e.message || e}`);
  }
}

async function deleteCurrent() {
  if (!activeId.value) return;
  if (!confirm("删除这个对话？聊天记录将一并删除。")) return;
  const id = activeId.value;
  try {
    await api.chatDeleteSession(id);
    sessions.value = sessions.value.filter((s) => s.id !== id);
    activeId.value = "";
    messages.value = [];
  } catch (e) {
    toast(`删除失败：${e.message || e}`);
  }
}

function scrollToBottom() {
  nextTick(() => {
    if (chatBody.value) chatBody.value.scrollTop = chatBody.value.scrollHeight;
  });
}

async function send() {
  const text = newMessage.value.trim();
  if (!text || sending.value) return;
  if (!activeId.value) {
    try { await newSession(); } catch { return; }
  }
  if (!wumiReady.value) {
    toast("先去「系统配置」填 wumi 模型");
    router.push("/settings");
    return;
  }

  sending.value = true;
  messages.value.push({ role: "user", content: text });
  messages.value.push({ role: "assistant", content: "" });
  newMessage.value = "";
  scrollToBottom();

  const sessionId = activeId.value;
  const { promise, abort } = api.chatStream(sessionId, text, (ev) => {
    const last = messages.value[messages.value.length - 1];
    if (!last) return;
    if (ev.type === "token" && ev.content) {
      if (streaming.value) last.content += ev.content;
      scrollToBottom();
    } else if (ev.type === "done") {
      last.content = ev.content || last.content;
      scrollToBottom();
    } else if (ev.type === "error") {
      last.content = ev.content || "wumi 暂时没反应";
      scrollToBottom();
    }
  });
  streamCtl.value = abort;
  try {
    await promise;
  } catch (e) {
    const last = messages.value[messages.value.length - 1];
    if (last && last.role === "assistant" && !last.content.trim() && !String(e?.message || e).includes("abort")) {
      last.content = `发送失败：${e.message || e}`;
    }
  } finally {
    streamCtl.value = null;
    sending.value = false;
    scrollToBottom();
    loadSessions();
  }
}

function onKeydown(e) {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    send();
  }
}

onMounted(async () => {
  await Promise.all([loadSessions(), checkWumi()]);
});
</script>

<template>
  <section class="view hall-view">
    <!-- 左侧：配置面板（Kimi Playground 风格） -->
    <aside class="hall-config">
      <!-- 模型 -->
      <details class="cp-panel" open>
        <summary>
          <span class="cp-title">模型</span>
        </summary>
        <div class="cp-body">
          <div class="cp-row">
            <span class="cp-model-name">{{ wumiModel || "未配置" }}</span>
            <a class="cp-link" @click.prevent="router.push('/settings')">去系统配置</a>
          </div>
          <div class="cp-row"><span>快速设置</span></div>
          <label class="cp-toggle">
            <span>Streaming</span>
            <input v-model="streaming" type="checkbox" />
          </label>
        </div>
      </details>

      <!-- 工具 -->
      <details class="cp-panel" open>
        <summary>
          <span class="cp-title">工具</span>
          <span class="cp-count">0 已选择</span>
        </summary>
        <div class="cp-body">
          <p class="cp-empty">暂无已选工具</p>
          <button type="button" class="cp-add" @click="donateOpen = true">添加工具</button>
        </div>
      </details>

      <!-- MCP 服务器 -->
      <details class="cp-panel" open>
        <summary>
          <span class="cp-title">MCP 服务器</span>
          <span class="cp-count">0 已连接</span>
        </summary>
        <div class="cp-body">
          <p class="cp-empty">暂无配置服务器</p>
          <button type="button" class="cp-add" @click="donateOpen = true">添加第一个服务器</button>
        </div>
      </details>

      <p class="cp-footer">动态加载工具 0</p>
    </aside>

    <!-- 右侧：对话区 -->
    <div class="hall-chat-area">
      <div class="hall-chat-head">
        <span>Airl-Tendō Kei凯伊</span>
        <span v-if="wumiModel" class="hall-model-badge">{{ wumiModel }}</span>
        <div class="hall-session-select">
          <select :value="activeId" @change="selectSession($event.target.value)" class="hall-select">
            <option value="" disabled>记忆大厅</option>
            <option v-for="s in sessions" :key="s.id" :value="s.id">{{ s.title }}</option>
          </select>
          <button type="button" class="hall-newbtn" @click="newSession" title="新建对话">＋ 桃信</button>
          <button v-if="activeId" type="button" class="hall-delbtn" @click="deleteCurrent" title="删除当前会话">🗑</button>
        </div>
      </div>

      <div v-if="!activeId" class="hall-welcome">
        <h1>你好，我是 wumi</h1>
        <p class="hall-welcome-sub">欢迎来自现实的旅人^-^</p>
        <button class="mini-action" type="button" @click="newSession">进入世界</button>
      </div>

      <template v-else>
        <div ref="chatBody" class="hall-chat" :class="{ 'is-loading': loadingMessages }">
          <div v-if="!loadingMessages && !messages.length" class="hall-chat-empty">
            和 wumi 说句话开始吧～
          </div>
          <div v-for="(m, i) in messages" :key="i" class="hall-msg" :class="m.role">
            <img v-if="m.role === 'assistant'" class="hall-avatar" src="/favicon-64.png" alt="" aria-hidden="true" />
            <div class="hall-bubble" :class="{ streaming: m.role === 'assistant' && i === messages.length - 1 && sending }">
              <span v-if="!m.content" class="hall-typing">…</span>
              <template v-else>{{ m.content }}</template>
            </div>
          </div>
        </div>

        <div class="hall-input-wrap">
          <div v-if="!wumiReady" class="hall-config-hint">
            还没有配置 wumi 模型 ——
            <a @click.prevent="router.push('/settings')">去「系统配置」填 API Key</a>
          </div>
          <div class="hall-input">
            <textarea v-model="newMessage" rows="1" placeholder="问个问题..."
              @keydown="onKeydown" :disabled="sending"></textarea>
            <button v-if="sending" type="button" class="hall-send stop" @click="stopGen" title="停止生成">
              <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" aria-hidden="true"><rect x="6" y="6" width="12" height="12" rx="2"/></svg>
            </button>
            <button v-else type="button" class="hall-send" :disabled="!newMessage.trim()" @click="send" title="发送">
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor"
                stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 19V5"/><path d="m5 12 7-7 7 7"/></svg>
            </button>
          </div>
          <p class="hall-input-hint">按 ⏎ 发送，⇧⏎ 换行</p>
        </div>
      </template>
    </div>

    <div v-if="toastMsg" class="toast app-toast">{{ toastMsg }}</div>

    <!-- 欢迎投稿弹窗 -->
    <div v-if="donateOpen" class="modal-mask" @click.self="donateOpen = false">
      <div class="modal-card donate-modal" role="dialog" aria-modal="true" aria-labelledby="donate-title">
        <div class="donate-head">
          <h3 id="donate-title">欢迎投稿</h3>
          <span class="donate-tag">还在建设中</span>
        </div>
        <p class="donate-text">唔。。提醒一下大家~<br />首页「添加工具」和「添加第一个MCP服务器」功能被凯伊吞掉了惹T^T<br />修起来工程量好大，靠我小脑子实在搞不完。<br />来帮帮咪叔叔吧，欢迎联系支持>_&lt;</p>
        <div class="donate-actions">
          <button class="mini-action danger" type="button" @click="donateOpen = false">知道了</button>
        </div>
      </div>
    </div>
  </section>
</template>
