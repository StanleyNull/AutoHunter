<script setup>
import { reactive, ref, onMounted } from "vue";
import { api } from "../api.js";

const loading = ref(true);
const saving = ref(false);
const toastMsg = ref("");
const meta = ref({ updated_at: null });

// ---- 一键更新 ----
const updateState = reactive({
  checking: false,
  info: null,       // check_update 返回
  updating: false,
  restarting: false,
  error: "",
  supported: true,   // 后端是否注册了 update 路由（原版不注册 → 隐藏整个区块）
});

async function checkUpdate() {
  updateState.checking = true;
  updateState.error = "";
  updateState.info = null;
  try {
    updateState.info = await api.checkUpdate();
    if (updateState.info?.error && /非 git|无法/.test(updateState.info.error)) {
      updateState.supported = false;
    }
  } catch (e) {
    const msg = String(e.message || e);
    if (/404|not found/i.test(msg)) { updateState.supported = false; }
    else { updateState.error = msg.replace(/^\d+\s*/, ""); }
  } finally {
    updateState.checking = false;
  }
}

async function runUpdate() {
  if (!confirm("确认更新？服务会自动重启，进行中的任务会优雅暂停。")) return;
  updateState.updating = true;
  updateState.error = "";
  try {
    const r = await api.runUpdate();
    if (r.ok) {
      updateState.restarting = true;
      pollHealth();
    } else {
      updateState.error = r.error || "更新失败";
      if (r.command) updateState.info = { ...updateState.info, rebuild_command: r.command };
    }
  } catch (e) {
    updateState.error = String(e.message || e).replace(/^\d+\s*/, "");
  } finally {
    updateState.updating = false;
  }
}

function pollHealth() {
  let attempts = 0;
  const timer = setInterval(async () => {
    attempts++;
    try {
      const r = await fetch("/health");
      if (r.ok) {
        clearInterval(timer);
        updateState.restarting = false;
        toast("更新完成，服务已重启 🎉");
        updateState.info = null;
        load();
      }
    } catch {}
    if (attempts > 60) { clearInterval(timer); updateState.restarting = false; updateState.error = "重启超时，请手动刷新页面"; }
  }, 3000);
}

const form = reactive({
  base_url: "",
  api_key: "",
  model: "",
  temperature: 0.3,
  api_key_set: false,
  fofa_key: "",
  fofa_key_set: false,
  fofa_base_url: "",
  max_pages: 20,
  page_size: 100,
  default_intent_mode: "",
  concurrency: 3,
  skip_score_threshold: -10,
  worker_prompt_version: "legacy",
});

function toast(m) {
  toastMsg.value = m;
  setTimeout(() => (toastMsg.value = ""), 2600);
}

async function load() {
  loading.value = true;
  try {
    const s = await api.getSettings();
    meta.value = { updated_at: s.updated_at };
    form.base_url = s.llm?.base_url || "";
    form.model = s.llm?.model || "";
    form.temperature = s.llm?.temperature ?? 0.3;
    form.api_key = "";
    form.api_key_set = s.llm?.api_key_set;
    form.fofa_key = "";
    form.fofa_key_set = s.fofa?.key_set;
    form.fofa_base_url = s.fofa?.base_url || "";
    form.max_pages = s.fofa?.max_pages ?? 20;
    form.page_size = s.fofa?.page_size ?? 100;
    form.default_intent_mode = s.fofa?.default_intent_mode || "";
    form.concurrency = s.defaults?.concurrency ?? 3;
    form.skip_score_threshold = s.defaults?.skip_score_threshold ?? -10;
    form.worker_prompt_version = s.defaults?.worker_prompt_version || "legacy";
  } finally {
    loading.value = false;
  }
}

async function save() {
  saving.value = true;
  try {
    const body = {
      llm: {
        base_url: form.base_url,
        model: form.model,
        temperature: Number(form.temperature),
      },
      fofa: {
        base_url: form.fofa_base_url,
        max_pages: Number(form.max_pages),
        page_size: Number(form.page_size),
        default_intent_mode: form.default_intent_mode,
      },
      defaults: {
        concurrency: Number(form.concurrency),
        skip_score_threshold: Number(form.skip_score_threshold),
        worker_prompt_version: form.worker_prompt_version,
      },
    };
    if (form.api_key.trim()) body.llm.api_key = form.api_key.trim();
    if (form.fofa_key.trim()) body.fofa.key = form.fofa_key.trim();
    const s = await api.updateSettings(body);
    meta.value = { updated_at: s.updated_at };
    form.api_key = "";
    form.fofa_key = "";
    form.api_key_set = s.llm?.api_key_set;
    form.fofa_key_set = s.fofa?.key_set;
    toast("系统配置已保存");
  } catch (e) {
    toast(String(e.message || e).replace(/^\d+\s*/, ""));
  } finally {
    saving.value = false;
  }
}

onMounted(() => {
  load();
  // 探测后端是否支持更新 API（原版不注册 → supported=false → 隐藏区块）
  checkUpdate();
});
</script>

<template>
  <section class="view settings-view">
    <header class="page-head">
      <h2>系统配置</h2>
      <p class="page-sub">
        全局默认 LLM / FOFA / 调度参数。新建任务留空时会使用此处配置；任务内填写可单独覆盖。
        <span v-if="meta.updated_at" class="settings-updated">上次保存 {{ meta.updated_at?.slice(0, 19).replace("T", " ") }}</span>
      </p>
    </header>

    <div v-if="loading" class="empty">加载中…</div>
    <div v-else class="settings-layout">
      <aside class="settings-summary" aria-label="当前系统配置摘要">
        <div class="settings-summary-head">
          <span>ACTIVE PROFILE</span>
          <b>全局默认</b>
        </div>
        <div class="settings-health">
          <div>
            <span>LLM</span>
            <b>{{ form.model || "未设置模型" }}</b>
          </div>
          <i :class="{ on: form.api_key_set }">{{ form.api_key_set ? "key set" : "no key" }}</i>
        </div>
        <div class="settings-health">
          <div>
            <span>FOFA</span>
            <b>{{ form.max_pages }} 页 · {{ form.page_size }} / 页</b>
          </div>
          <i :class="{ on: form.fofa_key_set }">{{ form.fofa_key_set ? "key set" : "no key" }}</i>
        </div>
        <dl class="settings-facts">
          <div>
            <dt>任务默认并发</dt>
            <dd>{{ form.concurrency }}</dd>
          </div>
          <div>
            <dt>低分跳过阈值</dt>
            <dd>{{ form.skip_score_threshold }}</dd>
          </div>
          <div>
            <dt>Worker 提示词</dt>
            <dd>{{ form.worker_prompt_version }}</dd>
          </div>
        </dl>
        <p class="settings-note">
          此处是运行期默认值。任务创建时若在高级区单独填写，则按任务配置覆盖。
        </p>
      </aside>

      <form class="form settings-form" @submit.prevent="save">
        <fieldset class="settings-block">
          <legend>
            <span>AI / LLM</span>
            <small>Worker、Reviewer、报告助手共用的默认模型通道</small>
          </legend>
          <div class="settings-grid">
            <label class="full">base_url
              <input v-model="form.base_url" placeholder="https://api.deepseek.com/v1" />
            </label>
            <p class="field-hint full">OpenAI 兼容接口地址（官方或自建均可），路径需要包含 <code>/v1</code>。</p>
            <label class="full">api_key
              <input v-model="form.api_key" type="password"
                :placeholder="form.api_key_set ? '已配置，留空不修改' : 'sk-...'" />
            </label>
            <label>模型名 <input v-model="form.model" placeholder="deepseek-v4-flash" /></label>
            <label>temperature
              <input v-model="form.temperature" type="number" step="0.1" min="0" max="2" />
            </label>
          </div>
        </fieldset>

        <fieldset class="settings-block">
          <legend>
            <span>FOFA</span>
            <small>Collector 默认资产搜集参数</small>
          </legend>
          <div class="settings-grid">
            <label class="full">FOFA key
              <input v-model="form.fofa_key" type="password"
                :placeholder="form.fofa_key_set ? '已配置，留空不修改' : 'FOFA API Key'" />
            </label>
            <label class="full">API 端点
              <input v-model="form.fofa_base_url" placeholder="https://fofa.info" />
            </label>
            <p class="field-hint full">自定义 FOFA 兼容端点（私有部署/镜像/代理网关），留空用官方地址。</p>
            <label>默认最大页数 <input v-model="form.max_pages" type="number" min="1" /></label>
            <label>每页条数 <input v-model="form.page_size" type="number" min="1" /></label>
            <label class="full">默认搜集方式
              <select v-model="form.default_intent_mode">
                <option value="">自动判断</option>
                <option value="syntax">查询语法（FOFA 或引擎原生均可）</option>
                <option value="intent">自然语言意图</option>
              </select>
            </label>
          </div>
        </fieldset>

        <fieldset class="settings-block">
          <legend>
            <span>调度默认</span>
            <small>新任务创建时的保守默认值</small>
          </legend>
          <div class="settings-grid">
            <label>新建任务默认并发 <input v-model="form.concurrency" type="number" min="1" max="32" /></label>
            <label>低分跳过阈值
              <input v-model="form.skip_score_threshold" type="number" step="1" />
            </label>
            <label class="full">Worker 提示词版本
              <select v-model="form.worker_prompt_version">
                <option value="legacy">legacy（旧版 23/25 风格）</option>
                <option value="current">current（当前省 token 版）</option>
                <option value="modern">modern（当前完整版）</option>
              </select>
            </label>
            <p class="field-hint full">Collector 评分低于此值的目标直接跳过，避免 worker 消耗在垃圾资产上。</p>
          </div>
        </fieldset>

        <div class="settings-actions">
          <button type="submit" class="primary" :disabled="saving">{{ saving ? "保存中…" : "保存配置" }}</button>
          <span>密钥输入框留空时不会覆盖已有值。</span>
        </div>
      </form>
    </div>

    <!-- 一键更新（后端未注册 update 路由时自动隐藏，如原版 rsync 部署） -->
    <section v-if="updateState.supported" class="settings-block update-section">
      <legend>
        <span>版本更新</span>
        <small>从 GitHub 拉取最新代码并自动重启</small>
      </legend>
      <div v-if="updateState.restarting" class="update-restarting">
        <div class="update-spinner"></div>
        <p>服务正在重启，自动重连中…</p>
      </div>
      <div v-else class="update-body">
        <button class="btn-check" @click="checkUpdate" :disabled="updateState.checking">
          {{ updateState.checking ? "检测中…" : "检查更新" }}
        </button>
        <div v-if="updateState.error" class="update-error">{{ updateState.error }}</div>
        <div v-if="updateState.info?.update_available" class="update-info">
          <div class="update-version">
            <span class="version-old">{{ updateState.info.current_commit }}</span>
            <span class="version-arrow">→</span>
            <span class="version-new">{{ updateState.info.latest_commit }}</span>
            <span class="update-badge">落后 {{ updateState.info.commits_behind }} 个提交</span>
          </div>
          <div class="update-latest-msg">{{ updateState.info.latest_message }}</div>
          <details class="update-files">
            <summary>变更文件 ({{ updateState.info.changed_files?.length || 0 }})</summary>
            <ul>
              <li v-for="f in updateState.info.changed_files" :key="f">{{ f }}</li>
            </ul>
          </details>
          <div v-if="updateState.info.hot_updateable" class="update-actions">
            <button class="primary" @click="runUpdate" :disabled="updateState.updating">
              {{ updateState.updating ? "更新中…" : "一键更新并重启" }}
            </button>
            <span class="update-hint">仅后端代码变更，可热更新（git pull + 自动重启）</span>
          </div>
          <div v-else class="update-actions rebuild">
            <p class="update-warn">⚠ 本次更新包含前端/Dockerfile 变更，需在服务器执行完整重建：</p>
            <code class="rebuild-cmd">{{ updateState.info.rebuild_command || 'git pull && docker compose up -d --build' }}</code>
          </div>
        </div>
        <div v-else-if="updateState.info && !updateState.info.update_available && !updateState.info.error" class="update-uptodate">
          ✓ 已是最新版本（{{ updateState.info.current_commit }}）
        </div>
      </div>
    </section>

    <div v-if="toastMsg" class="toast settings-toast">{{ toastMsg }}</div>
  </section>
</template>
