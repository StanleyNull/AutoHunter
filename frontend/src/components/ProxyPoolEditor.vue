<script setup>
import { onMounted, reactive, ref } from "vue";
import { api } from "../api.js";

/* 代理池编辑器：列表即时保存（每次增删改直接落服务端），无需外层提交按钮。 */

const loading = ref(true);
const enabled = ref(false);
const proxies = ref([]);
const toastMsg = ref("");
const toastType = ref("");

const showAdd = ref(false);
const addForm = reactive({
  name: "", protocol: "http", host: "", port: "",
  username: "", password: "",
});
const addBusy = ref(false);

const showImport = ref(false);
const importText = ref("");
const importFile = ref(null);
const importFileEl = ref(null);
const importBusy = ref(false);
const importResult = ref(null);

const testing = reactive({});
const testResult = reactive({});

function toast(msg, isError = false) {
  toastMsg.value = msg;
  toastType.value = isError ? "err" : "ok";
  setTimeout(() => { toastMsg.value = ""; }, 2600);
}

async function load() {
  loading.value = true;
  try {
    const res = await api.proxyList();
    enabled.value = !!res?.enabled;
    proxies.value = Array.isArray(res?.proxies) ? res.proxies : [];
  } catch (e) {
    toast(String(e.message || e), true);
  } finally {
    loading.value = false;
  }
}

async function onToggle() {
  // v-model 已先翻转 enabled；失败则回滚。此前读旧值发送，开关永远关不掉。
  const next = enabled.value;
  try {
    const res = await api.proxyToggle(next);
    enabled.value = !!res?.enabled;
    toast(enabled.value ? "代理池已启用：被封后自动/手动换 IP" : "代理池已关闭：全部直连");
  } catch (e) {
    enabled.value = !next;
    toast(String(e.message || e), true);
  }
}

function resetAddForm() {
  addForm.name = "";
  addForm.protocol = "http";
  addForm.host = "";
  addForm.port = "";
  addForm.username = "";
  addForm.password = "";
}

async function submitAdd() {
  const port = Number(addForm.port);
  if (!addForm.host.trim() || !Number.isInteger(port) || port < 1 || port > 65535) {
    toast("host 与端口（1-65535）必填", true);
    return;
  }
  addBusy.value = true;
  try {
    await api.proxyAdd({
      name: addForm.name.trim(),
      protocol: addForm.protocol,
      host: addForm.host.trim(),
      port,
      username: addForm.username.trim(),
      password: addForm.password,
      enabled: true,
    });
    toast("已添加代理");
    showAdd.value = false;
    resetAddForm();
    await load();
  } catch (e) {
    const msg = String(e.message || e);
    toast(msg.includes("409") ? "该代理已存在" : msg, true);
  } finally {
    addBusy.value = false;
  }
}

async function toggleRow(row) {
  try {
    await api.proxyUpdate(row.id, { enabled: !row.enabled });
    row.enabled = !row.enabled;
  } catch (e) {
    toast(String(e.message || e), true);
  }
}

async function removeRow(row) {
  if (!confirm(`确认删除代理「${row.name || row.display}」？`)) return;
  try {
    await api.proxyDelete(row.id);
    proxies.value = proxies.value.filter((p) => p.id !== row.id);
    toast("已删除");
  } catch (e) {
    toast(String(e.message || e), true);
  }
}

async function testRow(row) {
  testing[row.id] = true;
  delete testResult[row.id];
  try {
    const res = await api.proxyTest({ id: row.id });
    testResult[row.id] = res?.ok
      ? `连通 ${res.latency_ms}ms`
      : (res?.error || "测试失败");
    await load(); // 测试成功会解除冷却，刷新状态点
  } catch (e) {
    testResult[row.id] = String(e.message || e);
  } finally {
    testing[row.id] = false;
  }
}

function onImportFile(e) {
  importFile.value = e.target.files?.[0] || null;
}

async function submitImport() {
  if (!importText.value.trim() && !importFile.value) {
    toast("粘贴代理文本或选择 txt 文件", true);
    return;
  }
  importBusy.value = true;
  importResult.value = null;
  try {
    const res = await api.proxyImport(importText.value, importFile.value);
    importResult.value = {
      added: res?.added ?? 0, skipped: res?.skipped ?? 0, invalid: res?.invalid ?? 0,
    };
    importText.value = "";
    importFile.value = null;
    // 清空文件选择框：否则文件名仍显示但状态已清，且同文件二次选择不触发 change
    if (importFileEl.value) importFileEl.value.value = "";
    await load();
  } catch (e) {
    toast(String(e.message || e), true);
  } finally {
    importBusy.value = false;
  }
}

onMounted(load);
</script>

<template>
  <div class="proxy-pool">
    <div class="proxy-toolbar">
      <label class="proxy-switch">
        <input type="checkbox" v-model="enabled" @change="onToggle" />
        <span>启用代理池</span>
        <small>{{ enabled ? "挖洞流量走代理，被封自动/手动换 IP" : "关闭中：全部直连" }}</small>
      </label>
      <div class="proxy-actions">
        <button type="button" @click="showImport = !showImport">导入 txt / 粘贴</button>
        <button type="button" class="primary" @click="showAdd = !showAdd">+ 添加代理</button>
      </div>
    </div>

    <p v-if="toastMsg" class="proxy-toast" :class="toastType">{{ toastMsg }}</p>

    <div v-if="showAdd" class="proxy-form">
      <label>名称<input v-model="addForm.name" placeholder="可留空自动命名" /></label>
      <label>协议
        <select v-model="addForm.protocol">
          <option value="http">HTTP</option>
          <option value="https">HTTPS</option>
          <option value="socks5">SOCKS5</option>
        </select>
      </label>
      <label>host<input v-model="addForm.host" placeholder="1.2.3.4" /></label>
      <label>端口<input v-model="addForm.port" type="number" min="1" max="65535" placeholder="8080" /></label>
      <label>用户名<input v-model="addForm.username" placeholder="可空" /></label>
      <label>密码<input v-model="addForm.password" type="password" placeholder="可空" /></label>
      <div class="proxy-form-actions">
        <button type="button" :disabled="addBusy" @click="submitAdd">{{ addBusy ? "保存中…" : "保存" }}</button>
        <button type="button" @click="showAdd = false">取消</button>
      </div>
    </div>

    <div v-if="showImport" class="proxy-import">
      <label>粘贴代理（每行一条，支持 <code>scheme://user:pass@host:port</code>、<code>协议|host|port|用户|密码</code>、<code>host:port</code>）</label>
      <textarea v-model="importText" rows="6" placeholder="http://1.2.3.4:8080&#10;socks5://user:pass@5.6.7.8:1080&#10;9.9.9.9:3128"></textarea>
      <label class="proxy-import-file">或从 txt 文件导入
        <input ref="importFileEl" type="file" accept=".txt,.text,.list,.log,*/*" @change="onImportFile" />
      </label>
      <div class="proxy-form-actions">
        <button type="button" :disabled="importBusy" @click="submitImport">{{ importBusy ? "导入中…" : "导入" }}</button>
        <button type="button" @click="showImport = false; importResult = null">关闭</button>
      </div>
      <p v-if="importResult" class="proxy-import-result">
        新增 <b>{{ importResult.added }}</b> 条，重复跳过 <b>{{ importResult.skipped }}</b> 条，非法/无效 <b>{{ importResult.invalid }}</b> 行
      </p>
    </div>

    <div v-if="loading" class="proxy-empty">加载中…</div>
    <div v-else-if="!proxies.length" class="proxy-empty">
      <span>代理池为空。被封 IP 前提前把代理倒进来；不启用也不影响正常挖掘（直连）。</span>
    </div>

    <table v-else class="proxy-table">
      <thead>
        <tr><th>名称</th><th>协议</th><th>地址</th><th>状态</th><th>启用</th><th>操作</th></tr>
      </thead>
      <tbody>
        <tr v-for="row in proxies" :key="row.id" :class="{ off: row.enabled === false }">
          <td>{{ row.name }}</td>
          <td><span class="proxy-badge" :data-p="row.protocol">{{ row.protocol }}</span></td>
          <td><code>{{ row.display }}</code></td>
          <td>
            <span class="proxy-dot" :class="row.status" :title="row.status === 'cooldown' ? `冷却中（连续连接失败），剩 ${row.cooldown_remaining_sec}s` : '正常'"></span>
            {{ row.status === "cooldown" ? `冷却 ${row.cooldown_remaining_sec}s` : "正常" }}
          </td>
          <td>
            <input type="checkbox" :checked="row.enabled !== false" @change="toggleRow(row)" />
          </td>
          <td class="proxy-row-actions">
            <button type="button" :disabled="testing[row.id]" @click="testRow(row)">{{ testing[row.id] ? "测试中…" : "测试" }}</button>
            <button type="button" class="danger" @click="removeRow(row)">删除</button>
            <small v-if="testResult[row.id]" class="proxy-test-result">{{ testResult[row.id] }}</small>
          </td>
        </tr>
      </tbody>
    </table>

    <p class="proxy-note">
      覆盖范围：Worker 的 http_request 与 run_shell（curl/python 等读取环境变量；nmap/sqlmap 不读 env，需各自加 --proxy）。
      连接失败自动换下一个；被 WAF 封 IP 时 Worker 会调用 rotate_proxy 换出口并保留登录态。
    </p>
  </div>
</template>

<style scoped>
.proxy-pool { display: flex; flex-direction: column; gap: 12px; }
.proxy-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.proxy-switch { display: flex; align-items: center; gap: 8px; cursor: pointer; }
.proxy-switch small { opacity: 0.65; }
.proxy-actions { display: flex; gap: 8px; }
.proxy-actions .primary { font-weight: 600; }
.proxy-toast { margin: 0; font-size: 13px; }
.proxy-toast.ok { color: var(--ok, #4ade80); }
.proxy-toast.err { color: var(--danger, #f87171); }
.proxy-form, .proxy-import {
  display: grid; grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px; padding: 12px; border: 1px solid var(--border, #333); border-radius: 8px;
}
.proxy-form-actions { grid-column: 1 / -1; display: flex; gap: 8px; }
.proxy-import { grid-template-columns: 1fr; }
.proxy-import textarea { width: 100%; font-family: monospace; font-size: 12px; }
.proxy-import label { display: flex; flex-direction: column; gap: 4px; }
.proxy-import-file { flex-direction: row !important; align-items: center; gap: 8px !important; }
.proxy-import-result { margin: 0; font-size: 13px; }
.proxy-empty { opacity: 0.7; font-size: 13px; padding: 12px 0; }
.proxy-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.proxy-table th, .proxy-table td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border, #2a2a2a); }
.proxy-table tr.off td { opacity: 0.5; }
.proxy-badge {
  display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 11px;
  background: color-mix(in srgb, var(--accent, #3b9eff) 18%, transparent);
}
.proxy-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 4px; background: var(--ok, #4ade80); }
.proxy-dot.cooldown { background: var(--warn, #f59e0b); }
.proxy-row-actions { white-space: nowrap; }
.proxy-row-actions .danger { color: var(--danger, #f87171); }
.proxy-test-result { display: block; font-size: 11px; opacity: 0.75; }
.proxy-note { margin: 0; font-size: 12px; opacity: 0.6; }
@media (max-width: 720px) { .proxy-form { grid-template-columns: 1fr 1fr; } }
</style>
