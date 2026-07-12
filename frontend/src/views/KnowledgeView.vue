<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { api, canWrite } from "../api.js";

const stats = ref({ total: 0, enabled: 0, by_type: {}, by_processing: {} });
const rows = ref([]);
const initialLoading = ref(true);
const refreshing = ref(false);
const docType = ref("all");
const enabledFilter = ref("all");
const searchDraft = ref("");
const searchText = ref("");
const total = ref(0);
const page = ref(0);
const pageSize = 100;
const hasMore = ref(false);
let searchTimer = null;
const writable = computed(() => canWrite());

const tagPool = ref([]);
const pendingTags = ref([]);

const showEditor = ref(false);
const editorMode = ref("create");
const editorDoc = ref({ id: "", title: "", content: "", summary: "", doc_type: "pre_vuln", tags: [], enabled: true });
const editorSaving = ref(false);
const newTagName = ref("");

// 标签管理
const showTagPanel = ref(false);
const newTagPanelName = ref("");

// 批量上传
const showBatchUploader = ref(false);
const batchFiles = ref([]);
const batchUploading = ref(false);
const batchResult = ref("");

// 正在总结的队列：当有 pending/processing 文档时自动轮询
const processingDocs = computed(() => rows.value.filter(d => d.processing === "pending" || d.processing === "processing"));
let pollTimer = null;

const showDetail = ref(false);
const detailDoc = ref(null);
const detailLoading = ref(false);

const TYPE_META = {
  pre_vuln: { label: "漏洞前", icon: "🔍", hue: "info" },
  post_vuln: { label: "漏洞后", icon: "⚡", hue: "warn" },
};

const TYPE_TABS = [
  { id: "all", label: "全部" },
  { id: "pre_vuln", label: "漏洞前" },
  { id: "post_vuln", label: "漏洞后" },
];

const PROCESSING_META = {
  pending: { label: "待处理", hue: "muted" },
  processing: { label: "处理中", hue: "info" },
  ready: { label: "就绪", hue: "ok" },
  failed: { label: "失败", hue: "danger" },
};

async function loadStats() {
  try { stats.value = await api.knowledgeStats(); } catch { /* keep */ }
}

async function loadList() {
  if (!rows.value.length) initialLoading.value = true;
  else refreshing.value = true;
  try {
    const res = await api.knowledgeList(docType.value, enabledFilter.value, searchText.value, pageSize, {
      offset: page.value * pageSize,
    });
    rows.value = Array.isArray(res) ? res : (res.items || []);
    total.value = Array.isArray(res) ? rows.value.length : (res.total || 0);
    hasMore.value = !Array.isArray(res) && !!res.has_more;
  } catch {
    rows.value = [];
  } finally {
    initialLoading.value = false;
    refreshing.value = false;
  }
}

async function loadTags() {
  try { tagPool.value = await api.knowledgeTags(); } catch { /* keep */ }
  try { pendingTags.value = await api.knowledgePendingTags(); } catch { /* keep */ }
}

async function reload() {
  page.value = 0;
  await Promise.all([loadStats(), loadList(), loadTags()]);
  // 如果有正在处理的文档，启动轮询
  schedulePoll();
}

function nextPage() {
  if (!hasMore.value || refreshing.value) return;
  page.value += 1;
  loadList();
}

function prevPage() {
  if (page.value <= 0 || refreshing.value) return;
  page.value -= 1;
  loadList();
}

function schedulePoll() {
  clearTimeout(pollTimer);
  if (processingDocs.value.length > 0) {
    pollTimer = setTimeout(async () => {
      await loadList();
      await loadStats();
      schedulePoll();
    }, 3000);
  }
}

onMounted(reload);
onUnmounted(() => clearTimeout(pollTimer));
watch([docType, enabledFilter], reload);
watch(searchDraft, (v) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { searchText.value = v.trim(); page.value = 0; loadList(); }, 350);
});

function openCreate() {
  editorMode.value = "create";
  editorDoc.value = { id: "", title: "", content: "", summary: "", doc_type: "pre_vuln", tags: [], enabled: true };
  newTagName.value = "";
  showEditor.value = true;
}

function handleFileSelect(event) {
  const files = Array.from(event.target.files || []);
  batchFiles.value = files.filter(f => 
    f.type.startsWith("text/") || 
    f.name.endsWith(".txt") || f.name.endsWith(".md") || 
    f.name.endsWith(".json") || f.name.endsWith(".py") ||
    f.name.endsWith(".sh") || f.name.endsWith(".yaml") || 
    f.name.endsWith(".yml") || f.name.endsWith(".xml") ||
    f.name.endsWith(".html") || f.name.endsWith(".js")
  );
}

async function batchUpload() {
  if (!batchFiles.value.length) return;
  batchUploading.value = true;
  batchResult.value = "";
  try {
    const docs = [];
    for (const f of batchFiles.value) {
      const content = await f.text();
      if (content.trim()) {
        docs.push({ title: f.name.replace(/\.[^.]+$/, ""), content });
      }
    }
    if (!docs.length) {
      batchResult.value = "没有可用的文本文件";
      return;
    }
    const res = await api.knowledgeBatchCreate(docs);
    batchResult.value = `已上传 ${res.created} 篇文档，正在后台生成摘要...`;
    showBatchUploader.value = false;
    batchFiles.value = [];
    await reload();
  } catch (e) {
    batchResult.value = "上传失败: " + e.message;
  } finally {
    batchUploading.value = false;
  }
}

async function openEdit(doc) {
  editorMode.value = "edit";
  editorDoc.value = { ...doc, tags: [...(doc.tags || [])], content: "加载中..." };
  newTagName.value = "";
  showEditor.value = true;
  try {
    const full = await api.knowledgeGet(doc.id);
    editorDoc.value.content = full.content || "";
    editorDoc.value.summary = full.summary || editorDoc.value.summary;
  } catch { editorDoc.value.content = ""; }
}

function toggleTag(tagName) {
  const tags = editorDoc.value.tags;
  const idx = tags.indexOf(tagName);
  if (idx >= 0) tags.splice(idx, 1);
  else tags.push(tagName);
}

async function addNewTag() {
  const name = newTagName.value.trim();
  if (!name) return;
  try {
    await api.knowledgeCreateTag(name);
    await loadTags();
    newTagName.value = "";
    if (!editorDoc.value.tags.includes(name)) editorDoc.value.tags.push(name);
  } catch (e) {
    alert(e.message?.includes("409") ? "标签已存在" : "添加失败: " + e.message);
  }
}

async function addTagFromPanel() {
  const name = newTagPanelName.value.trim();
  if (!name) return;
  try {
    await api.knowledgeCreateTag(name);
    await loadTags();
    newTagPanelName.value = "";
  } catch (e) {
    alert(e.message?.includes("409") ? "标签已存在" : "添加失败: " + e.message);
  }
}

async function deleteTagFromPanel(name) {
  if (!confirm(`确认删除标签「${name}」？已使用此标签的文档不会自动移除。`)) return;
  try {
    await api.knowledgeDeleteTag(name);
    await loadTags();
  } catch (e) {
    alert("删除失败: " + e.message);
  }
}

async function approveTag(id) {
  try {
    await api.knowledgeApproveTag(id);
    await loadTags();
  } catch (e) {
    alert("通过失败: " + e.message);
  }
}

async function rejectTag(id) {
  try {
    await api.knowledgeRejectTag(id);
    await loadTags();
  } catch (e) {
    alert("拒绝失败: " + e.message);
  }
}

async function saveDoc() {
  if (!editorDoc.value.content.trim()) { alert("文档内容不能为空"); return; }
  editorSaving.value = true;
  try {
    if (editorMode.value === "create") {
      await api.knowledgeCreate({ title: editorDoc.value.title, content: editorDoc.value.content });
    } else {
      await api.knowledgeUpdate(editorDoc.value.id, {
        title: editorDoc.value.title, content: editorDoc.value.content,
        summary: editorDoc.value.summary, doc_type: editorDoc.value.doc_type,
        tags: editorDoc.value.tags, enabled: editorDoc.value.enabled,
      });
    }
    showEditor.value = false;
    await reload();
  } catch (e) { alert("保存失败: " + e.message); }
  finally { editorSaving.value = false; }
}

async function toggleEnabled(doc) {
  try { await api.knowledgeUpdate(doc.id, { enabled: !doc.enabled }); doc.enabled = !doc.enabled; await loadStats(); }
  catch (e) { alert("操作失败: " + e.message); }
}

async function reprocess(doc) {
  try { await api.knowledgeReprocess(doc.id); await reload(); }
  catch (e) { alert("重新处理失败: " + e.message); }
}

async function deleteDoc(doc) {
  if (!confirm(`确认删除「${doc.title}」？`)) return;
  try { await api.knowledgeDelete(doc.id); await reload(); }
  catch (e) { alert("删除失败: " + e.message); }
}

async function viewDetail(doc) {
  showDetail.value = true; detailLoading.value = true; detailDoc.value = null;
  try { detailDoc.value = await api.knowledgeGet(doc.id); }
  catch (e) { alert("加载失败: " + e.message); showDetail.value = false; }
  finally { detailLoading.value = false; }
}
</script>

<template>
  <div class="knowledge-page">
    <header class="page-head split">
      <div>
        <h2>人工知识库 <span class="kb-chip">KB</span></h2>
        <p class="page-sub">用户添加的安全测试技巧文档，AI在深挖阶段按需查阅（渐进式披露）。</p>
      </div>
      <div class="head-actions">
        <button v-if="writable" class="btn primary" @click="openCreate">+ 添加文档</button>
        <button v-if="writable" class="btn ghost" @click="showBatchUploader = true">批量上传</button>
        <router-link class="head-action" to="/">返回任务</router-link>
      </div>
    </header>

    <!-- 正在总结的文档队列 -->
    <div v-if="processingDocs.length" class="kb-queue-panel">
      <div class="kb-queue-header">
        <span class="kb-queue-title">正在生成摘要</span>
        <span class="kb-queue-count">{{ processingDocs.length }} 篇处理中</span>
      </div>
      <div class="kb-queue-list">
        <div v-for="doc in processingDocs" :key="doc.id" class="kb-queue-item">
          <span class="kb-queue-icon" :class="doc.processing">{{ doc.processing === 'processing' ? '⏳' : '⏸' }}</span>
          <span class="kb-queue-name">{{ doc.title }}</span>
          <span class="kb-queue-status" :class="doc.processing">{{ doc.processing === 'processing' ? 'AI分析中...' : '排队中' }}</span>
        </div>
      </div>
    </div>

    <div class="kb-dash">
      <div class="dash-card hero">
        <span class="dash-k">文档总量</span>
        <b class="dash-v">{{ stats.total }}</b>
        <span class="dash-sub">已启用 {{ stats.enabled }}</span>
      </div>
      <div class="dash-card" v-for="t in ['pre_vuln','post_vuln']" :key="t"
           :data-active="docType === t" @click="docType = docType === t ? 'all' : t">
        <span class="dash-icon">{{ TYPE_META[t].icon }}</span>
        <b class="dash-v">{{ stats.by_type?.[t] || 0 }}</b>
        <span class="dash-k">{{ TYPE_META[t].label }}</span>
      </div>
      <div class="dash-card" v-for="[k, v] in Object.entries(stats.by_processing || {})" :key="k"
           :class="PROCESSING_META[k]?.hue || ''">
        <span class="dash-icon">⚙</span>
        <b class="dash-v">{{ v }}</b>
        <span class="dash-k">{{ PROCESSING_META[k]?.label || k }}</span>
      </div>
    </div>

    <!-- 调用时机说明 -->
    <div class="kb-info-panel">
      <div class="kb-info-title">AI 调用时机</div>
      <div class="kb-info-body">
        <div class="kb-info-item"><span class="kb-info-icon">🔒</span>仅在<b>第二次深挖</b>（deepen_count ≥ 2）<b>且工具轮数 > 10</b>时才解锁 knowledge_lookup 工具</div>
        <div class="kb-info-item"><span class="kb-info-icon">🧠</span>AI 必须先依赖<b>自身推理能力</b>测试，知识库仅作辅助手段</div>
        <div class="kb-info-item"><span class="kb-info-icon">📋</span><b>渐进式披露</b>：第一次调用返回标题+摘要，AI 选择后用 doc_id 获取完整原文</div>
        <div class="kb-info-item"><span class="kb-info-icon">⚡</span><b>Type A</b>（漏洞前）：未发现漏洞时可查阅；<b>Type B</b>（漏洞后）：已提交 finding 或深挖上下文含 vuln_type 时才可查阅</div>
        <div class="kb-info-item"><span class="kb-info-icon">⚖️</span>知识库内容与 AI 分析冲突时，<b>AI 独立判断优先</b></div>
      </div>
    </div>

    <!-- 标签管理 -->
    <div class="kb-tag-panel-wrap">
      <div class="kb-tag-panel-header" @click="showTagPanel = !showTagPanel">
        <span class="kb-tag-panel-title">标签池管理</span>
        <span class="kb-tag-panel-count">{{ tagPool.length }} 个标签</span>
        <span class="kb-tag-panel-toggle">{{ showTagPanel ? '收起 ▲' : '展开 ▼' }}</span>
      </div>
      <div v-if="showTagPanel" class="kb-tag-panel-body">
        <div class="kb-tag-pool-list">
          <span v-for="t in tagPool" :key="t.name" class="tag-chip static">
            {{ t.name }}
            <span v-if="writable" class="tag-del" @click.stop="deleteTagFromPanel(t.name)">✕</span>
          </span>
          <span v-if="!tagPool.length" class="kb-tag-empty">暂无标签</span>
        </div>
        <div v-if="writable" class="tag-add-row">
          <input v-model="newTagPanelName" placeholder="添加新标签" @keydown.enter.prevent="addTagFromPanel" class="tag-add-input" />
          <button class="btn sm ghost" @click="addTagFromPanel">添加</button>
        </div>
        <!-- AI建议的待审核标签 -->
        <div v-if="pendingTags.length" class="pending-tags-section">
          <div class="pending-tags-title">AI 建议标签（待审核 {{ pendingTags.length }}）</div>
          <div class="pending-tags-list">
            <div v-for="pt in pendingTags" :key="pt.id" class="pending-tag-item">
              <span class="pending-tag-name">{{ pt.name }}</span>
              <div class="pending-tag-actions">
                <button class="btn sm primary" @click="approveTag(pt.id)">通过</button>
                <button class="btn sm danger-ghost" @click="rejectTag(pt.id)">拒绝</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="kb-toolbar">
      <div class="filter-tabs">
        <button v-for="tab in TYPE_TABS" :key="tab.id"
                :class="['tab-btn', { active: docType === tab.id }]"
                @click="docType = tab.id">{{ tab.label }}</button>
      </div>
      <select v-model="enabledFilter" class="filter-select">
        <option value="all">全部状态</option>
        <option value="enabled">已启用</option>
        <option value="disabled">已禁用</option>
      </select>
      <input v-model="searchDraft" class="filter-search" placeholder="搜索标题/摘要/标签..." />
    </div>

    <div v-if="initialLoading" class="kb-loading">加载中...</div>
    <div v-else-if="!rows.length" class="kb-empty">
      <p>暂无文档。{{ writable ? '点击「添加文档」上传技巧文档。' : '' }}</p>
    </div>
    <div v-else class="kb-list">
      <div v-for="doc in rows" :key="doc.id" class="kb-card" :class="{ disabled: !doc.enabled }">
        <div class="kb-card-head">
          <span class="kb-type-badge" :class="TYPE_META[doc.doc_type]?.hue || ''">
            {{ TYPE_META[doc.doc_type]?.icon }} {{ TYPE_META[doc.doc_type]?.label }}
          </span>
          <span v-if="doc.processing !== 'ready'" class="kb-proc-badge" :class="PROCESSING_META[doc.processing]?.hue || ''">
            {{ PROCESSING_META[doc.processing]?.label || doc.processing }}
          </span>
          <span class="kb-hit">引用 {{ doc.hit_count }} 次</span>
        </div>
        <h3 class="kb-title" @click="doc.processing === 'pending' || doc.processing === 'processing' ? null : viewDetail(doc)">{{ doc.title }}</h3>
        <p class="kb-summary">{{ doc.summary || '(无摘要)' }}</p>
        <div class="kb-tags" v-if="doc.tags?.length">
          <span v-for="t in doc.tags" :key="t" class="kb-tag">{{ t }}</span>
        </div>
        <div class="kb-card-foot">
          <span class="kb-date">{{ doc.updated_at?.slice(0, 16) }}</span>
          <div v-if="writable" class="kb-actions">
            <button v-if="doc.processing !== 'pending' && doc.processing !== 'processing'" class="btn sm ghost" @click="viewDetail(doc)">查看</button>
            <button v-if="doc.processing !== 'pending' && doc.processing !== 'processing'" class="btn sm ghost" @click="openEdit(doc)">编辑</button>
            <button v-if="doc.processing === 'failed'" class="btn sm ghost" @click="reprocess(doc)">重处理</button>
            <button v-if="doc.processing !== 'pending' && doc.processing !== 'processing'" class="btn sm ghost" @click="toggleEnabled(doc)">{{ doc.enabled ? '禁用' : '启用' }}</button>
            <button class="btn sm danger-ghost" @click="deleteDoc(doc)">删除</button>
          </div>
        </div>
      </div>
    </div>

    <div v-if="!initialLoading && total > pageSize" class="hard-pager">
      <button type="button" @click="prevPage" :disabled="page <= 0 || refreshing">上一页</button>
      <span>第 {{ page + 1 }} 页 · {{ page * pageSize + 1 }}-{{ page * pageSize + rows.length }}{{ hasMore ? '+' : '' }}</span>
      <button type="button" @click="nextPage" :disabled="!hasMore || refreshing">下一页</button>
    </div>

    <!-- 批量上传弹窗 -->
    <div v-if="showBatchUploader" class="kb-modal-backdrop" @click.self="showBatchUploader = false">
      <div class="kb-modal" style="max-width: 500px;">
        <h3>批量上传文档</h3>
        <p class="kb-batch-hint">选择文件夹或多个文件，支持 .txt .md .py .sh .yaml .json .xml .html .js</p>
        <input type="file" multiple @change="handleFileSelect" class="kb-file-input" />
        <div v-if="batchFiles.length" class="kb-file-list">
          <div v-for="f in batchFiles" :key="f.name" class="kb-file-item">📄 {{ f.name }} <span class="kb-file-size">{{ (f.size / 1024).toFixed(1) }}KB</span></div>
        </div>
        <div v-if="batchResult" class="kb-batch-result">{{ batchResult }}</div>
        <div class="kb-modal-actions">
          <button class="btn ghost" @click="showBatchUploader = false">取消</button>
          <button class="btn primary" :disabled="!batchFiles.length || batchUploading" @click="batchUpload">
            {{ batchUploading ? '上传中...' : `上传 ${batchFiles.length} 个文件` }}
          </button>
        </div>
      </div>
    </div>

    <div v-if="showEditor" class="kb-modal-backdrop" @click.self="showEditor = false">
      <div class="kb-modal">
        <h3>{{ editorMode === 'create' ? '添加技巧文档' : '编辑文档' }}</h3>
        <div class="kb-form">
          <label>标题</label>
          <input v-model="editorDoc.title" placeholder="文档标题（留空自动截取）" />
          <template v-if="editorMode === 'edit'">
            <label>摘要</label>
            <textarea v-model="editorDoc.summary" rows="3" placeholder="AI自动生成或手动填写"></textarea>
            <label>一级分类</label>
            <select v-model="editorDoc.doc_type">
              <option value="pre_vuln">漏洞前（Type A）— 发现漏洞前可查阅</option>
              <option value="post_vuln">漏洞后（Type B）— 确认漏洞后可查阅</option>
            </select>
            <label>二级标签（从标签池选择）</label>
            <div class="tag-pool">
              <span v-for="t in tagPool" :key="t.name"
                    class="tag-chip"
                    :class="{ selected: editorDoc.tags.includes(t.name) }"
                    @click="toggleTag(t.name)">
                {{ t.name }}
              </span>
            </div>
            <div class="tag-add-row">
              <input v-model="newTagName" placeholder="添加新标签到标签池" @keydown.enter.prevent="addNewTag" class="tag-add-input" />
              <button class="btn sm ghost" @click="addNewTag">添加</button>
            </div>
            <label class="checkbox-row">
              <input type="checkbox" v-model="editorDoc.enabled" class="kb-checkbox" /> <span>启用</span>
            </label>
          </template>
          <label>内容</label>
          <textarea v-model="editorDoc.content" rows="14" placeholder="粘贴技巧文档内容..."></textarea>
        </div>
        <div class="kb-modal-actions">
          <button class="btn ghost" @click="showEditor = false">取消</button>
          <button class="btn primary" :disabled="editorSaving" @click="saveDoc">
            {{ editorSaving ? '保存中...' : '保存' }}
          </button>
        </div>
      </div>
    </div>

    <div v-if="showDetail" class="kb-modal-backdrop" @click.self="showDetail = false">
      <div class="kb-modal">
        <div v-if="detailLoading" class="kb-loading">加载中...</div>
        <template v-else-if="detailDoc">
          <div class="kb-detail-head">
            <h3>{{ detailDoc.title }}</h3>
            <div class="kb-detail-meta">
              <span class="kb-type-badge" :class="TYPE_META[detailDoc.doc_type]?.hue || ''">
                {{ TYPE_META[detailDoc.doc_type]?.icon }} {{ TYPE_META[detailDoc.doc_type]?.label }}
              </span>
              <span class="kb-hit">引用 {{ detailDoc.hit_count }} 次</span>
              <span class="kb-date">{{ detailDoc.updated_at?.slice(0, 16) }}</span>
            </div>
          </div>
          <div v-if="detailDoc.tags?.length" class="kb-tags">
            <span v-for="t in detailDoc.tags" :key="t" class="kb-tag">{{ t }}</span>
          </div>
          <div v-if="detailDoc.summary" class="kb-detail-summary">
            <strong>摘要：</strong>{{ detailDoc.summary }}
          </div>
          <pre class="kb-detail-content">{{ detailDoc.content }}</pre>
        </template>
        <div class="kb-modal-actions">
          <button class="btn ghost" @click="showDetail = false">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.knowledge-page { padding: 16px; max-width: 1200px; margin: 0 auto; }
.page-head { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; flex-wrap: wrap; gap: 12px; }
.page-head h2 { margin: 0 0 4px; font-size: 1.4rem; }
.page-sub { margin: 0; color: var(--text-muted, #888); font-size: .85rem; }
.head-actions { display: flex; gap: 8px; align-items: center; }
.kb-chip { font-size: .6rem; background: var(--accent, #3b9eff); color: #fff; padding: 2px 6px; border-radius: 4px; vertical-align: middle; }
.kb-dash { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 16px; }
.dash-card { background: var(--card-bg, #1a1a2e); border: 1px solid var(--border, #333); border-radius: 8px; padding: 12px 16px; min-width: 100px; cursor: pointer; transition: border-color .15s; }
.dash-card:hover { border-color: var(--accent, #3b9eff); }
.dash-card.hero { background: var(--accent-bg, rgba(59,158,255,.1)); }
.dash-k { display: block; font-size: .7rem; color: var(--text-muted, #888); }
.dash-v { font-size: 1.6rem; font-weight: 700; }
.dash-sub { font-size: .7rem; color: var(--text-muted, #888); }
.dash-icon { font-size: 1.2rem; }
.kb-toolbar { display: flex; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; align-items: center; }
.filter-tabs { display: flex; gap: 4px; }
.tab-btn { padding: 5px 14px; border: 1px solid var(--border, #333); background: transparent; color: var(--text, #eee); border-radius: 6px; cursor: pointer; font-size: .85rem; }
.tab-btn.active { background: var(--accent, #3b9eff); color: #fff; border-color: var(--accent, #3b9eff); }
.filter-select { padding: 5px 10px; border: 1px solid var(--border, #333); background: var(--card-bg, #1a1a2e); color: var(--text, #eee); border-radius: 6px; font-size: .85rem; }
.filter-search { flex: 1; min-width: 200px; padding: 5px 12px; border: 1px solid var(--border, #333); background: var(--card-bg, #1a1a2e); color: var(--text, #eee); border-radius: 6px; font-size: .85rem; }
.kb-loading, .kb-empty { text-align: center; padding: 40px; color: var(--text-muted, #888); }
.kb-list { display: grid; gap: 10px; }
.kb-card { background: var(--card-bg, #1a1a2e); border: 1px solid var(--border, #333); border-radius: 8px; padding: 14px; transition: border-color .15s; }
.kb-card:hover { border-color: var(--accent, #3b9eff); }
.kb-card.disabled { opacity: .55; }
.kb-card-head { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; font-size: .75rem; }
.kb-type-badge { padding: 2px 8px; border-radius: 4px; font-weight: 600; }
.kb-type-badge.info { background: rgba(59,158,255,.15); color: #3b9eff; }
.kb-type-badge.warn { background: rgba(255,193,7,.15); color: #ffc107; }
.kb-proc-badge { padding: 2px 6px; border-radius: 4px; }
.kb-proc-badge.ok { background: rgba(40,200,100,.15); color: #28c864; }
.kb-proc-badge.danger { background: rgba(255,80,80,.15); color: #ff5050; }
.kb-proc-badge.info { background: rgba(59,158,255,.15); color: #3b9eff; }
.kb-proc-badge.muted { background: rgba(128,128,128,.15); color: #888; }
.kb-hit { margin-left: auto; color: var(--text-muted, #888); }
.kb-title { margin: 0 0 4px; font-size: 1rem; cursor: pointer; }
.kb-title:hover { color: var(--accent, #3b9eff); }
.kb-summary { margin: 0 0 6px; font-size: .82rem; color: var(--text-muted, #aaa); line-height: 1.4; }
.kb-tags { display: flex; gap: 4px; flex-wrap: wrap; margin-bottom: 6px; }
.kb-tag { font-size: .7rem; padding: 2px 8px; border-radius: 10px; background: rgba(128,128,128,.15); color: var(--text-muted, #aaa); }
.kb-card-foot { display: flex; justify-content: space-between; align-items: center; margin-top: 8px; }
.kb-date { font-size: .7rem; color: var(--text-muted, #666); }
.kb-actions { display: flex; gap: 4px; }
.btn { padding: 5px 14px; border-radius: 6px; border: 1px solid var(--border, #333); background: transparent; color: var(--text, #eee); cursor: pointer; font-size: .85rem; }
.btn.primary { background: var(--accent, #3b9eff); color: #fff; border-color: var(--accent, #3b9eff); }
.btn.ghost { background: transparent; }
.btn.sm { padding: 3px 8px; font-size: .75rem; }
.btn.danger-ghost { color: #ff5050; border-color: rgba(255,80,80,.3); }
.btn:hover { opacity: .85; }
.kb-modal-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,.6); display: flex; align-items: center; justify-content: center; z-index: 200; padding: 20px; }
.kb-modal { background: var(--bg, #0f0f1a); border: 1px solid var(--border, #333); border-radius: 12px; padding: 20px; max-width: 700px; width: 100%; max-height: 85vh; overflow-y: auto; }
.kb-modal h3 { margin: 0 0 14px; }
.kb-form { display: flex; flex-direction: column; gap: 6px; }
.kb-form label { font-size: .8rem; color: var(--text-muted, #888); margin-top: 8px; }
.kb-form input, .kb-form textarea, .kb-form select { width: 100%; padding: 6px 10px; border: 1px solid var(--border, #333); background: var(--card-bg, #1a1a2e); color: var(--text, #eee); border-radius: 6px; font-size: .85rem; font-family: inherit; }
.kb-form textarea { resize: vertical; }
.kb-modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }
.tag-pool { display: flex; flex-wrap: wrap; gap: 6px; padding: 8px; border: 1px solid var(--border, #333); border-radius: 6px; background: var(--card-bg, #1a1a2e); max-height: 120px; overflow-y: auto; }
.tag-chip { font-size: .75rem; padding: 3px 10px; border-radius: 12px; background: rgba(128,128,128,.12); color: var(--text-muted, #aaa); cursor: pointer; user-select: none; transition: all .12s; }
.tag-chip:hover { background: rgba(59,158,255,.2); color: #3b9eff; }
.tag-chip.selected { background: var(--accent, #3b9eff); color: #fff; }
.tag-add-row { display: flex; gap: 6px; margin-top: 6px; }
.tag-add-input { flex: 1; padding: 4px 10px; border: 1px solid var(--border, #333); background: var(--card-bg, #1a1a2e); color: var(--text, #eee); border-radius: 6px; font-size: .8rem; }
.checkbox-row { display: flex !important; align-items: center; gap: 6px; margin-top: 8px !important; }
.kb-checkbox { width: auto !important; margin: 0 !important; }
.kb-detail-head h3 { margin: 0 0 8px; }
.kb-detail-meta { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; font-size: .8rem; }
.kb-detail-summary { padding: 10px; background: rgba(59,158,255,.08); border-radius: 6px; margin-bottom: 10px; font-size: .85rem; line-height: 1.5; }
.kb-detail-content { white-space: pre-wrap; word-break: break-word; font-size: .82rem; line-height: 1.5; max-height: 50vh; overflow-y: auto; padding: 10px; background: var(--card-bg, #1a1a2e); border-radius: 6px; border: 1px solid var(--border, #333); }

/* 调用时机说明面板 */
.kb-info-panel { background: var(--card-bg, #1a1a2e); border: 1px solid var(--border, #333); border-left: 3px solid var(--accent, #3b9eff); border-radius: 8px; padding: 12px 16px; margin-bottom: 16px; }
.kb-info-title { font-size: .85rem; font-weight: 700; margin-bottom: 8px; color: var(--accent, #3b9eff); }
.kb-info-body { display: flex; flex-direction: column; gap: 4px; }
.kb-info-item { font-size: .78rem; color: var(--text-muted, #aaa); line-height: 1.5; }
.kb-info-item b { color: var(--text, #eee); }
.kb-info-icon { display: inline-block; width: 18px; text-align: center; }

/* 标签管理面板 */
.kb-tag-panel-wrap { background: var(--card-bg, #1a1a2e); border: 1px solid var(--border, #333); border-radius: 8px; margin-bottom: 16px; overflow: hidden; }
.kb-tag-panel-header { display: flex; align-items: center; gap: 10px; padding: 10px 14px; cursor: pointer; user-select: none; }
.kb-tag-panel-header:hover { background: rgba(59,158,255,.05); }
.kb-tag-panel-title { font-size: .85rem; font-weight: 600; }
.kb-tag-panel-count { font-size: .75rem; color: var(--text-muted, #888); }
.kb-tag-panel-toggle { margin-left: auto; font-size: .75rem; color: var(--text-muted, #888); }
.kb-tag-panel-body { padding: 10px 14px; border-top: 1px solid var(--border, #333); }
.kb-tag-pool-list { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 8px; }
.tag-chip.static { font-size: .75rem; padding: 3px 10px; border-radius: 12px; background: rgba(128,128,128,.12); color: var(--text-muted, #aaa); display: inline-flex; align-items: center; gap: 4px; }
.tag-del { cursor: pointer; font-size: .7rem; opacity: .6; }
.tag-del:hover { opacity: 1; color: #ff5050; }
.kb-tag-empty { font-size: .78rem; color: var(--text-muted, #666); }

/* AI建议标签审核区 */
.pending-tags-section { margin-top: 10px; padding-top: 8px; border-top: 1px dashed var(--border, #333); }
.pending-tags-title { font-size: .78rem; color: var(--accent, #3b9eff); margin-bottom: 6px; font-weight: 600; }
.pending-tags-list { display: flex; flex-direction: column; gap: 4px; }
.pending-tag-item { display: flex; align-items: center; justify-content: space-between; padding: 4px 8px; border-radius: 6px; background: rgba(255,193,7,.08); }
.pending-tag-name { font-size: .8rem; color: var(--text, #eee); }
.pending-tag-actions { display: flex; gap: 4px; }

/* 正在总结队列 */
.kb-queue-panel { background: var(--card-bg, #1a1a2e); border: 1px solid var(--border, #333); border-left: 3px solid #ffc107; border-radius: 8px; padding: 10px 14px; margin-bottom: 16px; }
.kb-queue-header { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.kb-queue-title { font-size: .85rem; font-weight: 600; color: #ffc107; }
.kb-queue-count { font-size: .75rem; color: var(--text-muted, #888); }
.kb-queue-list { display: flex; flex-direction: column; gap: 3px; max-height: 120px; overflow-y: auto; }
.kb-queue-item { display: flex; align-items: center; gap: 6px; font-size: .78rem; }
.kb-queue-icon { font-size: .8rem; }
.kb-queue-name { color: var(--text, #ddd); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.kb-queue-status { font-size: .72rem; color: var(--text-muted, #888); }
.kb-queue-status.processing { color: #3b9eff; }

/* 批量上传 */
.kb-batch-hint { font-size: .78rem; color: var(--text-muted, #888); margin: 0 0 10px; }
.kb-file-input { width: 100% !important; padding: 8px !important; border: 1px dashed var(--border, #333) !important; border-radius: 6px; color: var(--text-muted, #888); margin-bottom: 10px; }
.kb-file-list { max-height: 150px; overflow-y: auto; margin-bottom: 10px; }
.kb-file-item { font-size: .78rem; padding: 3px 6px; color: var(--text, #ddd); }
.kb-file-size { color: var(--text-muted, #666); font-size: .7rem; }
.kb-batch-result { font-size: .8rem; color: #28c864; margin-bottom: 8px; }
</style>
