<script setup>
import { ref, computed, watch, nextTick } from "vue";
import { marked } from "marked";
import DOMPurify from "dompurify";
import { api, canWrite, isReadonly } from "../api.js";
import { copyText } from "../clipboard.js";
import { CONF, buildEdusrcToolReport, buildReportMd, effectiveSeverity } from "../report.js";
import { fmtLocalTime } from "../format.js";

const props = defineProps({ findingId: String, mode: String, srcType: String }); // mode: view | review | submit | rejected | archived
const emit = defineEmits(["close", "updated", "toast"]);

const f = ref(null);
const editing = ref(false);
const edit = ref({});
const userSeverity = ref("");
const userNotes = ref("");
const deepenOpen = ref(false);
const deepenText = ref("");
const assistantText = ref("");
const assistantBusy = ref(false);
const assistantMessages = ref([]);
const assistantAbort = ref(null);
const raLog = ref(null);
const DEFAULT_ASSISTANT_WELCOME = "我是这份漏洞的报告助手。点下面的快捷指令，或直接问证据、等级、复现怎么写。润色结果可以一键写进编辑器。";
const ASSISTANT_PRESETS = [
  { label: "审证据", text: "判断这份报告证据链是否足够提交 SRC：缺什么、有没有像误报的地方、过审概率怎么看。" },
  { label: "润色成SRC口径", text: "按当前 SRC 类型把标题、描述、影响范围、复现步骤和 PoC 改成可直接提交的口径，并调用改稿工具。" },
  { label: "补复现步骤", text: "把复现步骤写成审核员能跟着点的逐步操作，补齐请求要点和判定成功的标志。" },
  { label: "校准等级", text: "根据实际危害校准严重/高危/中危/低危，说明为什么现在这个等级站得住或应该下调。" },
  { label: "现场再验证", text: "对 PoC 或关键接口再发一次定向请求，看漏洞是否仍在，并解读状态码和关键响应。" },
];
const SEVS = ["严重", "高危", "中危", "低危"];
const isEnterprise = computed(() => props.srcType === "enterprise");

watch(() => props.findingId, async (id) => {
  if (!id) { f.value = null; return; }
  f.value = await api.finding(id);
  const rv = f.value.review || {};
  const e = rv.user_edits || {};
  edit.value = {
    title: e.title ?? f.value.title,
    description: e.description ?? f.value.description,
    affected_scope: e.affected_scope ?? f.value.affected_scope,
    steps: (e.steps ?? f.value.steps ?? []).join("\n"),
    poc: e.poc ?? f.value.poc,
  };
  userSeverity.value = rv.user_severity || rv.severity_final || "";
  userNotes.value = rv.user_notes || "";
  editing.value = false;
  deepenOpen.value = false;
  deepenText.value = "";
  assistantText.value = "";
  assistantBusy.value = false;
  if (assistantAbort.value) {
    assistantAbort.value.abort();
    assistantAbort.value = null;
  }
  const saved = f.value.assistant_messages;
  assistantMessages.value = (saved?.length)
    ? saved
    : [{ role: "assistant", content: DEFAULT_ASSISTANT_WELCOME }];
}, { immediate: true });

function renderSafeMd(text) {
  return DOMPurify.sanitize(marked.parse(text || ""));
}

function fmtFindingTime(value) {
  return fmtLocalTime(value) || "-";
}

const html = computed(() => f.value ? renderSafeMd(buildReportMd(f.value)) : "");
const effSev = computed(() => f.value ? effectiveSeverity(f.value) : "-");
const review = computed(() => f.value?.review || {});
const confidenceText = computed(() => CONF[review.value.confidence] || review.value.confidence || "-");
const stepCount = computed(() => (f.value?.steps || []).length);
const chainCount = computed(() => (f.value?.kill_chain || []).length);
const readonly = computed(() => !canWrite());
const readonlyOnly = computed(() => isReadonly());

function renderAssistantMd(text) {
  return renderSafeMd(text);
}

async function saveEdits() {
  try {
    const user_edits = {
      title: edit.value.title, description: edit.value.description,
      affected_scope: edit.value.affected_scope,
      steps: edit.value.steps.split("\n").map((s) => s.trim()).filter(Boolean),
      poc: edit.value.poc,
    };
    await api.userReview(f.value.id, { user_edits, user_severity: userSeverity.value, user_notes: userNotes.value });
    f.value = await api.finding(f.value.id);
    editing.value = false;
    emit("toast", "已保存修改");
    emit("updated");
  } catch (e) {
    emit("toast", String(e.message || e).replace(/^\d+\s*/, ""));
  }
}

async function decide(status) {
  try {
    const res = await api.userReview(f.value.id, {
      user_status: status, user_severity: userSeverity.value, user_notes: userNotes.value,
    });
    emit("toast", status === "passed"
      ? `已通过 → 进入待提交${res.killsweep_triggered ? "，通杀 Hunter 已启动" : ""}${res.killsweep_skipped_reason ? "，已断开通杀递归" : ""}`
      : "已驳回");
    emit("updated");
    emit("close");
  } catch (e) {
    emit("toast", String(e.message || e).replace(/^\d+\s*/, ""));
  }
}

async function submitDeepen() {
  const d = deepenText.value.trim();
  if (!d) { emit("toast", "请先写一句深挖指令"); return; }
  try {
    const r = await api.deepen(f.value.id, d);
    emit("toast", r.message || "已打回深挖，目标重新入队");
    emit("updated");
    emit("close");
  } catch (e) {
    emit("toast", String(e.message || e).replace(/^\d+\s*/, ""));
  }
}

async function markSubmitted() {
  try {
    await api.userReview(f.value.id, { submitted: true });
    emit("toast", "已标记为已提交");
    emit("updated");
    emit("close");
  } catch (e) {
    emit("toast", String(e.message || e).replace(/^\d+\s*/, ""));
  }
}

async function restore() {
  try {
    await api.userReview(f.value.id, { user_status: "pending" });
    emit("toast", "已恢复到复审队列");
    emit("updated");
    emit("close");
  } catch (e) {
    emit("toast", String(e.message || e).replace(/^\d+\s*/, ""));
  }
}

async function restoreArchived() {
  // AI 未采纳（ignored/deepen）：verdict 本非 accepted，只改 user_status 无效，
  // 必须走专用接口把 verdict 改回 accepted 才能真正进复审队列。
  try {
    await api.restoreArchived(f.value.id);
    emit("toast", "已恢复到复审队列");
    emit("updated");
    emit("close");
  } catch (e) {
    emit("toast", String(e.message || e).replace(/^\d+\s*/, ""));
  }
}

function copyMd() {
  copyText(buildReportMd(f.value)).then(() => emit("toast", "报告已复制（Markdown）"))
    .catch(() => emit("toast", "复制失败，请使用导出按钮"));
}
function copyEdusrcJson() {
  const text = JSON.stringify(buildEdusrcToolReport(f.value), null, 2);
  copyText(text).then(() => emit("toast", "已复制 EduSRC 工具 JSON"))
    .catch(() => emit("toast", "复制失败，请使用导出按钮"));
}

const TOOL_LABEL = { http_request: "HTTP 请求", run_shell: "执行命令", propose_report_edits: "提出改稿" };

function stepLabel(ev) {
  if (ev.type === "thinking") return ev.text || "分析中…";
  if (ev.type === "tool_call") return `${TOOL_LABEL[ev.tool] || ev.tool}：${ev.summary || ""}`;
  if (ev.type === "tool_result") return `↳ ${ev.summary || "完成"}`;
  return ev.text || "";
}

function editFields(edits) {
  if (!edits) return [];
  return ["title", "description", "affected_scope", "steps", "poc", "severity"].filter((k) => edits[k]);
}

async function scrollAssistant() {
  await nextTick();
  const el = raLog.value;
  if (el) el.scrollTop = el.scrollHeight;
}

function stopAssistant() {
  if (assistantAbort.value) assistantAbort.value.abort();
}

function copyAssistant(m) {
  const text = (m.content || m.partial || "").trim();
  if (!text) { emit("toast", "还没有可复制的内容"); return; }
  copyText(text).then(() => emit("toast", "已复制助手回复")).catch(() => emit("toast", "复制失败"));
}

function applySuggestedEdits(edits) {
  if (!edits || !f.value) return;
  if (edits.title) edit.value.title = edits.title;
  if (edits.description) edit.value.description = edits.description;
  if (edits.affected_scope) edit.value.affected_scope = edits.affected_scope;
  if (Array.isArray(edits.steps)) edit.value.steps = edits.steps.join("\n");
  if (edits.poc) edit.value.poc = edits.poc;
  if (edits.severity) userSeverity.value = edits.severity;
  editing.value = true;
  emit("toast", "已填入编辑器，确认后点保存修改");
}

/** 聊天输入框 Enter 发送：跳过 IME 组合期（拼音输入法确认候选词时不触发发送）。 */
function onChatEnter(e, fn) {
  if (e.isComposing || e.keyCode === 229) return;
  e.preventDefault();
  fn();
}

async function askAssistant(preset = "") {
  const text = (preset || assistantText.value).trim();
  if (!text || assistantBusy.value || !f.value) return;
  assistantText.value = "";
  assistantMessages.value.push({ role: "user", content: text });
  assistantBusy.value = true;
  scrollAssistant();

  const liveMsg = { role: "assistant", content: "", steps: [], streaming: true };
  assistantMessages.value.push(liveMsg);
  const idx = assistantMessages.value.length - 1;
  const controller = new AbortController();
  assistantAbort.value = controller;

  const update = (patch) => {
    assistantMessages.value[idx] = { ...assistantMessages.value[idx], ...patch };
  };
  const pushStep = (ev) => {
    const cur = assistantMessages.value[idx];
    const steps = [...(cur.steps || [])];
    if (ev.type === "tool_result" && steps.length && steps[steps.length - 1].type === "tool_call") {
      steps[steps.length - 1] = { ...steps[steps.length - 1], result: stepLabel(ev) };
    } else {
      steps.push({ type: ev.type, label: stepLabel(ev), tool: ev.tool });
    }
    update({ steps });
    scrollAssistant();
  };

  try {
    await api.reportAssistantStream(f.value.id, text, (ev) => {
      switch (ev.type) {
        case "thinking":
        case "tool_call":
        case "tool_result":
          pushStep(ev);
          break;
        case "assistant_partial":
          update({ partial: ev.text });
          scrollAssistant();
          break;
        case "suggested_edits":
          update({ suggestedEdits: ev.edits || null });
          break;
        case "final":
          update({
            content: ev.text || "",
            partial: "",
            suggestedEdits: ev.suggested_edits || assistantMessages.value[idx].suggestedEdits || null,
          });
          scrollAssistant();
          break;
        case "done":
          update({
            content: ev.answer || assistantMessages.value[idx].content || "已完成。",
            streaming: false,
            partial: "",
            suggestedEdits: ev.suggested_edits || assistantMessages.value[idx].suggestedEdits || null,
          });
          break;
        default:
          break;
      }
    }, controller.signal);
    if (assistantMessages.value[idx].streaming) {
      update({ streaming: false });
    }
  } catch (e) {
    if (e?.name === "AbortError") {
      update({
        content: assistantMessages.value[idx].content || assistantMessages.value[idx].partial || "已停止。",
        streaming: false,
        partial: "",
      });
    } else {
      update({ content: `报告助手异常：${String(e.message || e)}`, streaming: false });
    }
  } finally {
    assistantBusy.value = false;
    assistantAbort.value = null;
    scrollAssistant();
  }
}
</script>

<template>
  <div class="drawer" :class="{ open: !!findingId }">
    <div v-if="f" class="drawer-content">
      <div class="md-toolbar">
        <button class="copy" @click="copyMd">复制 Markdown</button>
        <button v-if="!isEnterprise" class="copy" @click="copyEdusrcJson">复制 EduSRC JSON</button>
        <button v-if="mode === 'review' && !readonly" @click="editing = !editing">{{ editing ? "预览" : "编辑内容" }}</button>
        <span class="sev-pill" :class="effSev">{{ effSev }}</span>
        <span class="grow"></span>
        <button class="close" @click="emit('close')">×</button>
      </div>

      <!-- 编辑模式 -->
      <div v-if="editing" class="edit-form">
        <label>标题 <input v-model="edit.title" /></label>
        <label>等级
          <select v-model="userSeverity">
            <option v-for="s in SEVS" :key="s" :value="s">{{ s }}</option>
          </select>
        </label>
        <label>描述 <textarea v-model="edit.description" rows="3" /></label>
        <label>影响范围 <textarea v-model="edit.affected_scope" rows="2" /></label>
        <label>复现步骤（每行一步） <textarea v-model="edit.steps" rows="4" /></label>
        <label>PoC <textarea v-model="edit.poc" rows="3" /></label>
        <label>复审备注 <textarea v-model="userNotes" rows="2" placeholder="人工复审意见…" /></label>
        <button class="primary" @click="saveEdits">保存修改</button>
      </div>

      <!-- 预览模式：报告档案 + Markdown + 小助手 -->
      <div v-else class="report-scroll">
        <section class="report-brief">
          <div class="report-brief-main">
            <div class="eyebrow">VULNERABILITY DOSSIER</div>
            <h1>{{ f.review?.user_edits?.title || f.title }}</h1>
            <div class="report-target">{{ f.target_url }}</div>
          </div>
          <div class="report-brief-side">
            <span class="sev-pill" :class="effSev">{{ effSev }}</span>
            <b>{{ review.score ?? "-" }}</b>
            <small>review score</small>
          </div>
        </section>

        <section class="report-facts">
          <div><span>漏洞类型</span><b>{{ f.vuln_type }}</b></div>
          <div><span>归属单位</span><b>{{ f.edu_school || f.owner || "待确认" }}</b></div>
          <div><span>发现时间</span><b>{{ fmtFindingTime(f.created_at) }}</b></div>
          <div v-if="f.llm_model"><span>产出模型</span><b :title="f.llm_base_url || ''">{{ f.llm_model }}</b></div>
          <div><span>信度</span><b>{{ confidenceText }}</b></div>
          <div><span>复现步骤</span><b>{{ stepCount }}</b></div>
          <div><span>攻击链路</span><b>{{ chainCount }}</b></div>
        </section>

        <article class="markdown-body" v-html="html"></article>

        <section class="report-assistant">
          <div class="ra-head">
            <div>
              <span>报告助手</span>
              <small>{{ readonlyOnly ? "只读模式不可发送" : readonly ? "未认证，请先换令牌" : "问证据、等级、复现；可改稿进编辑器，也可做少量定向验证" }}</small>
            </div>
            <div v-if="!readonly" class="ra-actions">
              <button v-if="assistantBusy" class="ra-stop" @click="stopAssistant">停止</button>
            </div>
          </div>
          <div v-if="!readonly" class="ra-chips">
            <button
              v-for="p in ASSISTANT_PRESETS"
              :key="p.label"
              type="button"
              :disabled="assistantBusy"
              @click="askAssistant(p.text)"
            >{{ p.label }}</button>
          </div>
          <div ref="raLog" class="ra-log">
            <div v-for="(m, i) in assistantMessages" :key="i" class="ra-msg" :class="m.role">
              <span>{{ m.role === "user" ? "你" : "助手" }}</span>
              <div class="ra-body">
                <ul v-if="m.steps && m.steps.length" class="ra-steps">
                  <li v-for="(s, si) in m.steps" :key="si" class="ra-step" :class="s.type">
                    <span class="ra-step-ico">{{ s.type === "tool_call" ? "⚙" : s.type === "thinking" ? "…" : "•" }}</span>
                    <span class="ra-step-txt">
                      {{ s.label }}
                      <em v-if="s.result" class="ra-step-res">{{ s.result }}</em>
                    </span>
                  </li>
                </ul>
                <div v-if="m.streaming && m.partial && !m.content" class="ra-md ra-partial" v-html="renderAssistantMd(m.partial)"></div>
                <div v-if="m.content" class="ra-md" v-html="renderAssistantMd(m.content)"></div>
                <div v-if="m.streaming && !m.content && !m.partial && !(m.steps && m.steps.length)" class="ra-md ra-pending"><p>正在分析…</p></div>
                <span v-if="m.streaming" class="ra-cursor">▍</span>
                <div v-if="m.suggestedEdits && editFields(m.suggestedEdits).length" class="ra-suggest">
                  <div>
                    <b>可应用改稿</b>
                    <small>{{ editFields(m.suggestedEdits).join("、") }}{{ m.suggestedEdits.rationale ? ` · ${m.suggestedEdits.rationale}` : "" }}</small>
                  </div>
                  <button class="primary" :disabled="readonly" @click="applySuggestedEdits(m.suggestedEdits)">写入编辑器</button>
                </div>
                <div v-if="m.role === 'assistant' && (m.content || m.partial) && !m.streaming" class="ra-msg-actions">
                  <button type="button" @click="copyAssistant(m)">复制</button>
                </div>
              </div>
            </div>
          </div>
          <div v-if="!readonly" class="ra-input">
            <textarea v-model="assistantText" rows="2"
              placeholder="例：这个洞为什么不是普通信息泄露？再 curl 一下 PoC 看状态码。"
              :disabled="assistantBusy"
              @keydown.enter.exact="onChatEnter($event, askAssistant)"
              @keydown.esc="stopAssistant"></textarea>
            <button v-if="assistantBusy" class="ra-stop" @click="stopAssistant">停止</button>
            <button v-else class="primary" @click="askAssistant()" :disabled="!assistantText.trim()">发送</button>
          </div>
          <p v-if="!readonly" class="ra-hint">Enter 发送 · Shift+Enter 换行 · Esc 停止</p>
        </section>
      </div>

      <!-- 复审操作栏 -->
      <div v-if="mode === 'review' && !readonly" class="review-wrap">
        <!-- 继续深挖附言框（点按钮展开） -->
        <div v-if="deepenOpen" class="deepen-box">
          <label>深挖指令（告诉 worker 这一轮去把什么打穿，越具体越好）</label>
          <textarea v-model="deepenText" rows="2"
            placeholder="例：用 config.js 里的 SECRET 对 /ashx 接口做 sha1 签名，越权调用取出他人数据并贴出响应"></textarea>
          <div class="deepen-actions">
            <button class="ghost" @click="deepenOpen = false">取消</button>
            <button class="go" @click="submitDeepen">↻ 打回深挖并重新入队</button>
          </div>
        </div>
        <div class="review-bar">
          <div class="rb-sev">
            复审等级：
            <select v-model="userSeverity">
              <option v-for="s in SEVS" :key="s" :value="s">{{ s }}</option>
            </select>
          </div>
          <div class="rb-btns">
            <button class="deep" @click="deepenOpen = !deepenOpen">+ 继续深挖</button>
            <button class="ok" @click="decide('passed')">✓ 通过（进待提交）</button>
            <button class="no" @click="decide('rejected')">✕ 不通过</button>
          </div>
        </div>
      </div>

      <!-- 待提交操作栏 -->
      <div v-if="mode === 'submit' && !f.review?.submitted && !readonly" class="review-bar">
        <button class="ok" @click="markSubmitted">标记为已提交</button>
      </div>

      <!-- 已驳回操作栏 -->
      <div v-if="mode === 'rejected' && !readonly" class="review-wrap">
        <div v-if="deepenOpen" class="deepen-box">
          <label>深挖指令（告诉 worker 这一轮去把什么打穿，越具体越好）</label>
          <textarea v-model="deepenText" rows="2"
            placeholder="例：用泄露的初始密码 123456 实际登录某个真实账号，证明能进系统拿到数据"></textarea>
          <div class="deepen-actions">
            <button class="ghost" @click="deepenOpen = false">取消</button>
            <button class="go" @click="submitDeepen">↻ 打回深挖并重新入队</button>
          </div>
        </div>
        <div class="review-bar">
          <span class="rb-hint">此漏洞已被驳回</span>
          <span class="grow"></span>
          <button class="deep" @click="deepenOpen = !deepenOpen">+ 继续深挖</button>
          <button class="ok" @click="restore">↩ 恢复到复审队列</button>
        </div>
      </div>

      <!-- AI 未采纳操作栏（ignored/deepen 归档）：恢复走专用接口改 verdict，才能真正进复审 -->
      <div v-if="mode === 'archived' && !readonly" class="review-wrap">
        <div v-if="deepenOpen" class="deepen-box">
          <label>深挖指令（告诉 worker 这一轮去把什么打穿，越具体越好）</label>
          <textarea v-model="deepenText" rows="2"
            placeholder="例：用泄露的初始密码 123456 实际登录某个真实账号，证明能进系统拿到数据"></textarea>
          <div class="deepen-actions">
            <button class="ghost" @click="deepenOpen = false">取消</button>
            <button class="go" @click="submitDeepen">↻ 打回深挖并重新入队</button>
          </div>
        </div>
        <div class="review-bar">
          <span class="rb-hint">AI 未采纳，可救回复审或继续深挖</span>
          <span class="grow"></span>
          <button class="deep" @click="deepenOpen = !deepenOpen">+ 继续深挖</button>
          <button class="ok" @click="restoreArchived">↩ 恢复到复审队列</button>
        </div>
      </div>
    </div>
  </div>
  <div v-if="findingId" class="drawer-mask" @click="emit('close')"></div>
</template>
