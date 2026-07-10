<script setup>
import { ref, computed, onMounted, watch } from "vue";
import { api, authReadyRef, loadAuthRole } from "../api.js";

const now = new Date();
const viewYear = ref(now.getFullYear());
const viewMonth = ref(now.getMonth()); // 0-based
const selectedDate = ref(_todayStr());
const overview = ref({ month: "", days: [] });
const detail = ref(null);
const loadingOverview = ref(false);
const loadingDetail = ref(false);

const WEEKDAYS = ["一", "二", "三", "四", "五", "六", "日"];
const MONTH_NAMES = ["一月", "二月", "三月", "四月", "五月", "六月",
  "七月", "八月", "九月", "十月", "十一月", "十二月"];

function _todayStr() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

function _monthStr(y, m) {
  return `${y}-${String(m + 1).padStart(2, "0")}`;
}

const monthLabel = computed(() => `${viewYear.value}年${MONTH_NAMES[viewMonth.value]}`);

// 构建日历网格：6行7列，周一起始
const calendarCells = computed(() => {
  const y = viewYear.value;
  const m = viewMonth.value;
  const firstDay = new Date(y, m, 1);
  // 周一=0, 周日=6
  let startOffset = firstDay.getDay() - 1;
  if (startOffset < 0) startOffset = 6;
  const daysInMonth = new Date(y, m + 1, 0).getDate();
  const cells = [];
  // 上月填充
  const prevMonthDays = new Date(y, m, 0).getDate();
  for (let i = startOffset - 1; i >= 0; i--) {
    const day = prevMonthDays - i;
    const pm = m === 0 ? 11 : m - 1;
    const py = m === 0 ? y - 1 : y;
    cells.push({ day, dateStr: _monthStr(py, pm) + "-" + String(day).padStart(2, "0"), otherMonth: true });
  }
  // 当月
  for (let d = 1; d <= daysInMonth; d++) {
    cells.push({ day: d, dateStr: _monthStr(y, m) + "-" + String(d).padStart(2, "0"), otherMonth: false });
  }
  // 下月填充至 42 格
  const remaining = 42 - cells.length;
  for (let d = 1; d <= remaining; d++) {
    const nm = m === 11 ? 0 : m + 1;
    const ny = m === 11 ? y + 1 : y;
    cells.push({ day: d, dateStr: _monthStr(ny, nm) + "-" + String(d).padStart(2, "0"), otherMonth: true });
  }
  return cells;
});

// overview 数据按日期索引
const overviewMap = computed(() => {
  const m = {};
  for (const d of overview.value.days || []) {
    m[d.date] = d;
  }
  return m;
});

const todayStr = _todayStr();

function maxFindings() {
  let mx = 0;
  for (const d of overview.value.days || []) {
    if (d.accepted > mx) mx = d.accepted;
  }
  return mx || 1;
}

function heatStyle(dateStr) {
  const d = overviewMap.value[dateStr];
  if (!d || !d.accepted) return "";
  const intensity = d.accepted / maxFindings();
  // 用 accent 色 + 透明度做热力
  const opacity = 0.08 + intensity * 0.25;
  return `background: oklch(70% 0.14 235 / ${opacity.toFixed(3)})`;
}

function isToday(dateStr) {
  return dateStr === todayStr;
}

function selectDate(dateStr) {
  selectedDate.value = dateStr;
  loadDetail(dateStr);
}

function prevMonth() {
  if (viewMonth.value === 0) {
    viewMonth.value = 11;
    viewYear.value--;
  } else {
    viewMonth.value--;
  }
}

function nextMonth() {
  if (viewMonth.value === 11) {
    viewMonth.value = 0;
    viewYear.value++;
  } else {
    viewMonth.value++;
  }
}

function goToday() {
  const d = new Date();
  viewYear.value = d.getFullYear();
  viewMonth.value = d.getMonth();
  selectedDate.value = _todayStr();
  loadOverview();
  loadDetail(selectedDate.value);
}

async function loadOverview() {
  loadingOverview.value = true;
  try {
    overview.value = await api.dailyOverview(_monthStr(viewYear.value, viewMonth.value));
  } catch (e) {
    overview.value = { month: "", days: [] };
  } finally {
    loadingOverview.value = false;
  }
}

async function loadDetail(date) {
  loadingDetail.value = true;
  try {
    detail.value = await api.dailyStats(date);
  } catch (e) {
    detail.value = null;
  } finally {
    loadingDetail.value = false;
  }
}

function formatCost(c) {
  const v = Number(c || 0);
  if (v >= 100) return `¥${v.toFixed(0)}`;
  if (v >= 1) return `¥${v.toFixed(2)}`;
  if (v > 0) return `¥${v.toFixed(4)}`;
  return "—";
}

function formatTokens(n) {
  const v = Number(n || 0);
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(2)}M`;
  if (v >= 10_000) return `${Math.round(v / 1000)}K`;
  if (v >= 1000) return `${(v / 1000).toFixed(1)}K`;
  return String(v);
}

watch([viewYear, viewMonth], () => loadOverview());

onMounted(async () => {
  if (!authReadyRef.value) await loadAuthRole();
  await Promise.all([loadOverview(), loadDetail(selectedDate.value)]);
});
</script>

<template>
  <div class="daily-calendar-panel">
    <div class="dcp-left">
      <div class="dcp-cal-head">
        <button class="dcp-nav-btn" @click="prevMonth" title="上个月">‹</button>
        <span class="dcp-month-label">{{ monthLabel }}</span>
        <button class="dcp-nav-btn" @click="nextMonth" title="下个月">›</button>
        <button class="dcp-today-btn" @click="goToday">今天</button>
      </div>
      <div class="dcp-weekdays">
        <span v-for="w in WEEKDAYS" :key="w" class="dcp-wd">{{ w }}</span>
      </div>
      <div class="dcp-grid">
        <div
          v-for="cell in calendarCells"
          :key="cell.dateStr"
          class="dcp-cell"
          :class="{
            'other-month': cell.otherMonth,
            'selected': cell.dateStr === selectedDate,
            'is-today': isToday(cell.dateStr),
          }"
          :style="cell.otherMonth ? '' : heatStyle(cell.dateStr)"
          @click="selectDate(cell.dateStr)"
        >
          <span class="dcp-day-num">{{ cell.day }}</span>
          <template v-if="!cell.otherMonth && overviewMap[cell.dateStr]">
            <span v-if="overviewMap[cell.dateStr].accepted > 0" class="dcp-cell-badge">
              {{ overviewMap[cell.dateStr].accepted }}
            </span>
            <span v-if="overviewMap[cell.dateStr].cost > 0" class="dcp-cell-cost">
              {{ formatCost(overviewMap[cell.dateStr].cost) }}
            </span>
          </template>
        </div>
      </div>
    </div>

    <div class="dcp-right">
      <div v-if="loadingDetail" class="dcp-detail-loading">加载中…</div>
      <template v-else-if="detail">
        <div class="dcp-detail-head">
          <h3>{{ detail.date }}</h3>
          <span v-if="detail.date === todayStr" class="dcp-today-tag">今天</span>
        </div>

        <div class="dcp-stat-grid">
          <div class="dcp-stat warn">
            <span class="dcp-stat-val">{{ detail.user_reviews.pending }}</span>
            <span class="dcp-stat-label">待复审</span>
          </div>
          <div class="dcp-stat ok">
            <span class="dcp-stat-val">{{ detail.user_reviews.passed }}</span>
            <span class="dcp-stat-label">已通过</span>
          </div>
          <div class="dcp-stat info">
            <span class="dcp-stat-val">{{ detail.user_reviews.submitted }}</span>
            <span class="dcp-stat-label">已提交</span>
          </div>
          <div class="dcp-stat">
            <span class="dcp-stat-val">{{ detail.killsweep }}</span>
            <span class="dcp-stat-label">通杀列</span>
          </div>
          <div class="dcp-stat danger">
            <span class="dcp-stat-val">{{ detail.user_reviews.rejected }}</span>
            <span class="dcp-stat-label">已驳回</span>
          </div>
          <div class="dcp-stat danger">
            <span class="dcp-stat-val">{{ detail.archived }}</span>
            <span class="dcp-stat-label">AI未采纳</span>
          </div>
        </div>

        <div class="dcp-token-section">
          <div class="dcp-token-head">
            <span>Token 成本</span>
            <b class="dcp-cost-total">{{ formatCost(detail.token_usage.total_cost) }}</b>
          </div>
          <div class="dcp-token-summary">
            <span>输入 {{ formatTokens(detail.token_usage.total_prompt_tokens) }}</span>
            <span>输出 {{ formatTokens(detail.token_usage.total_completion_tokens) }}</span>
            <span>缓存命中 {{ formatTokens(detail.token_usage.total_cache_hit_tokens) }}</span>
            <span>请求 {{ detail.token_usage.total_requests }}</span>
          </div>
          <div v-if="detail.token_usage.by_model.length" class="dcp-model-list">
            <div v-for="m in detail.token_usage.by_model" :key="m.model" class="dcp-model-row">
              <span class="dcp-model-name" :title="m.model">{{ m.model || '未知模型' }}</span>
              <span class="dcp-model-tokens">
                入{{ formatTokens(m.prompt_tokens) }} / 出{{ formatTokens(m.completion_tokens) }}
              </span>
              <span class="dcp-model-cost">{{ formatCost(m.cost) }}</span>
            </div>
          </div>
          <div v-else class="dcp-no-token">当日无 Token 用量记录</div>
        </div>
      </template>
      <div v-else class="dcp-detail-loading">暂无数据</div>
    </div>
  </div>
</template>

<style scoped>
.daily-calendar-panel {
  display: flex;
  gap: 16px;
  background: var(--surface);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius);
  padding: 16px;
  margin-bottom: 16px;
}

.dcp-left {
  flex: 0 0 auto;
}

.dcp-right {
  flex: 1;
  min-width: 0;
}

.dcp-cal-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 10px;
}

.dcp-month-label {
  font-size: 15px;
  font-weight: 600;
  color: var(--ink);
  min-width: 90px;
  text-align: center;
}

.dcp-nav-btn {
  background: var(--surface-2);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-sm);
  color: var(--ink-2);
  cursor: pointer;
  font-size: 16px;
  width: 28px;
  height: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: background 0.15s;
}
.dcp-nav-btn:hover { background: var(--surface-3); }

.dcp-today-btn {
  background: var(--accent-bg);
  border: 1px solid var(--accent);
  border-radius: var(--radius-sm);
  color: var(--accent);
  cursor: pointer;
  font-size: 12px;
  padding: 4px 10px;
  margin-left: auto;
  transition: opacity 0.15s;
}
.dcp-today-btn:hover { opacity: 0.8; }

.dcp-weekdays {
  display: grid;
  grid-template-columns: repeat(7, 1fr);
  gap: 3px;
  margin-bottom: 4px;
}

.dcp-wd {
  text-align: center;
  font-size: 11px;
  color: var(--faint);
  padding: 2px 0;
}

.dcp-grid {
  display: grid;
  grid-template-columns: repeat(7, 1fr);
  gap: 3px;
}

.dcp-cell {
  width: 38px;
  height: 44px;
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-sm);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: flex-start;
  padding: 2px 0;
  cursor: pointer;
  position: relative;
  transition: border-color 0.15s, background 0.15s;
}

.dcp-cell.other-month {
  opacity: 0.3;
  cursor: default;
}

.dcp-cell:not(.other-month):hover {
  border-color: var(--accent);
}

.dcp-cell.selected {
  border-color: var(--accent);
  border-width: 2px;
  padding: 1px 0;
}

.dcp-cell.is-today .dcp-day-num {
  color: var(--accent);
  font-weight: 700;
}

.dcp-day-num {
  font-size: 12px;
  color: var(--ink-2);
  line-height: 1.4;
}

.dcp-cell-badge {
  font-size: 10px;
  color: var(--accent);
  font-weight: 600;
  line-height: 1;
}

.dcp-cell-cost {
  font-size: 9px;
  color: var(--faint);
  line-height: 1;
}

/* detail panel */
.dcp-detail-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}

.dcp-detail-head h3 {
  margin: 0;
  font-size: 15px;
  color: var(--ink);
}

.dcp-today-tag {
  font-size: 11px;
  color: var(--accent);
  background: var(--accent-bg);
  padding: 2px 8px;
  border-radius: 4px;
}

.dcp-stat-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 8px;
  margin-bottom: 16px;
}

.dcp-stat {
  background: var(--surface-2);
  border-radius: var(--radius-sm);
  padding: 8px;
  text-align: center;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.dcp-stat-val {
  font-size: 18px;
  font-weight: 700;
  color: var(--ink);
}

.dcp-stat-label {
  font-size: 11px;
  color: var(--muted);
}

.dcp-stat.ok .dcp-stat-val { color: var(--ok); }
.dcp-stat.danger .dcp-stat-val { color: var(--danger); }
.dcp-stat.warn .dcp-stat-val { color: var(--warn); }
.dcp-stat.info .dcp-stat-val { color: var(--info); }

.dcp-token-section {
  border-top: 1px solid var(--border-soft);
  padding-top: 12px;
}

.dcp-token-head {
  display: flex;
  align-items: baseline;
  gap: 8px;
  margin-bottom: 6px;
}

.dcp-token-head span {
  font-size: 13px;
  color: var(--muted);
}

.dcp-cost-total {
  font-size: 18px;
  font-weight: 700;
  color: var(--accent);
}

.dcp-token-summary {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}

.dcp-token-summary span {
  font-size: 11px;
  color: var(--faint);
}

.dcp-model-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.dcp-model-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  padding: 4px 8px;
  background: var(--surface-2);
  border-radius: var(--radius-sm);
}

.dcp-model-name {
  color: var(--ink-2);
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.dcp-model-tokens {
  color: var(--faint);
  font-size: 11px;
}

.dcp-model-cost {
  color: var(--accent);
  font-weight: 600;
  min-width: 60px;
  text-align: right;
}

.dcp-no-token {
  font-size: 12px;
  color: var(--faint);
  padding: 8px 0;
}

.dcp-detail-loading {
  color: var(--muted);
  font-size: 13px;
  padding: 20px 0;
}

@media (max-width: 768px) {
  .daily-calendar-panel {
    flex-direction: column;
  }
  .dcp-stat-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}
</style>
