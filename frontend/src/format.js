// 统一时间格式化工具。
// 后端返回的时间戳（created_at / user_reviewed_at 等）已是带时区信息的 ISO：
// findings/vulns 走 to_cst_iso 带 +08:00 偏移，运行日志走 UTC 的 Z。两者都携带
// 完整时刻信息，用 Date 解析后按【浏览器本地时区】渲染——保证每个洞显示的时间
// 用的是用户自己的时区，而不是固定的东八区。
export function fmtLocalTime(iso) {
  if (!iso) return "-";
  const s = String(iso).trim();
  // 已带时区（Z 或 ±HH:MM）直接解析；否则按 UTC 兜底补 Z，避免被当成本地裸时间。
  const hasTz = /[zZ]|[+-]\d{2}:\d{2}$/.test(s);
  const d = new Date(hasTz ? s : `${s}Z`);
  if (Number.isNaN(d.getTime())) return s.slice(0, 19).replace("T", " ");
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
