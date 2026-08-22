export async function copyText(text) {
  const value = String(text ?? "");
  if (navigator.clipboard?.writeText && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch {
      // Fallback below handles HTTP, denied permissions, and embedded contexts.
    }
  }

  const ta = document.createElement("textarea");
  ta.value = value;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.left = "-9999px";
  ta.style.top = "0";
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  ta.setSelectionRange(0, ta.value.length);
  try {
    const ok = document.execCommand("copy");
    if (!ok) throw new Error("execCommand copy returned false");
    return true;
  } finally {
    document.body.removeChild(ta);
  }
}

export function isLlmErrorEvent(ev = {}) {
  const k = String(ev.kind || "");
  if (k.startsWith("llm_") || k === "worker_auto_finish" || k === "quota_stop") return true;
  const text = `${ev.message || ""} ${ev._text || ""} ${ev.error || ""}`;
  return k === "target_requeued" && /LLM|额度|配额|不可用/.test(text);
}

export function formatLlmErrorCopy(ev = {}) {
  if (ev.error_copy) {
    const head = [
      ev.kind ? `event=${ev.kind}` : "",
      ev.model ? `model=${ev.model}` : "",
      ev.base_url ? `base_url=${ev.base_url}` : "",
      ev.ts ? `time=${ev.ts}` : "",
    ].filter(Boolean);
    return [...head, String(ev.error_copy)].join("\n");
  }
  const lines = [];
  if (ev.kind) lines.push(`kind=${ev.kind}`);
  if (ev.ts) lines.push(`time=${ev.ts}`);
  if (ev.model) lines.push(`model=${ev.model}`);
  if (ev.base_url) lines.push(`base_url=${ev.base_url}`);
  if (ev.error_kind) lines.push(`error_kind=${ev.error_kind}`);
  if (ev.status != null && ev.status !== "") lines.push(`status=${ev.status}`);
  if (ev.code) lines.push(`code=${ev.code}`);
  const summary = ev._text || ev.message || "";
  if (summary) lines.push(`message=${summary}`);
  if (ev.error && ev.error !== summary) lines.push(`error=${ev.error}`);
  if (ev.detail) lines.push(`detail=${ev.detail}`);
  if (ev.diagnostic) lines.push(`diagnostic=${ev.diagnostic}`);
  if (ev.summary && ev.summary !== summary) lines.push(`summary=${ev.summary}`);
  return lines.join("\n") || String(summary || ev.kind || "");
}

export function formatLlmTestCopy(test = {}) {
  if (test.error_copy) return String(test.error_copy);
  const parts = [`LLM ${test.ok ? "可用" : "不可用"}`];
  if (test.error) parts.push(test.error);
  for (const item of test.results || []) {
    parts.push(item.error_copy || [
      `ok=${item.ok}`,
      `name=${item.name || "-"}`,
      `model=${item.model || "-"}`,
      `base_url=${item.base_url || "-"}`,
      `status_code=${item.status_code || 0}`,
      item.error ? `error=${item.error}` : "",
      item.tool_calling ? `tool_calling=${item.tool_calling}` : "",
    ].filter(Boolean).join("\n"));
  }
  return parts.filter(Boolean).join("\n\n");
}

