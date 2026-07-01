// 把 finding（含 review + 用户编辑覆盖）拼成标准 Markdown 报告
const CONF = { confirmed: "确认", likely: "疑似", uncertain: "不确定" };
const LEVEL_MAP = { "严重": "grave", "高危": "high", "中危": "medium", "低危": "low" };
const CATEGORY_MAP = {
  "SQL注入漏洞": 1,
  "文件上传漏洞": 2,
  "代码执行漏洞": 3,
  "命令执行漏洞": 4,
  "XSS漏洞": 5,
  "CSRF漏洞": 6,
  "SSRF漏洞": 7,
  "点击劫持漏洞": 8,
  "弱口令": 9,
  "敏感信息泄露": 10,
  "其他漏洞": 13,
  "任意文件读取": 14,
  "任意文件下载": 15,
  "未授权访问": 16,
  "逻辑缺陷": 17,
  "疑似被黑/存在后门": 18,
  "AI漏洞": 19,
};

// 取生效值：用户编辑 > 原始
function eff(f, key) {
  const e = f.review?.user_edits || {};
  return e[key] !== undefined && e[key] !== null && e[key] !== "" ? e[key] : f[key];
}

export function effectiveSeverity(f) {
  return f.review?.user_severity || f.review?.severity_final || "-";
}

function slugPart(value) {
  const s = String(value || "").trim().toLowerCase();
  const slug = s.replace(/[^a-z0-9\u4e00-\u9fff]+/g, "-").replace(/^-+|-+$/g, "");
  return slug || "target";
}

function shortHash(value) {
  const s = String(value || "");
  let h = 2166136261;
  for (let i = 0; i < s.length; i += 1) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

function firstNumber(values, fallback) {
  for (const value of values) {
    const n = Number(value);
    if (Number.isFinite(n) && n > 0) return n;
  }
  return fallback;
}

function inferCategoryName(f) {
  const text = `${f.vuln_type || ""} ${eff(f, "title") || ""}`.toLowerCase();
  if (/sql|sqli|注入/.test(text)) return "SQL注入漏洞";
  if (/upload|file_upload|文件上传/.test(text)) return "文件上传漏洞";
  if (/command|cmd|命令执行/.test(text)) return "命令执行漏洞";
  if (/rce|code|ssti|deserialize|反序列化|代码执行/.test(text)) return "代码执行漏洞";
  if (/xss|跨站/.test(text)) return "XSS漏洞";
  if (/csrf/.test(text)) return "CSRF漏洞";
  if (/ssrf/.test(text)) return "SSRF漏洞";
  if (/clickjacking|点击劫持/.test(text)) return "点击劫持漏洞";
  if (/weak|password|弱口令|默认口令/.test(text)) return "弱口令";
  if (/download|任意文件下载/.test(text)) return "任意文件下载";
  if (/read|lfi|path|traversal|任意文件读取|路径穿越/.test(text)) return "任意文件读取";
  if (/info|leak|disclosure|sensitive|data|数据|泄露/.test(text)) return "敏感信息泄露";
  if (/logic|payment|captcha|业务|逻辑|验证码/.test(text)) return "逻辑缺陷";
  if (/ai|prompt|llm/.test(text)) return "AI漏洞";
  return "未授权访问";
}

export function buildReportCoreMd(f) {
  const rv = f.review || {};
  const sev = effectiveSeverity(f);
  const conf = CONF[rv.confidence] || rv.confidence || "-";
  const title = eff(f, "title");
  const desc = eff(f, "description");
  const scope = eff(f, "affected_scope");
  const steps = eff(f, "steps") || [];
  const poc = eff(f, "poc");
  const owner = f.owner || "-";

  // 证据数据样本（worker 取样的小表格 / 工具输出 / 备注），有才渲染
  const ev = f.evidence || {};
  const evParts = [];
  if (ev.extracted_data_sample) evParts.push(`**数据样本**\n\n${ev.extracted_data_sample}`);
  if (ev.tool_output) evParts.push(`**工具输出**\n\n\`\`\`\n${ev.tool_output}\n\`\`\``);
  if (ev.notes) evParts.push(`**说明**\n\n${ev.notes}`);
  const evBlock = evParts.length ? `\n## 证据数据\n\n${evParts.join("\n\n")}\n` : "";

  // 攻击链路：怎么一步步打下来的（侦察→定位→利用→取证）
  const chain = (f.kill_chain || []).filter((s) => s && s.method);
  let chainBlock = "";
  if (chain.length) {
    const flow = chain.map((s) => s.method).join(" → ");
    const detail = chain
      .map((s, i) => `${i + 1}. **${s.method}**${s.detail ? ` — ${s.detail}` : ""}`)
      .join("\n");
    chainBlock = `\n## 攻击链路\n\n\`${flow}\`\n\n${detail}\n`;
  }

  return `# ${title}

| 项目 | 内容 |
| --- | --- |
| **漏洞等级** | ${sev}（${rv.score ?? "-"} / 10） |
| **信度** | ${conf} |
| **漏洞类型** | \`${f.vuln_type}\` |
| **归属单位** | ${owner} |
| **目标 URL** | ${f.target_url} |

## 漏洞描述

${desc || "-"}

## 影响范围

${scope || "-"}

## 复现步骤

${steps.map((s, i) => `${i + 1}. ${s}`).join("\n") || "-"}

## 验证 PoC

\`\`\`bash
${poc || "-"}
\`\`\`

## 证据链

**原始请求**

\`\`\`http
${f.raw_request || "-"}
\`\`\`

**原始响应**

\`\`\`http
${f.raw_response || "-"}
\`\`\`
${evBlock}
## AI 审核结论

> ${(rv.reviewer_notes || "-").replace(/\n/g, "\n> ")}
${rv.user_notes ? `\n## 人工复审备注\n\n${rv.user_notes}` : ""}
${chainBlock}`;
}

export function buildEdusrcReportJson(f, content) {
  const title = eff(f, "title") || f.title || "AutoHunter 漏洞报告";
  const categoryName = inferCategoryName(f);
  const owner = (f.owner || f.review?.user_edits?.owner || "").trim();
  const firmName = owner && owner !== "-" ? owner : "待填写单位";
  const edits = f.review?.user_edits || {};
  const edusrcMeta = f.evidence?.edusrc || {};
  const firmId = firstNumber([edits.firm_id, edusrcMeta.firm_id, f.firm_id], 0);
  const companyId = firstNumber([edits.company_id, edusrcMeta.company_id, f.company_id], 3);
  const level = LEVEL_MAP[effectiveSeverity(f)] || "medium";
  return {
    id: `autohunter-${slugPart(f.vuln_type)}-${shortHash(`${f.id || ""}|${f.target_url || ""}|${title}`)}`,
    vuln_type: f.vuln_type || "custom",
    title,
    category: CATEGORY_MAP[categoryName] || CATEGORY_MAP["未授权访问"],
    level,
    firm_id: firmId,
    firm_name: firmName,
    company_id: companyId,
    credentials: "False",
    url: f.target_url || "",
    content,
  };
}

export function buildEdusrcToolReport(f) {
  return buildEdusrcReportJson(f, buildReportCoreMd(f));
}

export function buildReportMd(f) {
  const core = buildReportCoreMd(f);
  const edusrcJson = buildEdusrcToolReport(f);
  return `${core}

## EDUSRC 自动填充 JSON

> 可粘贴到 \`edusrc-tool\` 油猴脚本“导入报告”里；\`firm_id\` 默认为 0，提交前按 EDUSRC 单位搜索结果补全；\`company_id\` 未识别时默认为 3（其他厂商），不要写死具体开发商。

\`\`\`\`json
${JSON.stringify(edusrcJson, null, 2)}
\`\`\`\``;
}
