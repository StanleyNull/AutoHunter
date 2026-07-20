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
  // 归属单位：优先教育网离线库反查到的学校名
  const owner = (f.edu_school || "").trim() || f.owner || "-";

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
  const categoryName = inferCategoryName(f);
  // 归属单位：优先教育网离线库反查到的学校名 > worker 判定的 owner
  const eduSchool = (f.edu_school || "").trim();
  const owner = (eduSchool || f.owner || f.review?.user_edits?.owner || "").trim();
  const firmName = owner && owner !== "-" ? owner : "待填写单位";
  // EduSRC JSON 标题只写学校名（查不到才退回漏洞标题）
  const title = firmName !== "待填写单位"
    ? firmName
    : (eff(f, "title") || f.title || "AutoHunter 漏洞报告");
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

> 可粘贴到 \`edusrc-tool\` 油猴脚本"导入报告"里；\`firm_id\` 默认为 0，提交前按 EDUSRC 单位搜索结果补全；\`company_id\` 未识别时默认为 3（其他厂商），不要写死具体开发商。

\`\`\`\`json
${JSON.stringify(edusrcJson, null, 2)}
\`\`\`\``;
}

/**
 * 解析原始 HTTP 请求包，提取 method / path / headers / body。
 * raw_request 格式："GET /path HTTP/1.1\nHost: ...\nHeader: val\n\nbody"
 */
function parseRawRequest(raw) {
  const text = String(raw || "").trim();
  if (!text) return null;
  const lines = text.split("\n");
  const firstLine = lines[0] || "";
  const m = firstLine.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP\/[\d.]+/i);
  if (!m) return null;
  const method = m[1].toUpperCase();
  const path = m[2];
  const headers = {};
  let body = "";
  let bodyStart = -1;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim() === "") { bodyStart = i + 1; break; }
    const idx = lines[i].indexOf(":");
    if (idx > 0) {
      const k = lines[i].slice(0, idx).trim();
      const v = lines[i].slice(idx + 1).trim();
      headers[k] = v;
    }
  }
  if (bodyStart >= 0 && bodyStart < lines.length) {
    body = lines.slice(bodyStart).join("\n").trim();
  }
  return { method, path, headers, body };
}

/**
 * 从 finding 生成可执行的 Python PoC 脚本。
 * 优先从 raw_request 解析出 requests 调用；无 raw_request 则用 poc 文本作注释。
 */
export function buildReportPy(f) {
  const rv = f.review || {};
  const sev = effectiveSeverity(f);
  const title = eff(f, "title");
  const poc = eff(f, "poc");
  const steps = eff(f, "steps") || [];
  const targetUrl = f.target_url || "";
  const owner = (f.edu_school || "").trim() || f.owner || "-";

  // 尝试解析 raw_request
  const parsed = parseRawRequest(f.raw_request);

  const headerLines = [
    "#!/usr/bin/env python3",
    '"""',
    `漏洞 PoC 脚本 — AutoHunter 自动生成`,
    "",
    `标题: ${title}`,
    `漏洞类型: ${f.vuln_type || "-"}`,
    `目标: ${targetUrl}`,
    `归属单位: ${owner}`,
    `等级: ${sev}（score: ${rv.score ?? "-"}）`,
    `信度: ${rv.confidence || "-"}`,
    '"""',
    "",
    "import requests",
    "import urllib3",
    "import sys",
    "",
    "# 禁用 SSL 证书验证告警（测试环境）",
    "urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)",
    "",
  ];

  // 配置区
  let configLines = [
    "# ============ 目标配置 ============",
  ];

  let mainBody = "";

  if (parsed) {
    // 从 raw_request 构造 requests 脚本
    const host = parsed.headers["Host"] || parsed.headers["host"] || "";
    const scheme = targetUrl.startsWith("https") ? "https" : (host ? "http" : "http");
    const baseUrl = `${scheme}://${host}`;
    const fullUrl = host ? `${baseUrl}${parsed.path}` : targetUrl;

    configLines.push(`BASE_URL = "${baseUrl}"`);
    configLines.push(`TARGET_URL = "${fullUrl}"`);
    configLines.push("");

    // 构建 headers 字典
    const headerDict = Object.entries(parsed.headers)
      .filter(([k]) => k.toLowerCase() !== "host")
      .map(([k, v]) => `    "${k}": ${JSON.stringify(v)}`)
      .join(",\n");

    configLines.push("# ============ 请求头 ============");
    configLines.push(`HEADERS = {`);
    if (headerDict) configLines.push(headerDict);
    configLines.push("}");
    configLines.push("");

    if (parsed.body) {
      configLines.push("# ============ 请求体 ============");
      configLines.push(`BODY = ${JSON.stringify(parsed.body)}`);
      configLines.push("");
    }

    // main 函数
    mainBody = [
      "def main():",
      "    session = requests.Session()",
      "    session.verify = False",
      "",
      `    print(f"[*] 目标: {TARGET_URL}")`,
      `    print(f"[*] 方法: ${parsed.method}")`,
      "",
      `    resp = session.request(`,
      `        method=${JSON.stringify(parsed.method)},`,
      `        url=TARGET_URL,`,
      `        headers=HEADERS,`,
      parsed.body ? `        data=BODY,` : "",
      "        timeout=20,",
      "        allow_redirects=False,",
      "    )",
      "",
      '    print(f"[+] 状态码: {resp.status_code}")',
      '    print(f"[+] 响应长度: {len(resp.text)}")',
      '    print("[+] 响应内容:")',
      '    print(resp.text[:2000])',
      "",
      '    # 判断漏洞是否存在（根据实际响应特征修改）',
      '    if resp.status_code == 200:',
      '        print("[!] 漏洞验证成功")',
      '    else:',
      '        print("[-] 未检测到预期响应，请手动确认")',
      "",
    ].filter(Boolean).join("\n");
  } else {
    // 无 raw_request，使用 poc / steps 作为脚本
    configLines.push(`TARGET_URL = "${targetUrl}"`);
    configLines.push("");

    const commentLines = [];
    if (poc) {
      commentLines.push("# ============ PoC（来自报告） ============");
      poc.split("\n").forEach((line) => commentLines.push(`# ${line}`));
      commentLines.push("");
    }
    if (steps.length) {
      commentLines.push("# ============ 复现步骤 ============");
      steps.forEach((s, i) => commentLines.push(`# ${i + 1}. ${s}`));
      commentLines.push("");
    }

    mainBody = [
      ...commentLines,
      "def main():",
      "    session = requests.Session()",
      "    session.verify = False",
      "",
      `    print(f"[*] 目标: {TARGET_URL}")`,
      '    print("[!] 请根据上方 PoC / 复现步骤手动构造请求")',
      '    print("[!] 此脚本为框架模板，请填充实际请求逻辑")',
      "",
      "    # TODO: 根据 PoC 描述实现具体验证逻辑",
      "    # 示例:",
      '    # resp = session.get(TARGET_URL, timeout=20, verify=False)',
      '    # print(f"状态码: {resp.status_code}")',
      '    # print(resp.text[:2000])',
      "    pass",
      "",
    ].join("\n");
  }

  const footerLines = [
    "if __name__ == \"__main__\":",
    "    try:",
    "        main()",
    "    except requests.exceptions.ConnectionError as e:",
    '        print(f"[x] 连接失败: {e}")',
    "        sys.exit(1)",
    "    except KeyboardInterrupt:",
    '        print("[x] 用户中断")',
    "        sys.exit(0)",
    "",
  ];

  return [...headerLines, ...configLines, mainBody, "", ...footerLines].join("\n");
}

/** 生成文件名 slug */
export function reportSlug(f) {
  return slugPart(`${f.vuln_type}-${eff(f, "title")}-${f.id || ""}`);
}
