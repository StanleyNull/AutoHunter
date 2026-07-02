"""工具的 function calling schema 定义。

submit_finding 的参数 schema 直接对应 Finding 结构，强制 LLM 结构化输出
（用户决策：工具参数 schema 为主 + Pydantic 兜底校验）。
"""
from __future__ import annotations

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "发一个 HTTP 请求并返回完整的请求包、响应包、状态码、响应头和响应体。挖洞取证的首选工具。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "完整 URL"},
                    "method": {"type": "string", "description": "HTTP 方法", "default": "GET"},
                    "headers": {"type": "object", "description": "请求头键值对", "additionalProperties": {"type": "string"}},
                    "data": {"type": "string", "description": "请求体原始字符串（如表单 a=1&b=2）"},
                    "json_body": {"type": "object", "description": "JSON 请求体（与 data 二选一）"},
                    "follow_redirects": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "在工作目录执行 shell 命令并返回输出。可用 curl/nuclei/sqlmap/nmap/httpx/whatweb 或自写脚本。扫描器仅在已有明确入口/参数/模板时辅助，禁止泛扫。",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "要执行的完整命令"},
                    "timeout": {"type": "integer", "description": "超时秒数，默认 120"},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "decode_transform",
            "description": "纯本地解析编码/凭证：解码 base64/hex/url、解析 JWT(看 alg/payload 给攻击建议)、识别哈希、计算 md5/sha1/sha256。遇到看不懂的 token/参数/响应值先用它看清结构。零副作用。",
            "parameters": {
                "type": "object",
                "properties": {
                    "value": {"type": "string", "description": "要解析的字符串（token/编码串/凭证/响应字段值）"},
                    "mode": {
                        "type": "string",
                        "enum": ["auto", "base64", "hex", "url", "jwt", "hash"],
                        "description": "auto=自动尝试所有；指定则只做该种；hash=计算哈希并识别输入像哪种哈希。默认 auto。",
                        "default": "auto",
                    },
                },
                "required": ["value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "suggest_waf_bypass",
            "description": "纯本地 WAF 辅助：具体验证请求被 403/406/429/拦截页阻断时，据状态码/响应头/体和 payload 判断 WAF 指纹并给少量候选变形。不代表已绕过，必须再用 http_request 做 baseline vs variant 实证。",
            "parameters": {
                "type": "object",
                "properties": {
                    "payload": {"type": "string", "description": "被拦截的最小 payload 或可控参数值"},
                    "status_code": {"type": "integer", "description": "被拦截响应的 HTTP 状态码，如 403/406/429"},
                    "response_headers": {"type": "object", "description": "被拦截响应头", "additionalProperties": {"type": "string"}},
                    "response_body": {"type": "string", "description": "被拦截响应体片段"},
                    "context": {
                        "type": "string",
                        "enum": ["generic", "sqli", "xss", "path", "json", "api", "header"],
                        "description": "当前验证场景，用于排序候选变形",
                        "default": "generic",
                    },
                },
                "required": ["payload"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fofa_lookup",
            "description": "只读 FOFA 测绘：①确认目标归属(org/备案/证书)把 owner 填准；②查同 IP/同域开放的端口服务找隐藏攻击面。仅查 FOFA 不碰目标。拿裸 IP/确认不了归属时尤其有用。",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": 'FOFA 语法，如 ip="1.2.3.4" / host="example.com" / domain="x.com"'},
                    "size": {"type": "integer", "description": "返回样本数，默认 10，最大 30", "default": 10},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_duplicate_finding",
            "description": "提交漏洞前查重：用类型/标题/URL 对比全局同系统历史漏洞。只拦同系统同洞；duplicate=true 时不要再 submit，同系统其它 endpoint/类型/证据链可继续挖。",
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_type": {"type": "string", "description": "漏洞类型，如 idor/unauthorized_access/sql_injection"},
                    "title": {"type": "string", "description": "准备提交的漏洞标题"},
                    "target_url": {"type": "string", "description": "漏洞所在URL"},
                    "description": {"type": "string", "description": "简要描述，用于辅助模糊查重"},
                },
                "required": ["vuln_type", "title", "target_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_finding",
            "description": (
                "提交一个确认的漏洞。提交前必须先用 http_request/run_shell 取得真实证据"
                "（原始请求/响应包）。提交前必须如实填写 self_check 自检。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_type": {"type": "string", "description": "漏洞类型，如 sql_injection/rce/captcha_bypass/idor/unauthorized_access/file_upload"},
                    "title": {"type": "string", "description": "[目标]-[模块]-[简述]"},
                    "severity_claimed": {"type": "string", "enum": ["严重", "高危", "中危", "低危"]},
                    "target_url": {"type": "string"},
                    "owner": {"type": "string", "description": "归属单位/业务系统 + 确认依据。EduSRC 写学校/教育机构；企业模式写企业/集团/系统，如「XX集团 CRM（依据：证书CN+页面版权）」；核实不了填「待确认（原因…）」"},
                    "description": {"type": "string", "description": "漏洞类型、触发条件、影响范围"},
                    "steps": {"type": "array", "items": {"type": "string"}, "description": "逐条复现步骤"},
                    "poc": {"type": "string", "description": "可执行 PoC，curl 命令或 payload"},
                    "raw_request": {"type": "string", "description": "原始请求包"},
                    "raw_response": {"type": "string", "description": "原始响应包，含证明漏洞的关键差异"},
                    "evidence": {
                        "type": "object",
                        "properties": {
                            "extracted_data_sample": {"type": "string"},
                            "tool_output": {"type": "string"},
                            "notes": {"type": "string"},
                        },
                    },
                    "affected_scope": {"type": "string", "description": "影响面"},
                    "kill_chain": {
                        "type": "array",
                        "description": "攻击链路：按时间顺序记录你怎么一步步打下来的（侦察→定位→利用→取证），让人一眼看懂这洞的拿下方法",
                        "items": {
                            "type": "object",
                            "properties": {
                                "method": {"type": "string", "description": "这一步的方法/动作，如『审计前端JS』『提取API端点』『构造越权请求』『取出数据取证』"},
                                "detail": {"type": "string", "description": "这步具体做了什么、发现或得到了什么"},
                            },
                            "required": ["method"],
                        },
                    },
                    "self_check": {
                        "type": "object",
                        "description": "对照当前 SRC 模式忽略清单的自检",
                        "properties": {
                            "is_reflected_xss": {"type": "boolean"},
                            "needs_admin_login": {"type": "boolean"},
                            "needs_mitm": {"type": "boolean"},
                            "is_pure_info_leak": {"type": "boolean"},
                            "scanner_only_no_poc": {"type": "boolean"},
                            "is_public_interface": {"type": "boolean", "description": "该接口是否本就是面向公众的公开接口"},
                            "info_leak_hits_strict_list": {"type": "boolean", "description": "若信息泄露类：是否命中身份证照片/大头照/身份证号/密码哈希死规矩"},
                        },
                        "required": ["is_reflected_xss", "needs_admin_login", "needs_mitm", "is_pure_info_leak", "scanner_only_no_poc"],
                    },
                },
                "required": ["vuln_type", "title", "severity_claimed", "target_url", "description", "steps", "poc", "kill_chain", "self_check"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_intel",
            "description": "把可复用情报沉淀到全局情报库供后续 worker 复用。只报真验证有效的高价值情报：①cred=验证过能登录的账密；②endpoint=验证有效的未授权/敏感端点；③profile=技术栈/WAF/突破口画像。出洞或撞库成功后顺手报一条。维护器会拦截垃圾(未验证凭证/公开静态浅路径/占位画像/含失败结论)，别报这些。",
            "parameters": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "enum": ["cred", "endpoint", "profile"], "description": "情报类型"},
                    "payload": {
                        "type": "object",
                        "description": "按 kind 填：cred={username,password}；endpoint={path,vuln_type}；profile={key,value}",
                        "additionalProperties": {"type": "string"},
                    },
                    "summary": {"type": "string", "description": "一句话说明（可选），如『后台弱口令可登』"},
                    "verified": {"type": "boolean", "description": "是否亲自验证有效（true 会标记为高可信）", "default": False},
                },
                "required": ["kind", "payload"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_coverage",
            "description": "单站协作覆盖记录：把本路线已经盘点/验证过的 API、参数、测试类型和结论记下来，供后续 worker 避免重复并补盲区。没出洞也要在收尾前报告覆盖面。",
            "parameters": {
                "type": "object",
                "properties": {
                    "route": {"type": "string", "description": "当前路线名，如 site_map/site_js/site_auth，可留空由系统补"},
                    "summary": {"type": "string", "description": "一句话总结本轮覆盖面和主要结论"},
                    "endpoints": {
                        "type": "array",
                        "description": "已测试的接口/入口样例，控制在 20 条内，按价值排序",
                        "items": {
                            "type": "object",
                            "properties": {
                                "method": {"type": "string", "description": "GET/POST/PUT/DELETE 等"},
                                "path": {"type": "string", "description": "路径或完整 URL"},
                                "status": {"type": "string", "description": "状态码或结果状态，如 200/403/需登录/timeout"},
                                "checks": {"type": "string", "description": "测过的点：未授权/越权/注入/上传/配置泄露等"},
                                "result": {"type": "string", "description": "结论：公开正常/需登录/无差异/存在强线索/已提交漏洞等"},
                            },
                        },
                    },
                    "remaining": {"type": "string", "description": "尚未覆盖但值得后续路线继续的入口/参数/假设"},
                },
                "required": ["summary"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": "结束对当前目标的挖掘。所有该挖的都挖完了，或确认无漏洞时调用。",
            "parameters": {
                "type": "object",
                "properties": {
                    "verdict": {"type": "string", "enum": ["found", "no_vuln"], "description": "found=至少提交过一个漏洞；no_vuln=确认无漏洞"},
                    "summary": {"type": "string", "description": "本次挖掘总结：测了哪些面、为什么是这个结论"},
                    "deepen_lead": {
                        "type": "string",
                        "description": (
                            "可选。仅在你已经突破了某个入口（拿到凭证/token/登录态/可控参数/敏感接口）"
                            "但本轮没把它打穿成完整漏洞时填写：用一句话给出下一轮该如何顺着这个据点深挖的"
                            "具体方向（如：用拿到的 token 调 /api/admin/users 验证越权；用泄露的 ak/sk 调 OSS 列桶）。"
                            "没有可深挖的明确线索就留空。这会触发系统自动再派一轮定向深挖。"
                        ),
                    },
                },
                "required": ["verdict", "summary"],
            },
        },
    },
]


JS_ANALYZER_TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "analyze_javascript",
            "description": "审计前端 JS/接口/硬编码密钥/路由。SPA、登录页、接口藏前端、常规入口不足时优先用。传入口 URL 自动抓 HTML 和关联 JS 提取接口清单和攻击链，或传 JS 文本离线分析。只是线索地图，必须继续用 http_request/run_shell 实证。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "入口 URL 或 JS URL。传 URL 时会递归抓取关联 JS。"},
                    "text": {"type": "string", "description": "已拿到的 JS/HTML 文本；与 url 二选一。"},
                    "max_depth": {"type": "integer", "description": "递归抓取 JS 深度，默认 2，最大 4。"},
                    "max_assets": {"type": "integer", "description": "最多抓取资产数，默认 80，最大 150。"},
                },
            },
        },
    }
]


ENTERPRISE_SESSION_TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "session_set",
            "description": "【企业专属】登记已拿到的登录态(cookie 或鉴权头如 Authorization: Bearer xxx)，登记后所有 http_request 自动携带，且自动吸收响应 Set-Cookie。突破入口拿到凭证后先固化登录态，再深挖受限接口/枚举越权对象。",
            "parameters": {
                "type": "object",
                "properties": {
                    "cookies": {
                        "type": "object",
                        "description": "要维持的 cookie 键值对，如 {\"JSESSIONID\":\"xxx\"}",
                        "additionalProperties": {"type": "string"},
                    },
                    "headers": {
                        "type": "object",
                        "description": "要维持的鉴权头，如 {\"Authorization\":\"Bearer xxx\"}",
                        "additionalProperties": {"type": "string"},
                    },
                    "clear": {"type": "boolean", "description": "true=清空当前会话态后再设置（换账号时用）", "default": False},
                },
            },
        },
    }
]


REVIEWER_TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "submit_review",
            "description": "提交对当前 Finding 的审核结论。",
            "parameters": {
                "type": "object",
                "properties": {
                    "verdict": {"type": "string", "enum": ["accepted", "ignored", "deepen"], "description": "accepted=进最终列表 / ignored=丢弃 / deepen=线索有价值但利用没打穿，打回让 worker 定向深挖"},
                    "confidence": {"type": "string", "enum": ["confirmed", "likely", "uncertain"], "description": "信度分档"},
                    "severity_final": {"type": "string", "enum": ["严重", "高危", "中危", "低危"], "description": "最终等级，accepted 时必填"},
                    "score": {"type": "number", "description": "0-10 评分，必须落在等级对应区间"},
                    "in_scope": {"type": "boolean", "description": "是否在当前任务 SRC 范围内"},
                    "is_duplicate": {"type": "boolean", "default": False},
                    "ignore_reasons": {"type": "array", "items": {"type": "string"}, "description": "忽略理由，ignored 时必填"},
                    "downgrade_reasons": {"type": "array", "items": {"type": "string"}, "description": "降级理由"},
                    "deepen_directive": {"type": "string", "description": "深挖指令，verdict=deepen 时必填：具体告诉 worker 这一轮要把什么利用链打穿（如：用泄露的 secret 伪造签名调通 /api/order 取出他人订单数据）"},
                    "reviewer_notes": {"type": "string", "description": "判断依据"},
                },
                "required": ["verdict", "confidence", "score", "in_scope", "reviewer_notes"],
            },
        },
    },
]


KILLSWEEP_TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "fofa_search",
            "description": "用 FOFA 语法圈定同款系统并统计规模。返回命中总量(size)和样本资产列表（host/title/org）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "FOFA 查询语法，如 title=\"XX系统\" || body=\"特征字符串\""},
                    "edu_only": {"type": "boolean", "description": "是否只统计教育行业(自动叠加 .edu.cn/教育 org 限定)，默认 false 即全网", "default": False},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "对某个同款站点发请求，验证它是否同样存在该漏洞（实证通杀）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "default": "GET"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "data": {"type": "string"},
                    "json_body": {"type": "object"},
                    "follow_redirects": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "执行 shell 命令（curl 等）辅助验证同款站点。",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout": {"type": "integer"},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_killsweep",
            "description": "提交通杀分析结论。无论是否可通杀都要调用一次。",
            "parameters": {
                "type": "object",
                "properties": {
                    "is_generic_product": {"type": "boolean", "description": "该系统是否为有指纹特征的通用产品/框架（而非单位自研一次性系统）"},
                    "product_name": {"type": "string", "description": "通用产品/框架名称，如『XX教务系统』『RuoYi框架』；自研系统填『自研/无通用指纹』"},
                    "is_killsweep": {"type": "boolean", "description": "该漏洞是否为这套系统的通用缺陷、可一打一片（代码层缺陷=可通杀；单位个例配置=不可）"},
                    "confidence": {"type": "string", "enum": ["confirmed", "likely", "uncertain"], "description": "通杀判定信度：打了同款站点实证成功=confirmed"},
                    "fofa_query": {"type": "string", "description": "圈定同款系统的最优 FOFA 语法"},
                    "fingerprint": {"type": "string", "description": "指纹依据：用了哪些 title/body/server/favicon 特征"},
                    "asset_count": {"type": "integer", "description": "全网同款资产规模(FOFA size)"},
                    "edu_count": {"type": "integer", "description": "教育行业同款规模"},
                    "verified_url": {"type": "string", "description": "实际打的那个同款站点 URL（验证成功才填）"},
                    "verified": {"type": "boolean", "description": "是否打了1个同款站点并实证同样中招"},
                    "affected_table": {
                        "type": "array",
                        "description": "通杀影响明细表：每行是一个学校/单位与对应通杀洞，后端会写入查重库，避免后续重复报同一通杀洞。",
                        "items": {
                            "type": "object",
                            "properties": {
                                "school": {"type": "string", "description": "学校/单位名称；从 org/title/域名推断，未知填待确认"},
                                "url": {"type": "string", "description": "同款系统 URL/host"},
                                "host": {"type": "string", "description": "归一化 host，可不填，后端会补"},
                                "title": {"type": "string", "description": "站点标题"},
                                "vuln_title": {"type": "string", "description": "该学校对应的通杀漏洞标题"},
                                "status": {"type": "string", "enum": ["verified", "candidate"], "description": "verified=已打1个验证成功；candidate=FOFA圈定同款候选"},
                                "evidence": {"type": "string", "description": "证据/依据，如 FOFA命中、标题特征、验证响应摘要"},
                            },
                            "required": ["school", "url", "vuln_title", "status"],
                        },
                    },
                    "notes": {"type": "string", "description": "结论与批量利用建议；不可通杀时说明原因"},
                },
                "required": ["is_generic_product", "is_killsweep", "confidence", "notes"],
            },
        },
    },
]


ESCALATE_TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "顺着已确认的入口继续发包，尝试把危害做大（越权写、遍历、改密、接管、命令执行等）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "default": "GET"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "data": {"type": "string"},
                    "json_body": {"type": "object"},
                    "follow_redirects": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "执行 shell 命令（curl 等）辅助升级利用。",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout": {"type": "integer"},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_escalation",
            "description": (
                "仅当你已把原漏洞【实锤升级】——危害等级实际提升，或影响面出现数量级变化（如单点→批量接管/遍历）"
                "——时调用一次，交出升级后的完整证据链。没打穿、原地打转、危害没变，请改调 abandon_escalation。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_type": {"type": "string", "description": "升级后的漏洞类型，如『任意用户密码重置+账号接管』"},
                    "title": {"type": "string", "description": "升级后的漏洞标题（含归属单位/系统 + 升级后的危害）"},
                    "severity": {"type": "string", "enum": ["严重", "高危", "中危", "低危"], "description": "升级后的最终等级"},
                    "description": {"type": "string", "description": "升级利用链描述：从原入口如何一步步做大危害"},
                    "kill_chain": {
                        "type": "array",
                        "description": "升级攻击链路，逐步：[{method, detail}]",
                        "items": {
                            "type": "object",
                            "properties": {
                                "method": {"type": "string"},
                                "detail": {"type": "string"},
                            },
                        },
                    },
                    "poc": {"type": "string", "description": "完整可复现 PoC（含关键 curl/请求）"},
                    "raw_request": {"type": "string", "description": "关键升级步骤的原始请求"},
                    "raw_response": {"type": "string", "description": "证明升级成功的原始响应（真实成功证据）"},
                    "affected_scope": {"type": "string", "description": "量化影响面，如『大量用户/全部账号可被接管』"},
                    "impact_count": {"type": "integer", "description": "可量化的受影响对象数量（遍历/接管规模），无则填 0"},
                },
                "required": ["vuln_type", "title", "severity", "description", "poc", "raw_response"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "abandon_escalation",
            "description": "本次深挖没能显著升级危害（等级没提升、影响面没质变），放弃并说明原因。",
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {"type": "string", "description": "为什么放弃：试了哪些方向、卡在哪、为何危害没变大"},
                },
                "required": ["reason"],
            },
        },
    },
]


COLLECTOR_QUERY_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "gen_query",
            "description": "产出一条 FOFA 搜索语法，用于本轮目标搜集。",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "可直接调用的 FOFA 查询语法字符串"},
                    "reason": {"type": "string", "description": "一句话说明本轮覆盖的角度"},
                },
                "required": ["query"],
            },
        },
    },
]


COLLECTOR_EDU_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "judge_edu",
            "description": "批量判定资产是否属于中国教育行业（EduSRC 范围）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
	                                "index": {"type": "integer", "description": "对应输入资产的序号"},
	                                "is_edu": {"type": "boolean"},
	                                "school": {"type": "string", "description": "归属学校/教育机构全称，推断不出可空"},
	                            },
                            "required": ["index", "is_edu"],
                        },
                    },
                },
                "required": ["results"],
            },
        },
    },
]


def _compact_descriptions(value, limit: int = 72, _depth: int = 0):
    """压缩 function schema 里的自然语言描述，保留字段/required/enum 不变。

    OpenAI 兼容 function schema 会随每轮请求一起发送；长 description 是稳定但昂贵的
    prompt。系统提示已覆盖规则细节，这里只保留最短可辨识说明。
    """
    if isinstance(value, list):
        return [_compact_descriptions(item, limit, _depth + 1) for item in value]
    if not isinstance(value, dict):
        return value
    out = {}
    for key, item in value.items():
        if key == "description" and isinstance(item, str):
            if _depth > 2:
                continue
            text = " ".join(item.split())
            out[key] = text[:limit]
        else:
            out[key] = _compact_descriptions(item, limit, _depth + 1)
    return out


TOOL_SCHEMAS = _compact_descriptions(TOOL_SCHEMAS)
JS_ANALYZER_TOOL_SCHEMAS = _compact_descriptions(JS_ANALYZER_TOOL_SCHEMAS)
ENTERPRISE_SESSION_TOOL_SCHEMAS = _compact_descriptions(ENTERPRISE_SESSION_TOOL_SCHEMAS)
REVIEWER_TOOL_SCHEMAS = _compact_descriptions(REVIEWER_TOOL_SCHEMAS)
KILLSWEEP_TOOL_SCHEMAS = _compact_descriptions(KILLSWEEP_TOOL_SCHEMAS)
ESCALATE_TOOL_SCHEMAS = _compact_descriptions(ESCALATE_TOOL_SCHEMAS)
COLLECTOR_QUERY_SCHEMAS = _compact_descriptions(COLLECTOR_QUERY_SCHEMAS)
COLLECTOR_EDU_SCHEMAS = _compact_descriptions(COLLECTOR_EDU_SCHEMAS)
