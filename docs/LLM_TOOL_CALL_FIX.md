# LLM 工具调用异常修复

## 1. 出现的问题

接入 DeepSeek 兼容端点后，任务事件反复出现：

```text
LLM 暂时不可用，预计 5 秒后重试。
```

在进入冷却状态之前，LLM 实际已经返回了内容，但返回格式不是 OpenAI SDK 预期的标准 `message.tool_calls` 结构。

实际原因不是端点无法连接，而是 DeepSeek 兼容端点返回了非标准工具调用格式：

- 真实响应被放在 SDK 对象或 JSON 的 `data` 字段中。
- 工具参数使用 `argument`，而不是标准的 `arguments`。
- 工具调用以 DeepSeek DSML 文本标签返回，没有填充 `message.tool_calls`。

解析失败达到阈值后，AutoHunter 将 provider 放入冷却状态，于是前端只显示通用的“暂时不可用”。

## 2. 解决方法

在 LLM 客户端增加兼容层：

1. 解包对象和字典中的 `data` 响应。
2. 同时支持 `arguments`、`argument` 和嵌套 JSON 参数。
3. 解析 DSML 的 `invoke`、`parameter` 标签。
4. 将文本工具调用转换成 AutoHunter 内部的 `tool_calls` 对象。
5. 当请求包含工具但响应没有 `tool_calls` 时，自动启用上述文本解析。

## 3. 对应修补代码

以下行号以当前版本为准，可用 `nl -ba` 查看实际行号。

### 3.1 支持 `argument` 参数别名

文件：`app/llm/client.py:556-561`

在 `_extract_emulated_calls()` 中加入：

```python
args = fn.get(
    "arguments",
    fn.get("argument", it.get("arguments", it.get("argument", {}))),
)
```

### 3.2 增加 DSML 工具调用解析器

文件：`app/llm/client.py:571-655`

在 `_parse_emulated_tool_calls()` 前新增 `_parse_dsml_tool_calls()`，负责识别：

```text
<｜｜DSML｜｜ invoke name="http_request">
<｜｜DSML｜｜ parameter name="url" string="true">https://example.com</｜｜DSML｜｜ parameter>
<｜｜DSML｜｜ /invoke>
```

解析器应返回 `(content, calls)`，其中 `calls` 的每一项包含 `name` 和 JSON 字符串形式的 `arguments`。当前版本同时处理截断标签、HTML 实体和 `arguments` JSON 包装字段。

### 3.3 在工具调用入口启用 DSML 解析

文件：`app/llm/client.py:718-727`

将 `_apply_emulated_tool_calls()` 改为先调用 DSML 解析，再调用原有 JSON 解析：

```python
text = getattr(msg, "content", None) or ""
content, calls = _parse_dsml_tool_calls(text)
if calls:
    return SimpleNamespace(content=content, tool_calls=calls, role="assistant")
content, calls = _parse_emulated_tool_calls(content)
if calls:
    return SimpleNamespace(content=content, tool_calls=calls, role="assistant")
return msg
```

### 3.4 解包 `data` 响应

文件：`app/llm/client.py:801-807`

处理字典响应时，在读取 `choices` 前加入：

```python
nested = resp.get("data")
if isinstance(nested, dict) and any(
    key in nested for key in ("choices", "content", "message", "tool_calls", "data")
):
    return _coerce_chat_message(nested)
```

文件：`app/llm/client.py:830-839`

处理 SDK 对象时，在读取 `.choices` 前加入：

```python
nested = getattr(resp, "data", None)
if nested is not None and nested is not resp and (
    isinstance(nested, (dict, str, bytes, bytearray))
    or hasattr(nested, "choices")
    or hasattr(nested, "content")
):
    return _coerce_chat_message(nested)
```

### 3.5 原生工具调用缺少 `tool_calls` 时启用回退

文件：`app/llm/client.py:1458-1466`

将 `_finish()` 中的返回逻辑改为：

```python
msg = _strip_message_thinking(msg)
if prompt_tools or (tools_orig and not getattr(msg, "tool_calls", None)):
    return _apply_emulated_tool_calls(msg)
return msg
```

## 4. 回归测试

当前端点可能返回以下几种兼容性格式：

1. ChatCompletion 对象的标准字段为空，真实响应放在对象的 `.data` 中。
2. 顶层 JSON 通过 `data.choices` 包裹真实的 Chat Completions 响应。
3. 工具参数字段使用单数 `argument`，而不是标准的 `arguments`。
4. DeepSeek 思考模型把工具调用写在文本中，例如：

   ```text
   <｜｜DSML｜｜ invoke name="http_request">
   ...
   </｜｜DSML｜｜ invoke>
   ```

连续几次无法提取工具调用后，provider 健康检查会将端点置于短暂冷却，因此前端只看到通用的冷却提示。

### 测试文件

文件：`tests/test_llm_coerce.py:39-157`

新增覆盖：

- SDK 对象 `.data` 响应。
- `argument` 单数参数字段。
- 完整 DSML 工具调用。
- DSML 中嵌套 JSON 参数。

容器内验证命令：

```bash
docker exec autohunter python -m unittest tests.test_llm_coerce
```

结果：18 个测试通过。

## 实际端点验证

使用部署配置中的 LLM 端点在容器内进行了真实请求验证：

- 端点协议：OpenAI Chat Completions
- 模型：`deepseek-v4.1-flash`
- 连通性和鉴权：成功
- `http_request` 工具调用：成功解析

API key 不写入本文档，也不应提交到 Git。

## 部署说明

修改代码后需要重新构建并重建容器：

```bash
cd /opt/AutoHunter
docker compose build autohunter
docker compose up -d --force-recreate autohunter
```

检查服务状态：

```bash
curl http://127.0.0.1:18800/health
docker ps --filter name=autohunter
```

当前容器保持不使用 HTTP、HTTPS 或 SOCKS 代理；LLM 请求直接访问配置的端点。
