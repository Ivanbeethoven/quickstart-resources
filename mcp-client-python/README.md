# An LLM-Powered Chatbot MCP Client written in Python

See the [Building MCP clients](https://modelcontextprotocol.io/tutorials/building-a-client) tutorial for more information.

## LangGraph 集成示例

示例文件：`langgraph_mcp_example.py`

功能：
* 连接任意符合 MCP 协议的天气示例 Server（Python 或 Node）
* 使用规则或 LLM 决策来选择：直接回答 / 调用天气工具
* 通过 LangGraph 构建最小决策图并执行

ASCII 图：

```
	+---------+        +-----------+
	| decide  |---tool>|  tool     |
	| (route) |        +-----------+
	|         |---llm >|  llm      |
	+---------+        +-----------+
```

### 安装依赖

使用 pip：
```bash
cd mcp-client-python
pip install -e .
```

或使用 uv：
```bash
uv pip install -e .
```

### 运行（规则路由）
```bash
export ANTHROPIC_API_KEY=你的key
python langgraph_mcp_example.py ../weather-server-python/weather.py "上海今天天气怎么样？"
```

### 运行（LLM 路由）
```bash
export ANTHROPIC_API_KEY=你的key
export ROUTER_MODEL=claude-3-5-haiku-20241022  # 可选，默认 haiku
python langgraph_mcp_example.py ../weather-server-python/weather.py "写一首关于清晨的短诗" --llm-router
```

### 参数说明
| 参数 | 说明 |
|------|------|
| `<server_script_path>` | MCP server 脚本路径（.py 或 .js） |
| `<query>` | 用户输入文本 |
| `--llm-router` | 启用 LLM 决策路由 |
| `ROUTER_MODEL` | 环境变量，指定路由模型名称 |

### 决策逻辑
1. 规则模式：包含 “天气” / `weather` -> 调工具，否则直接回答。
2. LLM 模式：提示词要求产出 JSON `{action, reason}`；解析失败回退规则。

### 扩展建议
* 多工具排名：给每个工具打分（相关度、成本）
* JSON Schema 校验：严格验证 LLM 输出
* 结果缓存：相似查询命中缓存跳过调用
* 监控指标：记录 route 决策类型、失败回退次数

## 推送到你的仓库
1. 初始化新仓库（或 fork 原仓库）
2. 复制本目录到你的项目下
3. 调整 `pyproject.toml` 名称与描述
4. `git add . && git commit -m "Add LangGraph MCP example"`
5. `git remote add origin <your_repo_url>`（如已存在则跳过）
6. `git push origin main`

> 如果需要我生成一份独立最小仓库结构，也可以告诉我。
