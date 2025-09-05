"""LangGraph 集成 MCP Client 示例

此示例展示：
1. 启动（或假设已启动）一个 MCP Server（通过现有的 server 脚本）
2. 使用现有 `MCPClient` 连接并列出工具
3. 在 LangGraph 中把一个节点包装为对 MCP 工具的调用
4. 构建最小决策图：User Input -> decide -> (tool|llm) -> END

核心思想：
decide 节点做最轻量的路由逻辑（规则 / 可扩展为 LLM 决策）
tool 节点调用 MCP 暴露的工具（本例假设 weather 工具）
llm 节点直接用 Claude 生成回答

ASCII 图：
    +---------+        +-----------+
    | decide  |---tool>|  tool     |
    | (route) |        +-----------+
    |         |---llm >|  llm      |
    +---------+        +-----------+

运行方式（示例）:
    export ANTHROPIC_API_KEY=...  # 确保已设置
    python langgraph_mcp_example.py ../weather-server-python/weather.py "今天天气怎么样?" 

如果你的 server 是 NodeJS：
    python langgraph_mcp_example.py ../weather-server-typescript/dist/index.js "上海天气"
"""
from __future__ import annotations
import asyncio
import sys
import os
import json
import re
from typing import Dict, Any

from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_anthropic import ChatAnthropic

from client import MCPClient  # 复用现有客户端：负责通过 stdio 与 MCP Server 通信

# 定义图的状态（简单字典）
class GraphState(dict):
    """图状态容器

    这里用最简单的 dict 形式即可；在更复杂场景中可以：
    - 使用 TypedDict / pydantic 模型约束字段
    - 拆分多阶段中间结果（如：parsed_query, tool_plan, exec_results）
    """
    pass

async def build_mcp_session(server_path: str) -> MCPClient:
    """建立与 MCP Server 的会话

    这里让客户端自行通过 subprocess/stdio 启动对应脚本（python 或 node）
    返回已初始化并列出工具的 MCPClient 实例
    """
    client = MCPClient()
    await client.connect_to_server(server_path)
    return client

async def decide_node(state: GraphState) -> GraphState:
    """路由决策节点（支持规则 或 LLM 决策）

    运行模式：
    - 默认（rule）：关键词匹配（“天气” / “weather”）
    - LLM 模式：使用一个轻量模型输出 JSON {"action": "tool"|"llm", "reason": "..."}

    状态约定：
    - state['routing_mode'] in {'rule','llm'}
    - 若为 llm 且存在 state['llm_router']（ChatAnthropic 实例）则调用
    """
    mode = state.get("routing_mode", "rule")
    text: str = state["user_input"]

    # 规则模式（快速、无额外 token 成本）
    if mode == "rule":
        if "天气" in text or "weather" in text.lower():
            state["action"] = "tool"
        else:
            state["action"] = "llm"
        state["route_reason"] = "rule match"
        return state

    # LLM 模式
    router_llm = state.get("llm_router")
    if router_llm is None:
        # 回退到规则
        if "天气" in text or "weather" in text.lower():
            state["action"] = "tool"
        else:
            state["action"] = "llm"
        state["route_reason"] = "fallback rule (no router llm)"
        return state

    # 构造提示词（只要求非常结构化的 JSON 输出）
    system_msg = SystemMessage(content="你是一个路由决策器，只输出 JSON。")
    user_prompt = (
        "用户输入: " + text + "\n\n"
        "如果该问题需要调用天气类工具（包含地名 + 天气查询意图），action=tool，否则 action=llm。"\
        "\n输出格式严格为 JSON: {\"action\": \"tool|llm\", \"reason\": \"简短原因\"}"
    )

    try:
        resp = await router_llm.ainvoke([system_msg, HumanMessage(content=user_prompt)])
        raw = resp.content if isinstance(resp.content, str) else str(resp.content)
        # 提取 JSON（允许模型外层有其它字符）
        match = re.search(r"\{.*?\}", raw, re.DOTALL)
        data = json.loads(match.group(0)) if match else {}
        action = data.get("action") if data else None
        if action not in ("tool", "llm"):
            raise ValueError("invalid action")
        state["action"] = action
        state["route_reason"] = data.get("reason", "llm route")
    except Exception as e:  # 回退
        if "天气" in text or "weather" in text.lower():
            state["action"] = "tool"
        else:
            state["action"] = "llm"
        state["route_reason"] = f"fallback rule (error: {e.__class__.__name__})"

    return state

async def tool_node(state: GraphState) -> GraphState:
    """执行 MCP 工具调用

    流程：
    1. 动态列出工具（保证最新，亦可缓存）
    2. 选择第一个名称包含 weather 的工具
    3. 构造参数（从原始 query 中剔除 “天气” 关键字）
    4. 调用工具并写入结果到状态

    注意：真实场景中需：
    - 校验工具 input schema（可结合 jsonschema 做校验）
    - 捕获超时/异常并 fallback 到 LLM
    - 做结果解析与结构化
    """
    mcp_client: MCPClient = state["mcp_client"]
    query: str = state["user_input"]

    # 列出工具（可以放入缓存避免重复调用）
    resp = await mcp_client.session.list_tools()
    weather_tool = next((t for t in resp.tools if "weather" in t.name.lower()), None)
    if weather_tool is None:
        state["answer"] = "未找到 weather 工具"
        return state

    # 这里简单构造 location；若 query 为空则默认 "上海"
    location = query.replace("天气", "").strip() or "上海"
    tool_args: Dict[str, Any] = {"location": location}

    # 调用工具（可在此加入超时控制 asyncio.wait_for）
    result = await mcp_client.session.call_tool(weather_tool.name, tool_args)
    state["tool_result"] = result.content
    state["answer"] = f"工具结果: {result.content}"
    return state

async def llm_node(state: GraphState) -> GraphState:
    """直接 LLM 回复节点

    在未走工具路径时，提供通用回答。
    可扩展：
    - 检测 hallucination，必要时再 fallback 到工具
    - 增加系统提示拼接用户上下文记忆
    """
    llm: ChatAnthropic = state["llm"]
    query: str = state["user_input"]
    messages = [
        SystemMessage(content="你是一个简洁助手。"),
        HumanMessage(content=query)
    ]
    res = await llm.ainvoke(messages)
    state["answer"] = res.content
    return state

async def route(state: GraphState) -> str:
    """条件边路由函数：返回下一个节点名称"""
    return "tool" if state.get("action") == "tool" else "llm"

async def main():
    if len(sys.argv) < 3:
        print("用法: python langgraph_mcp_example.py <server_script_path> <query> [--llm-router]")
        sys.exit(1)

    server_path = sys.argv[1]
    user_query = sys.argv[2]
    use_llm_router = "--llm-router" in sys.argv[3:]

    mcp_client = await build_mcp_session(server_path)
    llm = ChatAnthropic(model="claude-3-5-sonnet-20241022", max_tokens=512)
    # 路由用小模型（可与主模型相同，这里区分展示）
    router_llm = ChatAnthropic(model=os.getenv("ROUTER_MODEL", "claude-3-5-haiku-20241022"), max_tokens=128)

    # --- 构建 LangGraph 图 ---
    graph = StateGraph(GraphState)
    # 添加节点
    graph.add_node("decide", decide_node)  # 决策 / 路由
    graph.add_node("tool", tool_node)      # 调用 MCP 工具
    graph.add_node("llm", llm_node)        # 直接 LLM 回复

    # 设置入口
    graph.set_entry_point("decide")
    # 决策节点的条件跳转：根据 route() 返回值选择下一个节点
    graph.add_conditional_edges("decide", route, {"tool": "tool", "llm": "llm"})
    # 终止边：tool 或 llm 任一执行后结束
    graph.add_edge("tool", END)
    graph.add_edge("llm", END)

    app = graph.compile()  # 编译成可执行图对象

    # --- 输出简单 ASCII 图示，便于直观理解 ---
    ascii_diagram = """\n当前执行图 (ASCII)：\n\n  +---------+        +-----------+\n  | decide  |---tool>|  tool     |\n  | (route) |        +-----------+\n  |         |---llm >|  llm      |\n  +---------+        +-----------+\n"""
    print(ascii_diagram)

    initial_state: GraphState = GraphState(
        user_input=user_query,
        mcp_client=mcp_client,
        llm=llm,
        llm_router=router_llm if use_llm_router else None,
        routing_mode="llm" if use_llm_router else "rule"
    )
    result = await app.ainvoke(initial_state)

    print("\n=== 最终答案 ===")
    print(result.get("answer"))
    print("\n[Route] mode=", initial_state["routing_mode"], "action=", result.get("action"), "reason=", result.get("route_reason"))

    await mcp_client.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
