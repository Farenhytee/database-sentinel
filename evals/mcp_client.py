"""Eval system M: a model used as an MCP client. Starts the real `sentinel-mcp` over stdio, sends the server's
own `audit` prompt, and lets the model call only the server's tools (no introspection handed over)."""
import asyncio
import json
import os
import sys
from pathlib import Path

from langchain_core.tools import StructuredTool
from langgraph.prebuilt import ToolNode, create_react_agent
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from database_sentinel.agent.llm import get_model
from database_sentinel.agent.models import Findings, clean
from database_sentinel.agent.prompts import EXTRACT_PROMPT

SERVER = str(Path(sys.executable).parent / "sentinel-mcp")


def _env(t) -> dict:
    env = {"PATH": os.environ.get("PATH", ""), "SENTINEL_DSN": t.dsn,
           "SENTINEL_REST_URL": t.rest_url or "", "SENTINEL_ANON_KEY": t.anon_key or ""}
    return env | ({"SENTINEL_REPO": t.repo_path} if t.repo_path else {})


def _wrap(session: ClientSession, tool) -> StructuredTool:
    async def call(**kwargs):
        r = await session.call_tool(tool.name, kwargs)
        text = json.dumps(r.structured_content, default=str) if r.structured_content else \
            "\n".join(getattr(c, "text", "") for c in r.content)
        return ("ERROR: " + text) if r.is_error else text
    return StructuredTool.from_function(coroutine=call, name=tool.name, description=tool.description or "",
                                        args_schema=tool.input_schema)


async def _audit(t, config: dict | None) -> list[dict]:
    async with stdio_client(StdioServerParameters(command=SERVER, env=_env(t))) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = [_wrap(session, x) for x in (await session.list_tools()).tools]
            prompt = "\n".join(m.content.text for m in (await session.get_prompt("audit")).messages)
            agent = create_react_agent(get_model(), ToolNode(tools, handle_tool_errors=True),
                                       response_format=(EXTRACT_PROMPT, Findings))
            out = await agent.ainvoke({"messages": [("user", prompt)]}, {"recursion_limit": 60, **(config or {})})
            return clean([f.model_dump() for f in out["structured_response"].findings])


_LOOP = asyncio.new_event_loop()  # one loop per process: langchain-openai caches its async client on the first loop


def mcp_audit(t, config: dict | None = None) -> list[dict]:
    return _LOOP.run_until_complete(_audit(t, config))
