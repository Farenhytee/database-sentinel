"""detect -> introspect -> analyze -> verify -> score -> report [-> approve (HITL) -> fix]."""
import json
from typing import TypedDict

from langchain_core.tools import tool
from langgraph.graph import END, StateGraph
from langgraph.runtime import Runtime
from langgraph.types import interrupt
from langgraph.prebuilt import ToolNode, create_react_agent

from database_sentinel.mcp_server import tools
from database_sentinel.mcp_server.db import query
from database_sentinel.mcp_server.target import Target

from .catalog import MANUAL, patterns, severity
from .fixes import fix_for
from .introspect import introspect
from .llm import get_model, model_id
from .models import Findings, clean
from .prompts import AGENT_SUFFIX, EXTRACT_PROMPT, analyst_prompt
from .rules import r0
from .scoring import score


# The Target (DSN with password) travels as runtime context, never in state, so checkpoints hold no credentials.
class State(TypedDict, total=False):
    introspection: dict
    candidates: list[dict]
    findings: list[dict]
    score: dict
    report: str
    model: str
    fixes: list[str]


def detect(s: State, runtime: Runtime[Target]) -> State:
    ok = query(runtime.context.dsn, "select count(*) = 2 as ok from pg_namespace where nspname in ('auth', 'storage')")
    if not ok[0]["ok"]:
        raise ValueError("target is not a Supabase project (no auth/storage schemas)")
    return {}


def do_introspect(s: State, runtime: Runtime[Target]) -> State:
    intro = introspect(runtime.context)
    return {"introspection": intro, "candidates": r0(intro)}


def _tools(t: Target):
    @tool
    def get_schema(schema_name: str = "public") -> dict:
        """Tables/views with RLS flag, anon/authenticated grants, columns, view SQL; functions with bodies."""
        return tools.get_schema(t, schema_name)

    @tool
    def run_audit_query(query_id: str) -> list[dict]:
        """Re-run one audit query, Q1..Q20."""
        return tools.run_audit_query(t, query_id)

    @tool
    def probe_as_anon(table: str) -> dict:
        """Ask PostgREST with the anon key whether a table/view is readable and how many rows anon sees."""
        return tools.probe_as_anon(t, table)

    return [get_schema, run_audit_query, probe_as_anon]


def analyze(s: State, runtime: Runtime[Target]) -> State:
    # handle_tool_errors: a bad tool arg goes back to the model as an error message instead of ending the audit
    agent = create_react_agent(get_model(), ToolNode(_tools(runtime.context), handle_tool_errors=True), prompt=analyst_prompt() + AGENT_SUFFIX,
                               response_format=(EXTRACT_PROMPT, Findings))
    msg = json.dumps({"introspection": s["introspection"], "candidates": s["candidates"]}, default=str)
    out = agent.invoke({"messages": [("user", msg)]}, {"recursion_limit": 25})
    findings = clean([f.model_dump() for f in out["structured_response"].findings])
    return {"findings": [{**f, "severity": severity(f["pattern_id"])} for f in findings], "model": model_id()}


# Patterns where anon reading rows proves the finding. Others (authenticated-only) can't be probed as anon.
PROBEABLE = {"RLS_DISABLED", "POLICIES_BUT_NO_RLS", "USING_TRUE", "VIEW_NO_SECURITY_INVOKER",
             "MATVIEW_EXPOSED", "SENSITIVE_COLUMNS"}


def verify(s: State, runtime: Runtime[Target]) -> State:
    """Flag findings anon can actually exploit. Never drops a finding."""
    t, out = runtime.context, []
    for f in s["findings"]:
        f = {**f, "verified": None}
        schema, _, name = f["object"].lower().partition(".")
        if f["pattern_id"] in PROBEABLE and schema == "public" and t.rest_url and t.anon_key:
            try:
                r = tools.probe_as_anon(t, name)
                f["verified"] = 200 <= r["status"] < 300 and (r["anon_rows_visible"] or 0) > 0  # 206 when rows > limit
            except Exception:
                pass  # unverifiable, not refuted
        out.append(f)
    return {"findings": out}


def do_score(s: State) -> State:
    return {"score": score([f["pattern_id"] for f in s["findings"]])}


def report(s: State) -> State:
    sc = s["score"]
    lines = [f"# Sentinel report\n\n**Score:** {sc['score']}/100 {sc['emoji']} {sc['headline']}\n"]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        fs = [f for f in s["findings"] if f["severity"] == sev]
        if fs:
            lines.append(f"## {sev}")
            lines += [f"- **{patterns()[f['pattern_id']]['title']}** `{f['object']}`: {f['evidence']}"
                      + (" · confirmed: anon can read rows" if f.get("verified") else "") for f in fs]
            lines.append("")
    lines.append("## Manual checks (need dashboard access)")
    lines += [f"- {patterns()[p]['title']}" for p in sorted(MANUAL) if p in patterns()]
    return {"report": "\n".join(lines)}


def approve(s: State) -> State:
    """HITL: pause until the user picks which findings to fix. Resume with Command(resume=[indexes])."""
    picked = interrupt({"findings": [{"i": i, "pattern_id": f["pattern_id"], "object": f["object"],
                                      "severity": f["severity"]} for i, f in enumerate(s["findings"])]})
    return {"fixes": [fix_for(s["findings"][i]) for i in picked or [] if 0 <= i < len(s["findings"])]}


def build_graph(checkpointer=None, fixes: bool = False):
    """fixes=True adds the approval pause + fix step and needs a checkpointer (MemorySaver locally, PostgresSaver in cloud)."""
    g = StateGraph(State, context_schema=Target)
    steps = [("detect", detect), ("introspect", do_introspect), ("analyze", analyze), ("verify", verify),
             ("score", do_score), ("report", report)] + ([("approve", approve)] if fixes else [])
    for name, fn in steps:
        g.add_node(name, fn)
    g.set_entry_point("detect")
    for (a, _), (b, _) in zip(steps, steps[1:]):
        g.add_edge(a, b)
    g.add_edge(steps[-1][0], END)
    return g.compile(checkpointer=checkpointer)
