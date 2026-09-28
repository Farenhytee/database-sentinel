"""detect -> introspect -> analyze -> score -> report."""
import json
from typing import TypedDict

from langchain_core.tools import tool
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import create_react_agent

from mcp_server import tools
from mcp_server.db import query
from mcp_server.target import Target

from .catalog import MANUAL, patterns, severity
from .introspect import introspect
from .llm import get_model, model_id
from .models import Findings
from .prompts import AGENT_SUFFIX, analyst_prompt
from .rules import r0
from .scoring import score


class State(TypedDict, total=False):
    target: Target
    introspection: dict
    candidates: list[dict]
    findings: list[dict]
    score: dict
    report: str
    model: str


def detect(s: State) -> State:
    ok = query(s["target"].dsn, "select count(*) = 2 as ok from pg_namespace where nspname in ('auth', 'storage')")
    if not ok[0]["ok"]:
        raise ValueError("target is not a Supabase project (no auth/storage schemas)")
    return {}


def do_introspect(s: State) -> State:
    intro = introspect(s["target"])
    return {"introspection": intro, "candidates": r0(intro)}


def _tools(t: Target):
    @tool
    def get_schema(schema: str = "public") -> dict:
        """Tables/views with RLS flag, anon/authenticated grants, columns, view SQL; functions with bodies."""
        return tools.get_schema(t, schema)

    @tool
    def run_audit_query(query_id: str) -> list[dict]:
        """Re-run one audit query, Q1..Q20."""
        return tools.run_audit_query(t, query_id)

    @tool
    def probe_as_anon(table: str) -> dict:
        """Ask PostgREST with the anon key whether a table/view is readable and how many rows anon sees."""
        return tools.probe_as_anon(t, table)

    return [get_schema, run_audit_query, probe_as_anon]


def analyze(s: State) -> State:
    agent = create_react_agent(get_model(), _tools(s["target"]), prompt=analyst_prompt() + AGENT_SUFFIX,
                               response_format=Findings)
    msg = json.dumps({"introspection": s["introspection"], "candidates": s["candidates"]}, default=str)
    out = agent.invoke({"messages": [("user", msg)]}, {"recursion_limit": 25})
    seen, findings = set(), []
    for f in out["structured_response"].findings:
        k = (f.pattern_id, f.object.lower())
        if k not in seen:
            seen.add(k)
            findings.append({**f.model_dump(), "severity": severity(f.pattern_id)})
    return {"findings": findings, "model": model_id()}


def do_score(s: State) -> State:
    return {"score": score([f["pattern_id"] for f in s["findings"]])}


def report(s: State) -> State:
    sc = s["score"]
    lines = [f"# Sentinel report\n\n**Score:** {sc['score']}/100 {sc['emoji']} {sc['headline']}\n"]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        fs = [f for f in s["findings"] if f["severity"] == sev]
        if fs:
            lines.append(f"## {sev}")
            lines += [f"- **{patterns()[f['pattern_id']]['title']}** `{f['object']}`: {f['evidence']}" for f in fs]
            lines.append("")
    lines.append("## Manual checks (need dashboard access)")
    lines += [f"- {patterns()[p]['title']}" for p in sorted(MANUAL) if p in patterns()]
    return {"report": "\n".join(lines)}


def build_graph():
    g = StateGraph(State)
    for name, fn in [("detect", detect), ("introspect", do_introspect), ("analyze", analyze),
                     ("score", do_score), ("report", report)]:
        g.add_node(name, fn)
    g.set_entry_point("detect")
    for a, b in [("detect", "introspect"), ("introspect", "analyze"), ("analyze", "score"), ("score", "report")]:
        g.add_edge(a, b)
    g.add_edge("report", END)
    return g.compile()
