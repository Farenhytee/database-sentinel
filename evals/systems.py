"""Systems under test. Each takes (target, introspection) and returns findings as dicts."""
import json

from database_sentinel.agent.introspect import introspect
from database_sentinel.agent.llm import get_model
from database_sentinel.agent.models import Findings
from database_sentinel.agent.prompts import analyst_prompt
from database_sentinel.agent.rules import r0

__all__ = ["SYSTEMS", "introspect"]


def run_r0(t, intro):
    return r0(intro)


def run_b0(t, intro):
    """Single prompt: full introspection dump -> one structured-output call. Same model as A."""
    llm = get_model().with_structured_output(Findings)
    out = llm.invoke([("system", analyst_prompt()), ("user", json.dumps(intro, default=str))])
    return [f.model_dump() for f in out.findings]


def run_a(t, intro):
    from database_sentinel.agent.graph import build_graph
    state = build_graph().invoke({"target": t})
    return state["findings"]


SYSTEMS = {"r0": run_r0, "b0": run_b0, "a": run_a}
