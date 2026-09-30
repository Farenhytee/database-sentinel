"""Systems under test. Each takes (target, introspection) and returns (findings, usage dict)."""
import json

from database_sentinel.agent.introspect import introspect
from database_sentinel.agent.llm import get_model
from database_sentinel.agent.models import Findings, clean
from database_sentinel.agent.prompts import analyst_prompt
from database_sentinel.agent.rules import r0
from database_sentinel.agent.usage import Usage, callbacks

__all__ = ["SYSTEMS", "introspect"]


def run_r0(t, intro):
    return r0(intro), {}


def run_b0(t, intro):
    """Single prompt: full introspection dump -> one structured-output call. Same model as A."""
    u = Usage()
    llm = get_model().with_structured_output(Findings)
    out = llm.invoke([("system", analyst_prompt()), ("user", json.dumps(intro, default=str))],
                     {"callbacks": callbacks(u)})
    return clean([f.model_dump() for f in out.findings]), u.as_dict()


def run_a(t, intro):
    from database_sentinel.agent.graph import build_graph
    u = Usage()
    state = build_graph().invoke({}, {"callbacks": callbacks(u)}, context=t)
    return state["findings"], u.as_dict()


SYSTEMS = {"r0": run_r0, "b0": run_b0, "a": run_a}
