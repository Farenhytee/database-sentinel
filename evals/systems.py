"""Systems under test. Each takes (target, introspection) and returns (findings, usage dict)."""
from database_sentinel.agent.introspect import introspect
from database_sentinel.agent.rules import r0
from database_sentinel.agent.usage import Usage, callbacks

__all__ = ["SYSTEMS", "introspect"]


def run_r0(t, intro):
    return r0(intro), {}


def run_b0(t, intro):
    """Single prompt: full introspection dump -> one structured-output call. Same model as A."""
    from database_sentinel.agent.graph import single_prompt
    u = Usage()
    return single_prompt(intro, {"callbacks": callbacks(u)}), u.as_dict()


def _graph(deep):
    def run(t, intro):
        from database_sentinel.agent.graph import build_graph
        u = Usage()
        state = build_graph(deep=deep).invoke({}, {"callbacks": callbacks(u)}, context=t)
        return state["findings"], u.as_dict()
    return run


# s = standard audit (B0 + verify, the default); a = deep audit (ReAct agent)
SYSTEMS = {"r0": run_r0, "b0": run_b0, "s": _graph(False), "a": _graph(True)}
