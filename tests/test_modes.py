"""Standard vs deep mode, offline: no network/db/LLM. Monkeypatches graph internals per module docstring in graph.py."""
import sys

import pytest

from database_sentinel.agent import cli, graph
from database_sentinel.agent.models import Finding, Findings
from database_sentinel.mcp_server import tools
from database_sentinel.mcp_server.target import Target

FINDING = {"pattern_id": "RLS_DISABLED", "object": "public.todos", "evidence": "rls off"}
TARGET = Target(dsn="postgresql://x", rest_url="http://127.0.0.1:54321", anon_key="anon", repo_path=None)


@pytest.fixture(autouse=True)
def base_mocks(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_KEY", "dummy")
    monkeypatch.setattr(graph, "query", lambda dsn, sql: [{"ok": True}])
    monkeypatch.setattr(graph, "introspect", lambda target: {})
    monkeypatch.setattr(graph, "r0", lambda intro: [])
    monkeypatch.setattr(tools, "probe_as_anon", lambda t, table, op="select": {
        "table": "todos", "status": 200, "anon_rows_visible": 3})


def _assert_common(out):
    assert out["findings"], "expected at least one finding"
    for f in out["findings"]:
        assert "severity" in f
        assert "verified" in f
    assert "public.todos" in out["report"]


def test_standard_mode_calls_single_prompt_once(monkeypatch):
    calls = []
    monkeypatch.setattr(graph, "single_prompt", lambda intro, config=None: calls.append(1) or [dict(FINDING)])

    def boom(*a, **k):
        raise AssertionError("create_react_agent must not be called in standard mode")
    monkeypatch.setattr(graph, "create_react_agent", boom)

    out = graph.build_graph(deep=False).invoke({}, context=TARGET)
    assert len(calls) == 1
    _assert_common(out)


def test_deep_mode_uses_react_agent(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("single_prompt must not be called in deep mode")
    monkeypatch.setattr(graph, "single_prompt", boom)

    created = []

    def fake_create_react_agent(*a, **k):
        created.append(1)

        class FakeAgent:
            def invoke(self, *a, **k):
                return {"structured_response": Findings(findings=[Finding(**FINDING, confidence=0.9)])}
        return FakeAgent()

    monkeypatch.setattr(graph, "create_react_agent", fake_create_react_agent)

    out = graph.build_graph(deep=True).invoke({}, context=TARGET)
    assert created == [1]
    _assert_common(out)


def test_cli_deep_flag_passed_to_build_graph(monkeypatch, capsys):
    seen = {}

    def fake_build_graph(*a, **k):
        seen.update(k)

        class G:
            def invoke(self, state, context=None):
                return {"report": "ok"}
        return G()

    monkeypatch.setattr(graph, "build_graph", fake_build_graph)
    monkeypatch.setattr(sys, "argv", ["sentinel-audit", "--dsn", "postgresql://x", "--deep"])

    cli.main()

    assert seen.get("deep") is True
    assert capsys.readouterr().out.strip() == "ok"
