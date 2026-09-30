from pathlib import Path

from database_sentinel.agent.catalog import MANUAL, NOT_EVALUATED, in_scope, patterns
from database_sentinel.agent.rules import r0
from database_sentinel.agent.scoring import score
from evals.matcher import match, norm
from evals.metrics import prf
from database_sentinel.mcp_server.queries import audit_queries
from database_sentinel.mcp_server.target import Target
from database_sentinel.mcp_server.tools import scan_repo

FIX = Path(__file__).parent / "fixtures" / "repo"


def test_catalog_parses():
    assert list(audit_queries()) == [f"Q{i}" for i in range(1, 21)]
    assert len(patterns()) == 27
    assert set(in_scope()).isdisjoint(MANUAL | NOT_EVALUATED)


def test_scoring():
    assert score([]) == {"score": 100, "emoji": "✅", "headline": "Generally well-configured."}
    assert score(["RLS_DISABLED"])["score"] == 75
    assert score(["RLS_DISABLED"] * 5)["score"] == 0  # floor
    assert score(["RLS_DISABLED", "USING_TRUE"])["emoji"] == "⚠️"  # 65


def test_matcher():
    assert norm("Todos") == "public.todos"
    assert norm('public.get_user_emails()') == "public.get_user_emails"
    assert norm("./src/lib/supabase.ts") == "src/lib/supabase.ts"
    assert norm(".env.local") == ".env.local"
    m = match([{"pattern_id": "RLS_DISABLED", "object": "todos"}, {"pattern_id": "RLS_PERFORMANCE", "object": "x"}],
              [{"pattern_id": "RLS_DISABLED", "object": "public.todos"}])
    assert (len(m["tp"]), len(m["fp"]), len(m["fn"])) == (1, 0, 0)  # out-of-scope id dropped
    assert prf(0, 0, 0) == (1.0, 1.0, 1.0)


def test_scan_repo_never_returns_values():
    hits = scan_repo(Target(dsn="", repo_path=str(FIX)))
    assert {h["pattern_id"] for h in hits} == {"SERVICE_ROLE_EXPOSED"}
    assert all(h["file"] == "src/supabase.ts" for h in hits)
    assert "eyJ" not in str(hits)


def test_r0_on_canned_rows():
    q = {f"Q{i}": [] for i in range(1, 21)}
    q["Q1"] = [{"tablename": "todos", "rls_enabled": False}, {"tablename": "orders", "rls_enabled": False}]
    q["Q3"] = [{"tablename": "orders"}]
    q["Q17"] = [{"name": "avatars", "public": True}]
    q["Q5"] = [{"tablename": "profiles", "cmd": "UPDATE"}]
    schema = {"relations": [{"name": "profiles", "columns": [{"name": "role", "auth_update": True}]}]}
    got = {(f["pattern_id"], f["object"]) for f in r0({"queries": q, "schema": schema, "scan": []})}
    assert got == {("RLS_DISABLED", "public.todos"), ("POLICIES_BUT_NO_RLS", "public.orders"),
                   ("PUBLIC_BUCKET", "storage.avatars"), ("MASS_ASSIGNMENT", "public.profiles")}


def test_allowlist_is_read_only():
    from database_sentinel.mcp_server.queries import is_read_only
    assert all(is_read_only(sql) for sql in audit_queries().values())
    for bad in ["DROP SCHEMA public CASCADE", "select 1; drop table x", "delete from t", "SELECT 1 FROM t; TRUNCATE t"]:
        assert not is_read_only(bad)


def test_mcp_exposes_no_write_tools():
    from database_sentinel.mcp_server import tools
    public = {n for n in dir(tools) if not n.startswith("_") and callable(getattr(tools, n)) and getattr(tools, n).__module__ == tools.__name__}
    assert public == {"run_audit_query", "get_schema", "probe_as_anon", "scan_repo"}


def test_docs_role_sql_in_sync():
    from database_sentinel.mcp_server.setup import role_sql
    docs = (Path(__file__).parents[1] / "docs" / "mcp.md").read_text()
    assert all(l in docs for l in role_sql().splitlines() if l.strip() and not l.startswith("--"))


def test_fix_for():
    from database_sentinel.agent.fixes import fix_for
    assert "ENABLE ROW LEVEL SECURITY" in fix_for({"pattern_id": "RLS_DISABLED", "object": "public.todos"})
    assert "WHERE id = 'invoices'" in fix_for({"pattern_id": "PUBLIC_BUCKET", "object": "storage.invoices"})
    evil = fix_for({"pattern_id": "RLS_DISABLED", "object": "public.x; drop table y"})
    assert all(l.startswith("--") for l in evil.splitlines())  # unsafe object -> comments only, no SQL
    assert fix_for({"pattern_id": "USING_TRUE", "object": "public.t"}).splitlines()[1].startswith("--")


def test_verify_flags_without_dropping(monkeypatch):
    from database_sentinel.agent import graph
    probes = {"todos": {"status": 200, "anon_rows_visible": 2}, "orders": {"status": 200, "anon_rows_visible": 0}}
    monkeypatch.setattr(graph.tools, "probe_as_anon", lambda t, name: probes[name])
    t = Target(dsn="", rest_url="http://x", anon_key="k")
    fs = [{"pattern_id": "RLS_DISABLED", "object": "public.todos"},
          {"pattern_id": "USING_TRUE", "object": "public.orders"},
          {"pattern_id": "MASS_ASSIGNMENT", "object": "public.profiles"}]
    from types import SimpleNamespace
    out = graph.verify({"findings": fs}, SimpleNamespace(context=t))["findings"]
    assert [f["verified"] for f in out] == [True, False, None]


def test_lock_detects_edit(tmp_path, monkeypatch):
    from evals import bench
    (tmp_path / "cases" / "099-x").mkdir(parents=True)
    (tmp_path / "cases" / "099-x" / "schema.sql").write_text("select 1;")
    (tmp_path / "splits.yaml").write_text('dev: []\ntest: ["099"]\n')
    monkeypatch.setattr(bench, "BENCH", tmp_path)
    monkeypatch.setattr(bench, "LOCK", tmp_path / "test.lock")
    bench.write_lock()
    bench.check_lock()
    (tmp_path / "cases" / "099-x" / "schema.sql").write_text("select 2;")
    import pytest
    with pytest.raises(SystemExit):
        bench.check_lock()


def test_clean_normalizes_and_dedupes():
    from database_sentinel.agent.models import clean
    out = clean([{"pattern_id": "SENSITIVE_COLUMNS", "object": "public.app_settings.stripe_key"},
                 {"pattern_id": "SENSITIVE_COLUMNS", "object": "app_settings"},
                 {"pattern_id": "POLICIES_BUT_NO_RLS", "object": "public.orders"},
                 {"pattern_id": "RLS_DISABLED", "object": "public.orders"}])
    assert [(f["pattern_id"], f["object"]) for f in out] == [("SENSITIVE_COLUMNS", "public.app_settings"),
                                                             ("POLICIES_BUT_NO_RLS", "public.orders")]
