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
