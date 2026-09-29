"""Shared introspection dump used by R0, B0 and the agent."""
from database_sentinel.mcp_server import tools
from database_sentinel.mcp_server.queries import audit_queries
from database_sentinel.mcp_server.target import Target


def introspect(t: Target) -> dict:
    return {"queries": {q: tools.run_audit_query(t, q) for q in audit_queries()},
            "schema": tools.get_schema(t),
            "scan": tools.scan_repo(t)}
