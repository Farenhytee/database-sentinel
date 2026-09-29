"""MCP server over the plain tool functions. Target comes from SENTINEL_* env vars.

`sentinel-mcp` runs it over stdio; `sentinel-mcp --role-sql` prints the read-only role SQL.
"""
import sys

from mcp.server.mcpserver import MCPServer

from database_sentinel.agent.prompts import client_prompt

from . import tools
from .paths import SUPABASE
from .setup import role_sql
from .target import Target

mcp = MCPServer("sentinel-mcp", instructions="Read-only Supabase security audit tools.")


@mcp.tool()
def run_audit_query(query_id: str) -> list[dict]:
    """Run one allowlisted audit query (Q1..Q20 from audit-queries.md)."""
    return tools.run_audit_query(Target.from_env(), query_id)


@mcp.tool()
def get_schema(schema: str = "public") -> dict:
    """Tables, views, columns, grants and functions in a schema."""
    return tools.get_schema(Target.from_env(), schema)


@mcp.tool()
def probe_as_anon(table: str, op: str = "select") -> dict:
    """Check via PostgREST whether the anon key can read a table (row count only)."""
    return tools.probe_as_anon(Target.from_env(), table, op)


@mcp.tool()
def scan_repo() -> list[dict]:
    """Scan the configured repo for exposed service-role keys / JWT secrets (locations only)."""
    return tools.scan_repo(Target.from_env())


@mcp.prompt(name="audit", description="Run a full Sentinel audit with your own LLM.")
def audit() -> str:
    return client_prompt()


@mcp.resource("sentinel://catalog/anti-patterns", name="anti-patterns", mime_type="text/markdown",
              description="Supabase anti-pattern catalog: IDs, severity, detection, fixes.")
def anti_patterns() -> str:
    return (SUPABASE / "anti-patterns.md").read_text()


@mcp.resource("sentinel://catalog/fix-templates", name="fix-templates", mime_type="text/markdown",
              description="Fix SQL templates. Show to the user; never run them.")
def fix_templates() -> str:
    return (SUPABASE / "fix-templates.md").read_text()


@mcp.resource("sentinel://setup/auditor-role", name="auditor-role", mime_type="text/x-sql",
              description="SQL creating the read-only sentinel_auditor role. The user runs it, not the agent.")
def auditor_role() -> str:
    return role_sql()


def main() -> None:
    if "--role-sql" in sys.argv:
        print(role_sql())
        return
    mcp.run()


if __name__ == "__main__":
    main()
