"""MCP server over the plain tool functions. Target comes from SENTINEL_* env vars.

`sentinel-mcp` runs it over stdio; `sentinel-mcp --role-sql` prints the read-only role SQL.
"""
import functools
import sys
from typing import Annotated, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from database_sentinel.agent.prompts import client_prompt

from . import tools
from .paths import SUPABASE
from .queries import audit_queries
from .setup import role_sql
from .target import Target

mcp = MCPServer("sentinel-mcp", instructions="Read-only Supabase security audit tools.")
# Every tool only reads. _REMOTE talks to the user's Supabase project, _LOCAL to files on this machine.
_REMOTE = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)
_LOCAL = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)


def _client_errors(fn):
    """Pass input errors (bad query id, table name...) to the client so its LLM can correct itself."""
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        try:
            return fn(*a, **kw)
        except (ValueError, KeyError) as e:
            raise ToolError(str(e)) from e
    return wrapper


@mcp.tool(title="Run an audit query", annotations=_REMOTE)
@_client_errors
def run_audit_query(query_id: Annotated[str, Field(description=(
        'One of "Q1" to "Q20". Q1-Q4: RLS status per table. Q5-Q11: policies. Q12-Q16: functions and views. '
        'Q17-Q18: storage buckets and their policies. Q19: sensitive column names. Q20: draft CREATE POLICY statements.'))]) -> list[dict]:
    """Run one fixed, read-only audit query against the Supabase Postgres catalog and return its rows.

    Use it to collect evidence for a security audit: the queries for the area you are checking, or all 20 for a
    full audit. Use get_schema instead when you need the raw tables, columns, grants and function bodies.
    Rows are schema metadata (tables, policies, functions, buckets), never table data, capped at 200 per query.
    You cannot pass your own SQL. An unknown query_id returns an error listing the allowed ids.
    Needs SENTINEL_DSN. Statements time out after 5 seconds.
    """
    return tools.run_audit_query(Target.from_env(), query_id)


@mcp.tool(title="Get schema metadata", annotations=_REMOTE)
@_client_errors
def get_schema(schema: Annotated[str, Field(description=(
        'Postgres schema name, letters, digits and underscores only, e.g. "public" or "storage". '
        "A schema that does not exist returns empty lists."))] = "public") -> dict:
    """List the tables, views and functions of one Postgres schema, with what the anon and authenticated roles may do.

    Use it to read policies and function code for logic mistakes, or to check a finding from run_audit_query.
    Returns {schema, relations, functions}. Each relation has its kind, whether RLS is on, anon and authenticated
    grants, columns with types, and the SQL of a view. Each function has its arguments, return type, SECURITY DEFINER
    flag, config, who may execute it, and the first 2000 characters of its body.
    Read-only: metadata only, never rows. Needs SENTINEL_DSN. Capped at 200 relations and 200 functions.
    """
    return tools.get_schema(Target.from_env(), schema)


@mcp.tool(title="Probe a table as an anonymous visitor", annotations=_REMOTE)
@_client_errors
def probe_as_anon(
        table: Annotated[str, Field(description='Bare table or view name in the public schema, e.g. "todos". No schema prefix, no quotes.')],
        op: Annotated[Literal["select"], Field(description='The operation to test. Only "select" exists: this tool never writes.')] = "select",
) -> dict:
    """Check whether an anonymous visitor can really read a table, by asking the project's REST API with the anon key.

    Use it after run_audit_query or get_schema flags a table, to confirm the exposure is real before reporting it.
    Sends one HEAD request, so no rows are downloaded. Returns {table, status, anon_rows_visible}: status is the
    HTTP status, anon_rows_visible is how many rows anon can see (0 when RLS hides them all, null when the request
    was refused or the table is not exposed).
    Needs SENTINEL_REST_URL and SENTINEL_ANON_KEY; without them it returns an error saying so.
    """
    return tools.probe_as_anon(Target.from_env(), table, op)


@mcp.tool(title="Scan the app's code for leaked keys", annotations=_LOCAL)
@_client_errors
def scan_repo() -> list[dict]:
    """Scan the app's source code on this machine for Supabase secrets that must never reach a browser.

    Use it once per audit, alongside the database tools: it covers the leaks the database cannot show.
    Looks for service-role JWTs, sb_secret_ keys, public env vars named SERVICE_ROLE and JWT secret assignments,
    in JS/TS, Vue, Svelte, HTML, JSON and .env files (skips node_modules, build output and .git).
    Returns [{pattern_id, kind, file, line}]: locations only, never the secret value. Takes no arguments;
    the folder comes from SENTINEL_REPO, and the result is an empty list when that is not set.
    SENTINEL_DSN must be set even though this tool does not connect to the database.
    """
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
    audit_queries()  # fail fast if the allowlist isn't read-only
    mcp.run()


if __name__ == "__main__":
    main()
