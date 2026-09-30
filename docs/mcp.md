# Sentinel MCP server

Read-only security audit tools for **Supabase**, usable from any MCP client (Claude Code, Claude Desktop, Cursor, …). Your own LLM does the analysis, so there's no API key or hosted service involved.

It can't change your database. There are no write, drop or delete tools, and the connection is read-only.

## Setup (3 steps)

### 1. Create a read-only login in Supabase

Open your project → **SQL Editor**, paste this, change `CHANGE_ME_TO_A_STRONG_PASSWORD`, then click **Run**. (`uvx --from git+https://github.com/Farenhytee/database-sentinel sentinel-mcp --role-sql` prints the same SQL.)

```sql
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_auditor') THEN
    CREATE ROLE sentinel_auditor LOGIN BYPASSRLS PASSWORD 'CHANGE_ME_TO_A_STRONG_PASSWORD';
  END IF;
END $$;
ALTER ROLE sentinel_auditor SET default_transaction_read_only = on;
ALTER ROLE sentinel_auditor SET statement_timeout = '5s';
GRANT USAGE ON SCHEMA storage TO sentinel_auditor;
GRANT SELECT ON storage.buckets TO sentinel_auditor;
```

This login can see your security settings (policies, grants, functions, buckets) but **not your data**.

Use letters and digits only in the password (symbols like `@ : / #` break connection strings).

**Your connection string** (used below as `SENTINEL_DSN`):
1. In the dashboard, click **Connect** → **Session pooler** and copy the URI.
2. Change the username `postgres.<project-ref>` to **`sentinel_auditor.<project-ref>`**.
3. Replace `[YOUR-PASSWORD]`, brackets included, with the password you just set.

```
postgresql://sentinel_auditor.<project-ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres
```
Never use the `postgres` login. It can write to your database. Sentinel is only read-only through `sentinel_auditor`. Won't connect? See [Connecting to hosted Supabase](#connecting-to-hosted-supabase).

### 2. Install

All options need [uv](https://docs.astral.sh/uv/getting-started/installation/) (`brew install uv` or `pip install uv`).

**Claude Code: plugin (recommended).** Installs the MCP server and the audit skill, and asks for your connection string.
```bash
claude plugin marketplace add Farenhytee/database-sentinel
claude plugin install database-sentinel@database-sentinel
```
Or inside Claude Code: `/plugin marketplace add Farenhytee/database-sentinel`, then `/plugin install database-sentinel@database-sentinel`.
Then set your connection string in Claude Code: `/plugin configure database-sentinel@database-sentinel`.

**Cursor**

[![Add to Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=sentinel&config=eyJzZW50aW5lbCI6eyJjb21tYW5kIjoidXZ4IiwiYXJncyI6WyItLWZyb20iLCJnaXQraHR0cHM6Ly9naXRodWIuY29tL0ZhcmVuaHl0ZWUvZGF0YWJhc2Utc2VudGluZWwiLCJzZW50aW5lbC1tY3AiXSwiZW52Ijp7IlNFTlRJTkVMX0RTTiI6InBvc3RncmVzcWw6Ly9zZW50aW5lbF9hdWRpdG9yLlBST0pFQ1RfUkVGOlBBU1NXT1JEQFBPT0xFUl9IT1NUOjU0MzIvcG9zdGdyZXMiLCJTRU5USU5FTF9SRVNUX1VSTCI6Imh0dHBzOi8vUFJPSkVDVF9SRUYuc3VwYWJhc2UuY28iLCJTRU5USU5FTF9BTk9OX0tFWSI6IkFOT05fS0VZIiwiU0VOVElORUxfUkVQTyI6IiJ9fX0%3D)

Then open **Cursor Settings → MCP → sentinel** and replace `PASSWORD`, `PROJECT_REF`, `POOLER_HOST` (e.g. `aws-0-<region>.pooler.supabase.com`, from **Connect → Session pooler**) and `ANON_KEY`.

**Claude Code: MCP server only**
```bash
claude mcp add sentinel \
  -e SENTINEL_DSN="postgresql://sentinel_auditor.<project-ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres" \
  -e SENTINEL_REST_URL="https://<project-ref>.supabase.co" \
  -e SENTINEL_ANON_KEY="<anon key>" \
  -- uvx --from git+https://github.com/Farenhytee/database-sentinel sentinel-mcp
```

**Claude Desktop or any other client:** add this to its MCP config (`claude_desktop_config.json`, `.cursor/mcp.json`, …):
```json
{
  "mcpServers": {
    "sentinel": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/Farenhytee/database-sentinel", "sentinel-mcp"],
      "env": {
        "SENTINEL_DSN": "postgresql://sentinel_auditor.<project-ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres",
        "SENTINEL_REST_URL": "https://<project-ref>.supabase.co",
        "SENTINEL_ANON_KEY": "<anon key>"
      }
    }
  }
}
```
Optional: add `"SENTINEL_REPO": "/path/to/your/app"` to also scan your code for leaked keys.

**Pin a version** (recommended): append `@v1.0.0` to the git URL, e.g. `git+https://github.com/Farenhytee/database-sentinel@v1.0.0`. Without it you get the latest `main`. The Claude Code plugin is pinned to its release automatically.

### 3. Run it

Pick the **`audit`** prompt in your client, or just ask: *"Audit my Supabase project."*

You get findings grouped by severity, each with evidence and a fix you can review, plus a list of manual checks that need the dashboard.

## Accuracy

The `audit` prompt carries the same rules as Sentinel's benchmarked single-prompt audit. On a blind test split of 10 Supabase projects (3 runs, `deepseek-v4-flash`), that audit scored **F1 0.849** and found every CRITICAL issue ([results](evals/2026-09-30-test-v0.2.1.md)). That run handed the model the data directly. Here your client's model gathers it through the tools, and that flow isn't benchmarked yet, so results depend on your client's model.

## Configuration

| Variable | Required | Used by |
|---|---|---|
| `SENTINEL_DSN` | yes | all database tools (the `sentinel_auditor` connection string) |
| `SENTINEL_REST_URL` | for `probe_as_anon` | project URL, e.g. `https://<ref>.supabase.co` |
| `SENTINEL_ANON_KEY` | for `probe_as_anon` | the public anon key (never the service-role key) |
| `SENTINEL_REPO` | for `scan_repo` | local path to your app's source |

## What's included

**Tools**

| Tool | Does | Returns |
|---|---|---|
| `run_audit_query(query_id)` | Runs one of the fixed audit queries `Q1`–`Q20` ([list](../backends/supabase/audit-queries.md)). No other SQL is accepted. | Up to 200 rows of catalog data |
| `get_schema(schema="public")` | Tables, views, columns, RLS flags, anon/authenticated grants, function definitions | Structure only, no rows |
| `probe_as_anon(table)` | Asks the REST API, using the anon key, whether anonymous users can read a table | HTTP status + row **count** |
| `scan_repo()` | Looks for service-role keys and JWT secrets in your frontend code | File and line only, **never the value** |

**Prompt:** `audit` gives your LLM the auditor instructions and the list of patterns to check.

**Resources:** `sentinel://catalog/anti-patterns`, `sentinel://catalog/fix-templates`, `sentinel://setup/auditor-role`.

Fix templates are suggestions for you to review. The server never applies them.

---

## Appendix

### Safety model
Five separate layers, any one of which blocks a write:
1. The audit queries are an allowlist loaded from [`audit-queries.md`](../backends/supabase/audit-queries.md). The server refuses to start if any of them isn't a single plain `SELECT`.
2. Every connection is opened read-only.
3. The role itself defaults to read-only transactions, with a 5-second statement timeout.
4. The role has no `SELECT` on any of your tables.
5. `probe_as_anon` only sends read (HEAD) requests.

### What it detects
The SQL- and code-visible Supabase patterns in [`anti-patterns.md`](../backends/supabase/anti-patterns.md): RLS disabled, policies without RLS, `USING (true)`, views bypassing RLS, exposed `SECURITY DEFINER`/RPC functions, `user_metadata` in policies, mass assignment, public buckets, sensitive columns, leaked service-role keys and JWT secrets, and more.

These need dashboard access and are reported as **manual checks**: email confirmation, password policy, OAuth redirects, anonymous sign-ins, rate limits.

### Connecting to hosted Supabase
- Verified on hosted Supabase (Postgres 17, session pooler): `BYPASSRLS` is allowed, the role stays read-only with the 5s timeout, and all 20 queries run.
- `password authentication failed for user "postgres"`: the username is still `postgres.<ref>`. Change it to `sentinel_auditor.<ref>`.
- The direct host `db.<ref>.supabase.co` also works (username `sentinel_auditor`, no suffix), but it's IPv6-only on some plans.
- If `CREATE ROLE … BYPASSRLS` is ever refused, remove `BYPASSRLS`. Only the bucket check (Q17) is affected.

### Errors
Input errors (unknown query id, invalid table name, missing `SENTINEL_REST_URL`) are returned to your client with the reason and the expected input (e.g. `probe_as_anon` takes a bare table name like `todos`), so the LLM can correct itself.

### Licence
`database_sentinel/mcp_server/` is AGPL-3.0. The Skill and the catalog Markdown files are MIT.
