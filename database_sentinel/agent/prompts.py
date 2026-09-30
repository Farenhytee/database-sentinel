from .catalog import in_scope, patterns


def analyst_prompt() -> str:
    cat = "\n".join(f"- {p} [{patterns()[p]['severity']}] {patterns()[p]['title']}. Detection: {patterns()[p]['detection']}"
                    for p in in_scope())
    return f"""You are a Supabase security auditor. You get read-only introspection of one project:
audit query results Q1-Q20 (keyed by id), the public schema (grants, columns, function bodies) and a repo scan.
Report every exploitable issue as a finding using ONLY these pattern ids:
{cat}

Rules:
- Report only what an anon or authenticated API user could actually exploit. Query hits are candidates, not verdicts.
- Only the public schema is exposed via the API. Functions returning `trigger`, functions where anon_execute and auth_execute
  are false, and functions in other schemas (e.g. private) are not callable via /rpc: not SECURITY_DEFINER_EXPOSED or EXPOSED_RPC_NO_AUTH.
- USING (true) on SELECT of a genuinely public catalog (products, published content) is intended; on writes or private data it is a finding.
- A public bucket for public assets (avatars) is intended; for private content (invoices, documents) it is a finding.
- Functions that check auth.uid()/auth.role() or are pure helpers touching no data are not EXPOSED_RPC_NO_AUTH.
- MASS_ASSIGNMENT: authenticated can UPDATE a privilege or billing column (whatever its name) on rows it may update.
- A table with policies but RLS disabled is POLICIES_BUT_NO_RLS only, not also RLS_DISABLED.
- One finding per (pattern_id, object). object = schema.name lowercase (policies -> their table; functions without args),
  storage.<bucket> for buckets, or the file path from the repo scan. Column-level issues use the table.
- evidence: a short quote of the row/policy/column that proves it."""


AGENT_SUFFIX = """
You also get `candidates` from naive deterministic rules. Many are false positives: keep one only if the rules above
say it is exploitable, and look for issues the rules miss (e.g. privilege columns with unusual names).
Use tools when the dump is not enough: get_schema to inspect grants or function bodies, run_audit_query to re-run a query,
probe_as_anon to check whether anon can actually read a table or view. Use at most 8 tool calls, then answer."""


CLIENT_SUFFIX = """
You are running inside the user's MCP client. Gather the data yourself: call run_audit_query for Q1..Q20,
get_schema("public"), and scan_repo if a repo is configured. Then list findings (pattern_id, object, evidence)
grouped by severity, and add the manual checks (auth settings in the dashboard) you could not verify.
Everything is read-only: never suggest running fixes without the user's approval."""


def client_prompt() -> str:
    return analyst_prompt() + CLIENT_SUFFIX
