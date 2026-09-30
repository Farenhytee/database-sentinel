"""Read-only audit tools. Never return row data or secret values."""
import base64
import json
import os
import re

import httpx

from .db import query
from .queries import audit_queries
from .target import Target

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


def run_audit_query(t: Target, query_id: str) -> list[dict]:
    """Run one allowlisted audit query (Q1..Q20) and return its rows."""
    qs = audit_queries()
    if query_id not in qs:
        raise ValueError(f"unknown query_id {query_id!r}; allowed: {', '.join(qs)}")
    return query(t.dsn, qs[query_id])


_TABLES = """
SELECT c.relname AS name, c.relkind AS kind, c.relrowsecurity AS rls,
  has_table_privilege('anon', c.oid, 'SELECT') AS anon_select,
  has_table_privilege('anon', c.oid, 'INSERT,UPDATE,DELETE') AS anon_write,
  has_table_privilege('authenticated', c.oid, 'UPDATE') AS auth_update,
  (SELECT json_agg(json_build_object('name', a.attname, 'type', format_type(a.atttypid, a.atttypmod),
     'auth_update', has_column_privilege('authenticated', c.oid, a.attname, 'UPDATE')) ORDER BY a.attnum)
   FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped) AS columns,
  CASE WHEN c.relkind = 'v' THEN pg_get_viewdef(c.oid) END AS view_def
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = %s AND c.relkind IN ('r','v','m','p')
ORDER BY c.relname
"""
_FUNCS = """
SELECT p.proname AS name, pg_get_function_identity_arguments(p.oid) AS args,
  pg_get_function_result(p.oid) AS returns, p.prosecdef AS security_definer, p.proconfig AS config,
  has_function_privilege('anon', p.oid, 'EXECUTE') AS anon_execute,
  has_function_privilege('authenticated', p.oid, 'EXECUTE') AS auth_execute,
  left(p.prosrc, 2000) AS body
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = %s AND p.prokind = 'f'
ORDER BY p.proname
"""


def get_schema(t: Target, schema: str = "public") -> dict:
    """Tables/views (RLS, anon/authenticated grants, columns, view SQL) and functions in a schema."""
    if not _IDENT.match(schema):
        raise ValueError("bad schema name")
    return {"schema": schema, "relations": query(t.dsn, _TABLES, (schema,)),
            "functions": query(t.dsn, _FUNCS, (schema,))}


def probe_as_anon(t: Target, table: str, op: str = "select") -> dict:
    """HEAD request to PostgREST with the anon key: can anon read this table, and how many rows?
    Only 'select' in v1; no rows are downloaded."""
    if op != "select":
        raise ValueError("only op='select' is allowed in v1")
    if not _IDENT.match(table):
        raise ValueError("bad table name")
    if not (t.rest_url and t.anon_key):
        raise ValueError("target has no rest_url/anon_key")
    r = httpx.head(f"{t.rest_url}/rest/v1/{table}", params={"select": "*", "limit": "1"},
                   headers={"apikey": t.anon_key, "Authorization": f"Bearer {t.anon_key}",
                            "Prefer": "count=exact"}, timeout=10)
    total = r.headers.get("content-range", "").rpartition("/")[2]
    return {"table": table, "status": r.status_code,
            "anon_rows_visible": int(total) if total.isdigit() else None}


_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_PUBLIC_SRK = re.compile(r"\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_)\w*SERVICE_ROLE\w*")
_SB_SECRET = re.compile(r"\bsb_secret_[A-Za-z0-9_-]{16,}")
_JWT_SECRET = re.compile(r"\b\w*JWT_SECRET\w*\s*[:=]\s*['\"]?[^\s'\"]{16,}")
_SKIP_DIRS = {".git", "node_modules", "dist", "build", ".next", ".venv"}
_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".json", ".env"}


def _jwt_role(tok: str) -> str | None:
    try:
        seg = tok.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))).get("role")
    except Exception:
        return None


def _scan_line(line: str) -> list[tuple[str, str]]:
    hits = [("SERVICE_ROLE_EXPOSED", "service_role JWT") for m in _JWT.finditer(line)
            if _jwt_role(m.group()) == "service_role"]
    if _PUBLIC_SRK.search(line):
        hits.append(("SERVICE_ROLE_EXPOSED", "public env var named SERVICE_ROLE"))
    if _SB_SECRET.search(line):
        hits.append(("SERVICE_ROLE_EXPOSED", "sb_secret_ key"))
    if _JWT_SECRET.search(line):
        hits.append(("JWT_SECRET_EXPOSED", "JWT secret assignment"))
    return hits


def scan_repo(t: Target) -> list[dict]:
    """Scan frontend code for service-role keys and JWT secrets. Returns locations, never values."""
    if not t.repo_path:
        return []
    out = []
    for root, dirs, files in os.walk(t.repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for f in files:
            if os.path.splitext(f)[1] not in _EXTS and not f.startswith(".env"):
                continue
            p = os.path.join(root, f)
            try:
                lines = open(p, encoding="utf-8", errors="ignore").read().splitlines()
            except OSError:
                continue
            rel = os.path.relpath(p, t.repo_path)
            for i, line in enumerate(lines, 1):
                out += [{"pattern_id": pid, "kind": kind, "file": rel, "line": i}
                        for pid, kind in _scan_line(line)]
    return out
