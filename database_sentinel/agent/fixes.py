"""Fix SQL for approved findings. Output only: Sentinel never executes it (the audit role is read-only anyway)."""
import re

from .catalog import patterns

_OBJ = re.compile(r"^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_$-]*$")  # schema.name, validated before it goes into SQL

_SQL = {
    "RLS_DISABLED": "ALTER TABLE {o} ENABLE ROW LEVEL SECURITY;\n-- Then add policies: fix-templates.md §2.",
    "POLICIES_BUT_NO_RLS": "ALTER TABLE {o} ENABLE ROW LEVEL SECURITY;",
    "VIEW_NO_SECURITY_INVOKER": "ALTER VIEW {o} SET (security_invoker = on);",
    "SECURITY_DEFINER_EXPOSED": "REVOKE EXECUTE ON FUNCTION {o} FROM public, anon, authenticated;",
    "EXPOSED_RPC_NO_AUTH": "REVOKE EXECUTE ON FUNCTION {o} FROM public, anon;",
    "MUTABLE_SEARCH_PATH": "ALTER FUNCTION {o} SET search_path = '';",
    "MATVIEW_EXPOSED": "REVOKE SELECT ON {o} FROM anon, authenticated;",
    "PUBLIC_BUCKET": "UPDATE storage.buckets SET public = false WHERE id = '{name}';",
    "MASS_ASSIGNMENT": "REVOKE UPDATE ON {o} FROM authenticated;\nGRANT UPDATE (<columns users may edit>) ON {o} TO authenticated;",
    "SENSITIVE_COLUMNS": "REVOKE SELECT ON {o} FROM anon, authenticated;\nGRANT SELECT (<non-secret columns>) ON {o} TO authenticated;",
}


def fix_for(f: dict) -> str:
    """SQL (or guidance) for one finding. Unknown shapes fall back to the catalog's fix text."""
    pid, obj = f["pattern_id"], f["object"].lower()
    head = f"-- {pid} on {f['object']}"
    tmpl = _SQL.get(pid)
    if tmpl and _OBJ.match(obj):
        return f"{head}\n{tmpl.format(o=obj, name=obj.split('.', 1)[1])}"
    guide = patterns().get(pid, {}).get("fix", "See fix-templates.md.")
    return head + "\n" + "\n".join(f"-- {line}" for line in guide.splitlines())
