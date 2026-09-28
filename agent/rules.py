"""R0: deterministic baseline. Maps introspection rows straight to findings, no LLM, no judgment."""
from .catalog import in_scope

_PRIV_COLS = {"role", "is_admin", "admin", "balance", "credits", "plan", "permissions", "is_verified", "tier"}


def _t(name: str, schema: str = "public") -> str:
    return f"{schema}.{name}".lower()


def r0(intro: dict) -> list[dict]:
    q, out = intro["queries"], []

    def add(pid: str, obj: str, ev: str):
        out.append({"pattern_id": pid, "object": obj, "evidence": ev, "confidence": 1.0})

    no_rls_with_policies = {r["tablename"] for r in q["Q3"]}
    for r in q["Q1"]:
        if not r["rls_enabled"] and r["tablename"] not in no_rls_with_policies:
            add("RLS_DISABLED", _t(r["tablename"]), "Q1 rls_enabled=false")
    for r in q["Q3"]:
        add("POLICIES_BUT_NO_RLS", _t(r["tablename"]), "Q3")
    for r in q["Q2"]:
        add("RLS_NO_POLICIES", _t(r["tablename"]), "Q2")
    for qid, pid in [("Q6", "USING_TRUE"), ("Q7", "USER_METADATA_IN_POLICY"), ("Q8", "UPDATE_NO_WITHCHECK"),
                     ("Q9", "POLICY_NO_ROLE_SCOPE"), ("Q10", "MULTIPLE_PERMISSIVE")]:
        for r in q[qid]:
            add(pid, _t(r["tablename"]), f"{qid} {r.get('policyname') or r.get('policies')}")
    for qid, pid in [("Q12", "SECURITY_DEFINER_EXPOSED"), ("Q13", "MUTABLE_SEARCH_PATH")]:
        for r in q[qid]:
            add(pid, _t(r["function_name"], r["schema"]), qid)
    for r in q["Q14"]:
        if not r["status"].startswith("✅"):
            add("VIEW_NO_SECURITY_INVOKER", _t(r["view_name"], r["schema"]), "Q14")
    for r in q["Q15"]:
        add("MATVIEW_EXPOSED", _t(r["matview_name"], r["schema"]), "Q15")
    for r in q["Q16"]:
        add("EXPOSED_RPC_NO_AUTH", _t(r["routine_name"], r["routine_schema"]), "Q16 anon EXECUTE")
    for r in q["Q17"]:
        if r["public"]:
            add("PUBLIC_BUCKET", f"storage.{r['name']}".lower(), "Q17 public=true")
    for r in q["Q19"]:
        add("SENSITIVE_COLUMNS", _t(r["table_name"], r["table_schema"]), f"Q19 {r['column_name']}")
    updatable = {r["tablename"] for r in q["Q5"] if r["cmd"] in ("UPDATE", "ALL")}
    for rel in intro["schema"]["relations"]:
        if rel["name"] in updatable:
            cols = [c["name"] for c in rel["columns"] or [] if c["auth_update"] and c["name"].lower() in _PRIV_COLS]
            if cols:
                add("MASS_ASSIGNMENT", _t(rel["name"]), f"authenticated can UPDATE {cols}")
    for h in intro["scan"]:
        add(h["pattern_id"], h["file"], f"{h['kind']} at line {h['line']}")

    keep = set(in_scope())
    seen, dedup = set(), []
    for f in out:
        k = (f["pattern_id"], f["object"])
        if f["pattern_id"] in keep and k not in seen:
            seen.add(k)
            dedup.append(f)
    return dedup
