"""Pattern catalog parsed from backends/supabase/anti-patterns.md (single source of truth)."""
import re
from functools import cache

from database_sentinel.mcp_server.paths import SUPABASE

_HEAD = re.compile(r"^(?:\S+\s+)?(CRITICAL|HIGH|MEDIUM|LOW|INFO): (.+)$")
_ID = re.compile(r"\*\*ID:\*\* `(\w+)`")
_DET = re.compile(r"\*\*Detection:\*\* (.+)")

# Need the Management API or live auth probes: reported as manual checks, never scored by evals.
MANUAL = {"GHOST_AUTH", "OAUTH_REDIRECT_WILDCARD", "WEAK_PASSWORD_CONFIG", "ANON_AUTH_ABUSE",
          "NO_RATE_LIMITING", "OPENAPI_EXPOSED", "SQL_EDITOR_TRAP"}
# SQL-visible but not a security finding on its own (perf; Postgres reuses USING as WITH CHECK).
NOT_EVALUATED = {"RLS_PERFORMANCE", "UPDATE_NO_WITHCHECK"}


@cache
def patterns() -> dict[str, dict]:
    out = {}
    for sec in (SUPABASE / "anti-patterns.md").read_text().split("\n## ")[1:]:
        head, pid = _HEAD.match(sec.splitlines()[0]), _ID.search(sec)
        if head and pid:
            det = _DET.search(sec)
            out[pid.group(1)] = {"severity": head.group(1), "title": head.group(2).strip(),
                                 "detection": det.group(1).strip() if det else ""}
    return out


def in_scope() -> list[str]:
    return [p for p in patterns() if p not in MANUAL | NOT_EVALUATED]


def severity(pattern_id: str) -> str:
    return patterns()[pattern_id]["severity"]
