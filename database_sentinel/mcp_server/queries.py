import re
from functools import cache

from .paths import SUPABASE

_Q = re.compile(r"^### (Q\d+):.*?```sql\n(.*?)```", re.S | re.M)
# Defense in depth: the allowlist may only ever contain plain SELECTs.
_WRITE = re.compile(r"\b(insert|update|delete|drop|truncate|alter|create|grant|revoke|comment|copy|call|do|vacuum|reindex|cluster|lock|set|reset)\b\s", re.I)


def is_read_only(sql: str) -> bool:
    body = re.sub(r"'[^']*'", "''", sql)  # ignore string literals
    return body.lstrip().lower().startswith("select") and ";" not in body.rstrip().rstrip(";") and not _WRITE.search(body)


@cache
def audit_queries() -> dict[str, str]:
    """Q1..Q20 from audit-queries.md: the allowlist. Only these ever run; any non-SELECT aborts loading."""
    qs = dict(_Q.findall((SUPABASE / "audit-queries.md").read_text()))
    bad = [q for q, sql in qs.items() if not is_read_only(sql)]
    if bad:
        raise RuntimeError(f"audit queries must be read-only SELECTs: {bad}")
    return qs
