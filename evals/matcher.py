"""Set-match findings to labels on (pattern_id, normalized object)."""
from database_sentinel.agent.catalog import in_scope
from database_sentinel.agent.models import norm_object


norm = norm_object


def keys(findings: list[dict]) -> set[tuple[str, str]]:
    scope = set(in_scope())
    return {(f["pattern_id"], norm(f["object"])) for f in findings if f["pattern_id"] in scope}


def match(pred: list[dict], labels: list[dict]) -> dict:
    p, g = keys(pred), keys(labels)
    v = keys([f for f in pred if f.get("verified")])  # confirmed by the anon probe
    return {"tp": sorted(p & g), "fp": sorted(p - g), "fn": sorted(g - p), "verified": sorted(v)}
