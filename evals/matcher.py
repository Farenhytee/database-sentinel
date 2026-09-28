"""Set-match findings to labels on (pattern_id, normalized object)."""
from agent.catalog import in_scope


def norm(obj: str) -> str:
    o = obj.strip().strip('"').lower().split("(")[0]
    if "/" in o or o.endswith((".ts", ".js", ".tsx", ".jsx", ".env")) or o.startswith(".env"):
        return o.removeprefix("./")  # repo file path
    return o if "." in o else f"public.{o}"


def keys(findings: list[dict]) -> set[tuple[str, str]]:
    scope = set(in_scope())
    return {(f["pattern_id"], norm(f["object"])) for f in findings if f["pattern_id"] in scope}


def match(pred: list[dict], labels: list[dict]) -> dict:
    p, g = keys(pred), keys(labels)
    return {"tp": sorted(p & g), "fp": sorted(p - g), "fn": sorted(g - p)}
