from typing import Literal

from pydantic import BaseModel, Field

from .catalog import in_scope

PatternId = Literal[tuple(in_scope())]  # type: ignore[valid-type]


class Finding(BaseModel):
    pattern_id: PatternId
    object: str = Field(description="schema.name (table/view/function, no args), storage.<bucket>, or repo file path")
    evidence: str = Field(description="Short quote of the policy/column/function/query row that proves it")
    confidence: float = Field(ge=0, le=1)


class Findings(BaseModel):
    findings: list[Finding]


def norm_object(obj: str) -> str:
    """schema.name lowercase; repo paths unchanged; columns and function args dropped (labels are per table/function)."""
    o = obj.strip().strip('"').lower().split("(")[0]
    if "/" in o or o.startswith(".env") or o.endswith((".ts", ".js", ".tsx", ".jsx", ".env")):
        return o.removeprefix("./")
    parts = o.split(".")
    return ".".join(parts[:2]) if len(parts) > 1 else f"public.{o}"


def clean(findings: list[dict]) -> list[dict]:
    """Normalize objects, dedupe, and apply the catalog rule: POLICIES_BUT_NO_RLS replaces RLS_DISABLED on a table."""
    out, seen = [], set()
    for f in findings:
        f = {**f, "object": norm_object(f["object"])}
        if (f["pattern_id"], f["object"]) not in seen:
            seen.add((f["pattern_id"], f["object"]))
            out.append(f)
    both = {f["object"] for f in out if f["pattern_id"] == "POLICIES_BUT_NO_RLS"}
    return [f for f in out if not (f["pattern_id"] == "RLS_DISABLED" and f["object"] in both)]
