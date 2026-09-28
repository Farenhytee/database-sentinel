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
