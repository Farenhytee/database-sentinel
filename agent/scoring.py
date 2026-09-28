"""Deterministic score, ported from core/scoring.md (Supabase column). The LLM never scores."""
import re
from functools import cache

from mcp_server.paths import CATALOG

from .catalog import severity

CAP, FLOOR = 30, 0
BANDS = [(80, "✅", "Generally well-configured."),
         (60, "⚠️", "Several issues — fix before exposing more users."),
         (40, "🟠", "Significant exposure — prioritize fixes this week."),
         (0, "🔴", "Critical exposure — likely already enumerable. Fix today.")]


@cache
def weights() -> dict[str, int]:
    rows = re.findall(r"^\| (CRITICAL|HIGH|MEDIUM|LOW|INFO) \| (-?\d+) \|", (CATALOG / "core" / "scoring.md").read_text(), re.M)
    return {sev: abs(int(w)) for sev, w in rows}


def score(pattern_ids: list[str]) -> dict:
    s = max(FLOOR, 100 - sum(min(CAP, weights()[severity(p)]) for p in pattern_ids))
    emoji, headline = next((e, h) for lo, e, h in BANDS if s >= lo)
    return {"score": s, "emoji": emoji, "headline": headline}
