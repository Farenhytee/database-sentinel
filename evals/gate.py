"""CI gate (free, no LLM): R0 on the dev split must not drop > 0.05 F1 below results/baseline.json."""
import json

from .bench import ROOT
from .run import evaluate

MAX_DROP = 0.05

base = json.loads((ROOT / "results" / "baseline.json").read_text())["r0"]["f1"]
f1 = evaluate("dev", ["r0"])["r0"]["f1"]
print(f"\nR0 dev F1 {f1:.3f} vs baseline {base:.3f}")
if f1 < base - MAX_DROP:
    raise SystemExit(f"FAIL: F1 dropped {base - f1:.3f} (> {MAX_DROP})")
