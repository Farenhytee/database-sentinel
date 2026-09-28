from collections import Counter

from agent.catalog import severity


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


def summarize(per_case: dict[str, dict], clean: set[str]) -> dict:
    """per_case: case_id -> match() result. Micro P/R/F1, recall by severity, FPs on clean controls."""
    tp = sum(len(m["tp"]) for m in per_case.values())
    fp = sum(len(m["fp"]) for m in per_case.values())
    fn = sum(len(m["fn"]) for m in per_case.values())
    p, r, f1 = prf(tp, fp, fn)
    hit, tot = Counter(), Counter()
    for m in per_case.values():
        for pid, _ in m["tp"]:
            hit[severity(pid)] += 1
            tot[severity(pid)] += 1
        for pid, _ in m["fn"]:
            tot[severity(pid)] += 1
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3),
            "recall_by_severity": {s: round(hit[s] / tot[s], 3) for s in tot},
            "clean_fp": sum(len(per_case[c]["fp"]) for c in clean if c in per_case)}
