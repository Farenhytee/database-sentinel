"""python -m evals.report [--split test] [--runs 3]: Markdown results table from results/runs.jsonl."""
import argparse
import json
from collections import defaultdict
from statistics import mean, median, pstdev

from .run import RUNS


def _pm(xs: list[float]) -> str:
    return f"{mean(xs):.3f} ± {pstdev(xs):.3f}" if len(xs) > 1 else f"{xs[0]:.3f}"


def _p95(xs: list[float]) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, round(0.95 * (len(xs) - 1)))]


def table(split: str = "test", runs: int = 3) -> str:
    groups = defaultdict(list)
    for line in RUNS.read_text().splitlines():
        r = json.loads(line)
        if r["split"] == split:
            groups[(r["system"], r["model"] or "—")].append(r)
    rows = ["| System | Model | Runs | Precision | Recall | F1 | CRITICAL recall | Clean FP | Verified precision | $/audit | p50 / p95 s |",
            "|---|---|---|---|---|---|---|---|---|---|---|"]
    for (system, model), rs in sorted(groups.items()):
        rs = rs[-runs:]
        lat = [x for r in rs for x in r["latency_s"]]
        cost = [u.get("cost_usd", 0) for r in rs for u in r.get("usage", []) if u]
        crit = [r["recall_by_severity"]["CRITICAL"] for r in rs if "CRITICAL" in r["recall_by_severity"]]
        ver = [r["verified_precision"] for r in rs if r.get("verified_precision") is not None]
        rows.append(f"| {system.upper()} | {model} | {len(rs)} | {_pm([r['precision'] for r in rs])} | "
                    f"{_pm([r['recall'] for r in rs])} | **{_pm([r['f1'] for r in rs])}** | "
                    f"{_pm(crit) if crit else '—'} | {mean(r['clean_fp'] for r in rs):.1f} | "
                    f"{_pm(ver) if ver else '—'} | {f'${mean(cost):.4f}' if cost else '$0'} | "
                    f"{median(lat):.1f} / {_p95(lat):.1f} |")
    return "\n".join(rows)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="test")
    ap.add_argument("--runs", type=int, default=3)
    a = ap.parse_args()
    print(table(a.split, a.runs))
