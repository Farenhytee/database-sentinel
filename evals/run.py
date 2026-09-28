"""python -m evals.run --split dev [--systems r0,b0,a] [--cases 001,002]"""
import argparse
import json
import subprocess
import time
from datetime import datetime, timezone

from dotenv import load_dotenv

from . import bench
from .matcher import match
from .metrics import summarize
from .systems import SYSTEMS, introspect

RUNS = bench.ROOT / "results" / "runs.jsonl"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="dev")
    ap.add_argument("--systems", default="r0,b0,a")
    ap.add_argument("--cases", default="")
    a = ap.parse_args()
    load_dotenv(bench.ROOT / ".env")
    systems = a.systems.split(",")
    cases = a.cases.split(",") if a.cases else bench.split(a.split)
    env = bench.local_env()
    per = {s: {} for s in systems}
    lat = {s: [] for s in systems}
    clean = set()
    for cid in cases:
        gold = bench.labels(cid)
        if not gold:
            clean.add(cid)
        bench.prepare(cid, env)
        t = bench.target(cid, env)
        intro = introspect(t)
        for s in systems:
            t0 = time.time()
            try:
                pred = SYSTEMS[s](t, intro)
            except Exception as e:  # one failed case must not kill the run
                print(f"  {cid} {s}: ERROR {e!r}")
                pred = []
            lat[s].append(round(time.time() - t0, 2))
            per[s][cid] = match(pred, gold)
            m = per[s][cid]
            print(f"  {cid} {s:3} tp={len(m['tp'])} fp={len(m['fp'])} fn={len(m['fn'])}"
                  + (f"  FP={m['fp']}" if m["fp"] else "") + (f"  FN={m['fn']}" if m["fn"] else ""))
    _report(a.split, systems, per, lat, clean)


def _report(split, systems, per, lat, clean):
    from agent.llm import model_id
    sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"\n{'system':8}{'P':>7}{'R':>7}{'F1':>7}{'TP':>5}{'FP':>5}{'FN':>5}{'cleanFP':>9}")
    RUNS.parent.mkdir(exist_ok=True)
    with RUNS.open("a") as fh:
        for s in systems:
            m = summarize(per[s], clean)
            print(f"{s:8}{m['precision']:7.3f}{m['recall']:7.3f}{m['f1']:7.3f}{m['tp']:5}{m['fp']:5}{m['fn']:5}{m['clean_fp']:9}")
            fh.write(json.dumps({"ts": ts, "sha": sha, "split": split, "system": s,
                                 "model": None if s == "r0" else model_id(), **m,
                                 "latency_s": lat[s], "per_case": per[s]}) + "\n")


if __name__ == "__main__":
    main()
