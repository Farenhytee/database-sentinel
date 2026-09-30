# Evals

How Database Sentinel's accuracy is measured, and every recorded run.

## Setup
- **Bench:** 25 labeled Supabase cases in `bench/cases/`, each applied to a fresh local Supabase. Labeling rules: [bench/README.md](../../bench/README.md).
- **Splits:** dev = 001–015 (12 vulnerable, 3 clean), used for tuning. Test = 016–025 (8 vulnerable, 2 clean), written blind by a separate agent and frozen by `bench/test.lock`. Test runs print aggregates only.
- **Systems:** R0 = deterministic rules (no LLM). B0 = one structured-output prompt over the full introspection dump. A = the agent (rule candidates → tool-using analysis → anon-probe verify).
- **Match:** a finding is correct if `pattern_id` and object (`schema.table`, `storage.<bucket>` or file path) both match a label.

## Run
```bash
pip install -e ".[dev]"
supabase start -x realtime,imgproxy,mailpit,postgres-meta,studio,edge-runtime,logflare,vector,supavisor
python -m evals.run --split dev --systems r0,b0,a     # model from SENTINEL_MODEL in .env
python -m evals.report --split test --runs 3          # results table
```
Each run appends to `results/runs.jsonl`. There's a 5-minute limit per system per case.

## Runs
| Date | Split | Model | Notes |
|---|---|---|---|
| 2026-09-29 | dev | deepseek-v4-flash | [Run 1: first LLM run](2026-09-29-dev-run1.md) |
| 2026-09-29 | dev | deepseek-v4-flash | [Run 2: after dev tuning](2026-09-29-dev-run2.md) |
| 2026-09-29 | test | deepseek-v4-flash | [Frozen v0.2.0, 3 runs: A F1 0.782, B0 0.766, R0 0.559](2026-09-29-test.md) |
| 2026-09-29 | dev | deepseek-v4-flash | [v0.2.1 fixes, 2 runs: A F1 0.963 / 0.945](2026-09-29-dev-v0.2.1.md) |
| 2026-09-30 | test | deepseek-v4-flash | [v0.2.1, 3 runs: A F1 0.831, B0 0.849 (fixes came from test failures)](2026-09-30-test-v0.2.1.md) |
| _pending_ | test | deepseek-v4-pro | 3 runs |
