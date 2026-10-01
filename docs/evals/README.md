# Evals

How Database Sentinel's accuracy is measured, and every recorded run.

## Setup
- **Bench:** 27 labeled Supabase cases in `bench/cases/`, each applied to a fresh local Supabase. Labeling rules: [bench/README.md](../../bench/README.md).
- **Splits:** dev = 001–015 + 026–027 (14 vulnerable, 3 clean), used for tuning. Test = 016–025 (8 vulnerable, 2 clean), written blind by a separate agent and frozen by `bench/test.lock`. Test runs print aggregates only.
- **Systems:** R0 = deterministic rules (no LLM). B0 = one structured-output prompt over the full introspection dump. S = standard audit (B0 + anon-probe verify, the default). M = a model as MCP client driving the real `sentinel-mcp` over stdio. A = deep audit (rule candidates → tool-using agent → verify).
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
| 2026-09-30 | dev | deepseek-v4-flash | Standard mode `s` (B0 + verify), 1 run: F1 1.000, 0 FP, 8 verified (precision 1.0), $0.0007/audit, p50 15s |
| 2026-09-30 | dev (16) | deepseek-v4-flash | After grant-aware Q1 + case 026: R0 0.737, **standard 0.933** ($0.0007), deep 0.931 ($0.0078). 026 traps avoided by both; both miss the second label (EXPOSED_RPC_NO_AUTH) on the definer RPC |
| 2026-09-30 | test | deepseek-v4-flash | [MCP flow (M), 3 runs: F1 0.865, P 0.905, crit recall 1.0](2026-09-30-test-mcp.md) |
| 2026-10-01 | test | deepseek-v4-flash | WITH CHECK rule (no WITH CHECK ≠ ownership reassignment) + neutral Q8 label + dev case 027, standard ×3: F1 0.776 / 0.889 / 0.844 (mean 0.836). Same-day old prompt: 0.844 / 0.818 / 0.851 (0.838). A wider variant (quotas count as billing) scored 0.805 and was dropped. Dev (17): 0.918; 027 has no false positives but misses the quota table |
| 2026-10-01 | test | deepseek-v4-pro | Standard ×3 (on the wider variant): F1 0.706 / 0.655 / 0.644 (mean 0.668), 11–18 FP per run, ~$0.0034/audit. Flash stays the default |
