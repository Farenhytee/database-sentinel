# Sentinel — Scoring

Scoring runs per-backend, then aggregates into a final headline figure.

---

## Per-backend weight tables

Each backend starts at 100 and deducts per finding. Weights vary because attack surface differs — Firebase rules misconfigurations usually expose *all* documents (binary outcome), while Supabase RLS gaps may only partially open a single table.

| Severity | Supabase | Firebase | MongoDB | Postgres self-hosted | MySQL self-hosted |
|----------|----------|----------|---------|----------------------|--------------------|
| CRITICAL | -25 | -30 | -30 | -25 | -25 |
| HIGH | -10 | -12 | -12 | -10 | -10 |
| MEDIUM | -5 | -5 | -5 | -5 | -5 |
| LOW | -2 | -2 | -2 | -2 | -2 |
| INFO | 0 | 0 | 0 | 0 | 0 |

**Rules:**
- Floor at 0. Negative scores aren't useful; "0/100 🔴" communicates the message.
- Cap deductions at 30 per finding to prevent one issue from dominating a multi-finding report.
- INFO-severity findings are listed but don't deduct.

**Why Firebase weights are higher:** A single `allow read, write: if true;` exposes the entire database with no further qualification. CVE-2025-48757-class issues on Firebase have averaged worse blast radius than equivalent Supabase RLS misconfigurations.

**Why MongoDB weights are higher:** MongoBleed-class issues (CVE-2025-14847) are pre-auth and provide RCE-adjacent leverage. Combined with `--bind_ip_all` defaults, a single CRITICAL on MongoDB frequently means full data exposure plus exploitation potential.

---

## Headline score: minimum, not average

```
headline_score = min(per_backend_scores)
```

A 95-point Postgres score does **not** redeem a 30-point Firebase score. The user is as exposed as their weakest backend.

Cross-backend findings (see §Cross-backend scoring below) deduct from the **lowest-scoring** affected backend, so they amplify the minimum rather than averaging it down.

---

## Score → emoji band

| Range | Emoji | Headline |
|-------|-------|----------|
| 80–100 | ✅ | "Generally well-configured." |
| 60–79 | ⚠️ | "Several issues — fix before exposing more users." |
| 40–59 | 🟠 | "Significant exposure — prioritize fixes this week." |
| 0–39 | 🔴 | "Critical exposure — likely already enumerable. Fix today." |

These bands are calibrated to the deduction tables above. With CRITICAL = -25/-30, even one CRITICAL finding lands in the 🟠/🔴 zone, which is intended.

---

## Cross-backend scoring

When multiple backends are detected and a cross-backend interaction is flagged (see `core/reporting.md`):

1. **Severity is set by the worse outcome.** If a Firebase Auth → Postgres `user_id` chain enables impersonation, severity = CRITICAL on both.
2. **Deduction lands on the lowest-scoring backend** — so a cross-backend critical pulls the headline score down further, never softens it.
3. **The finding is listed in the cross-backend section of the report**, not duplicated under each per-backend section.

---

## What scoring does NOT measure

- **Likelihood.** Severity is calibrated to *blast radius if exploited*, not "how likely is this to be exploited." Public anon-readable user table is CRITICAL whether or not anyone has actually scraped it yet.
- **Compliance.** Sentinel's score is operational, not regulatory. Compliance frameworks (SOC2, HIPAA, PCI) require their own audit and may flag patterns Sentinel scores as MEDIUM as actually CRITICAL for that regime.
- **Code quality.** Sentinel doesn't score test coverage, CI hygiene, or general code health — only configuration security relevant to the detected backends.

---

## Calibration discipline

When adding a new pattern to `backends/<name>/anti-patterns.md`:

1. **Severity must be justifiable from blast radius alone**, with reference to a CVE / breach / Splinter control. Don't invent severities.
2. **Recheck the weights table once per major release.** If the catalog has grown and CRITICAL findings have become routine, the weights are too stiff and need rebalancing.
3. **Avoid severity inflation.** If everything is CRITICAL, nothing is. The empirical 2025–2026 data lets us calibrate: MongoBleed = CRITICAL, missing email confirmation = MEDIUM, OpenAPI schema exposure = LOW.
