# Sentinel — Universal 7-Step Audit Workflow

This file defines the **abstract** workflow every backend extension specializes. Each `backends/<name>/workflow.md` fills in the *what* of each step (introspection commands, probing strategy, fix templates) without changing the *order*.

The dispatcher in root `SKILL.md` runs these steps once per detected backend, then aggregates findings into a single report.

---

## Invariants — true for every backend

1. **Step order is fixed.** Don't reorder. Don't skip Step 0 (credentials) or Step 4 (report) — these are how users experience the audit.
2. **Read-only by default.** Active/write probes always require explicit user opt-in. See `core/credentials.md` for the safe-handling contract and §3 below for the per-backend probing rules.
3. **Every finding gets a fix.** No bare problem reports. If a backend's anti-pattern catalog can't ship a fix, mark it `INFO` and explain why.
4. **Plain-English explanations.** "Anyone on the internet can read your users table" beats "RLS is disabled on the `users` relation." Tailor depth to the user's apparent skill level.
5. **Cite sources.** Every finding's severity should trace back to either a CVE, a documented breach, or a CIS/Splinter control. Per-backend `anti-patterns.md` files carry the citations.

---

## Step 0 — Detect, gather credentials, scan codebase

**Detection** runs first per `core/detection.md` and emits a JSON manifest of which backends are in scope. The dispatcher selects the matching `backends/<name>/workflow.md` files for the rest of the run.

**Per-backend credential gathering** is delegated to each backend's Step 0:
- Auto-discover from common locations (`.env*`, `*.toml`, `*.conf`, IaC files) before asking the user.
- Distinguish *public-key-in-client* (expected, treat as informational) from *privileged-key-in-client* (always CRITICAL). The mapping for each backend is in `core/credentials.md`.
- Never store credentials. Never log them. Use them in-memory for the audit and discard.

**Codebase scan** runs once across the whole repo regardless of backend count — it surfaces leaked secrets that any backend extension cares about (admin SDK JSON, `*_SERVICE_ROLE`, hardcoded JWTs, `.env` files in git, IaC with `0.0.0.0/0`).

---

## Step 1 — Schema / configuration introspection

Each backend defines its own introspection bundle. The contract:

- **Read-only.** Never write, never alter state.
- **One copy-pasteable block** the user can run in their preferred tool (SQL Editor, mongosh, firebase CLI, psql) and paste back. This is the most reliable execution path across environments.
- **Alternate execution paths** documented per backend: MCP server (Supabase, Postgres), Atlas Admin API (MongoDB), Firebase Management API + `firebase` CLI (Firebase), `psql` / `mysql` CLI (self-hosted).
- **Fall back gracefully** if the introspection privilege is missing — proceed to Step 3 (dynamic probing) with reduced confidence.

---

## Step 2 — Static analysis (anti-pattern matching)

Cross-reference Step 1 results against `backends/<name>/anti-patterns.md`. Each catalog ships ~15–25 patterns with stable IDs (`SB-*` Supabase, `FB-*` Firebase, `MG-*` MongoDB, `PG-*` Postgres, `MY-*` MySQL).

**Be exhaustive.** Check every table / collection / rule / role — don't sample.

**Calibrate severity.** A `USING(true)` policy on a public blog post is not the same as `USING(true)` on `payments`. Backend catalogs note when severity depends on context.

---

## Step 3 — Dynamic probing (safe by default, write probes opt-in)

The probing primitive differs per backend — there is **no universal safe-write equivalent of Supabase's `Prefer: tx=rollback`**. Each backend's workflow defines its strategy, but all must conform to:

| Backend | Read probe | Write probe | Notes |
|---------|------------|-------------|-------|
| Supabase | curl with anon key | `Prefer: tx=rollback` (PostgREST native) | Cleanest probe surface of any backend. |
| Postgres self-hosted | read introspection only | `BEGIN…ROLLBACK` (opt-in) | Native transactional DDL covers most ops; `CREATE DATABASE`/`TABLESPACE` are not transactional. |
| MySQL self-hosted | read introspection only | `_sentinel_probe` schema, then `DROP DATABASE` (opt-in, destructive) | DDL implicitly commits; no native rollback. Frame strongly. |
| MongoDB | unauthenticated `hello`/`ismaster`; `find` w/ `limit:1` | session + `abortTransaction` (4.0+ replica set / 4.2+ sharded); insert+delete on standalone (opt-in) | MongoBleed probe is a separate, opt-in network-level test. |
| Firebase | per-document `GET` w/ `pageSize=1`; multi-region domain enumeration | canary collection (`/_sentinel_probe/{random}`), one write, then delete (opt-in) | Rules-AST static probe replaces some dynamic write probes. |

**Universal rules:**
- Never probe writes without explicit user confirmation.
- Tag any residue (failed cleanup) in the report.
- For probes that require crafted protocol traffic (e.g., MongoBleed): gate on user opt-in *and* a separate `--allow-network-probes` style confirmation, since some monitoring systems will flag these as attacks.

---

## Step 4 — Generate the security report

Use the unified format defined in `core/reporting.md`. Each backend produces its own section; the dispatcher aggregates and adds a final cross-backend interactions section if multiple backends are present.

**Scoring** per `core/scoring.md`. Final headline score is the **minimum** of per-backend scores — a 95-point Postgres score does not redeem a 30-point Firebase score.

---

## Step 5 — Generate fixes

Each backend's `fix-templates.md` defines its template library. Fix output formats differ:

- **SQL backends** (Supabase, Postgres, MySQL): DDL/DCL + config-file diffs (`pg_hba.conf`, `postgresql.conf`, `my.cnf`).
- **MongoDB**: JS shell commands + `mongod.conf` YAML diffs.
- **Firebase**: rule files (`firestore.rules`, `database.rules.json`, `storage.rules`) + Cloud Function source + Remote Config JSON.

Each fix template is a **multi-format object** with: `language`, `before`, `after`, `applyMethod`, `rollbackMethod`, `validation`. Renderer chooses presentation based on the user's environment (PR-friendly diff vs. console paste).

**Always offer three delivery modes:** (a) write a migration / rules file, (b) apply now via available execution path, (c) step-by-step guidance.

---

## Step 6 — Continuous monitoring (CI workflow)

Offer a per-backend GitHub Action from `assets/ci/github-action-<backend>.yml`. The CI pattern is uniform:

- Triggers: push to main on relevant paths; weekly cron; manual dispatch.
- Two job modes: **static IaC scan** (always runs, no secrets needed) and **live audit** (gated on `vars.AUDIT_LIVE == 'true'` and the backend's secrets being configured).
- Comment on PR; upload report artifact; fail on CRITICAL.

---

## Step 7 — Preventive measures

Backend-specific hardening checklist. Generated only if the user opts in (so we don't drown a clean audit with unsolicited recommendations).

---

## Principles — apply to every step, every backend

- **Explain like a friend.** Concrete attack scenario for every finding.
- **Every finding gets a fix.**
- **Safe testing only.** Default read-only. Opt-in for any write or network probe.
- **Be thorough, not alarmist.** Calibrate severity to the data sensitivity and backend's threat model.
- **Praise good security.** If things are properly locked down, say so explicitly.
- **State limitations clearly.** Sentinel covers database/API/configuration security. It does not cover XSS, CSRF, SSRF, infrastructure, or business logic.
- **Adapt to skill level.** Technical user → be concise. Vibe-coder → explain RLS / rules / RBAC from scratch, walk through fixes.
- **The vibe-coding angle is the differentiator.** When in doubt about whether to flag a pattern: would Cursor / Bolt / Lovable / Claude Code generate this? If yes, flag it — even if it's not technically a CVE. See `references/vibe-coding-context.md`.
