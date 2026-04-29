# Sentinel Multi-Backend Expansion — Implementation Plan for Claude Code

**Source documents:** the existing `supabase-sentinel` repo (already on disk / GitHub), the research report `Multi-Backend Security Auditing: Extending Supabase Sentinel to Firebase, MongoDB, and Self-Hosted SQL` (the artifact from the previous turn).

**Scope of this plan:** add Firebase, MongoDB, self-hosted Postgres, and self-hosted MySQL to Sentinel under a composition architecture (`sentinel` root skill + per-backend modules loaded on demand). Each backend ships ~20 anti-patterns, its own introspection bundle, its own probing strategy, its own fix templates, and a CI workflow.

**Audience:** Claude Code, with the human author intervening at the decision points marked **`STOP — DECIDE`**.

---

## 0. Decisions to make BEFORE Phase 1

These four answers determine the shape of every later phase. Don't start Phase 1 until they're answered.

| # | Question | Default if no answer | Why it matters |
|---|---|---|---|
| **D1** | **Repo strategy: monorepo or multi-repo?** | Monorepo at `github.com/Farenhytee/sentinel` (rename of `supabase-sentinel`). | Multi-repo means duplicating the workflow scaffold five times. Monorepo means one `sentinel/` skill folder containing all backends — much easier for Claude Code to refactor across boundaries. |
| **D2** | **Root skill name: `sentinel`, `supashield`, or keep `supabase-sentinel`?** | `sentinel` (drops the Supabase-specific framing now that it's multi-backend). | The skill's `name` field in YAML frontmatter is what the Claude runtime matches against. We need to pick the name once and stick with it. The on-disk skill at `/mnt/skills/user/supashield/SKILL.md` and the GitHub repo `supabase-sentinel` are already inconsistent — this is the moment to fix that. |
| **D3** | **Backwards compat: keep the old skill name working?** | Yes — leave a stub `supabase-sentinel` skill that just delegates to `sentinel` with `--backend supabase` for one release cycle, then deprecate. | Existing users have it installed; silent breakage is bad. |
| **D4** | **Where does this work happen?** | A new branch `feat/multi-backend` on the existing repo, with a draft PR open from day one for incremental review. | A long-running branch is easier to roll back than five sequential merges to `main`. |

**STOP — DECIDE before continuing.** Once D1–D4 are answered, fill them into a `DECISIONS.md` at the repo root so subsequent Claude Code sessions don't have to re-derive them.

---

## 1. Architectural overview (read this once, then refer back)

We're moving from this:

```
supabase-sentinel/
├── SKILL.md              # 333 lines, Supabase-specific
├── references/
│   ├── audit-queries.md
│   ├── anti-patterns.md
│   ├── fix-templates.md
│   └── vibe-coding-context.md
├── assets/github-action-template.yml
├── README.md
└── LICENSE
```

To this:

```
sentinel/                            # was supabase-sentinel
├── SKILL.md                         # ~6-8K tokens; detection + dispatcher only
├── DECISIONS.md                     # D1-D4 answers
├── core/
│   ├── workflow.md                  # the abstract 7-step workflow (was inlined)
│   ├── detection.md                 # how to identify which backend(s)
│   ├── scoring.md                   # weight tables per backend
│   ├── reporting.md                 # report format + cross-backend section
│   └── credentials.md               # safe handling of secrets across backends
├── backends/
│   ├── supabase/                    # existing content, refactored to fit
│   │   ├── workflow.md
│   │   ├── anti-patterns.md         # SB-001..SB-027 (existing 27)
│   │   ├── audit-queries.md
│   │   └── fix-templates.md
│   ├── firebase/
│   │   ├── workflow.md
│   │   ├── anti-patterns.md         # FB-FS-*, FB-RT-*, FB-ST-*, FB-FN-*, FB-RC-*, FB-AC-*
│   │   ├── introspection.md
│   │   ├── rules-ast.md             # static analysis of firestore.rules / database.rules.json
│   │   ├── dynamic-probes.md
│   │   └── fix-templates.md
│   ├── mongodb/
│   │   ├── workflow.md
│   │   ├── anti-patterns.md         # MG-SH-*, MG-AT-*
│   │   ├── introspection.md
│   │   ├── mongobleed-probe.md      # the Wiz Nuclei-equivalent
│   │   └── fix-templates.md
│   ├── postgres-selfhosted/
│   │   ├── workflow.md
│   │   ├── anti-patterns.md         # PG-SC-*, PG-AU-*, PG-RLS-*, PG-EX-*, PG-PL-*, PG-BK-*
│   │   ├── introspection.sql
│   │   ├── pg-hba-parser.md
│   │   └── fix-templates.md
│   └── mysql-selfhosted/
│       ├── workflow.md
│       ├── anti-patterns.md         # MY-SC-*, MY-AU-*, MY-RB-*, MY-IC-*, MY-PL-*, MY-BK-*
│       ├── introspection.sql
│       └── fix-templates.md
├── references/
│   ├── vibe-coding-context.md       # the existing 2025-2026 research backing
│   ├── cve-feed.md                  # CVE list per backend, refreshed quarterly
│   └── tooling.md                   # pgdsat, FireScan, OpenFirebase, Nuclei templates
├── assets/
│   └── ci/
│       ├── github-action-supabase.yml      # existing
│       ├── github-action-firebase.yml
│       ├── github-action-mongodb.yml
│       ├── github-action-postgres.yml
│       └── github-action-mysql.yml
├── README.md                        # rewritten to describe Sentinel-the-suite
└── LICENSE
```

**The key invariant:** `SKILL.md` itself stays ~6-8K tokens. It does detection, picks the right backend(s), then `view`s the relevant `backends/<name>/*.md` files. Per-backend content is loaded only when relevant, preserving progressive disclosure.

---

## 2. Phase plan

We sequence by **risk-reduction first, then highest-impact backend, then completion**:

| Phase | What | Why this order | Estimated Claude Code sessions |
|---|---|---|---|
| **Phase 1** | Architectural refactor | Validate composition before building 4 new backends on it | 2-3 |
| **Phase 2** | MongoDB extension (MongoBleed-first) | Headline 2025 finding; smallest backend to validate the new architecture end-to-end | 3-4 |
| **Phase 3** | Firebase extension | Largest backend (5 sub-engines); needs the most rule-AST work | 5-7 |
| **Phase 4** | Postgres self-hosted | Easier than Firebase, harder than MongoDB | 3-4 |
| **Phase 5** | MySQL self-hosted | Sister of Phase 4; lots of code reuse | 2-3 |
| **Phase 6** | Cross-backend integration | Needs all extensions in place to test interactions | 2 |
| **Phase 7** | Distribution + polish | README, releases, deprecation notice for old skill name | 1-2 |

**Total budget:** ~18-25 Claude Code sessions. If you're hitting more than 30, something is off — pause and reassess.

---

## Phase 1 — Architectural refactor

**Goal:** restructure the existing Supabase-only repo to fit the composition architecture, *without changing any user-visible behavior*. By the end of Phase 1, running `sentinel` should produce exactly the same output as running the current `supabase-sentinel` skill.

**Context to load at session start:**
- This plan (this file)
- `DECISIONS.md`
- The existing `SKILL.md`
- All four files in `references/`

**Tasks:**

1. **Create the new directory structure** (`core/`, `backends/supabase/`, `references/`, `assets/ci/`). Don't delete the old files yet — we'll move them.

2. **Write `core/workflow.md`** by extracting the abstract 7-step workflow from the existing SKILL.md. Strip Supabase-specific details (RLS, PostgREST, `tx=rollback`); replace with placeholders like `[backend's introspection method]` and `[backend's safe probing technique]`. Each backend's `workflow.md` will fill these in.

3. **Write `core/detection.md`** — the signal table from §2.2 of the research report. List file patterns, env-var patterns, IaC resources, container images. The detector should output a JSON manifest like:

   ```json
   {
     "detected": [
       {"backend": "supabase", "confidence": "high", "signals": ["supabase/config.toml", "SUPABASE_URL in .env"]},
       {"backend": "firebase", "confidence": "medium", "signals": ["firebase.json"]}
     ]
   }
   ```

4. **Write `core/scoring.md`** with the per-backend weight tables from §2.7 of the research. Add the rule that final score is the lowest per-backend score (a 30-point Firebase score is not redeemed by a 95-point Postgres score).

5. **Write `core/reporting.md`** describing the report format. The existing Supabase report header generalizes — just add a "Backends audited" line and a final "Cross-backend interactions" section (placeholder for now; Phase 6 fills it in).

6. **Write `core/credentials.md`** covering safe handling: never store, never log; the Supabase-specific guidance about anon vs service_role generalizes to "public-key-in-client vs privileged-key-in-client" — reference the abstraction table in the research report.

7. **Move existing Supabase content into `backends/supabase/`:**
   - `references/audit-queries.md` → `backends/supabase/audit-queries.md`
   - `references/anti-patterns.md` → `backends/supabase/anti-patterns.md`
   - `references/fix-templates.md` → `backends/supabase/fix-templates.md`
   - Extract the 7-step workflow body from old `SKILL.md` → `backends/supabase/workflow.md`
   - Keep `references/vibe-coding-context.md` at the top level (it covers all backends, not just Supabase)

8. **Rewrite `SKILL.md`** as a dispatcher:
   - YAML frontmatter: name from D2, description triggering on the existing Supabase keywords *plus* Firebase, MongoDB, Postgres, MySQL, "database security audit", "vibe-coded app security"
   - Body: detection step → load relevant `backends/*/workflow.md` → run → aggregate → report
   - Target ~6-8K tokens. If it's bigger, push more content into `core/`.

9. **Create `assets/ci/github-action-supabase.yml`** by moving the existing `assets/github-action-template.yml`. Don't change its contents.

10. **Smoke test:** run a Supabase audit through the new structure on a known-vulnerable test project. Output should be byte-identical (or as close as practical) to what the old skill produced.

**Verification before moving to Phase 2:**
- [ ] `SKILL.md` is ≤8K tokens
- [ ] `backends/supabase/` exists and is self-contained
- [ ] Smoke test on a real Supabase project passes
- [ ] No file references the old paths (`references/audit-queries.md` etc.)
- [ ] Git diff is reviewable in a draft PR

**STOP — HUMAN REVIEW** before Phase 2. Architecture mistakes here are expensive to fix later.

---

## Phase 2 — MongoDB extension (MongoBleed-first)

**Goal:** ship the smallest backend extension end-to-end. By Phase 2 close, `sentinel` should detect a MongoDB project, run the MongoDB workflow, and catch MongoBleed exposure (CVE-2025-14847) plus the other 19 anti-patterns from the research report's catalog.

**Why MongoDB first:** the research report's takeaway #1 is "ship MongoBleed detection first." It's also the simplest backend — no rule-AST parsing (Firebase) or pooler config gymnastics (Postgres). It validates the architecture before we commit to harder backends.

**Context to load at session start:**
- The plan (this file)
- `core/workflow.md`, `core/detection.md`, `core/scoring.md`, `core/reporting.md`
- `backends/supabase/` (as the reference implementation)
- The MongoDB section of the research report (Part 1 §1.2, Part 3 §3.2)

**Tasks:**

1. **Create `backends/mongodb/` directory** with the structure from the research report §3.2.1.

2. **Write `backends/mongodb/anti-patterns.md`** covering all 20 patterns from research §3.2.2 (`MG-SH-001..014` and `MG-AT-001..006`). Each pattern entry must include:
   - ID
   - Severity (CRITICAL/HIGH/MEDIUM/LOW)
   - What happens (plain-English risk)
   - Root cause
   - Detection method (specific command or query)
   - Real-world impact with citation
   - Fix template reference

   **Start with `MG-SH-001` (MongoBleed).** Get this one fully right before doing the others — it's the headline, and getting the version-comparison + zlib-config check exactly correct sets the pattern.

3. **Write `backends/mongodb/introspection.md`** with the JS-shell introspection bundle from research §3.2.3. Format as a single copy-pasteable block the user can run in `mongosh`, plus the Atlas API curl commands separately.

4. **Write `backends/mongodb/mongobleed-probe.md`** — this is the safe network-level probe. Embed the Wiz Nuclei template's logic as a documented bash + `nc` snippet. **Critical:** the probe must be passive (read response only, do not exfiltrate content beyond version banner). Add an "OPT-IN" gate: don't run it without explicit user confirmation, because some monitoring systems will flag it.

5. **Write `backends/mongodb/workflow.md`** — adapt the 7-step workflow to MongoDB:
   - Step 0: detect MongoDB, gather connection string
   - Step 1: introspection (the bundle from task 3)
   - Step 2: static analysis against the 20 patterns
   - Step 3: dynamic probing — connection probe, optional MongoBleed probe (with opt-in)
   - Step 4: scored report
   - Step 5: fix SQL/JS
   - Step 6: GitHub Action setup
   - Step 7: preventive measures

6. **Write `backends/mongodb/fix-templates.md`** with the templates from research §3.2.4: hardened `mongod.conf`, least-privilege user creation, schema validator for role-escalation prevention.

7. **Update `core/detection.md`** to add MongoDB signals: `mongod.conf`, `*.bson`, `mongodb`/`mongoose`/`pymongo` in `package.json`/`requirements.txt`, `mongodb_atlas` in Terraform.

8. **Update `SKILL.md`** dispatcher to load `backends/mongodb/workflow.md` when MongoDB is detected.

9. **Write `assets/ci/github-action-mongodb.yml`** from research §3.2.5. Two job modes: static IaC scan (always runs) and live audit (gated on `vars.AUDIT_LIVE == 'true'`).

10. **Add MongoDB CVEs to `references/cve-feed.md`** — at minimum: CVE-2025-14847, CVE-2024-53900, CVE-2025-23061, CVE-2025-30706. Format with: CVE ID, severity, affected versions, patched versions, detection signal, link to advisory.

11. **End-to-end test:**
    - Spin up a vulnerable MongoDB locally (e.g., `mongo:7.0.20` with `--bind_ip_all` and no auth).
    - Run `sentinel` against it.
    - Expected findings: MG-SH-001 (MongoBleed), MG-SH-002 (no auth), MG-SH-003 (bind_ip_all), MG-SH-006 (no TLS).
    - Score should be ≤30.

**Verification before moving to Phase 3:**
- [ ] All 20 patterns documented with exact detection queries
- [ ] MongoBleed probe runs without exfiltrating data
- [ ] CI workflow runs green against a clean MongoDB and red against a vulnerable one
- [ ] `SKILL.md` is *still* ≤8K tokens (architecture is holding)
- [ ] A user with only Supabase still gets only Supabase output (no MongoDB noise)

**STOP — HUMAN REVIEW.** This is the architecture validation gate. If anything feels wrong about how MongoDB integrated, fix it now — Phases 3–5 will copy this pattern.

---

## Phase 3 — Firebase extension

**Goal:** the most complex backend. Five sub-engines (Firestore, RTDB, Storage, Cloud Functions, Remote Config) plus App Check, plus rules-AST static analysis, plus dynamic probing across multiple regional domain formats.

**Why this comes after MongoDB:** the architecture is now proven. Firebase's complexity will stress-test the composition model — if `backends/firebase/` blows past a sensible token budget, we know to introduce sub-modules.

**Context to load at session start:**
- The plan
- `core/*` and `SKILL.md`
- `backends/mongodb/` (as the second reference implementation)
- The Firebase section of the research report (Part 1 §1.1, Part 3 §3.1)

**Tasks:**

1. **Create `backends/firebase/` with sub-engine structure:**

   ```
   backends/firebase/
   ├── workflow.md
   ├── anti-patterns.md            # all 20+, grouped by sub-engine
   ├── introspection.md
   ├── rules-ast.md                # the static analyzer
   ├── dynamic-probes.md
   ├── appcheck-probe.md
   └── fix-templates/
       ├── firestore.rules.tmpl
       ├── database.rules.json.tmpl
       ├── storage.rules.tmpl
       ├── functions-app-check.ts.tmpl
       └── custom-claims.ts.tmpl
   ```

   If `anti-patterns.md` exceeds ~3K tokens, split it into `patterns-firestore.md`, `patterns-rtdb.md`, `patterns-storage.md`, `patterns-functions.md`, `patterns-remote-config.md`, `patterns-appcheck.md`. The dispatcher can load only the relevant ones.

2. **Write the 24 anti-patterns** from research §3.1.2 (FB-FS-001..008, FB-RT-001..004, FB-ST-001..004, FB-FN-001..004, FB-RC-001..002, FB-AC-001..002). **Start with FB-FS-001** ("`if true` test mode") and **FB-RT-001** ("RTDB root open") since these are the two most-exploited patterns in the 2025 breach data.

3. **Write `rules-ast.md`** — this is the new and hard part. We need to statically analyze Firebase Security Rules. Two paths:
   - **Path A (recommended for v1):** regex/pattern-matching on the rules text. Catches `if true`, `if request.auth != null` (without further conjuncts), `match /{document=**}` at root. Cheap, ~80% recall.
   - **Path B (v2):** real CEL/rules-language parser. Out of scope for now — note in the file as future work.

   Document the v1 patterns clearly so they can be replaced with a real parser later.

4. **Write `dynamic-probes.md`** with the canary-collection strategy from research §2.6. Required user opt-in for write probes; reads are safe by default. Include the multi-regional domain enumeration (`firebaseio.com`, `europe-west1.firebasedatabase.app`, etc.) — the OpenFirebase research showed regional fallback as a real bypass.

5. **Write `appcheck-probe.md`** — the enforcement check (200 without `X-Firebase-AppCheck` header → not enforced).

6. **Write `introspection.md`** with the `firebase` CLI commands and Management API curls from research §3.1.3.

7. **Write fix templates** as concrete files in `fix-templates/`. Each must compile/validate (test by running `firebase deploy --only firestore:rules --dry-run` against the templates in CI).

8. **Update `SKILL.md` dispatcher** for Firebase. Detection signals: `firebase.json`, `firestore.rules`, `database.rules.json`, `.firebaserc`, `google-services.json`, `GoogleService-Info.plist`.

9. **Write `assets/ci/github-action-firebase.yml`** from research §3.1.5.

10. **Update `references/cve-feed.md`** with the firebase-* npm CVEs (e.g., CVE-2024-7254 chain in firebase-firestore, firebase-functions, firebase-messaging).

11. **Update `references/tooling.md`** noting that Sentinel does not replace OpenFirebase / FireScan — it integrates them. Document how to run them alongside (Sentinel handles rule-AST + workflow; OpenFirebase handles APK extraction; FireScan handles interactive triage).

12. **End-to-end test:** create a deliberately-vulnerable test Firebase project with:
    - Firestore rules: `allow read, write: if true;`
    - RTDB rules: `{".read": true, ".write": true}`
    - Storage rules: open
    - One Cloud Function `onCall` without `enforceAppCheck`
    - One Remote Config parameter containing a fake AWS key

    Run sentinel. Should produce ~6+ critical findings, score ≤25.

**Verification before moving to Phase 4:**
- [ ] All 24 patterns documented
- [ ] Rules-AST analyzer catches the headline patterns (false-negative test on a curated set of 10 known-bad rules files)
- [ ] No write probe runs without opt-in
- [ ] Multi-regional RTDB enumeration works
- [ ] Total Firebase context loaded at audit time stays ≤15K tokens (sub-module split kicks in if not)
- [ ] CI workflow green/red as expected

**STOP — HUMAN REVIEW.** Token-budget check is critical here.

---

## Phase 4 — Postgres self-hosted extension

**Goal:** the second SQL backend. Postgres has a proper transactional `BEGIN…ROLLBACK` analogue to Supabase's `tx=rollback`, so probing is comparatively clean. The complexity is in pgBouncer and `pg_hba.conf` parsing.

**Context to load at session start:**
- The plan
- `core/*`, `SKILL.md`
- `backends/supabase/` (most directly analogous — same database engine)
- `backends/mongodb/` (for the architecture pattern)
- The Postgres section of the research report (Part 1 §1.3, Part 3 §3.3)

**Tasks:**

1. **Create `backends/postgres-selfhosted/` directory.**

2. **Write `anti-patterns.md`** covering all 22 patterns from research §3.3.2 (PG-SC-001..006, PG-AU-001..006, PG-RLS-001..003, PG-EX-001..003, PG-PL-001..003, PG-BK-001..002). **Start with PG-SC-001** (`pg_hba.conf` trust on non-loopback) and **PG-PL-001** (pgBouncer < 1.25.1 with CVE-2025-12819) since these are the highest-impact 2025 issues.

3. **Write `pg-hba-parser.md`** — `pg_hba.conf` is plain-text and easy to parse, but trust-mode detection has nuances (the `pg_hba_file_rules` view in PG 10+ is preferred over file parsing where available; document both paths).

4. **Write `introspection.sql`** — the SQL bundle from research §3.3.3. This is a single read-only script with appropriate role requirements (`pg_read_all_settings`, `pg_read_all_stats`, `pg_monitor`).

5. **Write `workflow.md`** adapting the 7 steps. Probing strategy: read-only by default, opt-in to active probing via `BEGIN…ROLLBACK` blocks.

6. **Write `fix-templates.md`** with research §3.3.4 templates: hardened `pg_hba.conf`, multi-tenant RLS template, hardened SECURITY DEFINER pattern.

7. **Add Postgres CVEs to `references/cve-feed.md`:** CVE-2025-1094, CVE-2025-8714, CVE-2025-8715, CVE-2025-2291 (pgBouncer), CVE-2025-12819 (pgBouncer). Note PG 13 EOL date (Nov 13 2025).

8. **Document pgdsat integration in `references/tooling.md`** — Sentinel runs alongside pgdsat, not instead of. Sentinel adds: vibe-coding patterns, IaC scanning, fix templates, multi-backend reporting. pgdsat covers: deeper CIS PG17 control coverage. The CI workflow should run both.

9. **Update detection signals** in `core/detection.md`: `pg_hba.conf`, `postgresql.conf`, `psql` in scripts, `postgres://` connection strings, `postgres:` Docker images, but **NOT** `supabase/config.toml` (that's Supabase, not self-hosted PG).

10. **Update `SKILL.md` dispatcher.**

11. **Write `assets/ci/github-action-postgres.yml`** from research §3.3.8 — the dual-mode action with services-spun-up Postgres + pgdsat + Sentinel.

12. **End-to-end test:** spin up `postgres:13` (EOL!) with `pg_hba.conf` containing `host all all 0.0.0.0/0 trust`. Expected findings: PG-SC-005 (EOL), PG-SC-001 (trust on non-loopback), PG-SC-003 (md5 password encryption — PG 13's default).

**Verification:**
- [ ] All 22 patterns documented
- [ ] `pg_hba.conf` parser handles the standard idioms (trust, scram-sha-256, md5, peer, hostssl)
- [ ] Active probing requires explicit opt-in
- [ ] CVE-2025-12819 detection works against a deliberately-old pgBouncer

---

## Phase 5 — MySQL self-hosted extension

**Goal:** sister of Phase 4. Lots of structural reuse from the Postgres extension; the unique work is the `mysql_native_password` deprecation handling and the docker-image patterns.

**Context to load at session start:**
- The plan
- `core/*`, `SKILL.md`
- `backends/postgres-selfhosted/` (template to copy from)
- The MySQL section of the research report (Part 1 §1.3, Part 3 §3.3.5–§3.3.9)

**Tasks:**

1. **Create `backends/mysql-selfhosted/`** mirroring the Postgres structure.

2. **Write the 18 anti-patterns** from research §3.3.5. **Start with MY-AU-004** (`mysql_native_password` users on 8.4+) — this is the most distinctly-MySQL-2025–2026 pattern. Then MY-AU-001 (anonymous accounts), MY-IC-001 (`MYSQL_ALLOW_EMPTY_PASSWORD`).

3. **Write `introspection.sql`** from research §3.3.6.

4. **Write `workflow.md`.** Probing caveat: MySQL DDL is implicitly committed, so the Postgres `BEGIN…ROLLBACK` trick doesn't apply. Use the `_sentinel_probe` schema approach (CREATE DATABASE + CREATE TABLE + DROP DATABASE). Frame strongly as opt-in with destructive-probe warning.

5. **Write `fix-templates.md`** from research §3.3.7: the `caching_sha2_password` migration template, anonymous-account drop, `root@%` rename.

6. **Add MySQL CVEs to `references/cve-feed.md`:** CVE-2025-21494, 21504, 21559, 30706 (Connector/J critical), 30722 (mysqldump), 50080, 50104, 9230, 9232, plus CVE-2026-21929 series. Cross-reference Oracle CPU dates.

7. **Update detection signals** for MySQL: `my.cnf`, `mysqld.cnf`, `mysql://` strings, `mysql:`/`mariadb:` Docker images.

8. **Update `SKILL.md` dispatcher.**

9. **Write `assets/ci/github-action-mysql.yml`** — same shape as Postgres action, with `mysql:8.4` service and `mysqlsh util.checkForServerUpgrade()` step.

10. **End-to-end test:** `mysql:5.7` with anonymous accounts + `MYSQL_ALLOW_EMPTY_PASSWORD=yes`. Expected findings: MY-IC-001, MY-AU-001, MY-AU-004 (5.7 still uses `mysql_native_password`), MY-SC-001 (5.7 EOL).

**Verification:**
- [ ] All 18 patterns documented
- [ ] Auth-plugin detection distinguishes 8.4+ from 8.0 / 5.7
- [ ] Destructive probe is clearly gated

---

## Phase 6 — Cross-backend integration

**Goal:** the value-add that none of the existing tools (pgdsat, OpenFirebase, FireScan, Wiz) provide — analyzing how multiple backends interact in a single application.

**Context to load at session start:**
- The plan
- `core/reporting.md`
- All five backend folders (just the workflow.md files, not the full pattern catalogs)
- Part 3 §3.4 of the research report

**Tasks:**

1. **Write `core/cross-backend.md`** documenting the interaction patterns to flag:
   - Firebase Auth UID claimed in JWT but unverified in API → Postgres `user_id` foreign key with no JWT-issuer check
   - Same secret reused across multiple backends (e.g., a `DATABASE_URL` and `MONGODB_URI` sharing a credential)
   - Service account JSON with both Firebase Admin and Cloud SQL access
   - Atlas Function calling Cloud Run which holds GCS service-account keys
   - Firebase data migrated to Postgres but the Firestore copy is still readable

2. **Update `core/detection.md`** to handle multi-backend cases. The detector should output *all* matching backends, not just the highest-confidence one.

3. **Update `SKILL.md` dispatcher** to run all detected backends and produce a unified report with a "Cross-backend interactions" section.

4. **Update `core/scoring.md`** — final score is `min(per_backend_scores)`, with cross-backend findings deducted from the lowest-scoring backend (so a critical cross-backend issue tied to Firebase deducts from the Firebase score).

5. **Update `core/reporting.md`** with the cross-backend section format.

6. **End-to-end test:** create a test project that uses Firebase Auth + Postgres data store with a deliberately-flawed integration (Postgres API endpoint accepts `user_id` from request body without verifying the Firebase JWT). Sentinel should flag this in the cross-backend section even though neither single-backend audit catches it.

**Verification:**
- [ ] Multi-backend project produces both per-backend reports + cross-backend section
- [ ] Single-backend project does not produce a cross-backend section (no false-positive noise)
- [ ] Cross-backend findings are tied to a backend for scoring purposes

---

## Phase 7 — Distribution + polish

**Goal:** make the new structure consumable by users.

**Tasks:**

1. **Rewrite `README.md`.** Lead with "Sentinel: security audits for Supabase, Firebase, MongoDB, Postgres, MySQL." Keep the Supabase Sentinel branding/screenshot/CVE-2025-48757 hook because it's still the cleanest narrative. Add per-backend sections with the same structure.

2. **Add `BACKENDS.md`** as a quick reference table — what each backend extension covers, what tools it integrates with, what CVEs it specifically flags.

3. **Backwards compat shim** (per D3): if you keep the `supabase-sentinel` skill name, it should be a thin SKILL.md that does `view` on `sentinel/SKILL.md` and runs with `--backend supabase` forced. Add a deprecation notice with a sunset date.

4. **Update vibe-coding-context.md** with the post-research additions:
   - The Sep 2025 OpenFirebase scan (~150 misconfigured apps from ~1200 scanned)
   - The May 2025 1.8M-password RTDB leak
   - MongoBleed CVE-2025-14847 with the CISA KEV addition
   - PostgreSQL CVE-2025-1094 / 8714 / 8715 chain
   - The vibe-coding-tool patterns (Cursor + Mongoose `User.find(req.body)`, Replit + Postgres `MYSQL_ALLOW_EMPTY_PASSWORD`, Claude Code with `pg_hba.conf trust 0.0.0.0/0`)

5. **Roadmap update** — items the research surfaced that should be on the public roadmap:
   - Real CEL parser for Firebase rules (replacing v1 regex approach)
   - Atlas Functions deeper analysis
   - PgBouncer config validator (parse `pgbouncer.ini` like we parse `pg_hba.conf`)
   - Cross-backend interaction patterns library expansion
   - CLI tool (`npx sentinel audit`) for non-Claude environments — already on the existing roadmap, now multi-backend

6. **Tag a `v2.0.0` release** on the repo (assuming D1 = monorepo). v1 was Supabase-only; v2 is multi-backend.

7. **Final smoke test:** run sentinel against three real projects:
   - A pure Supabase project (should produce identical output to v1)
   - A Firebase + Cloud Functions project
   - A multi-backend project (Firebase Auth + Postgres data)

   All three should produce sensible, actionable reports with no regressions.

---

## 3. Working principles for Claude Code

1. **One backend per session is ideal.** Phases 2–5 are sized so each fits comfortably in one Claude Code session's context. If you find yourself loading content from two backends simultaneously, you've drifted — pause and reassess.

2. **The 7-step workflow is the spine.** Don't redesign it per backend. Each backend fills in the *what* of each step (introspection commands, probing strategy, fix templates), not the *order* of steps.

3. **Reuse > rewrite.** Phase 5 (MySQL) should copy heavily from Phase 4 (Postgres). If you find yourself writing a unique solution for a problem already solved in `backends/supabase/` or `backends/mongodb/`, ask why.

4. **Test against real backends, not just unit tests.** Each phase has an "end-to-end test" task. Don't skip these — anti-pattern detection that works on synthetic test data and fails on real backends is the most common failure mode for security tooling.

5. **Token budget is a first-class concern.** `SKILL.md` ≤ 8K tokens is non-negotiable. If a phase's work pushes it over, factor content out into `core/` or `backends/<name>/`.

6. **The vibe-coding angle is the differentiator.** When in doubt about whether to flag a pattern, ask: "would Cursor / Bolt / Lovable / Claude Code generate this?" If yes, flag it — even if it's not technically a CVE. That's what the existing skill does well, and that's what the multi-backend version needs to keep doing.

7. **Cite sources.** Every anti-pattern entry must link back to its evidence (CVE, breach report, official docs). The existing Supabase patterns do this; preserve the standard.

8. **Don't reinvent existing tools.** pgdsat, OpenFirebase, FireScan, Wiz Nuclei templates — Sentinel integrates them, doesn't replace them. The unique value is workflow + prioritization + fix templates + cross-backend reasoning.

9. **Get destructive probing wrong, lose user trust forever.** Every active/write probe must be opt-in with a clear warning. If in doubt, default to read-only.

10. **STOP — HUMAN REVIEW markers exist for a reason.** Don't push past Phase 1, 2, 3 boundaries without human confirmation. Architecture mistakes get more expensive with each phase.

---

## 4. What success looks like

After Phase 7 ships:

- A user with any of {Supabase, Firebase, MongoDB self-hosted, Postgres self-hosted, MySQL self-hosted} can run sentinel and get a comprehensive audit.
- A user with multiple backends gets all per-backend audits *plus* a cross-backend interactions section.
- The skill catches every CVE flagged in the research report's CVE feed.
- The skill detects the headline 2025 patterns: MongoBleed, Firebase test-mode rules, pg_hba trust, mysql_native_password lingering, PgBouncer search_path injection, Lovable-style `if true` rules.
- `SKILL.md` is still ≤8K tokens. Per-backend content loads on demand. A Supabase-only audit doesn't pay the cost of Firebase/Mongo/SQL content.
- Existing Supabase users see no regression.
- The repo has CI workflows that prove every backend works against both clean and deliberately-vulnerable test instances.

That's the bar.
