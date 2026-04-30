# MongoDB backend — audit workflow

The 7-step Sentinel workflow specialized for MongoDB. The dispatcher in root `SKILL.md` loads this file when MongoDB is detected. Reference files (`anti-patterns.md`, `introspection.md`, `mongobleed-probe.md`, `fix-templates.md`) live in this same `backends/mongodb/` directory.

**What this audit covers:** self-hosted mongod (Docker / k8s / bare-metal), MongoDB Atlas, drivers in application code (Mongoose, Connector/J), Atlas Functions used as HTTPS endpoints. Out of scope: AWS DocumentDB, Azure Cosmos DB Mongo API (protocol-compatible, different implementation, different threat model).

**Why MongoDB needs its own audit:** The 2025–2026 events that triggered this module:
- **CVE-2025-14847 "MongoBleed"** — pre-auth heap memory disclosure via crafted compressed packets. ~87,000 internet-facing instances at disclosure (Dec 2025). CISA KEV.
- **Atlas Data API deprecation** (Sept 30 2025) — apps that "fixed" the outage by migrating to under-audited Atlas Functions are now in worse shape.
- **Mongoose populate-match injection** (CVE-2024-53900, CVE-2025-23061) — driver-side $where injection.
- **Vibe-coded `--bind_ip_all` defaults** — AI-generated docker-compose files routinely emit internet-bindable mongod.
- **Meow / READ_ME ransomware sweeps** — never stopped. Shadowserver scans 2024–2025 continue to find thousands of unauthenticated internet-exposed instances.

---

## Step 0 — Detect, gather connection details, scan codebase

**Detection** runs from `core/detection.md`. Trigger signals: `mongod.conf`, `MONGODB_URI` env var, `mongodb+srv://` or `mongodb://` connection strings, `mongo:` Docker images, `mongoose` / `mongodb` / `pymongo` / `motor` package dependencies, `mongodbatlas_*` Terraform resources.

**Distinguish Atlas from self-hosted:**
- `mongodb+srv://...mongodb.net` → Atlas
- `mongodb+srv://...docdb.amazonaws.com` → AWS DocumentDB (out of scope, skip)
- `mongodb+srv://...cosmos.azure.com` → Azure Cosmos DB Mongo API (out of scope, skip)
- Anything else → self-hosted (run all `MG-SH-*` patterns)

A single project can be both: an Atlas cluster for production data plus a self-hosted instance for dev. Audit each independently.

**Credential discovery** (per `core/credentials.md`):

```bash
# Connection strings — typically the privileged credential for MongoDB
grep -rE 'mongodb(\+srv)?://[^"'\'']*' \
  --include="*.env*" --include="*.ts" --include="*.js" --include="*.py" \
  --include="*.json" --include="*.yml" --include="*.yaml" 2>/dev/null \
  | grep -v node_modules

# Atlas API key pair (programmatic access)
grep -rE 'ATLAS_(PUBLIC|PRIVATE)_KEY|MONGODB_ATLAS_(PUBLIC|PRIVATE)_KEY' \
  --include="*.env*" 2>/dev/null

# Self-hosted root password env vars
grep -rE 'MONGO_INITDB_ROOT_(USERNAME|PASSWORD)' \
  --include="*.env*" --include="docker-compose*.yml" --include="Dockerfile*" 2>/dev/null
```

**Codebase red flags (report immediately, before introspection):**

| Pattern | Severity | Notes |
|---------|----------|-------|
| Connection string with embedded password committed to git | CRITICAL | `git ls-files` on `.env*`; rotate user credential |
| `MONGO_INITDB_ROOT_PASSWORD` blank or trivial in compose file | CRITICAL | Implies `MG-SH-002` once container starts |
| Hardcoded `mongodb+srv://...` URI in source (not env) | HIGH | Move to env, check git history |
| Atlas API key with `Owner` role in env | HIGH | `MG-AT-005` |
| `--bind_ip_all` in any compose / Dockerfile | CRITICAL | `MG-SH-003` likely |
| `--noauth` on command line | CRITICAL | `MG-SH-002` |
| `MYSQL_*` env vars near a `MONGO_*` connection (mistaken backend setup) | INFO | Often signals copy-pasted boilerplate gone wrong |

Confirm credential discovery with the user before issuing the first authenticated mongod request.

---

## Step 1 — Schema and configuration introspection

Read `introspection.md`. Three execution paths:

| Path | When to use |
|------|-------------|
| **A — `mongosh`** | Default. Direct connection to live cluster with read-class credentials. |
| **B — Atlas Admin API** | Required for `MG-AT-*` patterns. Programmatic API key with read-only role. |
| **C — IaC scan** | Always runs in parallel. Catches committed misconfigurations before they reach a live cluster. |

The introspection step produces a JSON object (schema in `introspection.md` §"Output schema for Step 2") that Step 2 consumes.

**If you only have application-level credentials** (e.g., `readWrite` on one DB), the audit runs in degraded mode: skip `db.adminCommand({ getCmdLineOpts: 1 })`, skip user enumeration. Source-only and IaC-only findings still produced. Note the degraded mode in the report header.

---

## Step 2 — Static analysis (anti-pattern matching)

Read `anti-patterns.md`. 20 patterns: 14 self-hosted (`MG-SH-001..014`), 6 Atlas (`MG-AT-001..006`).

**Always check first** (run these unconditionally on every MongoDB audit):

1. `MG-SH-001` — MongoBleed version compare. Even before introspection, if you have a `MONGODB_URI` and can read `buildInfo` over a degraded connection, version compare.
2. `MG-SH-002` — auth disabled. The single highest-likelihood ransomware vector.
3. `MG-SH-003` — internet-bound. Pair with `MG-SH-002` for the headline finding.
4. `MG-AT-001` — Atlas IP allowlist `0.0.0.0/0`. Same surface as `MG-SH-003` for Atlas.
5. `MG-SH-008` — self-modifiable role document, by source-scan against Mongoose patterns. Catches the AI-generated mass-assignment idiom.

**Tier 1 patterns (run if topology supports):**
- Replica set: `MG-SH-012` (keyfile permissions; needs host access)
- Sharded: `MG-SH-007` per shard

**Tier 2 patterns (run from introspection results):**
- Per-database: `MG-SH-007` (privileged role on app user) — cross-reference user from `MONGODB_URI`
- Per-collection: `MG-SH-008` (validator absence on user-shaped collections)

**Vibe-coding heuristic:** apply `core/workflow.md` §Principles. Patterns most likely to be AI-generated:
- `MG-SH-002` + `MG-SH-003` together — the classic "make networking simpler" docker-compose
- `MG-SH-008` — `findByIdAndUpdate(id, req.body)` is a Cursor / Mongoose default
- `MG-AT-002` — Atlas Function as bare DB pass-through with `arg.filter`
- `MG-AT-001` — the easiest Atlas onboarding path is "allow access from anywhere"

Tag these with `Likely AI-generated` in the finding body.

---

## Step 3 — Dynamic probing

**No protocol-level transactional rollback exists for MongoDB the way `Prefer: tx=rollback` does for Supabase.** Probing strategy depends on topology:

| Topology | Read probe | Write probe (opt-in) |
|----------|------------|----------------------|
| Standalone (mongod single-process) | `hello` / `ismaster`, `find` with `limit:1` | `_sentinel_probe.cleanup_test` collection: insert one doc, immediately delete. Frame as "minimal residue possible." |
| Replica set 4.0+ | as above | session + `startTransaction()` + insert + `abortTransaction()` — true rollback. |
| Sharded 4.2+ | as above | distributed transaction + abort. |
| Atlas | as above | use a *non-production* DB or the `_sentinel_probe` DB; transactions supported by default. |

**Read probes** (always allowed if introspection succeeded):

```javascript
// Cheap protocol-level reachability + version
db.adminCommand({ hello: 1 })

// Per collection, smallest possible read
db.getCollection("COLLECTION").find({}).limit(1).readConcern("local").toArray()
```

**Write probes** (gated on `--allow-write-probes` opt-in):

```javascript
// Replica/sharded — true rollback
const s = db.getMongo().startSession();
s.startTransaction();
try {
  s.getDatabase("YOUR_DB").getCollection("_sentinel_probe").insertOne({ probeAt: new Date() });
  s.abortTransaction();
} finally {
  s.endSession();
}

// Standalone — insert + immediate delete (best-effort cleanup)
const _id = ObjectId();
db.getSiblingDB("YOUR_DB").getCollection("_sentinel_probe").insertOne({ _id, probeAt: new Date() });
db.getSiblingDB("YOUR_DB").getCollection("_sentinel_probe").deleteOne({ _id });
```

**MongoBleed probe** (gated separately on `--allow-network-probes` + ownership confirmation): see `mongobleed-probe.md`. Single packet, no exfiltration. Use only when the version-check finding needs runtime confirmation or when the host vendor may have backported a fix.

**Probe result interpretation:**

| Outcome | Means |
|---------|-------|
| `find` returns docs to unauthenticated client | `MG-SH-002` confirmed (auth disabled) |
| `find` returns `not authorized` | auth enforced, role gating works |
| Write probe succeeds with attacker-controlled `role` field on user-shaped collection | `MG-SH-008` confirmed (mass assignment exploitable) |
| MongoBleed probe returns `vulnerable` | `MG-SH-001` confirmed at runtime |
| MongoBleed probe returns `patched` despite vulnerable version banner | annotate finding with "version banner mismatch — runtime patched" |

---

## Step 4 — Generate the report section

Use the unified format in `core/reporting.md`. MongoDB section header:

```
─────────────────────────────────────────────────────────
  MongoDB                                       42/100 🟠
─────────────────────────────────────────────────────────
  Cluster:    mongodb://prod-shard.example.com:27017 (replica set "rs0")
  Topology:   replica set, 3 members
  Version:    7.0.20  ⚠ MongoBleed-vulnerable (patched in 7.0.28)
  Atlas:      not detected
  Findings:   2 CRITICAL · 3 HIGH · 1 MEDIUM
```

**Scoring** per `core/scoring.md`: CRITICAL = -30 (vs -25 for Supabase). Justification: MongoBleed is RCE-adjacent and pre-auth; `--bind_ip_all` + no auth is a single configuration that exposes the entire dataset.

Cap deductions at 30 per finding. Floor at 0.

**Ordering within MongoDB section:**

1. CRITICAL findings first, with `MG-SH-001` (MongoBleed) at top if present
2. Then `MG-SH-002` / `MG-SH-003` (auth + network exposure)
3. Then `MG-AT-001` (Atlas allowlist)
4. HIGH findings ordered by likely-sensitive collection (`users`, `payments`, `tokens` > `logs`, `metrics`)
5. MEDIUM, LOW

**Each finding** uses the standard schema from `core/reporting.md`:

```
🔴 CRITICAL — mongod 7.0.20: MongoBleed (CVE-2025-14847)         [MG-SH-001]

  Risk:     A single TCP packet leaks fragments of MongoDB's memory —
            including credentials, queries, and document data — without
            requiring any login.
  Attack:   Attacker sends one crafted compressed packet to your mongod
            on port 27017. The server returns uninitialized heap memory.
            Repeated requests progressively dump more of the working set.
            Public PoC available since Dec 26 2025; CISA KEV.
  Proof:    buildInfo.version = "7.0.20" (vulnerable; patched in 7.0.28)
            zlib compression enabled (default): true
            (Active probe not run — gate not satisfied. To confirm at
            runtime, re-run with --allow-network-probes.)
  Source:   CVE-2025-14847 / CISA KEV / MongoDB Server Security Update Dec 2025

  Fix:
  Upgrade to 7.0.28 (or later 7.0.x). If upgrade is blocked, set
  net.compression.compressors = "snappy,zstd" in mongod.conf and restart.

  See backends/mongodb/fix-templates.md §1 for the version matrix.
```

---

## Step 5 — Generate fixes

Read `fix-templates.md`. Fix categories:

1. **Version upgrade matrix** — MongoBleed and other CVEs
2. **Hardened `mongod.conf`** — auth, bind, TLS, compression, JS, audit
3. **Least-privilege user creation** — `readWrite` scoped to one DB; authentication restrictions
4. **Schema validators** — JSON schema with `enum` constraint on role-like fields
5. **Driver upgrade matrix** — Mongoose, Connector/J
6. **Atlas Terraform** — restricted IP allowlist; PrivateLink template
7. **Atlas Function pattern** — typed-input replacement for direct pass-through

**Always offer three delivery modes:**
1. Write a `mongod.conf` patch / Terraform diff / migration JS file.
2. Apply now (only if the user has admin credentials and accepts the risk).
3. Step-by-step walkthrough.

**For MongoBleed:** the fix is unambiguously "upgrade." Don't suggest the compression workaround as a permanent solution — only as a same-day mitigation while the upgrade window is being scheduled.

---

## Step 6 — GitHub Action (continuous monitoring)

Read `assets/ci/github-action-mongodb.yml`. Two job modes:

- **Static IaC scan** (always runs, no secrets needed): grep on `*.tf`, `docker-compose*.yml`, `Dockerfile*`, `package.json`. Catches `MG-AT-001`, `MG-SH-002/003` in committed config.
- **Live audit** (gated on `vars.AUDIT_LIVE == 'true'`): runs introspection bundle; requires `MONGODB_AUDIT_URI`, optionally `ATLAS_PUB`/`ATLAS_PRIV`/`ATLAS_GROUP_ID` for `MG-AT-*` patterns.
- **MongoBleed probe** (gated on `vars.MONGOBLEED_PROBE == 'true'` AND `MONGOBLEED_PROBE_CONFIRM_AUTHORIZED=yes` env): runs the safe single-packet detector against `vars.MONGO_HOST`.

CI fails on `summary.critical > 0` or `headline_score < threshold` (default 70).

---

## Step 7 — Preventive measures

Recommend (only if the user opts in to a hardening pass — don't dump these on a clean audit):

1. **Patch on a schedule.** MongoDB ships server patches roughly quarterly; stale-by-six-months is a defensible threshold for a HIGH finding.
2. **Disable `enableLocalhostAuthBypass` after first admin creation.** `setParameter: enableLocalhostAuthBypass: false`.
3. **Require TLS for client connections** even on private networks. Defense-in-depth against compromised intermediary.
4. **Use Atlas PrivateLink / VPC peering** instead of IP allowlists where the cloud provider supports it.
5. **Schema validators on every collection** that stores roles, plans, or permissions. Mass-assignment is the single most common app-layer mistake.
6. **Replication keyfile rotation** annually; use x.509 internal auth on Enterprise.
7. **Rotate Atlas API keys quarterly.** Audit logs show last-use date; keys with no recent use are revocation candidates.
8. **Subscribe to MongoDB security mailing list** + monitor CISA KEV for new MongoDB CVEs.

---

## Reference files (load on demand)

- **`anti-patterns.md`** — 20 patterns (`MG-SH-001..014`, `MG-AT-001..006`) with severity, detection, fixes. Essential at Step 2.
- **`introspection.md`** — `mongosh` bundle, Atlas Admin API curls, IaC scan commands. Essential at Step 1.
- **`mongobleed-probe.md`** — safe single-packet CVE-2025-14847 probe. Opt-in only. Optional at Step 3.
- **`fix-templates.md`** — version matrix, `mongod.conf`, user creation, schema validators, Atlas Terraform. Essential at Step 5.
- **`core/workflow.md`** — universal 7-step contract. Re-read if behavior diverges from per-backend workflow.
- **`core/scoring.md`** — MongoDB-specific weights (CRITICAL = -30).
- **`core/reporting.md`** — unified report format.
- **`references/cve-feed.md`** — MongoDB CVEs maintained quarterly.
- **`references/vibe-coding-context.md`** — why these patterns proliferate; Cursor / Bolt / Lovable / Claude Code attribution data.
- **`assets/ci/github-action-mongodb.yml`** — CI workflow template. Read at Step 6.
