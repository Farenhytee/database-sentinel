# 🛡️ Database Sentinel

**A Claude Skill that audits your database backends for security vulnerabilities.**

Drop it into Claude Code, Cursor, or any Claude-powered environment. Say "audit my database" and get a comprehensive security report with exact fix code — in minutes, not days.

> **170+ Lovable apps were breached.** 20.1M rows were exposed across YC startups. ~87,000 MongoDB instances were left vulnerable to MongoBleed (CVE-2025-14847, CISA KEV). 1.8M Firebase passwords leaked in a single 2025 incident. 45% of AI-generated code introduces OWASP Top 10 vulnerabilities. Database Sentinel tests whether your security configuration *actually works* — not just whether it's present.

---

## What it does

Database Sentinel performs a 7-step security audit on whichever backend(s) your project uses:

1. **Detects** which backends you're using (Supabase, Firebase, MongoDB, self-hosted Postgres / MySQL)
2. **Scans your codebase** for exposed credentials, hardcoded keys, secrets in git
3. **Introspects each backend** — schema, policies, rules, users, roles, configuration
4. **Matches findings against backend-specific anti-pattern catalogs** sourced from CVEs, breach reports, CIS benchmarks, and 2025–2026 vibe-coding research
5. **Dynamically probes** with safe primitives (`tx=rollback`, canary collections, opt-in MongoBleed detector)
6. **Generates a scored security report** with plain-English explanations and concrete attacker scenarios
7. **Produces exact fix code** — SQL DDL, rule files, config diffs, Terraform — copy, paste, done

Cross-backend reasoning catches issues that single-backend scanners miss (e.g., a Firebase Auth UID trusted by a Postgres API without JWT verification).

---

## Status

| Phase | Backend | Status |
|-------|---------|--------|
| 1 | Supabase | ✅ shipped |
| 2 | MongoDB (self-hosted + Atlas) | ✅ shipped |
| 3 | Firebase (Firestore / RTDB / Storage / Functions / Remote Config) | 🚧 planned |
| 4 | PostgreSQL (self-hosted, including pgBouncer) | 🚧 planned |
| 5 | MySQL (self-hosted) | 🚧 planned |
| 6 | Cross-backend interaction analysis | 🚧 planned |
| 7 | Distribution + polish | 🚧 planned |

Database Sentinel was previously **Supabase Sentinel** (single-backend). The rename happened during Phase 1 of the multi-backend expansion. A backwards-compat shim at `compat/supabase-sentinel/` preserves the old skill name through at least the next minor release — existing users see no regression.

---

## Quick start

### Option 1: Claude Code / Cursor

Clone the skill into your project's skills directory, or a central one:

```bash
git clone https://github.com/Farenhytee/database-sentinel.git ~/claude-skills/database-sentinel
```

Then ask Claude:

```
Audit my database
```

Database Sentinel will detect which backend(s) your project uses, run the relevant audits, and produce a unified report. If multiple backends are present (Firebase Auth + Postgres data, etc.), the report includes a cross-backend interactions section once Phase 6 lands.

### Option 2: Single-backend invocation

If you only want to audit a specific backend, ask explicitly:

```
Audit my Supabase project
Audit my MongoDB instance
```

The dispatcher narrows the scope.

### Option 3: Manual (any AI assistant)

Copy the contents of `SKILL.md` plus the relevant `backends/<name>/workflow.md` into your system prompt. Walk through the 7 steps with your credentials.

---

## What it catches

### Supabase (Phase 1) — 27 patterns

| Severity | Pattern | What |
|----------|---------|------|
| 🔴 CRITICAL | `SB-001` `RLS_DISABLED` | Tables without Row-Level Security — fully exposed to the internet |
| 🔴 CRITICAL | `SB-002` `SERVICE_ROLE_EXPOSED` | service_role key in frontend code — bypasses ALL security |
| 🔴 CRITICAL | `SB-003` `POLICIES_BUT_NO_RLS` | Policies written but RLS never enabled — false security |
| 🔴 CRITICAL | `SB-005` `WRITE_USING_TRUE` | INSERT/UPDATE/DELETE with `USING(true)` — anyone can modify |
| 🟠 HIGH | `SB-006` `USING_TRUE_SELECT` | All rows readable by anonymous users on sensitive tables |
| 🟠 HIGH | `SB-007` `VIEW_NO_SECURITY_INVOKER` | Views bypass RLS, run as superuser |
| 🟠 HIGH | `SB-008` `SECURITY_DEFINER_EXPOSED` | Functions in public schema bypass RLS, callable via API |
| 🟠 HIGH | `SB-009` `USER_METADATA_IN_POLICY` | Policies reference user-modifiable metadata — privilege escalation |
| 🟠 HIGH | `SB-010` `UPDATE_NO_WITHCHECK` | UPDATE policies without WITH CHECK — mass assignment risk |
| 🟠 HIGH | `SB-011` `GHOST_AUTH` | Unconfirmed email signups grant authenticated sessions |
| 🟠 HIGH | `SB-012` `STORAGE_NO_RLS` | Storage bucket missing access control policies |
| 🟠 HIGH | `SB-013` `JWT_SECRET_EXPOSED` | JWT signing secret leaked — can forge any user's token |
| 🟡 MEDIUM | + 15 more patterns | See `backends/supabase/anti-patterns.md` |

### MongoDB (Phase 2) — 20 patterns

| Severity | Pattern | What |
|----------|---------|------|
| 🔴 CRITICAL | `MG-SH-001` MongoBleed (CVE-2025-14847, CISA KEV) | Pre-auth heap memory disclosure via crafted compressed packet. ~87K instances exposed at disclosure. |
| 🔴 CRITICAL | `MG-SH-002` Auth disabled | mongod running with no authentication — Meow ransomware attack surface |
| 🔴 CRITICAL | `MG-SH-003` Internet-bound mongod | `--bind_ip_all` + 27017 reachable — paired with `MG-SH-002` for total compromise |
| 🔴 CRITICAL | `MG-AT-001` Atlas allowlist `0.0.0.0/0` | Atlas cluster reachable from anywhere on the internet |
| 🟠 HIGH | `MG-SH-004` localhost auth bypass + container exec | `enableLocalhostAuthBypass` true + `docker exec` access |
| 🟠 HIGH | `MG-SH-005` Server-side JS enabled | `$where` / `$function` / `mapReduce` reachable — NoSQL-RCE surface |
| 🟠 HIGH | `MG-SH-006` TLS not required | Plaintext traffic on the wire |
| 🟠 HIGH | `MG-SH-007` Privileged role on app user | App connects as `root` / `dbAdminAnyDatabase` etc. |
| 🟠 HIGH | `MG-SH-008` Self-modifiable role document | `findByIdAndUpdate(id, req.body)` + no validator + role field |
| 🟠 HIGH | `MG-AT-002` Atlas Function as DB pass-through | NoSQL injection over HTTPS — proliferated post-Data-API-deprecation |
| 🟠 HIGH | `MG-AT-003` Atlas Data API still in code | Deprecated Sept 30 2025; broken AND likely rotated to less-audited Functions |
| 🟡 MEDIUM | `MG-SH-009` Mongoose < 8.9.5 | CVE-2024-53900 / CVE-2025-23061 — populate-match `$where` injection |
| 🟡 MEDIUM | + 8 more patterns | See `backends/mongodb/anti-patterns.md` |

The MongoBleed network probe (`backends/mongodb/mongobleed-probe.md`) ships a single-packet detector that confirms exploitability at runtime — verified against `mongo:7.0.20` (vulnerable) and `mongo:7.0.28` (patched). It's read-only, gated behind two opt-in confirmations, and never extracts content.

---

## Example output

```
╔════════════════════════════════════════════════════════╗
║                  SENTINEL SECURITY AUDIT               ║
╠════════════════════════════════════════════════════════╣
║  Backends:   supabase, mongodb                         ║
║  Scanned:    2026-04-30 14:30 UTC                      ║
║  Score:      0/100 🔴                                  ║
║  Summary:    2 backends, 8 findings (3C / 4H / 1M)     ║
╚════════════════════════════════════════════════════════╝

─────────────────────────────────────────────────────────
  Supabase                                       35/100 🔴
─────────────────────────────────────────────────────────

🔴 CRITICAL — public.users: RLS Disabled                  [SB-001]

  Risk:     Anyone on the internet can read your entire users table.
  Attack:   Open browser DevTools → copy anon key → curl the API → dump
            all emails, names, and metadata.
  Proof:    curl returns [{"id":"...","email":"user@real.com",...}]
  Source:   CVE-2025-48757 / Splinter 0013_rls_disabled_in_public

  Fix:
  ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

  CREATE POLICY "users_select_own"
    ON public.users FOR SELECT TO authenticated
    USING ((SELECT auth.uid()) = id);

─────────────────────────────────────────────────────────
  MongoDB                                         0/100 🔴
─────────────────────────────────────────────────────────

🔴 CRITICAL — mongod 7.0.20: MongoBleed (CVE-2025-14847)  [MG-SH-001]

  Risk:     A single TCP packet leaks fragments of MongoDB's memory —
            including credentials, queries, and document data — without
            requiring any login.
  Attack:   Public PoC available since Dec 26 2025; CISA KEV. Repeated
            requests progressively dump more of the working set.
  Proof:    buildInfo.version = "7.0.20" (vulnerable; patched in 7.0.28)
            zlib compression enabled (default): true
            Active probe returned: vulnerable (opCode=2012, 163 bytes)
  Source:   CVE-2025-14847 / CISA KEV / MongoDB Server Security Update Dec 2025

  Fix:
  Upgrade to 7.0.28+. Same-day mitigation if upgrade is blocked:
  net.compression.compressors = "snappy,zstd"  in mongod.conf

✅ PASSING — Supabase: orders, payments, invoices, subscriptions
```

---

## File structure

```
database-sentinel/
├── SKILL.md                                # Dispatcher — detects backends, routes audits (~2K tokens)
├── DECISIONS.md                            # Locked architecture decisions (D1-D4 + supersessions)
├── core/
│   ├── workflow.md                         # Universal 7-step audit workflow
│   ├── detection.md                        # Backend detection + JSON manifest
│   ├── scoring.md                          # Per-backend weights, min-aggregation
│   ├── reporting.md                        # Unified report format (text + JSON)
│   └── credentials.md                      # Public-vs-privileged key handling
├── backends/
│   ├── supabase/                           # Phase 1 — implemented
│   │   ├── workflow.md                     # 7-step audit specialized for Supabase
│   │   ├── audit-queries.md                # 20 SQL queries for schema introspection
│   │   ├── anti-patterns.md                # 27 patterns (SB-001..SB-027)
│   │   └── fix-templates.md                # SQL fix templates (7 RLS patterns + more)
│   └── mongodb/                            # Phase 2 — implemented
│       ├── workflow.md                     # 7-step audit specialized for MongoDB
│       ├── introspection.md                # mongosh + Atlas Admin API + IaC scan
│       ├── anti-patterns.md                # 20 patterns (MG-SH-001..014, MG-AT-001..006)
│       ├── mongobleed-probe.md             # Safe CVE-2025-14847 single-packet detector
│       ├── fix-templates.md                # Version matrix + mongod.conf + validators + Atlas TF
│       └── test-recipe.md                  # Document-only end-to-end test recipe
├── compat/
│   └── supabase-sentinel/                  # Backwards-compat shim (forces backend=supabase)
│       └── SKILL.md
├── references/
│   ├── vibe-coding-context.md              # CVE-2025-48757, breach studies — cross-backend
│   └── cve-feed.md                         # Cross-backend CVE list (MongoBleed seeded)
├── assets/
│   └── ci/
│       ├── github-action-supabase.yml      # 1 job — security audit
│       └── github-action-mongodb.yml       # 3 jobs — static IaC, live audit, MongoBleed probe
├── README.md                               # this file
├── LICENSE                                 # MIT
├── DECISIONS.md
└── sentinel-implementation-plan.md         # Multi-backend expansion roadmap
```

**How progressive disclosure works:** Claude loads only `SKILL.md` (~2K tokens) plus `core/*` initially. When detection identifies a backend, the matching `backends/<name>/workflow.md` and on-demand reference files load. A Supabase-only audit doesn't pay the cost of MongoDB content; future Firebase / Postgres / MySQL extensions follow the same pattern.

---

## Continuous monitoring (GitHub Actions)

Each implemented backend ships a CI workflow template:

| Backend | Workflow | Job modes |
|---------|----------|-----------|
| Supabase | `assets/ci/github-action-supabase.yml` | Single job — security audit (introspection + dynamic probes) |
| MongoDB | `assets/ci/github-action-mongodb.yml` | Three jobs — static IaC scan (always runs, no secrets), live audit (gated on `vars.AUDIT_LIVE == 'true'`), MongoBleed probe (gated on `vars.MONGOBLEED_PROBE == 'true'` + ownership confirmation) |

Workflows trigger on relevant file changes (migrations, rule files, IaC, dependency manifests), weekly cron (Monday 06:00 UTC), and manual dispatch. They post PR comments, upload report artifacts, and fail the build on critical findings.

Just ask: "Set up continuous security monitoring for this project."

---

## Research backing

Database Sentinel's anti-pattern database is sourced from:

### Supabase / Firebase / vibe-coding ecosystem
- **CVE-2025-48757** — 170+ Lovable apps exposed, CVSS 9.3 (Matt Palmer, May 2025)
- **Escape.tech** — 2,000+ vulnerabilities across 5,600 vibe-coded apps (October 2025)
- **Veracode** — 45% of AI-generated code introduces OWASP Top 10 vulnerabilities (July 2025)
- **Carnegie Mellon SusVibes** — 82.8% of functionally correct AI code was insecure (December 2025)
- **SupaExplorer** — 11% of indie apps expose Supabase credentials (January 2026)
- **ModernPentest** — 20.1M rows exposed across 107 YC startups (March 2026)
- **OpenFirebase / Icex0 (Sept 2025)** — ~150 Firebase apps with unauthenticated read/write
- **Zendata (May 2025)** — 1.8M plaintext Firebase passwords leaked across 900+ apps
- **GitGuardian** — 19.8M Firebase secrets leaked in public GitHub
- **Supabase Splinter** — All 16 official security lints mapped and extended
- **Wiz Research** — Critical auth bypass in Base44 vibe-coding platform (July 2025)

### MongoDB / Atlas
- **CVE-2025-14847 "MongoBleed"** (CVSS 8.7, CISA KEV) — pre-auth heap disclosure, ~87K exposed instances
- **CVE-2024-53900 / CVE-2025-23061** — Mongoose populate-match `$where` injection
- **CVE-2025-30706** — MongoDB Connector/J critical (Oracle CPU April 2025)
- **MongoDB Atlas Data API deprecation** (Sept 30 2025)
- **Shadowserver / Meow ransomware tracking** (continuing 2024–2025 sweeps)
- **CIS MongoDB 7 Benchmark v1.2**

See `references/vibe-coding-context.md` and `references/cve-feed.md` for the full citation set.

---

## What Database Sentinel catches that built-in tools miss

| Backend | Built-in tool | What it misses | Database Sentinel covers |
|---------|---------------|----------------|---------------------|
| Supabase | Splinter (16 lints) | Whether policies actually prevent unauthorized access | Live `tx=rollback` testing of every CRUD path against every table |
| Supabase | Splinter | Ghost-auth (email-confirmation bypass) | Sign-up probe with `.invalid` TLD |
| Supabase | Splinter | Mass-assignment via `UPDATE` without `WITH CHECK` + sensitive columns | Cross-references column names with policy shape |
| Supabase | Splinter | Codebase scanning | Finds service_role keys in frontend code, hardcoded JWTs, committed `.env` files |
| MongoDB | Atlas Advisor | MongoBleed runtime confirmation | Single-packet protocol-level detector (verified against 7.0.20 + 7.0.28) |
| MongoDB | Atlas Advisor | Self-modifiable role documents | Source-pattern + collection-validator cross-check |
| MongoDB | Trivy / Aikido | Atlas-specific config (allowlists, IAM, CMK) | Direct Atlas Admin API audit |
| MongoDB | mongoaudit (abandoned 2018) | Active in 2025+ | Maintained pattern catalog with 2025–2026 CVEs |

---

## Safety

Database Sentinel is designed to be safe for production use:

- **Default read-only.** Introspection queries only read system catalogs (`pg_tables`, `pg_policies`, `getCmdLineOpts`, etc.). No DDL or DML by default.
- **Write probes are opt-in.** Per-backend strategy:
  - **Supabase** — `Prefer: tx=rollback` (PostgREST native; zero data modified)
  - **Postgres self-hosted** — `BEGIN…ROLLBACK` (transactional DDL)
  - **MongoDB replica/sharded** — session + `abortTransaction()`
  - **MongoDB standalone** — canary collection insert+delete (best-effort cleanup, framed as opt-in)
  - **Firebase** — canary collection at `/_sentinel_probe/{random}`
  - **MySQL self-hosted** — `_sentinel_probe` schema + `DROP DATABASE` (opt-in, destructive — explicit warning)
- **Network probes (MongoBleed) are double-opt-in.** Audit policy must enable network probes AND user must confirm host ownership separately. Some monitoring tools alert on the probe packet, even though it's a single 42-byte read-only test.
- **Auth probes use `.invalid` TLD.** Test emails use RFC 6761 reserved domains that cannot receive mail.
- **Credentials never stored.** Held in memory for the audit, discarded at end. Reports redact credential values.
- **Open source.** Audit the auditor — every query, probe, and pattern is in this repo.

---

## Contributing

Contributions are welcome. The most valuable contributions:

1. **New anti-patterns** — Found a security issue not in our database? Add it to the relevant `backends/<name>/anti-patterns.md` with severity, detection query, fix code, and real-world evidence (CVE / breach / Splinter / CIS).
2. **Fix template improvements** — Better policy patterns, edge cases, or performance optimizations in `backends/<name>/fix-templates.md`.
3. **Live testing** — Run Database Sentinel against your own backends and report false positives / negatives. Live testing is what caught three real bugs during Phase 2 (see `backends/mongodb/mongobleed-probe.md` "Empirically verified" annotations).
4. **New backend extensions** — Phases 3–5 are open. Follow the structure of `backends/mongodb/` and `backends/supabase/`. The implementation plan (`sentinel-implementation-plan.md`) has the contract for each.
5. **Vibe-coding pattern attribution** — When you find a pattern that's plausibly AI-generated by Cursor / Bolt / Lovable / Claude Code, document it. This is the project's wedge.

### How to contribute

1. Fork the repo
2. Branch (`git checkout -b add-new-pattern`)
3. Add your changes with clear documentation and citations
4. PR with a description of the pattern and evidence

---

## Roadmap

### Shipping next
- **Phase 3** — Firebase (Firestore + RTDB + Storage + Cloud Functions + Remote Config + App Check). The largest extension; sub-modules per Firebase product to manage token budget.
- **Phase 4** — PostgreSQL self-hosted, including pgBouncer (CVE-2025-12819 detection)
- **Phase 5** — MySQL self-hosted (Oracle CPU CVE coverage; `mysql_native_password` deprecation handling for 8.4+)
- **Phase 6** — Cross-backend interaction analysis (Firebase Auth → Postgres trust paths, etc.)
- **Phase 7** — README polish (this), `BACKENDS.md` quick reference, deprecation timeline for the `supabase-sentinel` shim

### Future
- **CLI tool** — `npx database-sentinel audit` for non-Claude environments
- **MCP server** — programmatic access for CI/CD and dashboards
- **VS Code extension** — inline security warnings in the editor
- **Premium dashboard** — historical trending, multi-project views, Slack alerts

---

## Naming history

- **Supabase Sentinel** (v1) — single-backend Supabase auditor. Original release.
- **Sentinel** (working name during Phase 1 architectural refactor)
- **DB Sentinel** (v2, transitional working name during multi-backend rollout)
- **Database Sentinel** (v3, current) — multi-backend; full word "database" for explicit skill-discovery framing and to match the GitHub repo name

The `supabase-sentinel` skill name still works via the compat shim at `compat/supabase-sentinel/`. It forces the audit to Supabase only and produces output indistinguishable from v1. Sunset date: TBD; through at least the next minor release.

---

## License

MIT — use it however you want, commercially or otherwise.

---

<p align="center">
  <b>Built for the vibe-coding era.</b><br>
  Because "it works" and "it's secure" are two very different things.
</p>
