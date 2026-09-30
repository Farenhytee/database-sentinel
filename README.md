# 🛡️ Database Sentinel

[![ci](https://github.com/Farenhytee/database-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Farenhytee/database-sentinel/actions/workflows/ci.yml)

**Security audits for your database backend.** Ask "audit my database" and get a scored report with exact fix code.

Works as a **Claude Skill** (Supabase, MongoDB), a **read-only MCP server** for any AI client, or a **CLI agent** that uses your own model (both Supabase).

---

## Changelog

**v0.2.1 (2026-09-30)**
- **Test F1:** agent 0.782 → 0.831, single-prompt 0.766 → 0.849. No crashes or timeouts ([results](docs/evals/2026-09-30-test-v0.2.1.md)).
- **Fixed:**
  - A bad tool argument no longer ends the audit; the error goes back to the model.
  - OpenRouter calls route to the fastest provider (slow ones caused timeouts).
  - The agent's final findings step no longer lists candidates it had dismissed.

**v0.2.0 (2026-09-29)**
- **Published test results:** agent F1 0.782, single-prompt 0.766, rules 0.559 on a blind, locked 10-case test split, 3 runs each ([results](docs/evals/2026-09-29-test.md)).
- **Bench:** 25 labeled cases (15 dev, 10 blind test).
- **Agent:**
  - **Verify step:** probes as anon to confirm exploitable findings.
  - **`--fix`:** prints fix SQL for findings you pick. It's never executed.
  - **Cost reporting:** tokens, $ and tool calls for each audit.
- **CI:** free rules-only regression gate.

**2026-09-29**
- **One-command install:** Claude Code plugin (skill + MCP server, prompts for your connection string) and an **Add to Cursor** button.
- **Install from GitHub:** one command for the MCP server (`uvx --from git+… sentinel-mcp`) and the agent (`pipx install "database-sentinel[agent] @ git+…"`).
- `sentinel-mcp --role-sql` prints the read-only role setup SQL.
- Clearer errors: the MCP client now sees why a call failed, and the CLI prints a single-line error.

**2026-09-28**
- **New: [MCP server](docs/mcp.md)** for Supabase. Four read-only tools, an `audit` prompt and the pattern catalog as resources. Your own LLM does the analysis, so it's free.
- **New: lite agent** (`sentinel-audit`). A LangGraph pipeline that works with any OpenAI-compatible model: OpenRouter, OpenAI, or local Ollama.
- **New: benchmark + evals.** 10 labeled Supabase cases, with precision/recall/F1 compared across a rules baseline, a single-prompt baseline and the agent.
- **Fixed:** six Supabase audit queries. Q8 (UPDATE without WITH CHECK) never matched anything, Q16 and Q19 missed rows for least-privilege roles, and Q6, Q13 and Q14 had wrong conditions.

---

## Quick start

**Claude Code** installs the audit skill and the MCP server in one go (needs [uv](https://docs.astral.sh/uv/getting-started/installation/)):
```bash
claude plugin marketplace add Farenhytee/database-sentinel
claude plugin install database-sentinel@database-sentinel
```
Supabase users: create the read-only login ([step 1](docs/mcp.md#1-create-a-read-only-login-in-supabase)), then run `/plugin configure database-sentinel@database-sentinel` in Claude Code. Then ask: `Audit my database`.

**Cursor** &nbsp; [![Add to Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=sentinel&config=eyJzZW50aW5lbCI6eyJjb21tYW5kIjoidXZ4IiwiYXJncyI6WyItLWZyb20iLCJnaXQraHR0cHM6Ly9naXRodWIuY29tL0ZhcmVuaHl0ZWUvZGF0YWJhc2Utc2VudGluZWwiLCJzZW50aW5lbC1tY3AiXSwiZW52Ijp7IlNFTlRJTkVMX0RTTiI6InBvc3RncmVzcWw6Ly9zZW50aW5lbF9hdWRpdG9yOlBBU1NXT1JEQGRiLlBST0pFQ1RfUkVGLnN1cGFiYXNlLmNvOjU0MzIvcG9zdGdyZXMiLCJTRU5USU5FTF9SRVNUX1VSTCI6Imh0dHBzOi8vUFJPSkVDVF9SRUYuc3VwYWJhc2UuY28iLCJTRU5USU5FTF9BTk9OX0tFWSI6IkFOT05fS0VZIiwiU0VOVElORUxfUkVQTyI6IiJ9fX0%3D)

**Other MCP clients, and full setup:** [MCP guide](docs/mcp.md)

<details>
<summary>More ways to install</summary>

**Skill only** (Claude Code picks it up automatically):
```bash
git clone https://github.com/Farenhytee/database-sentinel.git ~/.claude/skills/database-sentinel
```

**CLI agent** (Supabase, bring your own model):
```bash
pipx install "database-sentinel[agent] @ git+https://github.com/Farenhytee/database-sentinel"
export SENTINEL_BASE_URL=http://localhost:11434/v1 SENTINEL_MODEL=<model>   # Ollama, or any OpenAI-compatible API + SENTINEL_API_KEY
sentinel-audit --dsn "postgresql://sentinel_auditor:<password>@<host>:5432/postgres" \
  --rest-url https://<ref>.supabase.co --anon-key <anon key> --repo ./my-app
```
</details>

---

## What it catches

| Backend | Patterns | Examples |
|---|---|---|
| Supabase | 27 ([catalog](backends/supabase/anti-patterns.md)) | RLS disabled, service-role key in frontend, `USING (true)`, views bypassing RLS, exposed `SECURITY DEFINER` functions, `user_metadata` in policies, mass assignment, public buckets |
| MongoDB | 20 ([catalog](backends/mongodb/anti-patterns.md)) | MongoBleed (CVE-2025-14847), auth disabled, `0.0.0.0/0` Atlas allowlist, server-side JS, privileged app user |

Full tables are in [Appendix A](#a-pattern-highlights).

## Safety

- **Read-only by default.** Only system catalogs are read. The MCP server and agent can't write, drop or delete anything.
- **Your rows are never read.** The audit role has no access to table data. Repo scans report file and line, never secret values.
- **Write and network probes are opt-in** (Skill only). Details are in [Appendix D](#d-safety-details).

## Status

| Backend | Skill | MCP server / agent |
|---|---|---|
| Supabase | ✅ | ✅ |
| MongoDB | ✅ | planned |
| Firebase, Postgres, MySQL, cross-backend | planned | planned |

## License

MIT. Exception: `database_sentinel/agent/`, `database_sentinel/mcp_server/` and `database_sentinel/kb/` are AGPL-3.0 (see the `LICENSE` in each).

---

## Appendix

### A. Pattern highlights

**Supabase**

| Severity | Pattern | What |
|---|---|---|
| 🔴 CRITICAL | `RLS_DISABLED` | Tables without Row-Level Security are fully exposed |
| 🔴 CRITICAL | `SERVICE_ROLE_EXPOSED` | service_role key in frontend code bypasses all security |
| 🔴 CRITICAL | `POLICIES_BUT_NO_RLS` | Policies written but RLS never enabled |
| 🟠 HIGH | `USING_TRUE` | `USING (true)` on writes or private data |
| 🟠 HIGH | `VIEW_NO_SECURITY_INVOKER` | Views bypass RLS and run as their owner |
| 🟠 HIGH | `SECURITY_DEFINER_EXPOSED` | RLS-bypassing functions callable via the API |
| 🟠 HIGH | `USER_METADATA_IN_POLICY` | Policies trust user-editable metadata |
| 🟠 HIGH | `MASS_ASSIGNMENT` | Users can update privilege/billing columns on their own rows |
| 🟠 HIGH | `GHOST_AUTH` | Unconfirmed sign-ups get authenticated sessions |
| 🟠 HIGH | `JWT_SECRET_EXPOSED` | Leaked signing secret lets attackers forge any token |
| 🟡 MEDIUM | + 17 more | [anti-patterns.md](backends/supabase/anti-patterns.md) |

**MongoDB**

| Severity | Pattern | What |
|---|---|---|
| 🔴 CRITICAL | `MG-SH-001` MongoBleed (CVE-2025-14847, CISA KEV) | Pre-auth heap memory disclosure; ~87K instances exposed at disclosure |
| 🔴 CRITICAL | `MG-SH-002` Auth disabled | No authentication (Meow ransomware surface) |
| 🔴 CRITICAL | `MG-SH-003` Internet-bound mongod | `--bind_ip_all` + reachable 27017 |
| 🔴 CRITICAL | `MG-AT-001` Atlas allowlist `0.0.0.0/0` | Cluster reachable from anywhere |
| 🟠 HIGH | `MG-SH-005` Server-side JS enabled | `$where` / `$function` / `mapReduce` reachable |
| 🟠 HIGH | `MG-SH-007` Privileged app user | App connects as `root` / `dbAdminAnyDatabase` |
| 🟠 HIGH | `MG-AT-002` Atlas Function pass-through | NoSQL injection over HTTPS |
| 🟡 MEDIUM | + 13 more | [anti-patterns.md](backends/mongodb/anti-patterns.md) |

The MongoBleed probe ([mongobleed-probe.md](backends/mongodb/mongobleed-probe.md)) is a single-packet, read-only detector. It was verified against `mongo:7.0.20` (vulnerable) and `7.0.28` (patched), and runs only after two opt-in confirmations.

### B. How the Skill audits

1. Detect backends. 2. Scan code for exposed credentials. 3. Introspect schema, policies and config. 4. Match against the anti-pattern catalogs. 5. Probe safely (opt-in). 6. Score and report. 7. Generate fix code.

Only `SKILL.md` (~2K tokens) and `core/*` load up front; each backend's files load only when that backend is detected.

### C. Example output

```
╔════════════════════════════════════════════════════════╗
║                  SENTINEL SECURITY AUDIT               ║
║  Backends: supabase        Score: 35/100 🔴            ║
╚════════════════════════════════════════════════════════╝

🔴 CRITICAL — public.users: RLS Disabled                  [RLS_DISABLED]
  Risk:   Anyone on the internet can read your entire users table.
  Attack: Copy the anon key from DevTools → curl the API → dump all rows.
  Source: CVE-2025-48757 / Splinter 0013_rls_disabled_in_public
  Fix:    ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
          CREATE POLICY "users_select_own" ON public.users FOR SELECT
            TO authenticated USING ((SELECT auth.uid()) = id);
```

### D. Safety details

- **Supabase write probes:** `Prefer: tx=rollback`, so no data is modified.
- **MongoDB write probes:** session + `abortTransaction()` on replica sets; canary insert + delete on standalone (opt-in).
- **MongoBleed network probe:** double opt-in; some monitoring tools alert on the 42-byte probe packet.
- **Auth probes** use `.invalid` email domains (RFC 6761).
- **Credentials** are held in memory for the audit only, and redacted in reports.
- **MCP server:** five independent read-only layers ([details](docs/mcp.md#safety-model)).

### E. Benchmark and evals

`bench/cases/` holds labeled Supabase schemas applied to a local Supabase. `evals/` scores three systems on precision, recall and F1: R0 (rules, no LLM), B0 (single prompt) and A (agent). The test split is frozen and never tuned on.

Test split (10 blind, locked cases), `deepseek-v4-flash`, 3 runs each:

| Version | System | Precision | Recall | F1 | CRITICAL recall | $/audit |
|---|---|---|---|---|---|---|
| v0.2.1 | A (agent) | 0.851 | 0.818 | **0.831** | 1.000 | $0.0044 |
| v0.2.1 | B0 (single prompt) | 0.810 | 0.894 | **0.849** | 1.000 | $0.0008 |
| v0.2.0 (frozen, [details](docs/evals/2026-09-29-test.md)) | A (agent) | 0.774 | 0.803 | 0.782 | 1.000 | $0.0024 |
| v0.2.0 (frozen) | B0 (single prompt) | 0.795 | 0.743 | 0.766 | 0.889 | $0.0016 |
| both | R0 (rules) | 0.413 | 0.864 | 0.559 | 1.000 | $0 |

v0.2.1 fixes the crashes and timeouts seen in the v0.2.0 test run. The fixes were diagnosed on dev only, but they came from test failures, so v0.2.0 is the blind number ([v0.2.1 details](docs/evals/2026-09-30-test-v0.2.1.md)). A and B0 are within noise of each other. The agent is more precise, gives fewer false alarms on clean projects and verifies findings as anon, at ~5× the cost.

```bash
pip install -e ".[dev]" && supabase start && python -m evals.run --split dev
```

### F. Continuous monitoring (GitHub Actions)

Templates: [`github-action-supabase.yml`](assets/ci/github-action-supabase.yml) and [`github-action-mongodb.yml`](assets/ci/github-action-mongodb.yml). They run on migration, rule or IaC changes, weekly, or manually, then comment on the PR and fail the build on critical findings. Ask Claude: *"Set up continuous security monitoring for this project."*

### G. Repo layout

```
SKILL.md, core/, backends/{supabase,mongodb}/, references/   Claude Skill (MIT)
database_sentinel/mcp_server/                                MCP server (AGPL)
database_sentinel/agent/                                     lite agent (AGPL)
bench/, evals/, tests/, supabase/                            benchmark, eval harness, local Supabase
docs/mcp.md                                                  MCP setup guide
compat/supabase-sentinel/                                    old skill name shim
```

### H. Research sources

CVE-2025-48757 (170+ Lovable apps), Escape.tech (2,000+ vulns in 5,600 vibe-coded apps), Veracode (45% of AI code has OWASP Top 10 issues), CMU SusVibes, ModernPentest (20.1M rows, 107 YC startups), Supabase Splinter lints, CVE-2025-14847 MongoBleed, Mongoose CVE-2024-53900 / CVE-2025-23061, CIS MongoDB 7 Benchmark. Full list: [vibe-coding-context.md](references/vibe-coding-context.md), [cve-feed.md](references/cve-feed.md).

### I. Contributing

Most valuable: new anti-patterns with evidence (CVE, breach report, or lint), better fix templates, false-positive/negative reports from live use, and new backends following `backends/supabase/`. Fork, branch, and open a PR with the pattern and its source. Contributions to the AGPL directories need a CLA.

### J. Naming history

Supabase Sentinel (v1) → Database Sentinel (v3, multi-backend). The `supabase-sentinel` name still works through `compat/supabase-sentinel/`.
