# 🛡️ Supabase Sentinel

**A Claude Skill that audits your Supabase project for security vulnerabilities.**

Drop it into Claude Code, Cursor, or any Claude-powered environment. Say "audit my Supabase project" and get a comprehensive security report with exact fix SQL — in minutes, not days.

> **170+ Lovable apps were breached.** 20.1M rows were exposed across YC startups. 45% of AI-generated code introduces OWASP Top 10 vulnerabilities. Supabase's built-in Security Advisor only checks whether RLS *exists* — Supabase Sentinel tests whether it actually *works*.

---

## What it does

Supabase Sentinel performs a 7-step security audit on any Supabase project:

1. **Scans your codebase** for exposed service_role keys, hardcoded JWTs, and secrets committed to git
2. **Introspects your database** schema — tables, RLS policies, views, functions, storage buckets
3. **Matches against 27 known vulnerability patterns** sourced from CVE-2025-48757, 10 published security studies, and thousands of documented breaches
4. **Dynamically probes your API** using the `Prefer: tx=rollback` technique (zero data modified, safe for production)
5. **Tests ghost auth** — can attackers create unconfirmed accounts and access your data?
6. **Generates a scored security report** with plain-English explanations and concrete attacker scenarios
7. **Produces exact fix SQL** — copy, paste, done

---

## Quick start

### Option 1: Claude Code / Cursor

Copy the skill folder into your project:

```bash
# Clone into your project's skills directory
git clone https://github.com/Farenhytee/supabase-sentinel.git .claude/skills/supabase-sentinel

# Or if you have a central skills directory
git clone https://github.com/Farenhytee/supabase-sentinel.git ~/claude-skills/supabase-sentinel
```

Then just ask Claude:

```
Audit my Supabase project for security issues
```

Claude will auto-detect your Supabase credentials from `.env` files, run the full audit, and present a report.

### Option 2: Claude.ai (with computer use)

1. Download this repo as a ZIP
2. Upload it to a Claude.ai conversation with computer use enabled
3. Ask: "Use the Supabase Sentinel skill to audit my Supabase project"
4. Provide your Supabase URL and keys when prompted

### Option 3: Manual (any AI assistant)

Copy the contents of `SKILL.md` into your system prompt or conversation, then follow the workflow with your Supabase credentials.

---

## What it catches

### Critical

| Pattern | Description |
|---------|-------------|
| `RLS_DISABLED` | Tables without Row-Level Security — fully exposed to the internet |
| `SERVICE_ROLE_EXPOSED` | service_role key in frontend code — bypasses ALL security |
| `POLICIES_BUT_NO_RLS` | Policies written but RLS never enabled — false sense of security |
| `WRITE_USING_TRUE` | INSERT/UPDATE/DELETE with `USING(true)` — anyone can modify data |

### High

| Pattern | Description |
|---------|-------------|
| `USING_TRUE_SELECT` | All rows readable by anonymous users on sensitive tables |
| `VIEW_NO_SECURITY_INVOKER` | Views bypass RLS, running as superuser |
| `SECURITY_DEFINER_EXPOSED` | Functions in public schema bypass RLS, callable via API |
| `USER_METADATA_IN_POLICY` | Policies reference user-modifiable metadata — privilege escalation |
| `UPDATE_NO_WITHCHECK` | UPDATE policies without WITH CHECK — mass assignment risk |
| `GHOST_AUTH` | Unconfirmed email signups grant authenticated sessions |
| `STORAGE_NO_RLS` | Storage bucket missing access control policies |
| `JWT_SECRET_EXPOSED` | JWT signing secret leaked — can forge any user's token |

### Medium

| Pattern | Description |
|---------|-------------|
| `RLS_NO_POLICIES` | RLS enabled but no policies — all access silently denied (bug) |
| `POLICY_NO_ROLE_SCOPE` | Policy applies to all roles including anonymous |
| `MULTIPLE_PERMISSIVE` | Multiple permissive policies OR'd — most permissive wins |
| `RLS_PERFORMANCE` | `auth.uid()` not cached — performance degradation, potential DoS |
| `PUBLIC_BUCKET` | Storage bucket publicly accessible without auth |
| `SENSITIVE_COLUMNS` | Columns named `password`, `api_key`, etc. exposed via API |
| + 9 more patterns | See `references/anti-patterns.md` for the full list |

---

## Example output

```
╔════════════════════════════════════════════════════════╗
║          SUPABASE SENTINEL SECURITY REPORT             ║
╠════════════════════════════════════════════════════════╣
║  Project:   https://myapp.supabase.co                  ║
║  Scanned:   2026-03-15 14:30 UTC                       ║
║  Score:     35/100 🔴                                   ║
║  Summary:   12 tables, 8 policies, 7 findings          ║
╚════════════════════════════════════════════════════════╝

🔴 CRITICAL — users: RLS Disabled

  Risk:     Anyone on the internet can read your entire users table
  Attack:   Open browser DevTools → copy anon key → curl the API → dump all emails, names, metadata
  Proof:    curl returns [{"id":"...","email":"user@real.com",...}]

  Fix:
  ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

  CREATE POLICY "users_select_own"
    ON public.users FOR SELECT TO authenticated
    USING ((SELECT auth.uid()) = id);

🟠 HIGH — profiles: SELECT policy uses USING(true)

  Risk:     All user profiles are readable by anyone, including anonymous users
  Attack:   Enumerate all profiles via the API to harvest user data
  ...

✅ PASSING: orders, payments, invoices, subscriptions (4 tables properly secured)
```

---

## File structure

```
supabase-sentinel/
├── SKILL.md                           # Core skill — 7-step audit workflow (333 lines)
├── references/
│   ├── audit-queries.md               # 20 SQL queries for schema introspection
│   ├── anti-patterns.md               # 27 vulnerability patterns with severity/detection/fix
│   ├── fix-templates.md               # SQL fix templates — 7 RLS patterns, storage, auth, prevention
│   └── vibe-coding-context.md         # CVE-2025-48757, research studies, platform analysis
├── assets/
│   └── github-action-template.yml     # CI/CD workflow for continuous monitoring
├── README.md
└── LICENSE                            # MIT
```

**How progressive disclosure works:** When Claude loads this skill, it only reads the 333-line `SKILL.md` initially (~5000 tokens). Reference files are loaded on-demand during specific audit steps — `audit-queries.md` at Step 1, `anti-patterns.md` at Step 2, `fix-templates.md` at Step 5. This keeps context usage efficient.

---

## Continuous monitoring (GitHub Action)

Supabase Sentinel can generate a GitHub Action that:
- Runs on every push to `supabase/migrations/`
- Runs weekly (Monday 6am UTC)
- Posts findings as PR comments
- Blocks merges on CRITICAL findings

Just ask: "Set up continuous security monitoring for this project."

See `assets/github-action-template.yml` for the template.

---

## Research backing

This skill's anti-pattern database is sourced from:

- **CVE-2025-48757** — 170+ Lovable apps exposed, CVSS 9.3 (Matt Palmer, May 2025)
- **Escape.tech** — 2,000+ vulnerabilities across 5,600 vibe-coded apps (October 2025)
- **Veracode** — 45% of AI-generated code introduces OWASP Top 10 vulnerabilities (July 2025)
- **Carnegie Mellon SusVibes** — 82.8% of functionally correct AI code was insecure (December 2025)
- **SupaExplorer** — 11% of indie apps expose Supabase credentials (January 2026)
- **ModernPentest** — 20.1M rows exposed across 107 YC startups (March 2026)
- **Wiz Research** — Critical auth bypass in Base44 vibe-coding platform (July 2025)
- **Supabase Security Retro 2025** — Official documentation of built-in advisor capabilities and gaps
- **Supabase Splinter** — All 16 official security lints mapped and extended

See `references/vibe-coding-context.md` for the full research breakdown.

---

## What Supabase Sentinel catches that Supabase Security Advisor doesn't

Supabase's built-in Security Advisor (Splinter) runs 16 lints. Supabase Sentinel extends this with:

| Gap | What Splinter misses | Supabase Sentinel covers |
|-----|---------------------|-------------------|
| Policy correctness | Only checks if policies exist | Tests if they actually prevent unauthorized access |
| Dynamic probing | Static analysis only | Live API testing with `tx=rollback` |
| Ghost auth | Not checked | Tests email confirmation bypass |
| Mass assignment | Not checked | Detects UPDATE without WITH CHECK + sensitive columns |
| Storage config | Not checked | Audits bucket visibility and storage.objects RLS |
| Codebase scanning | Not applicable | Finds service_role keys in frontend code |
| Key exposure | Not checked | Detects hardcoded JWTs and committed .env files |
| Column-level security | Not checked | Flags sensitive columns accessible via API |
| CI/CD integration | Not available | GitHub Action for continuous monitoring |

---

## Contributing

Contributions are welcome! The most valuable contributions are:

1. **New anti-patterns** — Found a Supabase security issue not in our database? Add it to `references/anti-patterns.md` with severity, detection query, fix SQL, and real-world evidence.
2. **Fix template improvements** — Better RLS policy patterns, edge cases, or performance optimizations in `references/fix-templates.md`.
3. **Testing on real projects** — Run Supabase Sentinel on your own Supabase projects and report false positives/negatives.
4. **Platform-specific patterns** — Document security patterns specific to Lovable, Bolt, Replit, or other vibe-coding platforms.

### How to contribute

1. Fork this repo
2. Create a branch (`git checkout -b add-new-pattern`)
3. Add your changes with clear documentation
4. Submit a PR with a description of the pattern and evidence

---

## Roadmap

- [ ] **CLI tool** — `npx supabase-sentinel audit` for non-Claude environments
- [ ] **MCP server** — programmatic access for CI/CD and dashboards
- [ ] **Firebase support** — extend to Firebase Security Rules auditing
- [ ] **Premium dashboard** — historical trending, multi-project views, Slack alerts
- [ ] **VS Code extension** — inline security warnings in the editor

---

## Safety

Supabase Sentinel is designed to be safe for production use:

- **Dynamic tests use `Prefer: tx=rollback`** — PostgREST processes the request, evaluates RLS, returns the result, then rolls back. Zero data modified.
- **Auth probes use `.invalid` TLD** — test emails use RFC 2606 reserved domains that cannot receive mail.
- **Read-only introspection** — schema queries only read `pg_tables`, `pg_policies`, and `information_schema`. No DDL or DML.
- **Open source** — audit the auditor. Every query and test is visible in the source.

---

## License

MIT — use it however you want, commercially or otherwise.

---

<p align="center">
  <b>Built for the vibe-coding era.</b><br>
  Because "it works" and "it's secure" are two very different things.
</p>
