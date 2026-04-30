# Sentinel — Report Format

Unified report layout for single- and multi-backend audits. Each backend produces a section in this format; the dispatcher concatenates them and adds a cross-backend section if applicable.

---

## Top-level header

```
╔════════════════════════════════════════════════════════╗
║                  SENTINEL SECURITY AUDIT               ║
╠════════════════════════════════════════════════════════╣
║  Backends:   [comma-separated list]                    ║
║  Scanned:    [ISO 8601 UTC timestamp]                  ║
║  Score:      [headline X/100] [emoji]                  ║
║  Summary:    [N] backends, [M] findings (C/H/M/L)      ║
╚════════════════════════════════════════════════════════╝
```

`Backends:` lists the detected set in the order they were audited (alphabetical for stable diffs in CI).
`Score:` is the **minimum** of per-backend scores (see `core/scoring.md`).
`Summary:` is a quick count: "2 backends, 14 findings (3 CRITICAL / 5 HIGH / 4 MEDIUM / 2 LOW)".

---

## Per-backend section

One section per detected backend. Header:

```
─────────────────────────────────────────────────────────
  Supabase                                       42/100 🟠
─────────────────────────────────────────────────────────
  Project:    https://abcdefg.supabase.co
  Tables:     12 audited
  Policies:   8 reviewed
  Findings:   2 CRITICAL · 3 HIGH · 1 MEDIUM
```

Then findings, ordered: CRITICAL first → HIGH → MEDIUM → LOW → INFO. Within severity, sort by likely sensitivity of the affected resource (users / payments / orders before posts / comments / settings).

---

## Finding format

Every finding follows the same shape across backends:

```
🔴 CRITICAL — users: RLS Disabled                       [SB-001]

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
```

Required fields:

- **Severity emoji + label** — 🔴 CRITICAL · 🟠 HIGH · 🟡 MEDIUM · ℹ️ LOW · 💬 INFO
- **Resource identifier** — table / collection / file / role / function name
- **Short title** — under ~50 chars
- **Pattern ID** in brackets — `SB-NNN`, `FB-XX-NNN`, `MG-XX-NNN`, `PG-XX-NNN`, `MY-XX-NNN`
- **Risk** — one sentence a non-developer understands
- **Attack** — concrete attacker scenario (who, with what access, gets what)
- **Proof** — exact command output, query result, or rules-AST excerpt
- **Source** — CVE / Splinter lint ID / CIS control / breach citation
- **Fix** — exact SQL, JS, rules, or config diff. No "consider" or "you might want to" — direct imperative.

Optional fields:

- **Likely AI-generated** tag if the pattern matches known Cursor / Bolt / Lovable / Claude Code output (see `references/vibe-coding-context.md`)
- **Splinter lint ID** if mapped (Supabase only)
- **CIS control** if mapped (Postgres / MySQL self-hosted)

---

## Passing section

After findings, list properly-secured resources:

```
✅ PASSING — Supabase

  orders, payments, invoices, subscriptions
    RLS enabled with appropriate ownership policies, no service_role
    leakage detected, OpenAPI schema not exposed.
```

This isn't filler — it's calibration. Praising what's done right helps non-technical users distinguish what to keep from what to change.

---

## Cross-backend interactions section

Only emitted when multiple backends are detected AND at least one cross-backend interaction is flagged. Format:

```
─────────────────────────────────────────────────────────
  Cross-Backend Interactions                    -25 to score
─────────────────────────────────────────────────────────

🔴 CRITICAL — Firebase Auth + Postgres self-hosted: Trust without verification

  Risk:     Your Postgres API trusts a Firebase user ID from the request
            body without verifying the JWT issuer. Anyone can impersonate
            any user by sending their UID.
  Attack:   curl -X POST $API/orders -d '{"user_id":"victim_uid", ...}'
            — no JWT validation; Postgres write succeeds with attacker
            data attributed to the victim.
  Affects:  firebase (UID source) + postgres-selfhosted (trust point)
  Score:    -25 deducted from postgres-selfhosted (lower of the two).

  Fix:
  - In your API middleware, verify the Firebase ID token before passing
    user_id to Postgres:
        const decoded = await admin.auth().verifyIdToken(req.headers.authorization);
        const userId = decoded.uid;  // never req.body.user_id
  - Add an integration test that a forged user_id is rejected.
```

Cross-backend findings are listed by overall severity, then by which backends they touch.

Patterns to flag (non-exhaustive — `core/cross-backend.md` will be the canonical list once Phase 6 lands):

1. Auth UID from one backend trusted by another without JWT verification.
2. Same secret reused across multiple connection strings.
3. Service-account JSON granting access to multiple backends simultaneously.
4. Firebase data migrated to Postgres but Firestore copy still readable.
5. Atlas Function calling Cloud Run that holds GCS service-account keys.

---

## Footer

```
─────────────────────────────────────────────────────────

Total findings: 2 CRITICAL · 3 HIGH · 1 MEDIUM · 0 LOW
Headline score: 42/100 🟠 (driven by Firebase 35/100)

Want me to:
  [1] Generate migration / fix files for everything above?
  [2] Set up GitHub Actions for continuous monitoring per backend?
  [3] Walk through the top 3 fixes step-by-step?

Limitations: Sentinel covers database / API / configuration security.
It does not cover XSS, CSRF, SSRF, business logic, or infrastructure
beyond the data layer.
```

The footer always offers the same three follow-ups; they map to Steps 5, 6, and 5-with-handholding respectively.

---

## Machine-readable output (for CI)

The same report renders as JSON for CI pipelines. Schema:

```json
{
  "schema_version": 1,
  "scanned_at": "2026-04-29T14:30:00Z",
  "backends": [
    {
      "name": "supabase",
      "score": 42,
      "findings": [
        {
          "severity": "CRITICAL",
          "pattern_id": "SB-001",
          "resource": "public.users",
          "title": "RLS Disabled",
          "risk": "...",
          "attack": "...",
          "proof": "...",
          "source": "CVE-2025-48757",
          "fix": {
            "language": "sql",
            "before": "...",
            "after": "ALTER TABLE public.users ENABLE ROW LEVEL SECURITY; ...",
            "apply_method": "psql / Dashboard SQL Editor",
            "rollback_method": "ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;",
            "validation": "SELECT rowsecurity FROM pg_tables WHERE tablename='users';"
          },
          "ai_generated_tag": false
        }
      ],
      "passing": ["orders", "payments", "invoices", "subscriptions"]
    }
  ],
  "cross_backend_findings": [],
  "headline_score": 42,
  "summary": {
    "total": 6,
    "critical": 2,
    "high": 3,
    "medium": 1,
    "low": 0,
    "info": 0
  }
}
```

This format is the contract for `assets/ci/github-action-*.yml` — actions parse it with `jq` to gate merges on `headline_score >= threshold` or `summary.critical == 0`.

---

## Style rules

- **Active voice.** "Anyone can read your users table" — not "user data is potentially accessible."
- **Concrete attackers.** "An attacker who copies your anon key from DevTools" — not "a bad actor."
- **No marketing words.** Sentinel is a tool, not a product pitch. No "industry-leading," "best-in-class," "comprehensive coverage."
- **Cite when possible.** Every CRITICAL/HIGH should reference a CVE or named breach. The vibe-coding context file is the source of record.
