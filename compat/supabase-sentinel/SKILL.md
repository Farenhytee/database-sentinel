---
name: supabase-sentinel
description: "Audit any Supabase project for security vulnerabilities, RLS misconfigurations, exposed API keys, auth bypasses, and storage issues. Use this skill whenever the user mentions Supabase security, RLS policies, database security audit, security review, penetration testing a Supabase app, checking if their database is exposed, hardening their Supabase project, fixing RLS, or anything related to securing a Supabase or vibe-coded application. Also trigger when the user asks about securing apps built with Lovable, Bolt, Replit, Cursor, or any AI coding tool that uses Supabase as a backend. Even if the user just says 'is my app secure' or 'check my database' and their project uses Supabase, use this skill. (DEPRECATED: this skill is a backwards-compat shim. Prefer the multi-backend `sentinel` skill, which covers Supabase plus Firebase, MongoDB, self-hosted Postgres, and self-hosted MySQL.)"
---

# Supabase Sentinel — backwards-compat shim

> **DEPRECATED.** This skill exists only to preserve the original `supabase-sentinel` trigger surface for users who installed it before the multi-backend rename. New audits should use the **`sentinel`** skill (one level up at the repo root), which handles Supabase identically and adds Firebase, MongoDB, self-hosted Postgres, and self-hosted MySQL.
>
> Sunset date: TBD — keep at minimum through the next minor release of Sentinel. After that, this stub will be removed and `supabase-sentinel` will resolve to the multi-backend skill via skill-name aliasing.

## What this shim does

When invoked, this skill:

1. Loads the parent **`sentinel`** skill's workflow.
2. Forces the audit to **Supabase only** — even if other backends are detected in the working directory, only the Supabase audit runs.
3. Behaves identically to the v1 Supabase Sentinel: same 7-step workflow, same 27 anti-patterns (`SB-001..SB-027`), same fix templates, same CI workflow template.

## How to invoke

Same as before — say things like:

- "Audit my Supabase project for security issues"
- "Is my Supabase database exposed?"
- "Check my RLS policies"
- "Run a security review of this Supabase app"

The shim will dispatch to the multi-backend `sentinel` skill with `backend=supabase` pinned.

## Behavior contract

The shim **must**:

- Run the same 7-step workflow as the v1 Supabase Sentinel.
- Produce a report indistinguishable from the v1 output (same scoring, same finding format, same Passing section, same footer).
- Reference the same files: `../../backends/supabase/workflow.md`, `../../backends/supabase/anti-patterns.md`, `../../backends/supabase/audit-queries.md`, `../../backends/supabase/fix-templates.md`, `../../assets/ci/github-action-supabase.yml`.
- Skip detection of other backends (the user invoked the Supabase-specific skill explicitly).

The shim **must not**:

- Audit Firebase, MongoDB, or self-hosted SQL backends, even if signals are present.
- Emit a "cross-backend interactions" section (single-backend mode only).
- Mention the rename in the report itself unless the user asks how to migrate. The deprecation notice belongs in tool output / changelog, not in the user-facing audit report.

## Migration

Users who want multi-backend coverage should invoke `sentinel` instead — same triggers, broader coverage. No project changes are needed; detection picks up the additional backends automatically.

If only Supabase is in use, `sentinel` and `supabase-sentinel` produce identical output. The rename is purely about expanding the trigger surface.

---

## Implementation pointer

The actual workflow lives at `../../backends/supabase/workflow.md`. This file is intentionally thin — it exists so the `supabase-sentinel` skill name continues to resolve until the deprecation window closes.
