# Database Sentinel — Locked Decisions

Decisions made before Phase 1 begins, per `sentinel-implementation-plan.md` §0. Subsequent sessions should treat these as immutable unless explicitly overturned. Overturns are recorded inline with date.

| ID | Question | Decision | Rationale |
|----|----------|----------|-----------|
| **D1** | Repo strategy: monorepo or multi-repo? | **Monorepo** at `/Library/Personal/supabase skill/` (current path). | Single skill folder containing all backends. One git history; refactors cross boundaries cleanly. |
| **D2** | Root skill name | **`database-sentinel`** *(superseded `db-sentinel`, 2026-04-30; superseded `sentinel`, 2026-04-30)* | Originally `sentinel`, then briefly `db-sentinel`. Renamed to `database-sentinel` to (a) make the database-security framing fully explicit in skill discovery — the abbreviation `db-` is less searchable than the full word — and (b) match the GitHub repo name `Farenhytee/database-sentinel` so the clone URL, repo, and skill identifier all align. The skill `name:` field in `SKILL.md` frontmatter is `database-sentinel`. The project is referred to as **Database Sentinel** in user-facing docs (README, report headers); shorthand "Sentinel" is fine in internal references where context is clear. |
| **D3** | Backwards compatibility for `supabase-sentinel` | **Yes — ship a stub.** A second skill named `supabase-sentinel` exists at `compat/supabase-sentinel/SKILL.md` and forces `--backend supabase` against the dispatcher. Sunset date TBD; keep through at least the next minor release. | Existing users have it installed. Silent breakage is unacceptable. |
| **D4** | Where the work happens | **Local-only branch.** No GitHub remote configured. PRs are not part of the workflow yet. | Matches current repo state (no remote in `git remote -v`). |

## Conventions derived from these decisions

- Skill name in YAML frontmatter at the root: `name: database-sentinel`
- Backwards-compat stub frontmatter: `name: supabase-sentinel`, body delegates to `database-sentinel` with `backend=supabase` pinned
- Per-backend modules live at `backends/<name>/` with the structure defined in `sentinel-implementation-plan.md` §1
- `references/` at the root holds cross-backend material (vibe-coding-context, CVE feed, tooling)
- `assets/ci/` holds per-backend GitHub Action templates

## Defaults applied for unanswered Phase 1 questions

| Q | Question | Applied default |
|---|----------|-----------------|
| Q1 | Session scope | **Phase 1 only** this session. Stop at the `STOP — HUMAN REVIEW` gate before Phase 2. |
| Q2 | End-to-end tests | **Document-only** (Docker recipes recorded; no live runs in this environment). |
| Q3 | "Integrate" external tools | **Reference, don't invoke.** External tools (pgdsat, FireScan, OpenFirebase, Wiz Nuclei templates) are documented in `references/tooling.md`. SKILL.md does not shell out to them. |
| Q4 | Phase 1 smoke test | **Structural verification.** Confirm no SKILL.md path references the old layout; document the manual smoke-test recipe for the user. |
| Q5 | Token budget enforcement | **Rough `wc -w * 1.3`** as proxy. Acceptable for the ≤8K SKILL.md contract; revisit if a real tokenizer becomes available. |
