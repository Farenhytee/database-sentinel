# Benchmark

`cases/NNN-slug/`: `schema.sql` (applied to a fresh local Supabase), `labels.yaml`, optional `frontend/` (fake keys only).
`splits.yaml`: dev/test assignment. **Test split is frozen: never tune on it.**

Each case ends with a `-- seed` block inserting a few rows into its tables, so `probe_as_anon` can tell "readable" from "empty". `seed_users.sql` runs first and creates alice (`00000000-0000-0000-0000-000000000001`) and bob (`…0002`) in `auth.users`.

## Labeling rules
Labels are exhaustive for in-scope patterns (`agent.catalog.in_scope()`). Object: `schema.name` lowercase (policies → their table, functions without args), `storage.<bucket>`, or file path relative to `frontend/`.

A table with policies but RLS off is POLICIES_BUT_NO_RLS only (not also RLS_DISABLED).

Objective (label whenever present): RLS_DISABLED (only if anon or authenticated has table privileges), POLICIES_BUT_NO_RLS, RLS_NO_POLICIES, USER_METADATA_IN_POLICY, POLICY_NO_ROLE_SCOPE, MULTIPLE_PERMISSIVE, MUTABLE_SEARCH_PATH (SECURITY DEFINER without search_path), VIEW_NO_SECURITY_INVOKER and MATVIEW_EXPOSED (only if the API roles can select them), SERVICE_ROLE_EXPOSED, JWT_SECRET_EXPOSED.

Judgment (label only when exploitable):
- USING_TRUE: `true` on a write, or on SELECT of data not meant to be public. Public catalogs (`products`, published posts) are not findings.
- SECURITY_DEFINER_EXPOSED: callable via `/rpc` by anon/authenticated. Trigger functions, revoked functions and non-exposed schemas are not.
- EXPOSED_RPC_NO_AUTH: anon-executable function touching data with no auth check. Pure helpers (e.g. `slugify`) and functions checking `auth.uid()` are not.
- PUBLIC_BUCKET: public bucket holding private content (invoices, documents). Avatars/public assets are not.
- SENSITIVE_COLUMNS: secret/credential/payment column selectable by anon or authenticated (one per table).
- MASS_ASSIGNMENT: authenticated can UPDATE a privilege/billing column (any name) on rows it can update.

Not evaluated: manual-check patterns (auth config), RLS_PERFORMANCE, UPDATE_NO_WITHCHECK (Postgres reuses USING as WITH CHECK), STORAGE_NO_RLS (RLS is always on for `storage.objects`).
