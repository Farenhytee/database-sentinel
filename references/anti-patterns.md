# Anti-Pattern Database

Complete catalog of Supabase security vulnerability patterns. Each entry includes severity, description, detection method, real-world impact, and fix.

## Table of contents

1. [CRITICAL — RLS Disabled](#critical-severity)
2. [CRITICAL — Service Role Key Exposed](#srk-exposed)
3. [CRITICAL — Policies Exist but RLS Disabled](#false-security)
4. [HIGH — Overly Permissive Policies](#permissive-policies)
5. [HIGH — Views Bypassing RLS](#views-bypass)
6. [HIGH — Security Definer Functions Exposed](#secdef-functions)
7. [HIGH — user_metadata in Policies](#user-metadata)
8. [HIGH — Missing WITH CHECK on UPDATE](#missing-withcheck)
9. [HIGH — Mass Assignment via Column Updates](#mass-assignment)
10. [HIGH — Ghost Auth (Email Confirmation Bypass)](#ghost-auth)
11. [HIGH — Missing Storage RLS](#storage-rls)
12. [HIGH — JWT Secret Exposure](#jwt-secret)
13. [HIGH — Exposed RPC Functions](#exposed-rpc)
14. [MEDIUM — Policies Not Scoped to Roles](#unscoped-policies)
15. [MEDIUM — Multiple Permissive Policies OR'd](#multiple-permissive)
16. [MEDIUM — RLS Enabled but No Policies](#rls-no-policies)
17. [MEDIUM — Performance Anti-Patterns](#performance)
18. [MEDIUM — Materialized Views in API](#matviews)
19. [MEDIUM — Function Search Path Mutable](#mutable-searchpath)
20. [MEDIUM — Public Storage Buckets](#public-buckets)
21. [MEDIUM — Sensitive Column Names](#sensitive-columns)
22. [MEDIUM — OAuth Redirect Wildcards](#oauth-redirects)
23. [MEDIUM — Weak Password Configuration](#weak-passwords)
24. [MEDIUM — Anonymous Auth Abuse](#anon-auth)
25. [LOW — Missing Rate Limiting](#rate-limiting)
26. [LOW — OpenAPI Schema Exposure](#openapi-exposure)
27. [INFO — SQL Editor Testing Trap](#sql-editor-trap)

---

<a id="critical-severity"></a>
## 🔴 CRITICAL: RLS Disabled on Public Tables

**ID:** `RLS_DISABLED`
**Splinter lint:** `0013_rls_disabled_in_public`
**What happens:** Tables without RLS in the public schema are fully accessible to anyone with the anon key — read, write, update, delete. The anon key is embedded in frontend JavaScript by design and is visible to anyone who opens browser DevTools.
**Root cause:** Tables created via SQL Editor, migrations, ORMs (Prisma, Drizzle), or Supabase CLI do NOT have RLS enabled by default. Only tables created via the Dashboard Table Editor get RLS auto-enabled. AI code generators almost always use SQL/migrations.
**Real-world impact:** CVE-2025-48757 — 170+ Lovable apps exposed. DeepStrike found thousands of exposed instances globally. ModernPentest exposed 20.1M rows at 107 YC startups.
**Detection:** See audit-queries.md Q1.
**Fix:** `ALTER TABLE public.TABLE_NAME ENABLE ROW LEVEL SECURITY;` then create appropriate policies. See fix-templates.md for policy patterns.

<a id="srk-exposed"></a>
## 🔴 CRITICAL: Service Role Key in Frontend Code

**ID:** `SERVICE_ROLE_EXPOSED`
**What happens:** The service_role key has `BYPASSRLS` privilege — it ignores ALL Row Level Security policies. When embedded in client-side code, attackers get unrestricted database access equivalent to root/superuser.
**Root cause:** Developers use `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` or similar public env var prefixes, or hardcode the key directly. AI code generators frequently make this mistake because they don't understand the distinction between anon and service_role keys.
**Detection:** Search JS bundles for JWT patterns starting with `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`. Decode any found JWTs and check if the `role` claim is `service_role`. Also grep for env variable names containing `SERVICE_ROLE` with public prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`).
**Fix:** Remove from all frontend code. Use server-side only (Next.js Server Components, API Routes, Edge Functions). Import `'server-only'` guard in admin client files. Rotate key if exposed: Dashboard → Settings → API.

<a id="false-security"></a>
## 🔴 CRITICAL: Policies Defined but RLS Not Enabled

**ID:** `POLICIES_BUT_NO_RLS`
**Splinter lint:** `0007_policy_exists_rls_disabled`
**What happens:** Developer wrote RLS policies (showing security awareness) but forgot the `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` statement. Policies are stored but never enforced. The table appears to be secured in dashboard policy views.
**Detection:** See audit-queries.md Q3.
**Fix:** `ALTER TABLE public.TABLE_NAME ENABLE ROW LEVEL SECURITY;`

<a id="permissive-policies"></a>
## 🟠 HIGH: Overly Permissive Policies (USING true)

**ID:** `USING_TRUE`
**Splinter lint:** `0024_permissive_rls_policy`
**What happens:** `USING (true)` means "this policy matches all rows." On a SELECT policy, all rows are readable by the target role. On INSERT/UPDATE/DELETE, all writes are allowed.
**Root cause:** Developers want to "make it work" during development, add `USING (true)`, and forget to restrict it before deployment. AI code generators default to this pattern because it's the simplest working policy.
**Detection:** See audit-queries.md Q6.
**Fix:** Replace with appropriate ownership check: `USING ((SELECT auth.uid()) = user_id)`. For intentionally public-read tables (blog posts, products), a SELECT `USING (true)` is acceptable — but write operations should always be restricted. Flag as HIGH only on write operations; INFO on SELECT for non-sensitive tables.

<a id="views-bypass"></a>
## 🟠 HIGH: Views Bypassing RLS

**ID:** `VIEW_NO_SECURITY_INVOKER`
**Splinter lint:** `0010_security_definer_view`
**What happens:** PostgreSQL views run with the creating user's privileges by default (SECURITY DEFINER). Views created via SQL Editor are owned by `supabase_admin` (superuser), so they bypass ALL RLS on underlying tables. A view joining `users` and `orders` would expose all data regardless of RLS policies on those tables.
**Detection:** See audit-queries.md Q14.
**Fix (PostgreSQL 15+):** `ALTER VIEW view_name SET (security_invoker = true);`
**Fix (older versions):** `REVOKE SELECT ON view_name FROM anon, authenticated;` or move view to a non-exposed schema.

<a id="secdef-functions"></a>
## 🟠 HIGH: SECURITY DEFINER Functions in Exposed Schemas

**ID:** `SECURITY_DEFINER_EXPOSED`
**What happens:** Functions with `SECURITY DEFINER` in the public schema run with the creator's (often superuser) privileges. They're callable by anyone via `/rest/v1/rpc/function_name` and completely bypass RLS.
**Root cause:** Developers need functions that access data across users (admin operations, aggregations) and use SECURITY DEFINER without realizing it's API-accessible.
**Detection:** See audit-queries.md Q12.
**Fix:** Move to a private schema (not exposed via API): `ALTER FUNCTION function_name SET SCHEMA private;`. Or revoke execution: `REVOKE EXECUTE ON FUNCTION function_name FROM PUBLIC, anon, authenticated;`. Always add `SET search_path = public` to prevent search path injection.

<a id="user-metadata"></a>
## 🟠 HIGH: RLS Policies Referencing user_metadata

**ID:** `USER_METADATA_IN_POLICY`
**Splinter lint:** `0015_rls_references_user_metadata`
**What happens:** `user_metadata` (stored as `raw_user_meta_data` in `auth.users`) is modifiable by the authenticated user via `supabase.auth.update({ data: { role: 'admin' } })`. Any RLS policy that checks `user_metadata` for authorization decisions can be bypassed by the user simply updating their own metadata.
**Detection:** See audit-queries.md Q7.
**Fix:** Replace `auth.jwt() -> 'user_metadata'` with `auth.jwt() -> 'app_metadata'` in all policies. `app_metadata` can only be set server-side (via service_role key or Dashboard).

<a id="missing-withcheck"></a>
## 🟠 HIGH: Missing WITH CHECK on UPDATE Policies

**ID:** `UPDATE_NO_WITHCHECK`
**What happens:** UPDATE policies with only USING (no WITH CHECK) allow users to update rows they own but set ANY values — including changing `user_id` to another user, setting `is_admin = true`, or modifying `balance`.
**Detection:** See audit-queries.md Q8.
**Fix:** Add WITH CHECK that mirrors or extends the USING clause:
```sql
CREATE POLICY "update_own" ON posts FOR UPDATE TO authenticated
  USING ((SELECT auth.uid()) = user_id)
  WITH CHECK ((SELECT auth.uid()) = user_id);
```

<a id="mass-assignment"></a>
## 🟠 HIGH: Mass Assignment via Column Updates

**ID:** `MASS_ASSIGNMENT`
**What happens:** RLS is row-level, not column-level. An UPDATE policy allowing users to modify their own rows also allows modifying ANY column — including `is_admin`, `role`, `credits`, `balance`, or `plan`. Attackers inject extra fields in PATCH requests.
**Detection:** Check for tables with UPDATE policies that contain sensitive columns (role, admin, balance, credits, plan, permissions). Cross-reference with column-level privileges.
**Fix options:**
1. Column-level privileges: `REVOKE UPDATE (is_admin, role, balance) ON users FROM authenticated;`
2. Trigger guard: Create a BEFORE UPDATE trigger that resets sensitive columns to their old values.
3. API proxy: Handle sensitive updates through Edge Functions instead of direct API access.

<a id="ghost-auth"></a>
## 🟠 HIGH: Ghost Auth (Email Confirmation Bypass)

**ID:** `GHOST_AUTH`
**What happens:** When email confirmation is disabled (or confirmations are auto-confirmed), `signUp()` returns a valid session with the `authenticated` role immediately. Attackers create accounts with fake emails and bypass all RLS policies that check for `auth.uid()` (which just checks for any authenticated user, not a specific verified one).
**Detection:** Attempt signup with the probe described in SKILL.md Step 3, Test 5. If `access_token` is returned, ghost auth is active.
**Fix:** Enable email confirmation in Dashboard → Authentication → Providers → Email → "Confirm email." Also add email verification check to sensitive RLS policies:
```sql
CREATE POLICY "verified_only" ON sensitive_data FOR SELECT TO authenticated
  USING (auth.jwt()->>'email_confirmed_at' IS NOT NULL);
```

<a id="storage-rls"></a>
## 🟠 HIGH: Missing Storage RLS Policies

**ID:** `STORAGE_NO_RLS`
**What happens:** `storage.objects` has its own separate RLS policies. Developers who properly configure database table RLS often completely forget about storage. Without storage policies, uploads and downloads may be unrestricted.
**Detection:** See audit-queries.md Q18.
**Fix:** Create storage-specific policies. See fix-templates.md for storage policy patterns.

<a id="jwt-secret"></a>
## 🟠 HIGH: JWT Secret Exposure

**ID:** `JWT_SECRET_EXPOSED`
**What happens:** The legacy symmetric JWT secret can be used to forge JWTs for any user or role, including service_role. If leaked via source control, logs, error messages, or build artifacts, attackers gain complete database access.
**Detection:** Search codebase for JWT secrets (long base64 strings that don't look like standard Supabase keys). Check `.env` files committed to git.
**Fix:** Migrate to asymmetric JWT signing keys (available since Q4 2024). Dashboard → Settings → JWT Signing Keys → Migrate. Rotate the secret if exposed.

<a id="exposed-rpc"></a>
## 🟠 HIGH: Exposed RPC Functions Without Auth

**ID:** `EXPOSED_RPC_NO_AUTH`
**What happens:** All functions in exposed schemas are callable via `/rest/v1/rpc/function_name`. If they don't internally check `auth.uid()` or role, anyone can execute them.
**Detection:** See audit-queries.md Q16.
**Fix:** Revoke execution: `REVOKE EXECUTE ON FUNCTION function_name FROM anon;` or move to a private schema.

<a id="unscoped-policies"></a>
## 🟡 MEDIUM: Policies Not Scoped to Correct Roles

**ID:** `POLICY_NO_ROLE_SCOPE`
**What happens:** Policies without a `TO` clause (or with `TO public`) apply to ALL roles including `anon`. Anonymous internet users get the same access as authenticated users.
**Detection:** See audit-queries.md Q9.
**Fix:** Add `TO authenticated` (or a custom role) to restrict who the policy applies to.

<a id="multiple-permissive"></a>
## 🟡 MEDIUM: Multiple Permissive Policies OR'd Together

**ID:** `MULTIPLE_PERMISSIVE`
**Splinter lint:** `0006_multiple_permissive_policies`
**What happens:** Multiple PERMISSIVE policies for the same table/operation/role combine with OR logic. If one is overly broad, it overrides all others. Developers expect AND logic.
**Detection:** See audit-queries.md Q10.
**Fix:** Use RESTRICTIVE policies for conditions that must ALWAYS be true (AND logic): `CREATE POLICY "must_be_owner" ON posts AS RESTRICTIVE ...`

<a id="rls-no-policies"></a>
## 🟡 MEDIUM: RLS Enabled but No Policies

**ID:** `RLS_NO_POLICIES`
**Splinter lint:** `0008_rls_enabled_no_policy`
**What happens:** RLS enabled + zero policies = deny all access. This is usually a development oversight causing silent application failures, not a deliberate security choice.
**Detection:** See audit-queries.md Q2.
**Fix:** Create appropriate policies for the table's access pattern. See fix-templates.md.

<a id="performance"></a>
## 🟡 MEDIUM: RLS Performance Anti-Patterns

**ID:** `RLS_PERFORMANCE`
**Splinter lint:** `0003_auth_rls_initplan`
**What happens:** `auth.uid()` called directly (not wrapped in `SELECT`) is re-evaluated per row, causing severe performance degradation on large tables. Can be exploited for denial-of-service via crafted queries.
**Detection:** See audit-queries.md Q11.
**Fix:** Replace `auth.uid()` with `(SELECT auth.uid())` in all policies. Add indexes on columns referenced in policy expressions.

<a id="matviews"></a>
## 🟡 MEDIUM: Materialized Views in API

**ID:** `MATVIEW_EXPOSED`
**Splinter lint:** `0016_materialized_view_in_api`
**What happens:** Materialized views cannot have RLS policies. If in the public schema, they're fully accessible via the API.
**Detection:** See audit-queries.md Q15.
**Fix:** Move to a non-exposed schema or restrict access via column-level privileges.

<a id="mutable-searchpath"></a>
## 🟡 MEDIUM: Function Search Path Mutable

**ID:** `MUTABLE_SEARCH_PATH`
**Splinter lint:** `0011_function_search_path_mutable`
**What happens:** SECURITY DEFINER functions without a fixed `search_path` are vulnerable to search path injection — an attacker creates objects in a schema that shadows the intended objects.
**Detection:** See audit-queries.md Q13.
**Fix:** `ALTER FUNCTION function_name SET search_path = public;`

<a id="public-buckets"></a>
## 🟡 MEDIUM: Public Storage Buckets

**ID:** `PUBLIC_BUCKET`
**What happens:** Public buckets bypass all access controls. Files are accessible via direct URL without any authentication. All file URLs are guessable if you know the bucket name and file path.
**Detection:** See audit-queries.md Q17.
**Fix:** `UPDATE storage.buckets SET public = false WHERE id = 'bucket_name';` Use signed URLs for temporary access.

<a id="sensitive-columns"></a>
## 🟡 MEDIUM: Sensitive Column Names Exposed

**ID:** `SENSITIVE_COLUMNS`
**Splinter lint:** `0023_sensitive_columns_in_api`
**What happens:** Columns named `password`, `api_key`, `token`, `ssn`, etc. in public tables suggest sensitive data accessible via the API.
**Detection:** See audit-queries.md Q19.
**Fix:** Move sensitive data to a private schema, encrypt at rest, or use column-level privileges to restrict access.

<a id="oauth-redirects"></a>
## 🟡 MEDIUM: OAuth Redirect URL Wildcards

**ID:** `OAUTH_REDIRECT_WILDCARD`
**What happens:** Overly permissive redirect URL patterns (e.g., `https://**`) allow attackers to redirect OAuth tokens to attacker-controlled domains.
**Detection:** Check Dashboard → Authentication → URL Configuration. Flag wildcards in production.
**Fix:** Set exact redirect URLs for production. Use wildcards only for development/preview deployments.

<a id="weak-passwords"></a>
## 🟡 MEDIUM: Weak Password Configuration

**ID:** `WEAK_PASSWORD_CONFIG`
**What happens:** Default minimum password length is 6 characters. HaveIBeenPwned leaked password checking is Pro-plan only.
**Detection:** Check auth settings for minimum password length.
**Fix:** Set minimum to 8+ characters. Enable leaked password protection if on Pro plan.

<a id="anon-auth"></a>
## 🟡 MEDIUM: Anonymous Auth Abuse

**ID:** `ANON_AUTH_ABUSE`
**Splinter lint:** `0012_anon_sign_ins_enabled`
**What happens:** Anonymous sign-ins create users with the `authenticated` role without any credentials. Without CAPTCHA, attackers can flood the system.
**Detection:** Check if anonymous auth is enabled in Dashboard settings.
**Fix:** Disable if not needed. If needed, add restrictive policies for anonymous users and enable CAPTCHA:
```sql
CREATE POLICY "block_anon_users" ON sensitive_data AS RESTRICTIVE
  FOR ALL TO authenticated
  USING ((auth.jwt()->>'is_anonymous')::boolean IS NOT TRUE);
```

<a id="rate-limiting"></a>
## ℹ️ LOW: Missing Rate Limiting

**ID:** `NO_RATE_LIMITING`
**What happens:** PostgREST has no built-in per-user rate limiting for read operations. Write operations can be rate-limited via `db_pre_request` function.
**Detection:** Check if `pgrst.db_pre_request` is configured.
**Fix:** Implement rate limiting via db_pre_request for writes. Use external gateway (Cloudflare Workers, Zuplo) for read rate limiting.

<a id="openapi-exposure"></a>
## ℹ️ LOW: OpenAPI Schema Exposure

**ID:** `OPENAPI_EXPOSED`
**What happens:** The `/rest/v1/` root endpoint may return the full OpenAPI spec to anon users, revealing all table names, columns, and types.
**Detection:** `curl "SUPABASE_URL/rest/v1/" -H "apikey: ANON_KEY"` — if it returns JSON schema, it's exposed.
**Fix:** Supabase restricted this in March 2026. If still accessible, contact support or use a custom schema.

<a id="sql-editor-trap"></a>
## ℹ️ INFO: SQL Editor Testing Trap

**ID:** `SQL_EDITOR_TRAP`
**What happens:** The Supabase SQL Editor runs as the `postgres` superuser, bypassing all RLS. Developers test queries there, see expected results, and think their app is secure — but real API users see different results.
**Impact:** Not a vulnerability itself, but causes developers to miss RLS issues during testing.
**Fix:** Always test using the Dashboard's role impersonation feature, or test via the API with actual user JWTs. Use pgTAP tests for automated RLS verification.
