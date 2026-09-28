# Audit Queries Reference

Complete SQL query library for Supabase security introspection. Run these via the Supabase SQL API, Management API, or ask the user to execute them in the Dashboard SQL Editor.

## Table of contents

1. [RLS Status Checks](#1-rls-status-checks) — Tables without RLS, false security states
2. [Policy Analysis](#2-policy-analysis) — Extract and analyze all RLS policies
3. [Function and View Analysis](#3-function-and-view-analysis) — Security definer risks, mutable search paths
4. [Storage Security](#4-storage-security) — Bucket configs, storage RLS
5. [Auth Configuration](#5-auth-configuration) — Sensitive columns, callable functions
6. [Full Policy Reconstruction](#6-full-policy-reconstruction) — Regenerate CREATE POLICY statements
7. [Executing Queries via API](#7-executing-queries-via-api) — How to run these programmatically

---

## 1. RLS status checks

### Q1: All tables in public schema with RLS status

This is the single most important query. Any table with `rowsecurity = false` is fully exposed to anyone with the anon key.

```sql
SELECT
  schemaname,
  tablename,
  rowsecurity AS rls_enabled,
  CASE WHEN rowsecurity THEN '✅' ELSE '🔴 EXPOSED' END AS status
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY rowsecurity ASC, tablename;
```

### Q2: Tables with RLS enabled but NO policies defined

RLS enabled + no policies = all access denied. This is usually a bug — the developer enabled RLS but forgot to create policies, causing silent application failures.

```sql
SELECT c.relname AS tablename, 'RLS ON but no policies' AS issue
FROM pg_class c
JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE c.relkind = 'r'
  AND c.relrowsecurity = true
  AND n.nspname = 'public'
  AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid);
```

### Q3: Tables with policies defined but RLS NOT enabled (false security)

This is a critical trap — policies exist (the developer wrote them) but RLS is disabled, so they're never enforced. The developer thinks the table is protected.

```sql
SELECT c.relname AS tablename, 'Policies exist but RLS DISABLED' AS issue
FROM pg_class c
JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE c.relkind = 'r'
  AND c.relrowsecurity = false
  AND n.nspname = 'public'
  AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid);
```

### Q4: Summary — table security posture

Combines all three states into one overview query.

```sql
SELECT
  t.tablename,
  t.rowsecurity AS rls_enabled,
  COUNT(p.policyname) AS policy_count,
  CASE
    WHEN NOT t.rowsecurity AND COUNT(p.policyname) = 0 THEN '🔴 CRITICAL: No RLS, no policies'
    WHEN NOT t.rowsecurity AND COUNT(p.policyname) > 0 THEN '🔴 CRITICAL: Policies exist but RLS disabled'
    WHEN t.rowsecurity AND COUNT(p.policyname) = 0 THEN '🟡 MEDIUM: RLS on but no policies (deny-all)'
    ELSE '✅ RLS enabled with policies'
  END AS status
FROM pg_tables t
LEFT JOIN pg_policies p ON t.tablename = p.tablename AND t.schemaname = p.schemaname
WHERE t.schemaname = 'public'
GROUP BY t.tablename, t.rowsecurity
ORDER BY t.rowsecurity ASC, policy_count ASC;
```

---

## 2. Policy analysis

### Q5: All policies with full details

The master policy query. Returns everything needed to analyze policy logic.

```sql
SELECT
  schemaname,
  tablename,
  policyname,
  permissive,
  roles,
  cmd,
  qual AS using_expression,
  with_check AS with_check_expression
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename, cmd, policyname;
```

### Q6: Overly permissive policies (USING true / WITH CHECK true)

Any policy with `USING (true)` grants that operation to everyone in the target role. On SELECT, it means all rows are readable. On INSERT/UPDATE/DELETE, it means unrestricted writes.

```sql
SELECT
  tablename,
  policyname,
  cmd,
  roles,
  qual AS using_expr,
  with_check,
  CASE
    WHEN qual = 'true' AND cmd = 'SELECT' THEN '🟠 HIGH: All rows readable by ' || roles::text
    WHEN qual = 'true' AND cmd IN ('UPDATE','DELETE','ALL') THEN '🔴 CRITICAL: Unrestricted write by ' || roles::text
    WHEN with_check = 'true' AND cmd IN ('INSERT','UPDATE','ALL') THEN '🟠 HIGH: Any data can be inserted/updated by ' || roles::text
    ELSE '⚠️ Check manually'
  END AS risk
FROM pg_policies
WHERE schemaname = 'public'
  AND (qual = 'true' OR with_check = 'true');
```

### Q7: Policies referencing user_metadata (privilege escalation risk)

`user_metadata` (raw_user_meta_data) is modifiable by the user via `supabase.auth.update()`. Policies that use it for authorization decisions allow users to self-escalate privileges.

```sql
SELECT
  tablename,
  policyname,
  cmd,
  qual,
  with_check,
  '🟠 HIGH: user_metadata is user-modifiable — use app_metadata instead' AS risk
FROM pg_policies
WHERE schemaname = 'public'
  AND (
    qual::text LIKE '%user_metadata%'
    OR qual::text LIKE '%raw_user_meta_data%'
    OR with_check::text LIKE '%user_metadata%'
    OR with_check::text LIKE '%raw_user_meta_data%'
  );
```

### Q8: UPDATE policies missing WITH CHECK (mass assignment risk)

UPDATE policies need both USING (which rows can be updated) and WITH CHECK (what values are allowed). Without WITH CHECK, users can change ownership columns.

```sql
SELECT
  tablename,
  policyname,
  qual AS using_expr,
  with_check,
  '🟠 HIGH: UPDATE policy without WITH CHECK — users may reassign row ownership' AS risk
FROM pg_policies
WHERE schemaname = 'public'
  AND cmd = 'UPDATE'
  AND (with_check IS NULL OR with_check = '');
```

### Q9: Policies not scoped to specific roles (applies to anon)

Policies without a TO clause apply to ALL roles including `anon`, meaning anonymous internet users get access.

```sql
SELECT
  tablename,
  policyname,
  cmd,
  roles,
  '🟠 HIGH: Policy applies to all roles including anon' AS risk
FROM pg_policies
WHERE schemaname = 'public'
  AND roles = '{public}';
```

### Q10: Multiple permissive policies (OR logic trap)

Multiple PERMISSIVE policies on the same table/operation/role combine with OR logic. The most permissive policy wins, which often isn't what the developer intended.

```sql
SELECT
  tablename,
  cmd,
  roles,
  array_agg(policyname) AS policies,
  count(*) AS policy_count,
  '🟡 MEDIUM: ' || count(*) || ' permissive policies OR''d together — most permissive wins' AS risk
FROM pg_policies
WHERE schemaname = 'public'
  AND permissive = 'PERMISSIVE'
GROUP BY tablename, cmd, roles
HAVING count(*) > 1;
```

### Q11: Performance anti-pattern — auth.uid() not wrapped

Using `auth.uid()` directly causes it to be evaluated per-row. Wrapping in `(SELECT auth.uid())` triggers Postgres's initPlan optimization, caching the result per-statement.

```sql
SELECT
  tablename,
  policyname,
  qual,
  '🟡 MEDIUM: Wrap auth.uid() in (SELECT auth.uid()) for performance' AS recommendation
FROM pg_policies
WHERE schemaname = 'public'
  AND qual IS NOT NULL
  AND qual LIKE '%auth.uid()%'
  AND qual NOT LIKE '%(select auth.uid())%'
  AND qual NOT LIKE '%(SELECT auth.uid())%';
```

---

## 3. Function and view analysis

### Q12: SECURITY DEFINER functions in exposed schemas

Functions with SECURITY DEFINER run with the creator's privileges (usually superuser), bypassing all RLS. If they're in the `public` schema, anyone can call them via `/rest/v1/rpc/function_name`.

```sql
SELECT
  n.nspname AS schema,
  p.proname AS function_name,
  pg_get_functiondef(p.oid) AS definition,
  '🟠 HIGH: SECURITY DEFINER function callable via API — bypasses all RLS' AS risk
FROM pg_proc p
JOIN pg_namespace n ON p.pronamespace = n.oid
WHERE p.prosecdef = true
  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'extensions', 'auth', 'storage', 'pgsodium', 'vault', 'supabase_functions', 'graphql', 'graphql_public', 'realtime', '_realtime', 'pgsodium_masks', 'pgbouncer', 'net', '_analytics');
```

### Q13: Functions with mutable search_path

SECURITY DEFINER functions without a fixed search_path are vulnerable to search path injection attacks.

```sql
SELECT
  n.nspname AS schema,
  p.proname AS function_name,
  '🟡 MEDIUM: Mutable search_path on SECURITY DEFINER function' AS risk
FROM pg_proc p
JOIN pg_namespace n ON p.pronamespace = n.oid
WHERE p.prosecdef = true
  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'extensions', 'auth', 'storage', 'pgsodium', 'vault')
  AND NOT EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig, '{}')) c WHERE c LIKE 'search_path=%');
```

### Q14: Views without security_invoker (bypass RLS)

Views created via SQL Editor are owned by supabase_admin (superuser). Without `security_invoker = true` (Postgres 15+), they bypass all RLS on underlying tables.

```sql
SELECT
  n.nspname AS schema,
  c.relname AS view_name,
  pg_get_userbyid(c.relowner) AS owner,
  CASE
    WHEN EXISTS (
      SELECT 1 FROM pg_options_to_table(c.reloptions)
      WHERE option_name = 'security_invoker' AND option_value IN ('true', 'on', '1')
    ) THEN '✅ security_invoker enabled'
    ELSE '🟠 HIGH: View bypasses RLS (runs as ' || pg_get_userbyid(c.relowner) || ')'
  END AS status
FROM pg_class c
JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE c.relkind = 'v'
  AND n.nspname = 'public';
```

### Q15: Materialized views in public schema (no RLS support)

Materialized views cannot have RLS policies. If they're in the public schema, they're directly accessible via the API.

```sql
SELECT
  n.nspname AS schema,
  c.relname AS matview_name,
  '🟡 MEDIUM: Materialized view cannot have RLS — accessible via API' AS risk
FROM pg_class c
JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE c.relkind = 'm'
  AND n.nspname = 'public';
```

### Q16: Functions callable by anon role

Lists all functions that anonymous (unauthenticated) users can execute via the API.

```sql
SELECT
  n.nspname AS routine_schema,
  p.proname AS routine_name,
  p.prosecdef AS security_definer,
  '⚠️ INFO: Callable by anon role via /rest/v1/rpc/' || p.proname AS note
FROM pg_proc p
JOIN pg_namespace n ON p.pronamespace = n.oid
WHERE n.nspname = 'public'
  AND p.prokind = 'f'
  AND has_function_privilege('anon', p.oid, 'EXECUTE');
```

---

## 4. Storage security

### Q17: Storage bucket configuration

Public buckets bypass all access controls — files are served directly from S3 without touching the database.

```sql
SELECT
  id,
  name,
  public,
  CASE
    WHEN public THEN '🟠 HIGH: Public bucket — all files accessible without auth'
    ELSE '✅ Private bucket'
  END AS status
FROM storage.buckets
ORDER BY public DESC;
```

### Q18: Storage RLS policies

Storage uses its own RLS on `storage.objects`. Missing policies = no uploads/downloads allowed (or unrestricted if RLS is disabled).

```sql
SELECT
  tablename,
  policyname,
  cmd,
  roles,
  qual,
  with_check
FROM pg_policies
WHERE schemaname = 'storage';
```

---

## 5. Auth configuration

### Q19: Sensitive column names exposed via API

Columns with names suggesting sensitive data that are accessible through the public schema API.

```sql
SELECT
  n.nspname AS table_schema,
  c.relname AS table_name,
  a.attname AS column_name,
  format_type(a.atttypid, a.atttypmod) AS data_type,
  '⚠️ Sensitive column exposed via API' AS warning
FROM pg_attribute a
JOIN pg_class c ON a.attrelid = c.oid
JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE n.nspname = 'public'
  AND c.relkind IN ('r', 'v', 'm', 'p')
  AND a.attnum > 0 AND NOT a.attisdropped
  AND (has_column_privilege('anon', c.oid, a.attnum, 'SELECT')
       OR has_column_privilege('authenticated', c.oid, a.attnum, 'SELECT'))
  AND lower(a.attname) IN (
    'password', 'password_hash', 'hashed_password',
    'secret', 'secret_key', 'api_key', 'api_secret',
    'token', 'access_token', 'refresh_token', 'auth_token',
    'credit_card', 'card_number', 'cvv', 'expiry',
    'ssn', 'social_security', 'national_id', 'tax_id',
    'private_key', 'encryption_key', 'jwt_secret',
    'stripe_key', 'openai_key', 'aws_key'
  );
```

---

## 6. Full policy reconstruction

### Q20: Generate CREATE POLICY statements

Reconstructs the full SQL for every policy — useful for code review, migration generation, and documentation.

```sql
SELECT
  'CREATE POLICY "' || pol.polname || '"'
  || ' ON ' || nsp.nspname || '.' || rel.relname
  || CASE WHEN pol.polpermissive THEN '' ELSE ' AS RESTRICTIVE' END
  || ' FOR ' || CASE pol.polcmd
      WHEN 'r' THEN 'SELECT'
      WHEN 'a' THEN 'INSERT'
      WHEN 'w' THEN 'UPDATE'
      WHEN 'd' THEN 'DELETE'
      WHEN '*' THEN 'ALL'
      ELSE pol.polcmd::text
    END
  || ' TO ' || CASE
      WHEN pol.polroles = '{0}' THEN 'public'
      ELSE (SELECT string_agg(rolname, ', ') FROM pg_roles WHERE oid = ANY(pol.polroles))
    END
  || COALESCE(' USING (' || pg_get_expr(pol.polqual, pol.polrelid) || ')', '')
  || COALESCE(' WITH CHECK (' || pg_get_expr(pol.polwithcheck, pol.polrelid) || ')', '')
  || ';' AS policy_sql
FROM pg_catalog.pg_policy pol
JOIN pg_catalog.pg_class rel ON pol.polrelid = rel.oid
JOIN pg_catalog.pg_namespace nsp ON rel.relnamespace = nsp.oid
WHERE nsp.nspname = 'public'
ORDER BY rel.relname, pol.polcmd;
```

---

## 7. Executing queries via API

### Option A: Via Supabase REST API (if SQL RPC is exposed)

Some projects expose a generic SQL execution function. Try:

```bash
curl -s -X POST "SUPABASE_URL/rest/v1/rpc/exec_sql" \
  -H "apikey: SERVICE_ROLE_KEY" \
  -H "Authorization: Bearer SERVICE_ROLE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = '\''public'\''"}'
```

### Option B: Ask the user to run in Dashboard

If API execution isn't available, provide the SQL and ask the user to:
1. Open their Supabase Dashboard
2. Go to SQL Editor
3. Paste and run each query
4. Copy the results back

Format the queries as a single block they can paste all at once.

### Option C: Via Supabase CLI (if available locally)

```bash
supabase db execute --sql "SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public'"
```

### Option D: Direct Postgres connection

```bash
psql "postgresql://postgres:[password]@db.[project-ref].supabase.co:5432/postgres" \
  -c "SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public'"
```
