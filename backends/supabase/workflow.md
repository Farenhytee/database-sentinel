# Supabase backend — audit workflow

The 7-step Sentinel workflow specialized for Supabase. The dispatcher in root `SKILL.md` loads this file when Supabase is detected. Reference files (`audit-queries.md`, `anti-patterns.md`, `fix-templates.md`) live in this same `backends/supabase/` directory.

**Why Supabase needs its own audit:** Supabase auto-generates REST APIs for every table in the public schema, but security (Row-Level Security) is opt-in, not opt-out. Without RLS, the anon key — intentionally embedded in frontend JavaScript and visible in browser DevTools — becomes a master key to the entire database. Real-world impact: CVE-2025-48757 exposed 170+ production apps. 20.1M rows were found exposed across YC startups. 45% of AI-generated code introduces OWASP Top 10 vulnerabilities. Supabase's built-in Security Advisor only checks whether RLS exists — not whether policies actually prevent unauthorized access. This skill tests both.

## Step 0 — Gather credentials and scan codebase

**First, check the user's project directory for credentials automatically.** Look in these locations before asking the user to provide anything:

```bash
# Check common env file locations
cat .env 2>/dev/null; cat .env.local 2>/dev/null; cat .env.development 2>/dev/null
# Check Supabase CLI config
cat supabase/config.toml 2>/dev/null
# Find Supabase references in source
grep -r "SUPABASE_URL\|SUPABASE_ANON_KEY\|SUPABASE_SERVICE_ROLE\|supabaseUrl\|supabaseKey" \
  --include="*.env*" --include="*.toml" --include="*.ts" --include="*.js" -l 2>/dev/null | head -20
```

Extract: `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`. If found, confirm with the user before proceeding. If not found, ask for them. Explain:
- The anon key is already public (embedded in their frontend). Sharing it reveals nothing new.
- The service_role key is needed for schema introspection (reading table structures and policy definitions). Used read-only, never stored.
- Without the service_role key, you can still run dynamic testing (Steps 3-4 only) using the anon key, but cannot inspect policy logic or generate precise fixes.

See `../../core/credentials.md` for the cross-backend rules on safe key handling. The Supabase-specific mapping: anon key = "public-key-in-client" (expected), service_role key = "privileged-key-in-client" (always CRITICAL if found in client bundle).

**Simultaneously, scan the codebase for security red flags:**

```bash
# CRITICAL: service_role key in frontend/client code
grep -rn "SERVICE_ROLE\|service_role" \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.vue" --include="*.svelte" -l 2>/dev/null | grep -v "node_modules\|.next\|dist\|build\|.env"

# CRITICAL: Public env var prefixes on secret keys
grep -rn "NEXT_PUBLIC_.*SERVICE\|VITE_.*SERVICE\|REACT_APP_.*SERVICE\|EXPO_PUBLIC_.*SERVICE" \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.env*" 2>/dev/null

# HIGH: Hardcoded Supabase JWTs in source files (not env)
grep -rn "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" 2>/dev/null \
  | grep -v "node_modules\|.env"

# HIGH: .env files committed to git
git ls-files --cached .env .env.local .env.production 2>/dev/null

# MEDIUM: Supabase client initialization patterns — check for service_role in browser clients
grep -rn "createClient\|createServerClient\|createBrowserClient" \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  -A 5 2>/dev/null | grep -v "node_modules" | head -40
```

Record codebase findings separately — report them even before database introspection.

---

## Step 1 — Schema introspection

Requires the service_role key. If unavailable, skip to Step 3.

**How to execute SQL — try in order:**
1. **Supabase MCP** (if connected): Use `Supabase:execute_sql` tool directly. This is the easiest path.
2. **Ask user to paste results**: Provide the SQL, ask them to run in Dashboard → SQL Editor, paste output. Most reliable for most users.
3. **Direct Postgres** (if they have connection string): `psql "postgresql://postgres:[pass]@db.[ref].supabase.co:5432/postgres"`.

**Run this combined introspection query (give this to the user as one block):**

```sql
-- Supabase Sentinel Introspection Query v1.0
-- Run this in your Supabase Dashboard SQL Editor and paste the results

-- 1. Table security posture
SELECT 'TABLE_STATUS' AS query, t.tablename, t.rowsecurity AS rls_enabled,
  COUNT(p.policyname) AS policy_count
FROM pg_tables t
LEFT JOIN pg_policies p ON t.tablename = p.tablename AND t.schemaname = p.schemaname
WHERE t.schemaname = 'public'
GROUP BY t.tablename, t.rowsecurity
ORDER BY t.rowsecurity ASC, policy_count ASC;

-- 2. All policy details
SELECT 'POLICY' AS query, schemaname, tablename, policyname, permissive, roles, cmd,
  qual AS using_expr, with_check
FROM pg_policies WHERE schemaname = 'public' ORDER BY tablename, cmd;

-- 3. Views in public schema
SELECT 'VIEW' AS query, n.nspname, c.relname AS view_name,
  pg_get_userbyid(c.relowner) AS owner
FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE c.relkind = 'v' AND n.nspname = 'public';

-- 4. SECURITY DEFINER functions
SELECT 'SECDEF_FUNC' AS query, n.nspname, p.proname
FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid
WHERE p.prosecdef = true AND n.nspname NOT IN ('pg_catalog','information_schema','extensions',
  'auth','storage','pgsodium','vault','supabase_functions','graphql','graphql_public',
  'realtime','_realtime','pgsodium_masks','pgbouncer','net','_analytics');

-- 5. Storage buckets
SELECT 'BUCKET' AS query, id, name, public FROM storage.buckets;

-- 6. Storage policies
SELECT 'STORAGE_POLICY' AS query, tablename, policyname, cmd, roles, qual, with_check
FROM pg_policies WHERE schemaname = 'storage';

-- 7. Sensitive columns
SELECT 'SENSITIVE_COL' AS query, table_name, column_name, data_type
FROM information_schema.columns
WHERE table_schema = 'public' AND lower(column_name) IN (
  'password','password_hash','secret','secret_key','api_key','api_secret',
  'token','access_token','refresh_token','credit_card','card_number',
  'cvv','ssn','social_security','private_key','stripe_key','openai_key');

-- 8. Functions callable by anon
SELECT 'ANON_FUNC' AS query, routine_name
FROM information_schema.routine_privileges
WHERE grantee = 'anon' AND privilege_type = 'EXECUTE'
  AND routine_schema NOT IN ('pg_catalog','information_schema','extensions','auth','storage');

-- 9. Materialized views
SELECT 'MATVIEW' AS query, c.relname
FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE c.relkind = 'm' AND n.nspname = 'public';
```

Read `audit-queries.md` for additional queries if deeper analysis is needed (policy reconstruction, mutable search paths, etc.).

---

## Step 2 — Static analysis (anti-pattern matching)

Read `anti-patterns.md` for the complete 27-pattern database. Analyze every result from Step 1 against these checks. Be exhaustive — check every table, every policy, every function.

**For each table, verify ALL of the following:**

1. **RLS enabled?** No → CRITICAL. This is the #1 cause of Supabase breaches.
2. **Has policies?** RLS enabled + zero policies → MEDIUM (deny-all, likely a bug).
3. **Policies exist but RLS disabled?** → CRITICAL (developer wrote policies but forgot to enable RLS — false security).
4. **SELECT policy permissive?** `USING(true)` on sensitive tables → HIGH. On public-content tables → INFO.
5. **Write policies permissive?** `USING(true)` or `WITH CHECK(true)` on INSERT/UPDATE/DELETE → CRITICAL.
6. **UPDATE has WITH CHECK?** If USING without WITH CHECK → HIGH. Cross-reference: does the table have `is_admin`, `role`, `plan`, `balance`, `credits` columns? If so → CRITICAL (mass assignment of privileges).
7. **Policies scoped to roles?** `roles = {public}` (no TO clause) → MEDIUM, applies to anon.
8. **Uses user_metadata?** `qual`/`with_check` contains `user_metadata` or `raw_user_meta_data` → HIGH.
9. **auth.uid() wrapped?** Uses `auth.uid()` but not `(SELECT auth.uid())` → MEDIUM (performance).
10. **Multiple permissive policies for same table/op/role?** → MEDIUM (OR logic trap).

**For views:** No `security_invoker = true`? → HIGH. Bypasses all RLS on underlying tables.

**For functions:** `SECURITY DEFINER` in exposed schema? → HIGH. Callable via API, bypasses RLS. No fixed `search_path`? → MEDIUM.

**For storage:** Public buckets → MEDIUM. No `storage.objects` policies → HIGH.

**For auth:** Sensitive column names in public tables → MEDIUM. Functions callable by anon → INFO (list for review).

---

## Step 3 — Dynamic testing (safe probing)

**Safety guarantee:** `Prefer: tx=rollback` tells PostgREST to evaluate the request fully, return the result, then roll back the transaction. Zero data modified. Safe for production. (Supabase is the only backend with a primitive this clean — see `../../core/workflow.md` §3 for the cross-backend probing contract.)

**For each table, run all four CRUD tests with the anon key:**

```bash
PROJECT="SUPABASE_URL"
ANON="ANON_KEY"
TABLE="TABLE_NAME"

# SELECT
curl -s "$PROJECT/rest/v1/$TABLE?select=*&limit=1" -H "apikey: $ANON" -H "Authorization: Bearer $ANON"

# INSERT (safe rollback)
curl -s -X POST "$PROJECT/rest/v1/$TABLE" -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \
  -H "Content-Type: application/json" -H "Prefer: return=representation, tx=rollback" -d '{}'

# UPDATE (safe rollback)
curl -s -X PATCH "$PROJECT/rest/v1/$TABLE?id=eq.0" -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \
  -H "Content-Type: application/json" -H "Prefer: tx=rollback" -d '{"id":"probe"}'

# DELETE (safe rollback)
curl -s -X DELETE "$PROJECT/rest/v1/$TABLE?id=eq.0" -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \
  -H "Prefer: tx=rollback"
```

**Response interpretation — be precise:**
- Non-empty JSON array on SELECT → 🔴 DATA EXPOSED
- Empty array `[]` on SELECT → ✅ Protected (or table empty — note ambiguity)
- `"code":"42501"` → ✅ RLS denied access
- `"code":"PGRST301"` → ✅ JWT required
- `"code":"42P01"` → Table doesn't exist via API (skip)
- `"code":"23502"` (NOT NULL violation) on INSERT → ⚠️ RLS *permitted* the insert, but data validation failed. **This is still a vulnerability** — attacker just needs to provide valid column values.
- `"code":"23505"` (unique constraint) on INSERT → ⚠️ Same — RLS permitted, constraint stopped it.
- 201 or returned data on INSERT → 🔴 Anon can write
- Any successful response on UPDATE/DELETE → ⚠️ Writes potentially allowed

**Ghost auth test:**

```bash
curl -s "$PROJECT/auth/v1/signup" -H "apikey: $ANON" -H "Content-Type: application/json" \
  -d '{"email":"sentinel-probe@test.invalid","password":"Pr0beTest!2345"}'
```

- Response contains `"access_token"` → 🔴 Ghost auth active. Unconfirmed accounts get sessions.
- `"Confirm your email"` with no access_token → ✅ Email confirmation enabled.
- `"Email signups are disabled"` → ✅ (or uses other auth providers).

**If ghost auth succeeds:** Re-run ALL table tests using the returned JWT instead of the anon key. This tests what an attacker with a trivially-obtained session can access, since many policies only check `TO authenticated` without further restrictions.

**OpenAPI schema test:**

```bash
curl -s "$PROJECT/rest/v1/" -H "apikey: $ANON" | head -100
```

If JSON with `"paths"` or `"definitions"` → 🟡 Table names and column types exposed.

---

## Step 4 — Generate the security report

Use the cross-backend report format defined in `../../core/reporting.md`. The Supabase header looks like:

```
╔════════════════════════════════════════════════════════╗
║          SENTINEL — Supabase Security Report           ║
╠════════════════════════════════════════════════════════╣
║  Project:   [url]                                      ║
║  Scanned:   [date/time UTC]                            ║
║  Score:     [X/100] [emoji]                            ║
║  Summary:   [N] tables, [N] policies, [N] findings    ║
╚════════════════════════════════════════════════════════╝
```

**Scoring:** Per `../../core/scoring.md`, Supabase weights are CRITICAL = -25, HIGH = -10, MEDIUM = -5, LOW = -2. Floor at 0.
Emoji: 80-100 ✅, 60-79 ⚠️, 40-59 🟠, 0-39 🔴.

**For each finding:**

```
[emoji] [SEVERITY] — [Table/Resource]: [Short Title]

  Risk:     [One sentence a non-developer understands]
  Attack:   [Concrete attacker scenario]
  Proof:    [curl command or query result that proves this]

  Fix:
  [exact SQL]
```

**Ordering:** CRITICAL first → HIGH → MEDIUM. Within severity, tables with likely-sensitive data first (users, payments, orders, tokens > posts, comments, settings).

**End the report with:**
1. "Passing" section — tables/resources that are properly secured.
2. Count summary: "X CRITICAL, Y HIGH, Z MEDIUM findings across N tables."
3. Offer: "Want me to generate a migration file with all fixes?"
4. Offer: "Want me to set up a GitHub Action for continuous monitoring?"
5. Limitation note: "This covers database/API security. It does not cover XSS, CSRF, SSRF, or infrastructure."

---

## Step 5 — Generate fix SQL

Read `fix-templates.md` for the complete template library (8 categories, 7 policy patterns).

**Policy generation rules — always follow these:**
1. `(SELECT auth.uid())` not `auth.uid()` — initPlan caching for performance.
2. Separate policies per operation — never FOR ALL.
3. Both USING and WITH CHECK on UPDATE policies.
4. Always scope with TO clause (authenticated, anon, or custom role).
5. `app_metadata` not `user_metadata` for authorization.
6. Generate indexes for policy columns.
7. Include the auto-enable RLS event trigger for future tables.

**Determine the right policy pattern per table:**
- Table has `user_id` column → ownership pattern (Pattern A in fix-templates)
- Table has `team_id`/`org_id` → team-based (Pattern B)
- Table has `is_public`/`published` → public-read + auth-write (Pattern C)
- Admin data → role-based via app_metadata (Pattern D)
- Sensitive data → verified-only (Pattern E) or MFA-enforced (Pattern F)

**Ask user how to receive fixes:** migration file, apply now, or step-by-step guidance.

---

## Step 6 — GitHub Action (optional)

Read `../../assets/ci/github-action-supabase.yml`. Create `.github/workflows/supabase-sentinel.yml`. User needs to add `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY` as repository secrets. Action runs on migration changes + weekly, posts PR comments, fails on CRITICAL.

---

## Step 7 — Preventive measures

Recommend these one-time hardening steps. Generate the SQL if the user wants:

1. **Auto-enable RLS event trigger** — ensures future tables get RLS automatically.
2. **Move sensitive tables to private schema** — `api_keys`, `secrets`, `internal_config` shouldn't be API-exposed.
3. **Restrict default grants** — revoke INSERT/UPDATE/DELETE from anon on read-only tables.
4. **Enable email confirmation** if not already on.
5. **Review OAuth redirect URLs** — no wildcards in production.
6. **Minimum 8-char passwords** with leaked password protection.
7. **Consider disabling Data API** if app only uses Edge Functions.
8. **Column-level privileges** on tables with sensitive columns (revoke UPDATE on is_admin, role, balance).

---

## Reference files (load on demand)

- **`audit-queries.md`** — Full 20-query SQL library. For additional queries beyond those inlined above.
- **`anti-patterns.md`** — 27 vulnerability patterns (`SB-001..SB-027`) with severity, root cause, detection, Splinter lint IDs, real-world examples. Essential reading at Step 2.
- **`fix-templates.md`** — SQL fix templates: enable RLS, 7 RLS policy patterns (ownership/team/public-read/role-based/verified/MFA/anonymous-block), storage policies, auth hardening, function fixes, column security, migration template. Essential at Step 5.
- **`../../references/vibe-coding-context.md`** — CVE-2025-48757 details, security studies, why LLMs generate insecure code. Cross-backend; read when user asks "why."
- **`../../assets/ci/github-action-supabase.yml`** — CI/CD workflow. Read at Step 6.
