# Fix Templates

Copy-pasteable SQL fix patterns for every anti-pattern. Each template is parameterized — replace `TABLE_NAME`, `user_id`, etc. with the actual values from the user's schema.

## Table of contents

1. [Enable RLS](#1-enable-rls)
2. [Common RLS Policy Patterns](#2-common-rls-policy-patterns)
3. [Storage Policies](#3-storage-policies)
4. [Auth Hardening](#4-auth-hardening)
5. [Function and View Fixes](#5-function-and-view-fixes)
6. [Preventive Measures](#6-preventive-measures)
7. [Column-Level Security](#7-column-level-security)
8. [Migration File Template](#8-migration-file-template)

---

## 1. Enable RLS

### Enable RLS on a single table

```sql
ALTER TABLE public.TABLE_NAME ENABLE ROW LEVEL SECURITY;
```

### Enable RLS on ALL public tables at once

```sql
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN
    SELECT tablename FROM pg_tables
    WHERE schemaname = 'public' AND NOT rowsecurity
  LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY;', r.tablename);
    RAISE NOTICE 'Enabled RLS on: %', r.tablename;
  END LOOP;
END $$;
```

### Auto-enable RLS on all future tables (event trigger)

```sql
CREATE OR REPLACE FUNCTION public.auto_enable_rls()
RETURNS event_trigger LANGUAGE plpgsql AS $$
DECLARE cmd RECORD;
BEGIN
  FOR cmd IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
    IF cmd.object_type = 'table'
       AND cmd.schema_name = 'public' THEN
      EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY;', cmd.object_identity);
      RAISE NOTICE 'Auto-enabled RLS on: %', cmd.object_identity;
    END IF;
  END LOOP;
END $$;

CREATE EVENT TRIGGER auto_enable_rls ON ddl_command_end
  WHEN TAG IN ('CREATE TABLE', 'CREATE TABLE AS')
  EXECUTE FUNCTION public.auto_enable_rls();
```

---

## 2. Common RLS policy patterns

Always follow these rules when generating policies:
- Use `(SELECT auth.uid())` not `auth.uid()` (initPlan caching for performance)
- Separate policies per operation — never use `FOR ALL`
- Always include both USING and WITH CHECK on UPDATE policies
- Scope with `TO authenticated` or `TO anon` — never leave unscoped
- Use `app_metadata` not `user_metadata` for authorization claims

### Pattern A: User owns their data (most common)

The user can only access rows where their user ID matches a column.

```sql
-- SELECT: Users read own rows
CREATE POLICY "Users can read own TABLE_NAME"
  ON public.TABLE_NAME FOR SELECT
  TO authenticated
  USING ((SELECT auth.uid()) = user_id);

-- INSERT: Users create rows owned by themselves
CREATE POLICY "Users can insert own TABLE_NAME"
  ON public.TABLE_NAME FOR INSERT
  TO authenticated
  WITH CHECK ((SELECT auth.uid()) = user_id);

-- UPDATE: Users update own rows, cannot change ownership
CREATE POLICY "Users can update own TABLE_NAME"
  ON public.TABLE_NAME FOR UPDATE
  TO authenticated
  USING ((SELECT auth.uid()) = user_id)
  WITH CHECK ((SELECT auth.uid()) = user_id);

-- DELETE: Users delete own rows
CREATE POLICY "Users can delete own TABLE_NAME"
  ON public.TABLE_NAME FOR DELETE
  TO authenticated
  USING ((SELECT auth.uid()) = user_id);
```

### Pattern B: Team/organization-based access (multi-tenant)

Users access data belonging to their team/organization.

```sql
-- SELECT: Team members can read team data
CREATE POLICY "Team members read TABLE_NAME"
  ON public.TABLE_NAME FOR SELECT
  TO authenticated
  USING (
    team_id IN (
      SELECT team_id FROM public.team_members
      WHERE user_id = (SELECT auth.uid())
    )
  );

-- INSERT: Team members can create team data
CREATE POLICY "Team members insert TABLE_NAME"
  ON public.TABLE_NAME FOR INSERT
  TO authenticated
  WITH CHECK (
    team_id IN (
      SELECT team_id FROM public.team_members
      WHERE user_id = (SELECT auth.uid())
    )
  );

-- UPDATE: Team members can update team data
CREATE POLICY "Team members update TABLE_NAME"
  ON public.TABLE_NAME FOR UPDATE
  TO authenticated
  USING (
    team_id IN (
      SELECT team_id FROM public.team_members
      WHERE user_id = (SELECT auth.uid())
    )
  )
  WITH CHECK (
    team_id IN (
      SELECT team_id FROM public.team_members
      WHERE user_id = (SELECT auth.uid())
    )
  );
```

Remember to add an index: `CREATE INDEX idx_team_members_user ON team_members(user_id);`

### Pattern C: Public read, authenticated write

For content that's publicly viewable but only editable by the owner.

```sql
-- SELECT: Anyone can read (including anonymous)
CREATE POLICY "Public read TABLE_NAME"
  ON public.TABLE_NAME FOR SELECT
  TO anon, authenticated
  USING (true);

-- INSERT: Only authenticated users, own rows
CREATE POLICY "Auth users insert TABLE_NAME"
  ON public.TABLE_NAME FOR INSERT
  TO authenticated
  WITH CHECK ((SELECT auth.uid()) = user_id);

-- UPDATE: Only owner
CREATE POLICY "Owner updates TABLE_NAME"
  ON public.TABLE_NAME FOR UPDATE
  TO authenticated
  USING ((SELECT auth.uid()) = user_id)
  WITH CHECK ((SELECT auth.uid()) = user_id);

-- DELETE: Only owner
CREATE POLICY "Owner deletes TABLE_NAME"
  ON public.TABLE_NAME FOR DELETE
  TO authenticated
  USING ((SELECT auth.uid()) = user_id);
```

### Pattern D: Role-based access (admin/user)

Using `app_metadata` for role-based access control. Never use `user_metadata`.

```sql
-- Admin: Full access
CREATE POLICY "Admins full access TABLE_NAME"
  ON public.TABLE_NAME FOR ALL
  TO authenticated
  USING (
    (SELECT auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
  );

-- Regular users: Own data only
CREATE POLICY "Users own data TABLE_NAME"
  ON public.TABLE_NAME FOR SELECT
  TO authenticated
  USING (
    (SELECT auth.uid()) = user_id
    OR (SELECT auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
  );
```

### Pattern E: Verified users only

Restrict to users who confirmed their email address.

```sql
CREATE POLICY "Verified users only TABLE_NAME"
  ON public.TABLE_NAME FOR ALL
  TO authenticated
  USING (
    (SELECT auth.jwt() ->> 'email_confirmed_at') IS NOT NULL
  );
```

### Pattern F: MFA-enforced access

Restrict sensitive operations to users with MFA verified.

```sql
CREATE POLICY "MFA required TABLE_NAME"
  ON public.TABLE_NAME AS RESTRICTIVE
  FOR ALL TO authenticated
  USING (
    (SELECT auth.jwt() ->> 'aal') = 'aal2'
  );
```

### Pattern G: Block anonymous auth users

When anonymous sign-ins are enabled but you want to exclude them from certain tables.

```sql
CREATE POLICY "No anonymous access TABLE_NAME"
  ON public.TABLE_NAME AS RESTRICTIVE
  FOR ALL TO authenticated
  USING (
    (SELECT (auth.jwt() ->> 'is_anonymous')::boolean) IS NOT TRUE
  );
```

---

## 3. Storage policies

### User-scoped storage (files in user's folder)

```sql
-- Users can upload to their own folder
CREATE POLICY "User upload to own folder"
  ON storage.objects FOR INSERT
  TO authenticated
  WITH CHECK (
    bucket_id = 'BUCKET_NAME'
    AND (SELECT auth.uid())::text = (storage.foldername(name))[1]
  );

-- Users can read their own files
CREATE POLICY "User read own files"
  ON storage.objects FOR SELECT
  TO authenticated
  USING (
    bucket_id = 'BUCKET_NAME'
    AND (SELECT auth.uid())::text = (storage.foldername(name))[1]
  );

-- Users can update their own files
CREATE POLICY "User update own files"
  ON storage.objects FOR UPDATE
  TO authenticated
  USING (
    bucket_id = 'BUCKET_NAME'
    AND (SELECT auth.uid())::text = (storage.foldername(name))[1]
  );

-- Users can delete their own files
CREATE POLICY "User delete own files"
  ON storage.objects FOR DELETE
  TO authenticated
  USING (
    bucket_id = 'BUCKET_NAME'
    AND (SELECT auth.uid())::text = (storage.foldername(name))[1]
  );
```

### Restrict file types

```sql
CREATE POLICY "Images only upload"
  ON storage.objects FOR INSERT
  TO authenticated
  WITH CHECK (
    bucket_id = 'images'
    AND storage.extension(name) IN ('jpg', 'jpeg', 'png', 'gif', 'webp')
  );
```

### Make bucket private

```sql
UPDATE storage.buckets SET public = false WHERE id = 'BUCKET_NAME';
```

---

## 4. Auth hardening

### Rate limiting for write operations

```sql
-- Create private rate limiting table
CREATE TABLE IF NOT EXISTS private.rate_limits (
  id bigserial PRIMARY KEY,
  ip inet NOT NULL,
  request_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_rate_limits_ip_time ON private.rate_limits (ip, request_at);

-- Create pre-request function
CREATE OR REPLACE FUNCTION public.check_request()
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  req_method text := current_setting('request.method', true);
  req_ip inet;
  count_recent integer;
BEGIN
  IF req_method IN ('GET', 'HEAD') OR req_method IS NULL THEN RETURN; END IF;

  req_ip := split_part(
    current_setting('request.headers', true)::json->>'x-forwarded-for',
    ',', 1
  )::inet;

  SELECT count(*) INTO count_recent
  FROM private.rate_limits
  WHERE ip = req_ip AND request_at > now() - interval '5 minutes';

  IF count_recent > 100 THEN
    RAISE SQLSTATE 'PGRST' USING
      message = '{"code":"RATE_LIMITED","message":"Too many requests"}'::text,
      detail = '{"status":429,"headers":{"Retry-After":"300"}}'::text;
  END IF;

  INSERT INTO private.rate_limits (ip, request_at) VALUES (req_ip, now());
END; $$;

-- Enable pre-request function
ALTER ROLE authenticator SET pgrst.db_pre_request = 'public.check_request';
NOTIFY pgrst, 'reload config';
```

---

## 5. Function and view fixes

### Fix SECURITY DEFINER function

```sql
-- Option 1: Move to private schema
ALTER FUNCTION public.FUNCTION_NAME SET SCHEMA private;

-- Option 2: Keep in public but fix search_path and revoke
ALTER FUNCTION public.FUNCTION_NAME SET search_path = public;
REVOKE EXECUTE ON FUNCTION public.FUNCTION_NAME FROM anon;
```

### Fix view to use security_invoker

```sql
-- PostgreSQL 15+
ALTER VIEW public.VIEW_NAME SET (security_invoker = true);

-- Older versions: restrict access
REVOKE ALL ON public.VIEW_NAME FROM anon, authenticated;
-- Then grant back selectively
GRANT SELECT ON public.VIEW_NAME TO authenticated;
```

---

## 6. Preventive measures

### Disable Data API entirely (if using Edge Functions only)

```sql
-- In Dashboard: Settings → API → Data API → Disable
-- Or expose a custom schema instead of public
```

### Move sensitive tables to private schema

```sql
ALTER TABLE public.api_keys SET SCHEMA private;
ALTER TABLE public.internal_config SET SCHEMA private;
```

---

## 7. Column-level security

### Protect sensitive columns from updates

```sql
-- Revoke UPDATE on specific columns
REVOKE UPDATE (is_admin, role, plan, balance, credits)
  ON public.users FROM authenticated;

-- Or use a trigger guard
CREATE OR REPLACE FUNCTION protect_sensitive_columns()
RETURNS TRIGGER AS $$
BEGIN
  NEW.is_admin := OLD.is_admin;
  NEW.role := OLD.role;
  NEW.plan := OLD.plan;
  NEW.balance := OLD.balance;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER guard_sensitive_columns
  BEFORE UPDATE ON public.users
  FOR EACH ROW
  EXECUTE FUNCTION protect_sensitive_columns();
```

### Hide sensitive columns from reads

```sql
-- Only grant SELECT on safe columns
REVOKE SELECT ON public.users FROM authenticated;
GRANT SELECT (id, name, email, avatar_url, created_at)
  ON public.users TO authenticated;
```

---

## 8. Migration file template

When saving fixes as a migration file:

```sql
-- Migration: Supabase Sentinel security fixes
-- Generated: TIMESTAMP
-- Findings: N CRITICAL, N HIGH, N MEDIUM

-- ============================================
-- CRITICAL FIXES
-- ============================================

-- Fix: Enable RLS on TABLE_NAME (was: exposed to anonymous access)
ALTER TABLE public.TABLE_NAME ENABLE ROW LEVEL SECURITY;

-- Fix: Add ownership policies to TABLE_NAME
CREATE POLICY "users_select_own_TABLE_NAME"
  ON public.TABLE_NAME FOR SELECT TO authenticated
  USING ((SELECT auth.uid()) = user_id);

CREATE POLICY "users_insert_own_TABLE_NAME"
  ON public.TABLE_NAME FOR INSERT TO authenticated
  WITH CHECK ((SELECT auth.uid()) = user_id);

CREATE POLICY "users_update_own_TABLE_NAME"
  ON public.TABLE_NAME FOR UPDATE TO authenticated
  USING ((SELECT auth.uid()) = user_id)
  WITH CHECK ((SELECT auth.uid()) = user_id);

CREATE POLICY "users_delete_own_TABLE_NAME"
  ON public.TABLE_NAME FOR DELETE TO authenticated
  USING ((SELECT auth.uid()) = user_id);

-- ============================================
-- HIGH FIXES
-- ============================================

-- (additional fixes here)

-- ============================================
-- PREVENTIVE: Auto-enable RLS on future tables
-- ============================================

-- (event trigger from section 1)

-- ============================================
-- PERFORMANCE: Add indexes for RLS policy columns
-- ============================================

CREATE INDEX IF NOT EXISTS idx_TABLE_NAME_user_id ON public.TABLE_NAME (user_id);
```
