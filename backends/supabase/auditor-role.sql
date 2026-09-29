-- Sentinel read-only audit role. Run once in the Supabase SQL editor; replace the password first.
-- Reads the system catalog (policies, grants, functions) and bucket config only. It has no SELECT on
-- any of your tables, so it can never read your rows. BYPASSRLS only lets it see storage.buckets config.
-- Connection string: postgresql://sentinel_auditor:<password>@<host>:5432/postgres
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_auditor') THEN
    CREATE ROLE sentinel_auditor LOGIN BYPASSRLS PASSWORD 'CHANGE_ME_TO_A_STRONG_PASSWORD';
  END IF;
END $$;
ALTER ROLE sentinel_auditor SET default_transaction_read_only = on;
ALTER ROLE sentinel_auditor SET statement_timeout = '5s';
GRANT USAGE ON SCHEMA storage TO sentinel_auditor;
GRANT SELECT ON storage.buckets TO sentinel_auditor;
