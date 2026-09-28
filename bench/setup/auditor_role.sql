-- Read-only audit role. Catalog (pg_*) is readable by default; only bucket config needs a grant.
-- BYPASSRLS is safe here: the role has no SELECT on any table except storage.buckets (config, not user data).
-- Local bench password only; customers set their own.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_auditor') THEN
    CREATE ROLE sentinel_auditor LOGIN BYPASSRLS PASSWORD 'sentinel_local_only';
  END IF;
END $$;
ALTER ROLE sentinel_auditor SET default_transaction_read_only = on;
ALTER ROLE sentinel_auditor SET statement_timeout = '5s';
GRANT USAGE ON SCHEMA storage TO sentinel_auditor;
GRANT SELECT ON storage.buckets TO sentinel_auditor;
