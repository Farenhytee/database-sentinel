# Sentinel — Credential Handling

Generalizes the Supabase anon-vs-service-role distinction to all backends. Every extension's Step 0 must conform to this contract.

---

## Core contract

1. **Never store credentials.** Hold in memory for the duration of the audit. Discard at end.
2. **Never log credential values.** Tool output, tool logs, and the report all redact credentials. The report may include the *URL* (`https://abc.supabase.co`) and the *project ID*, but never the keys.
3. **Auto-discover before asking.** Each backend has a Step 0 file-scan list. If a credential is found locally, confirm with the user before using it.
4. **Distinguish public-key-in-client from privileged-key-in-client.** Public keys are expected and informational; privileged keys in client code are always CRITICAL findings, regardless of which backend.
5. **Read-only by default.** Even with a privileged credential, the audit only *reads* (introspection). Write probes require a separate explicit user opt-in (see `core/workflow.md` §3).
6. **One audit, one credential set.** Don't accept credentials for backends Sentinel hasn't already detected — that's a vector for accidentally auditing the wrong project.

---

## Public-key vs privileged-key mapping per backend

| Backend | Public key (expected in client) | Privileged key (always CRITICAL if in client) |
|---------|----------------------------------|------------------------------------------------|
| Supabase | `SUPABASE_ANON_KEY` (JWT, role=`anon`) | `SUPABASE_SERVICE_ROLE_KEY` (JWT, role=`service_role`, has `BYPASSRLS`) |
| Firebase | API key + project ID + app ID (firebaseConfig in client JS is by design) | Admin SDK service-account JSON (`firebase-adminsdk-*.json`); Cloud Functions deploy keys |
| MongoDB | (none — driver requires credentials in connection string) | Any DB user credentials (`MONGODB_URI`); Atlas API key with `Project Owner`+ |
| Postgres self-hosted | (none — driver requires credentials) | Any DSN (`postgres://user:pwd@host/db`); especially `postgres` superuser |
| MySQL self-hosted | (none — driver requires credentials) | Any DSN (`mysql://user:pwd@host/db`); especially `root@%` |

**Why this matters:**

For Supabase, the anon key in the browser bundle is harmless *if* RLS is configured correctly. That's the entire security model. So finding the anon key in client code is informational — finding the service_role key in client code is catastrophic.

For Firebase, the same logic applies in reverse: `firebaseConfig` (with API key) **must** be in the client bundle. The API key is not a secret — it's an identifier. The Admin SDK service-account JSON is the secret, and it must never appear in client code, public buckets, or git history.

For MongoDB / Postgres / MySQL self-hosted, there is no public-key concept. *Any* credential leakage is a finding.

---

## Discovery locations per backend

Each backend's Step 0 runs grep against these patterns. Sentinel does not read files outside the project directory unless the user explicitly provides a path.

### Supabase

```bash
cat .env 2>/dev/null
cat .env.local 2>/dev/null
cat .env.development 2>/dev/null
cat supabase/config.toml 2>/dev/null
grep -rln "SUPABASE_URL\|SUPABASE_ANON_KEY\|SUPABASE_SERVICE_ROLE\|supabaseUrl\|supabaseKey" \
  --include="*.env*" --include="*.toml" --include="*.ts" --include="*.js" 2>/dev/null | head -20
```

### Firebase

```bash
cat firebase.json 2>/dev/null
cat .firebaserc 2>/dev/null
ls firebase-adminsdk-*.json service-account-*.json 2>/dev/null    # red flag if present in repo
grep -rln "firebaseConfig\|firebase\.initializeApp\|FIREBASE_" \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.env*" 2>/dev/null | head -20
echo "$GOOGLE_APPLICATION_CREDENTIALS"   # if set, points to admin-SDK JSON
```

### MongoDB

```bash
grep -rE "mongodb(\+srv)?://[^\"']*" \
  --include="*.env*" --include="*.ts" --include="*.js" --include="*.py" --include="*.json" \
  --include="*.yml" --include="*.yaml" 2>/dev/null | grep -v node_modules
cat mongod.conf /etc/mongod.conf 2>/dev/null | grep -E "^\s*(user|pwd|password)"
```

### Postgres self-hosted

```bash
grep -rE "(DATABASE_URL|POSTGRES_URL|PG_URL)=postgres(ql)?://[^\"']*" \
  --include="*.env*" --include="docker-compose*.yml" --include="Dockerfile*" 2>/dev/null
grep -rE "POSTGRES_(PASSWORD|USER|DB|HOST_AUTH_METHOD)=" \
  --include="*.env*" --include="docker-compose*.yml" 2>/dev/null
[ -f pg_hba.conf ] && cat pg_hba.conf
```

### MySQL self-hosted

```bash
grep -rE "(DATABASE_URL|MYSQL_URL)=mysql://[^\"']*" \
  --include="*.env*" --include="docker-compose*.yml" 2>/dev/null
grep -rE "MYSQL_(ROOT_PASSWORD|PASSWORD|USER|DATABASE|ALLOW_EMPTY_PASSWORD|RANDOM_ROOT_PASSWORD)=" \
  --include="*.env*" --include="docker-compose*.yml" 2>/dev/null
[ -f my.cnf ] && cat my.cnf
```

---

## Confirming with the user before using credentials

Always confirm before issuing the first authenticated request. Template:

> I found `SUPABASE_SERVICE_ROLE_KEY` in `.env.local`. I'll use it read-only to introspect your database schema (RLS policies, table privileges, function definitions). I won't store it. Should I proceed?

If the user declines, fall back to the unprivileged audit path (Step 3 only, anon key / unauthenticated probes only).

If the user provides a different credential than what was discovered, prefer the user-provided one. Note in the report which credential source was used.

---

## Red-flag patterns surfaced during discovery

These are findings *in their own right*, reported in Step 0 even before any introspection:

| Pattern | Severity | Notes |
|---------|----------|-------|
| Privileged key in client-bundled file (`*.tsx`, `*.jsx`, `*.vue`, `*.svelte`) | CRITICAL | Maps to: Supabase `SERVICE_ROLE_EXPOSED`, Firebase `FB-FN-003`, MongoDB `MG-AT-005`, Postgres `PG-AU-001` |
| Privileged key with public env-var prefix (`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `EXPO_PUBLIC_*`) | CRITICAL | Same — these prefixes ship to the browser by build-tool default |
| Credential committed to git (`git ls-files` returns `.env*`) | CRITICAL | `git rm --cached`, rotate the credential, force-push or accept history rewrite |
| Hardcoded JWT in source (long base64 string starting `eyJhbGciOi...`) | HIGH | Even if it's the anon key, hardcoding signals that other keys may be hardcoded too |
| Service-account JSON committed (`firebase-adminsdk-*.json`, `*-service-account.json`) | CRITICAL | Rotate the key in console; `git filter-repo` to scrub history |
| MongoDB connection string with embedded password in source (not env) | HIGH | Move to env; rotate if committed |
| `pg_hba.conf` with `trust` for non-loopback addresses | CRITICAL | Per Postgres extension `PG-SC-001` |
| `MYSQL_ALLOW_EMPTY_PASSWORD=yes` in production compose file | CRITICAL | Per MySQL extension `MY-IC-001` |

---

## What NOT to ask the user for

- **Read-only introspection from Sentinel never requires more than a privileged-key-equivalent.** If a backend can be audited fully with a less-privileged key (e.g., a Postgres `pg_monitor` role instead of superuser), prefer that — and explain the tradeoff.
- **Never request the JWT signing secret** for any backend. It's not needed for an audit, and asking for it normalizes leaking it.
- **Never request user passwords** to "test login flow." Sentinel does not test login flows. (The ghost-auth probe creates a throwaway account with `.invalid` TLD; it does not use real user credentials.)

---

## Discard checklist (end of audit)

- [ ] All credentials cleared from in-memory variables.
- [ ] Report does not contain any credential values (only redacted forms / URLs / project IDs).
- [ ] No tool log line contains a credential.
- [ ] No file written by Sentinel contains a credential.

This is enforced by the report renderer in `core/reporting.md` (machine-readable JSON includes a redaction pass before write).
