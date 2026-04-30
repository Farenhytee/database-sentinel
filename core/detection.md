# Sentinel — Backend Detection

Detection runs **first**, before any backend-specific workflow. It produces a JSON manifest of which backends are in scope; the dispatcher loads the matching `backends/<name>/workflow.md` files for each.

**Multi-backend is the rule, not the exception.** Real apps frequently use Firebase Auth + Postgres data store + Atlas analytics, or Supabase + Redis cache, or MongoDB + a separate auth provider. Detect *all* matches, not just the highest-confidence one.

---

## Output schema

```json
{
  "detected": [
    {
      "backend": "supabase",
      "confidence": "high",
      "signals": ["supabase/config.toml", "SUPABASE_URL in .env.local"],
      "connection_profile": {
        "url": "https://abcdefg.supabase.co",
        "has_anon_key": true,
        "has_service_role_key": false
      }
    },
    {
      "backend": "firebase",
      "confidence": "medium",
      "signals": ["firebase.json"],
      "connection_profile": {
        "project_id": "myapp-prod",
        "products_in_use": ["firestore", "storage"]
      }
    }
  ],
  "unknown_signals": []
}
```

`confidence` levels:
- **high** — multiple independent signals (config file + env var, or IaC + container image)
- **medium** — one strong signal (config file or pinned dependency)
- **low** — one weak signal (string match in a comment or example file)

`connection_profile` carries hostnames, ports, project IDs — **never credentials**. Extensions read credentials at their Step 0 only.

---

## Signal table

Detection runs in priority order:

### 1. Config files in repo

| Backend | File | Confidence |
|---------|------|------------|
| Supabase | `supabase/config.toml` | high |
| Supabase | `supabase/migrations/*.sql` | medium |
| Firebase | `firebase.json` | high |
| Firebase | `firestore.rules`, `database.rules.json`, `storage.rules` | high |
| Firebase | `.firebaserc` | medium |
| Firebase | `google-services.json`, `GoogleService-Info.plist` | medium |
| MongoDB | `mongod.conf`, `/etc/mongod.conf` | high |
| MongoDB | `*.bson` | low (might be data dump) |
| Postgres self-hosted | `pg_hba.conf` | high |
| Postgres self-hosted | `postgresql.conf` | high |
| MySQL self-hosted | `my.cnf`, `mysqld.cnf` | high |

### 2. Environment variables / connection strings

| Backend | Pattern | Notes |
|---------|---------|-------|
| Supabase | `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY` | URL must contain `.supabase.co` for high confidence |
| Firebase | `FIREBASE_*`, `FIREBASE_PROJECT_ID`, `GOOGLE_APPLICATION_CREDENTIALS` pointing to admin SDK JSON | |
| MongoDB | `MONGODB_URI`, `MONGO_INITDB_ROOT_*`, `MONGO_URL` | Distinguish Atlas (`mongodb+srv://...mongodb.net`) from self-hosted |
| Postgres self-hosted | `DATABASE_URL=postgres://...`, `PGHOST`, `PGPORT`, `PGUSER` | **Exclude** if URL host matches `*.supabase.co`, `*.neon.tech`, `*.amazonaws.com` (managed) — those are managed Postgres, not self-hosted |
| MySQL self-hosted | `DATABASE_URL=mysql://...`, `MYSQL_HOST`, `MYSQL_USER` | Exclude if host matches `*.planetscale.com`, `*.amazonaws.com` |

Detection should distinguish managed PaaS (PlanetScale, Neon, RDS) from true self-hosted Postgres/MySQL. Managed instances are out of scope for the self-hosted backend modules — their auditable surface is the IAM / network-rules layer of the cloud provider, which Sentinel doesn't currently cover.

### 3. Source-code SDK imports

| Backend | Imports / API calls |
|---------|---------------------|
| Supabase | `@supabase/supabase-js`, `createClient(supabaseUrl, ...)` |
| Firebase | `firebase`, `firebase-admin`, `firebase/firestore`, `firebase/auth`, `firebase/storage`, `firebase-functions`, `getFirestore()`, `initializeApp(firebaseConfig)` |
| MongoDB | `mongodb`, `mongoose`, `pymongo`, `motor`, `connect(MONGODB_URI)`, `MongoClient(...)` |
| Postgres self-hosted | `pg`, `psycopg2`, `psycopg`, `node-postgres`, `Pool({connectionString: ...})` |
| MySQL self-hosted | `mysql2`, `mysql`, `mysqlclient`, `mysql-connector-python` |

### 4. Package manifests (pinned dependencies)

| Backend | Manifest entry |
|---------|----------------|
| Supabase | `package.json` → `@supabase/supabase-js` |
| Firebase | `package.json` → `firebase`, `firebase-admin`, `firebase-functions`; `pubspec.yaml` → `firebase_core`, `cloud_firestore`; `Podfile` → `Firebase/Firestore` |
| MongoDB | `package.json` → `mongodb`, `mongoose`; `requirements.txt` → `pymongo`, `motor`; `pom.xml` → `mongodb-driver-sync` |
| Postgres self-hosted | `package.json` → `pg`; `requirements.txt` → `psycopg2`, `psycopg`; `Cargo.toml` → `tokio-postgres` |
| MySQL self-hosted | `package.json` → `mysql2`; `requirements.txt` → `mysql-connector-python`; `pom.xml` → `mysql-connector-j` |

### 5. Container images

| Backend | Image patterns |
|---------|----------------|
| MongoDB | `mongo:`, `mongo-express:`, `bitnami/mongodb:` |
| Postgres self-hosted | `postgres:`, `bitnami/postgresql:`, `timescale/timescaledb:` |
| MySQL self-hosted | `mysql:`, `mariadb:`, `bitnami/mysql:`, `percona:` |

### 6. IaC resources

| Backend | Resource patterns |
|---------|-------------------|
| Firebase | `google_firebase_*`, `google_firestore_*`, `firebaseFirestore`, `firebaseStorage` (Pulumi) |
| MongoDB Atlas | `mongodbatlas_*`, `mongodbatlas_project_ip_access_list`, `mongodbatlas_database_user` |
| Self-hosted SQL | `aws_db_instance` (RDS — note: managed, not self-hosted), `helm_release` charts named `bitnami/postgresql`, `bitnami/mysql` |
| Postgres / MySQL | `kubernetes_stateful_set` for `postgres:` / `mysql:` images |

---

## Detection commands (one-shot bundle)

The dispatcher runs this from the project root:

```bash
#!/usr/bin/env bash
set -euo pipefail
declare -A FOUND

# Supabase
([ -f supabase/config.toml ] || \
 grep -rln "SUPABASE_URL\|@supabase/supabase-js\|supabase\.co" \
   --include="*.env*" --include="*.toml" --include="*.ts" --include="*.tsx" \
   --include="*.js" --include="*.jsx" --include="*.json" 2>/dev/null \
   | grep -v node_modules | head -1) && FOUND[supabase]=1

# Firebase
([ -f firebase.json ] || [ -f firestore.rules ] || [ -f .firebaserc ] || \
 grep -rln "firebase\.initializeApp\|firebaseConfig\|firebase-admin\|firebase/firestore" \
   --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.json" 2>/dev/null \
   | grep -v node_modules | head -1) && FOUND[firebase]=1

# MongoDB
([ -f mongod.conf ] || [ -f /etc/mongod.conf ] || \
 grep -rlE "mongodb(\+srv)?://|MongoClient\(|mongoose\.connect" \
   --include="*.env*" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
   --include="*.py" --include="*.json" --include="*.yml" --include="*.yaml" 2>/dev/null \
   | grep -v node_modules | head -1) && FOUND[mongodb]=1

# Postgres self-hosted (exclude managed PaaS)
if grep -rlE "DATABASE_URL=postgres(ql)?://|psycopg2|psycopg|node-postgres|^postgres:" \
     --include="*.env*" --include="Dockerfile*" --include="docker-compose*.yml" 2>/dev/null \
     | grep -v node_modules | head -1 > /dev/null; then
  if ! grep -rE "supabase\.co|neon\.tech|amazonaws\.com|render\.com" --include="*.env*" 2>/dev/null > /dev/null; then
    FOUND[postgres-selfhosted]=1
  fi
fi
([ -f pg_hba.conf ] || [ -f postgresql.conf ]) && FOUND[postgres-selfhosted]=1

# MySQL self-hosted
([ -f my.cnf ] || [ -f mysqld.cnf ] || \
 grep -rlE "DATABASE_URL=mysql://|mysql2|mysql-connector|^mysql:|^mariadb:" \
   --include="*.env*" --include="Dockerfile*" --include="docker-compose*.yml" --include="package.json" 2>/dev/null \
   | grep -v node_modules | head -1) && FOUND[mysql-selfhosted]=1

# Emit
for backend in "${!FOUND[@]}"; do echo "$backend"; done
```

Production implementations should run each detection branch in parallel and emit the structured JSON manifest above. The shell snippet here is the documentation contract — actual execution is handled by the dispatcher.

---

## Edge cases

- **Managed Postgres (Supabase / Neon / RDS):** detected as Supabase if Supabase signals are present, otherwise *not flagged* under `postgres-selfhosted`. RDS-via-IAM is out of scope.
- **Firebase + Cloud Firestore but no `firebase.json`:** treat as `medium` confidence based on SDK imports alone. Ask the user to confirm the project ID.
- **Hybrid Atlas + self-hosted MongoDB:** detect both. Atlas signals (`mongodb+srv://...mongodb.net`, `mongodbatlas_*` Terraform) trigger Atlas-specific patterns; non-Atlas connection strings trigger self-hosted patterns.
- **Connection string in CI vault, not repo:** Sentinel only sees what's in the working directory. If the user references "my MongoDB on Atlas" without any signal, ask them to provide the connection string explicitly — don't fabricate detection.

---

## What detection does NOT do

- **Does not credential-check.** Detection reports presence of env-var *names* and config files; it does not read secret values until the relevant backend's Step 0 needs them.
- **Does not network-probe.** Detection is purely repo-local. Reaching out to verify a `supabase.co` URL is reachable belongs to Step 3 of that backend's workflow.
- **Does not rank.** All detected backends are audited. There is no "primary" backend to choose.
