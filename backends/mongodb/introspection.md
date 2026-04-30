# MongoDB — Introspection Bundle

Read-only commands that produce the inputs `anti-patterns.md` Step 2 consumes. Run during Step 1 of the workflow (`workflow.md`). Three execution paths: `mongosh`, Atlas Admin API, IaC scan.

**Safety contract:** every command in this file is read-only. No writes, no DDL, no role changes. The audit explicitly does **not** alter authentication state, roles, configuration, or indexes.

---

## Path A — `mongosh` against the live instance

Run as a user with at minimum `clusterMonitor` + `read` on each application database. If only the application credential is available, the audit runs in degraded mode (skips role/user enumeration).

### A.1 — Server fingerprint

```javascript
// === SECTION: SERVER FINGERPRINT ===
db.runCommand({ buildInfo: 1 }).version           // → MongoBleed (MG-SH-001) version compare
db.runCommand({ buildInfo: 1 }).versionArray
db.runCommand({ buildInfo: 1 }).modules           // ["enterprise"] vs []
db.runCommand({ buildInfo: 1 }).gitVersion
db.adminCommand({ getCmdLineOpts: 1 }).parsed     // → MG-SH-002, 003, 005, 006, 010
```

Save the entire `getCmdLineOpts.parsed` object — it answers most config-shape patterns at once.

### A.2 — Server parameters

```javascript
db.adminCommand({
  getParameter: 1,
  enableLocalhostAuthBypass: 1,    // → MG-SH-004
  enableTestCommands: 1,           // → MG-SH-011
  authSchemaVersion: 1,
  scramSHA1AuthAlgorithmIterationCount: 1,
  scramSHA256AuthAlgorithmIterationCount: 1
})
```

> **Note on MG-SH-005 (server-side JS):** `javascriptEnabled` is **not** a runtime tunable — `getParameter` returns `"no option found to get"` on MongoDB 7.0+. It's a startup-only setting. Detect via the static path first; only fall through to the active probe if the static path is inconclusive.
>
> **Static (preferred):**
> ```javascript
> // From getCmdLineOpts.parsed in §A.1:
> db.adminCommand({ getCmdLineOpts: 1 }).parsed.security?.javascriptEnabled
> // === false  → MG-SH-005 cleared (JS explicitly disabled)
> // missing / true → MG-SH-005 fires (default is enabled)
> ```
>
> **Active confirmation (use only if the static path is inconclusive AND write probes are opted in):** run a `$where` query against any collection. If it succeeds, JS is enabled. This is a *read* probe (no data is modified) but it does execute attacker-shaped JavaScript on the server, so route it through the same opt-in gate as write probes.
> ```javascript
> // Run only with --allow-write-probes opt-in
> db.getSiblingDB("admin").runCommand({
>   find: "system.version",
>   filter: { $where: "true" },
>   limit: 1
> }).cursor   // success → MG-SH-005 confirmed
> ```
>
> Verified empirically against `mongo:7.0.20` during Phase 2 testing — the `getParameter` form errors with `"no option found to get"`; the `getCmdLineOpts.parsed.security` form is the canonical detection path.

### A.3 — Topology

```javascript
db.adminCommand({ listShards: 1 })       // sharded cluster?  (silent error on standalone/replica)
rs.status()                              // replica set state? (errors on standalone)
db.adminCommand({ hello: 1 }).msg        // "isdbgrid" → mongos
db.adminCommand({ hello: 1 }).setName    // replica set name if any
```

This determines which write-probe strategy is available in Step 3 (transactions on replica/sharded; canary collection on standalone).

### A.4 — Users + roles (per database)

```javascript
// Run per database (reduce by listing them first)
db.adminCommand({ listDatabases: 1 }).databases.forEach(d => {
  if (["admin","config","local"].includes(d.name)) return;  // walk these separately
  print("=== " + d.name + " ===");
  db.getSiblingDB(d.name).getUsers({ showCredentials: false, showPrivileges: true });
});

// Admin DB users (super-privileged candidates)
db.getSiblingDB("admin").getUsers({ showCredentials: false, showPrivileges: true });

// Custom roles
db.getSiblingDB("admin").getRoles({ showPrivileges: true, showBuiltinRoles: false });
```

Output is parsed by Step 2 against `MG-SH-007` (privileged role on app user). Cross-reference user names against discovered `MONGODB_URI` values from `core/credentials.md` discovery.

### A.5 — Connection / session sample (read)

```javascript
db.runCommand({ connectionStatus: 1, showPrivileges: true })
// Tells you what role the *current* introspection user has — informs degraded-mode messaging.
```

### A.6 — Collection inventory + validators

```javascript
// Per application database
db.getSiblingDB("YOUR_APP_DB").runCommand({ listCollections: 1, nameOnly: false })
// For each collection, inspect options.validator
//   → MG-SH-008 (self-modifiable role document) flags collections whose name matches
//     /user|profile|account|member/i AND whose validator is empty
```

Optional sample for `MG-SH-008`:
```javascript
db.getSiblingDB("YOUR_APP_DB").getCollection("users").findOne(
  {},
  { role: 1, isAdmin: 1, permissions: 1, plan: 1, _id: 0 }
)
```

### A.7 — Server-side JS reachability test

```javascript
// Should fail on modern, hardened deployments
db.runCommand({ eval: "1+1" })   // legacy command; absence is not proof, presence is failure
```

---

## Path B — Atlas Admin API

Required for `MG-AT-*` patterns. Uses a programmatic API key (read-only role suffices). Never use `Project Owner` keys for an audit.

```bash
# Auth: digest, programmatic API key
ATLAS_PUB=...           # public key
ATLAS_PRIV=...          # private key
ATLAS_GID=...           # group / project ID
ATLAS_ORG=...           # organization ID
H='-H "Accept: application/vnd.atlas.2025-03-12+json"'

# B.1 Network access list — MG-AT-001
curl --user "$ATLAS_PUB:$ATLAS_PRIV" --digest -s \
  "https://cloud.mongodb.com/api/atlas/v2/groups/$ATLAS_GID/networkAccessLists" \
  -H "Accept: application/vnd.atlas.2025-03-12+json"

# B.2 Database users — MG-AT-004, MG-SH-007
curl --user "$ATLAS_PUB:$ATLAS_PRIV" --digest -s \
  "https://cloud.mongodb.com/api/atlas/v2/groups/$ATLAS_GID/databaseUsers" \
  -H "Accept: application/vnd.atlas.2025-03-12+json"

# B.3 Project API keys — MG-AT-005
curl --user "$ATLAS_PUB:$ATLAS_PRIV" --digest -s \
  "https://cloud.mongodb.com/api/atlas/v2/orgs/$ATLAS_ORG/apiKeys" \
  -H "Accept: application/vnd.atlas.2025-03-12+json"

# B.4 Encryption-at-rest config — MG-AT-006
curl --user "$ATLAS_PUB:$ATLAS_PRIV" --digest -s \
  "https://cloud.mongodb.com/api/atlas/v2/groups/$ATLAS_GID/encryptionAtRest" \
  -H "Accept: application/vnd.atlas.2025-03-12+json"

# B.5 Cluster inventory + version — MG-SH-001 also applies if Atlas not yet patched
curl --user "$ATLAS_PUB:$ATLAS_PRIV" --digest -s \
  "https://cloud.mongodb.com/api/atlas/v2/groups/$ATLAS_GID/clusters" \
  -H "Accept: application/vnd.atlas.2025-03-12+json"
# Atlas auto-patches MongoBleed; this is here for completeness.
```

If the user has the Atlas CLI configured locally, use it instead:
```bash
atlas accessLists list --projectId $ATLAS_GID -o json
atlas dbusers list --projectId $ATLAS_GID -o json
atlas clusters list --projectId $ATLAS_GID -o json
```

---

## Path C — IaC scan (no live access required)

Runs against Terraform / Pulumi / docker-compose / Helm files in the working directory. Always available, even when no cluster credentials exist.

### C.1 — Terraform (Atlas)

```bash
# MG-AT-001 — wide-open access list
grep -rE 'cidr_block\s*=\s*"0\.0\.0\.0/0"' --include="*.tf" 2>/dev/null

# MG-AT-001 — IP access list resource shape
grep -rB 2 -A 6 'mongodbatlas_project_ip_access_list' --include="*.tf" 2>/dev/null

# MG-AT-004 / MG-AT-005 — over-privileged users / keys
grep -rB 2 -A 6 -E 'mongodbatlas_database_user|mongodbatlas_(project_api_key|access_list_api_key)' \
  --include="*.tf" 2>/dev/null

# Look for atlasAdmin / GROUP_OWNER / ORG_OWNER in roles
grep -rE 'role_name\s*=\s*"(atlasAdmin|GROUP_OWNER|ORG_OWNER)"' --include="*.tf" 2>/dev/null
```

### C.2 — docker-compose / Dockerfile

```bash
# MG-SH-002 / MG-SH-003 — auth + bind together
grep -rE 'command:.*--noauth|command:.*--bind_ip_all|MONGO_INITDB_ROOT_PASSWORD\s*:\s*$' \
  --include="docker-compose*.yml" --include="Dockerfile*" 2>/dev/null

# MG-SH-002 — image without an admin user setup
grep -rB 2 -A 10 'image:\s*mongo' --include="docker-compose*.yml" 2>/dev/null
# Manual review: any mongo service without MONGO_INITDB_ROOT_USERNAME +
# MONGO_INITDB_ROOT_PASSWORD is auth-disabled by default until first user is created.

# MG-SH-006 — no TLS in compose
grep -rE 'mongo.*--tlsMode|--sslMode' --include="docker-compose*.yml" 2>/dev/null
# Absence is informational, not definitive — TLS may be terminated upstream.
```

### C.3 — Helm values / Kubernetes manifests

```bash
grep -rE 'auth\.enabled\s*:\s*false|architecture\s*:\s*standalone' \
  --include="values*.yaml" --include="*.values.yaml" 2>/dev/null
```

For Bitnami `bitnami/mongodb` chart, the relevant values are `auth.enabled` (must be `true`) and `tls.enabled`.

### C.4 — Source (driver-side patterns)

These are detected during Step 0 codebase scan but listed here for completeness because Step 2 cross-references them with introspection results.

```bash
# MG-SH-008 — Mongoose mass-assignment patterns
grep -rE '(findByIdAndUpdate|findOneAndUpdate)\s*\([^,]+,\s*req\.body\)' \
  --include="*.ts" --include="*.tsx" --include="*.js" 2>/dev/null | grep -v node_modules
grep -rE 'Model\.update\s*\([^,]+,\s*req\.body\)' \
  --include="*.ts" --include="*.tsx" --include="*.js" 2>/dev/null | grep -v node_modules

# MG-SH-009 — outdated Mongoose
grep -E '"mongoose":\s*"' package.json 2>/dev/null

# MG-SH-005 — server-side JS injection patterns
grep -rE '\$where\s*:|aggregate.*\$function' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.py" 2>/dev/null \
  | grep -v node_modules

# MG-AT-003 — deprecated Data API references
grep -rE '/api/atlas/v[0-9.]+/groups/[^/]+/dataAPI|/app/[^/]+/endpoint/data/v1/action/' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.py" 2>/dev/null \
  | grep -v node_modules

# MG-SH-014 — credentials in shell history
grep -E 'mongo(dump|restore|sh).*--password' \
  ~/.bash_history ~/.zsh_history /etc/cron* 2>/dev/null
```

---

## Output schema for Step 2

The introspection step packages results into a JSON object the static analyzer consumes:

```json
{
  "topology": "standalone | replicaSet | sharded | atlas",
  "version": "7.0.27",
  "modules": ["enterprise"],
  "cmdLineOpts": { /* full parsed object */ },
  "parameters": {
    "enableLocalhostAuthBypass": true,
    "javascriptEnabled": true,
    "enableTestCommands": 0
  },
  "users": [
    {
      "db": "admin",
      "user": "root",
      "roles": [{"role": "root", "db": "admin"}]
    }
  ],
  "collections": [
    {
      "db": "app",
      "name": "users",
      "validator": null,
      "sample_role_field_present": true
    }
  ],
  "atlas": {
    "networkAccessLists": [...],
    "databaseUsers": [...],
    "apiKeys": [...],
    "encryptionAtRest": { "enabled": false }
  },
  "iac": {
    "terraform_findings": ["..."],
    "compose_findings": ["..."],
    "source_findings": ["..."]
  },
  "introspection_user_role": "clusterMonitor",   // for degraded-mode messaging
  "errors": []
}
```

Static analyzers in Step 2 read this object and emit findings keyed by `MG-SH-*` / `MG-AT-*` IDs.

---

## Degraded mode

If Sentinel can't get any of the three paths working — no `mongosh` reachability, no Atlas API key, no IaC files — it falls back to:

1. Source-only scan (Path C.4) — catches `MG-SH-008`, `MG-SH-009`, `MG-AT-003`, parts of `MG-SH-005`.
2. Connection-string structure analysis from `MONGODB_URI` — confirms TLS use (`tls=true` query param), retry config (`retryWrites=true`), at most flags `MG-SH-013`.
3. Public-internet probe (opt-in, separately gated): TCP connect on 27017 of the URI host, `hello` command, version banner. No further commands. See [`mongobleed-probe.md`](mongobleed-probe.md) §"Banner-only mode."

Degraded mode produces a report with confidence noted: "Audit ran without database introspection. Findings cover IaC and source patterns only. Re-run with introspection access to cover MG-SH-001, 002, 003, 004, 006, 007, 010, 011."
