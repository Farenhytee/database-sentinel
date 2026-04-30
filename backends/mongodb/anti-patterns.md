# MongoDB Anti-Pattern Catalog

20 patterns covering MongoDB self-hosted (`MG-SH-001..014`) and Atlas (`MG-AT-001..006`). Severity weights from `core/scoring.md` (CRITICAL = -30 for MongoDB; HIGH = -12; MEDIUM = -5; LOW = -2).

Each entry has: pattern ID, severity, what happens (plain-English), root cause, detection method (concrete query / command / file pattern), real-world impact with citation, fix template reference.

**Loading order:** `workflow.md` Step 2 reads this file. Detection commands assume the introspection bundle from `introspection.md` Step 1 has already produced the inputs (`getCmdLineOpts`, `buildInfo`, `db.getUsers()`, `listCollections`).

---

## Table of contents

**Self-hosted (MG-SH-*)** — patterns that apply to mongod instances you run yourself (Docker, k8s, on-prem, EC2).

1. [MG-SH-001 — MongoBleed (CVE-2025-14847)](#mg-sh-001) 🔴 CRITICAL
2. [MG-SH-002 — Authentication disabled](#mg-sh-002) 🔴 CRITICAL
3. [MG-SH-003 — Internet-bound mongod](#mg-sh-003) 🔴 CRITICAL
4. [MG-SH-004 — localhost auth bypass + container exec](#mg-sh-004) 🟠 HIGH
5. [MG-SH-005 — Server-side JS enabled](#mg-sh-005) 🟠 HIGH
6. [MG-SH-006 — TLS not required](#mg-sh-006) 🟠 HIGH
7. [MG-SH-007 — Privileged role on application user](#mg-sh-007) 🟠 HIGH
8. [MG-SH-008 — Self-modifiable role document](#mg-sh-008) 🟠 HIGH
9. [MG-SH-009 — Outdated driver / Mongoose CVE chain](#mg-sh-009) 🟡 MEDIUM
10. [MG-SH-010 — Audit log not configured](#mg-sh-010) 🟡 MEDIUM
11. [MG-SH-011 — `enableTestCommands = 1` in production](#mg-sh-011) 🟡 MEDIUM
12. [MG-SH-012 — Replica-set keyfile world-readable](#mg-sh-012) 🟡 MEDIUM
13. [MG-SH-013 — Driver options without retryWrites/readConcern](#mg-sh-013) ℹ️ LOW
14. [MG-SH-014 — `mongodump`/`mongorestore` credentials in shell history](#mg-sh-014) ℹ️ LOW

**Atlas (MG-AT-*)** — patterns that apply to MongoDB Atlas (managed cloud).

15. [MG-AT-001 — Atlas IP allowlist `0.0.0.0/0`](#mg-at-001) 🔴 CRITICAL
16. [MG-AT-002 — Atlas Function as direct DB pass-through](#mg-at-002) 🟠 HIGH
17. [MG-AT-003 — Atlas Data API still in code](#mg-at-003) 🟠 HIGH
18. [MG-AT-004 — Atlas DB user with Atlas-admin role](#mg-at-004) 🟡 MEDIUM
19. [MG-AT-005 — API key with Project Owner](#mg-at-005) 🟡 MEDIUM
20. [MG-AT-006 — Encryption-at-rest using cloud default key](#mg-at-006) ℹ️ LOW

---

<a id="mg-sh-001"></a>
## 🔴 MG-SH-001 — MongoBleed (CVE-2025-14847)

| Field | Value |
|-------|-------|
| **ID** | `MG-SH-001` |
| **Severity** | CRITICAL (-30) |
| **CVE** | CVE-2025-14847 (CVSS 8.7) |
| **Discovered** | Joe Desimone (Elastic Security) — disclosed Dec 19 2025 |
| **PoC public** | Dec 26 2025 |
| **CISA KEV** | Dec 29 2025 |
| **Class** | CWE-130 — pre-auth heap memory disclosure |
| **Trigger** | Crafted `OP_COMPRESSED` message with mismatched `uncompressedSize` field; zlib compression negotiated (default-enabled) |

**What happens:** A single TCP packet to mongod returns fragments of uninitialized heap memory in the response. No authentication required. No login needed. Repeated requests progressively drain more heap, often producing credentials, BSON document fragments, session tokens, API keys, and internal pointer values.

**Root cause:** Bug in zlib-based decompression path. The server reads the attacker-supplied `uncompressedSize` field at face value and copies that many bytes from a heap buffer that was only partially populated by the actual decompression. Affects every supported MongoDB version line 4.0+ on default config.

**Affected versions:**

| Major | Vulnerable | Patched |
|-------|------------|---------|
| 8.2.x | 8.2.0–8.2.2 | **8.2.3** |
| 8.0.x | 8.0.0–8.0.16 | **8.0.17** |
| 7.0.x | 7.0.0–7.0.27 | **7.0.28** |
| 6.0.x | 6.0.0–6.0.26 | **6.0.27** |
| 5.0.x | 5.0.0–5.0.31 | **5.0.32** |
| 4.4.x | 4.4.0–4.4.29 | **4.4.30** |
| 4.2 / 4.0 / 3.6 | all | EOL — no patch |

**Workaround if upgrade isn't immediate:** Disable zlib compression — `--networkMessageCompressors snappy,zstd` (omit `zlib`). Confirms via `db.runCommand({getCmdLineOpts:1}).parsed.net.compression.compressors`.

**Atlas:** auto-patched by MongoDB; no customer action.

**Detection (in priority order):**

1. **Static — version compare:**
   ```javascript
   db.runCommand({ buildInfo: 1 }).version
   // compare against patched table above
   ```
2. **Static — zlib enabled in config:**
   ```javascript
   db.runCommand({ getCmdLineOpts: 1 }).parsed.net.compression.compressors
   // includes "zlib" → vulnerable surface even if version unknown
   ```
3. **Hunting signatures (post-incident):**
   - Spike (>1k) of "Slow query" log lines containing `errMsg: incorrect BSON length in element with field name`
   - Connection bursts >50K connections/min from a single source IP
   - Absence of client-driver metadata on connect (legitimate drivers always send `event ID 51800`)
4. **Active probe:** see [`mongobleed-probe.md`](mongobleed-probe.md) for the safe single-packet Wiz Nuclei equivalent. Opt-in only.

**Real-world impact:**
- ~87,000 internet-facing instances reported by Censys (Dec 2025)
- ~146,000 by Cortex Xpanse
- ~200,000 by Shodan
- 42% of cloud environments by Wiz survey
- Active exploitation since Dec 26 2025 PoC release; reported credential-extraction in the wild within days.

**Fix:** see [`fix-templates.md`](fix-templates.md) §1 — version upgrade matrix; §2 — `mongod.conf` with compression workaround if upgrade is blocked.

**Sources:** NVD CVE-2025-14847; MongoDB Server Security Update Dec 2025 blog; Wiz, Akamai, Bitsight, Tenable, CISA KEV; Wiz Nuclei template `mongo-cve-2025-14847.yaml`.

---

<a id="mg-sh-002"></a>
## 🔴 MG-SH-002 — Authentication disabled

| Field | Value |
|-------|-------|
| **ID** | `MG-SH-002` |
| **Severity** | CRITICAL (-30) |

**What happens:** mongod accepts connections without requiring credentials. Any client that can reach the port reads, writes, drops databases, and creates admin users. Combined with `MG-SH-003` (internet-bound), this is "Meow attack" surface — historical waves ransomed ~22,900 unauthenticated MongoDB instances in 2020 and ~7,500 in 2021 (Shadowserver). New entrants from the vibe-coding cohort show up monthly.

**Root cause:** `security.authorization` not set to `enabled` in `mongod.conf`, or `--noauth` on the command line. Default-config Docker images do not require auth until the operator creates an admin user — a step often skipped.

**Detection:**
```javascript
db.runCommand({ getCmdLineOpts: 1 }).parsed.security
// Expected: { authorization: "enabled", ... }
// Vulnerable: missing security block, or authorization: "disabled", or --noauth in argv
```

Also: a successful `db.adminCommand({ listDatabases: 1 })` from an unauthenticated client confirms the absence of auth.

**Fix:** see [`fix-templates.md`](fix-templates.md) §2 (enable auth) and §3 (create least-privilege application user).

**Source:** MongoDB security checklist; Shadowserver ransomware tracking; Infosecurity Magazine.

---

<a id="mg-sh-003"></a>
## 🔴 MG-SH-003 — Internet-bound mongod

| Field | Value |
|-------|-------|
| **ID** | `MG-SH-003` |
| **Severity** | CRITICAL (-30) |

**What happens:** mongod binds to `0.0.0.0` (all interfaces) and port 27017 is reachable from the public internet. Combined with `MG-SH-002` or any RCE-class CVE, this is total compromise.

**Root cause:** `net.bindIp: 0.0.0.0` or `net.bindIpAll: true` in `mongod.conf`, or `--bind_ip_all` on the command line. AI-generated `docker-compose.yml` files frequently emit `command: ["mongod", "--bind_ip_all"]` "to make networking simpler." Note: MongoDB Community 6.0+ Docker images default to `--bind_ip 127.0.0.1` *only if no command override is given* — any `command:` override removes the safety.

**Detection:**
```javascript
db.runCommand({ getCmdLineOpts: 1 }).parsed.net
// Vulnerable: bindIp = "0.0.0.0" or bindIpAll = true

// Also static:
grep -E "bind_ip_all|bindIp:.*0\.0\.0\.0|bindIpAll:.*true" \
  mongod.conf docker-compose*.yml
```

External reachability check (active, opt-in):
```bash
# From outside the network
nc -zv $PUBLIC_HOSTNAME 27017
# Or:
curl -s --connect-timeout 3 http://$PUBLIC_HOSTNAME:27017
# Response "It looks like you are trying to access MongoDB over HTTP" = exposed
```

**Fix:** see [`fix-templates.md`](fix-templates.md) §2 — bind to `127.0.0.1` or specific private IPs; firewall the port; if Atlas, use VPC peering or private endpoint instead.

**Source:** MongoDB security checklist; Shadowserver scans 2024–2025.

---

<a id="mg-sh-004"></a>
## 🟠 MG-SH-004 — localhost auth bypass + container exec

| Field | Value |
|-------|-------|
| **ID** | `MG-SH-004` |
| **Severity** | HIGH (-12) |

**What happens:** `enableLocalhostAuthBypass` is *true by default* in mongod. It permits creation of the first admin user from a localhost connection without authentication. Fine in principle — but in containerized deployments where any user with `docker exec` access can become localhost on the mongod container, combined with a forgotten step-2 of authentication setup, this becomes a privilege-escalation path.

**Root cause:** Default config + ops process that doesn't disable the bypass after the first admin is created.

**Detection:**
```javascript
db.adminCommand({ getParameter: 1, enableLocalhostAuthBypass: 1 })
// Vulnerable: { enableLocalhostAuthBypass: true }
```

**Fix:** `setParameter: enableLocalhostAuthBypass: false` in `mongod.conf` after initial admin creation. See [`fix-templates.md`](fix-templates.md) §2.

**Source:** MongoDB documentation; security retro reports.

---

<a id="mg-sh-005"></a>
## 🟠 MG-SH-005 — Server-side JS enabled

| Field | Value |
|-------|-------|
| **ID** | `MG-SH-005` |
| **Severity** | HIGH (-12) |

**What happens:** `$where`, `$function`, and `mapReduce` execute attacker-controlled JavaScript inside the database server. Combined with NoSQL injection (`MG-SH-009`), this is RCE-adjacent — read arbitrary collections, return data the user shouldn't see, in some configurations escape to the host.

**Root cause:** `--noscripting` not set; `security.javascriptEnabled` not `false`. Many self-hosted deployments leave the default on.

Live operators in 2025 vibe-coded Express/Mongoose apps:
```javascript
{ $where: "this.password == this.username" }
[{$match:{}}, {$project:{x:{$function:{body:"function(){...}", args:[], lang:"js"}}}}]
```

**Detection (preferred — static, no execution):**
```javascript
// From getCmdLineOpts.parsed (collected in introspection.md §A.1):
db.adminCommand({ getCmdLineOpts: 1 }).parsed.security?.javascriptEnabled
// === false → MG-SH-005 cleared (JS explicitly disabled)
// missing / true → MG-SH-005 fires (server default is enabled)
```

> `javascriptEnabled` is **not** a runtime `getParameter` field on MongoDB 7.0+ — `getParameter` returns `"no option found to get"`. The only reliable detection paths are the static `getCmdLineOpts` field (above) or an active `$where` confirmation (below).

**Detection (active confirmation, gated on write-probe opt-in):**
```javascript
// Run only with --allow-write-probes — does not modify data, but executes
// attacker-shaped JS on the server.
db.getSiblingDB("admin").runCommand({
  find: "system.version", filter: { $where: "true" }, limit: 1
}).cursor   // success → MG-SH-005 confirmed
```

**Detection (source-side):** search application code for `$where` / `$function` operators that take user input:
```bash
grep -rE '\$where|\$function' --include="*.ts" --include="*.js" --include="*.py" 2>/dev/null | grep -v node_modules
```

**Fix:** `security.javascriptEnabled: false` in `mongod.conf`. See [`fix-templates.md`](fix-templates.md) §2.

**Source:** MongoDB docs; PayloadsAllTheThings/NoSQL Injection 2025; Soroush Dalili "MongoDB NoSQL Injection with Aggregation Pipelines." `javascriptEnabled` runtime-tunability behavior verified against `mongo:7.0.20` during Phase 2 testing.

---

<a id="mg-sh-006"></a>
## 🟠 MG-SH-006 — TLS not required

| Field | Value |
|-------|-------|
| **ID** | `MG-SH-006` |
| **Severity** | HIGH (-12) |

**What happens:** Connections accepted in plaintext over the wire. Credentials, queries, and result sets all visible to anyone in the network path (LAN sniffer, compromised router, mis-configured load balancer).

**Detection:**
```javascript
db.runCommand({ getCmdLineOpts: 1 }).parsed.net.tls
// Expected: { mode: "requireTLS", certificateKeyFile: "...", CAFile: "..." }
// Vulnerable: missing, or mode in {"disabled", "allowTLS", "preferTLS"}
```

**Fix:** `net.tls.mode: requireTLS` + `certificateKeyFile` + `CAFile`. See [`fix-templates.md`](fix-templates.md) §2.

**Source:** MongoDB docs; CIS MongoDB 7 Benchmark v1.2.

---

<a id="mg-sh-007"></a>
## 🟠 MG-SH-007 — Privileged role on application user

| Field | Value |
|-------|-------|
| **ID** | `MG-SH-007` |
| **Severity** | HIGH (-12) |

**What happens:** The application connects as a user with `root`, `__system`, `dbAdminAnyDatabase`, `clusterAdmin`, or similar over-broad role. Any application-level NoSQL injection or auth bypass becomes a database-wide compromise.

**Detection:**
```javascript
// Per database, list users and inspect roles
db.getUsers({ showCredentials: false, showPrivileges: true })
// Flag any user with roles[].role in:
//   "root", "__system", "dbAdminAnyDatabase", "userAdminAnyDatabase",
//   "readWriteAnyDatabase", "clusterAdmin", "clusterMonitor"
// where the same user appears in application connection strings
```

Cross-reference against discovered `MONGODB_URI` user fragments.

**Fix:** Create a dedicated `readWrite` role scoped to one database. See [`fix-templates.md`](fix-templates.md) §3 — least-privilege user creation.

**Source:** MongoDB role docs; CIS benchmark control 5.x.

---

<a id="mg-sh-008"></a>
## 🟠 MG-SH-008 — Self-modifiable role document

| Field | Value |
|-------|-------|
| **ID** | `MG-SH-008` |
| **Severity** | HIGH (-12) |

**What happens:** The application stores user roles in an application collection (e.g., `users.role`) and trusts the value without enforcement. A `findByIdAndUpdate(id, req.body)` or `User.update({_id}, req.body)` in vibe-coded Express/Mongoose code lets a user PATCH their own role to `"admin"`. This is the MongoDB equivalent of Supabase's `user_metadata` self-elevation pattern.

**Root cause:** No JSON schema validator on the collection + Mongoose model accepts whole-body update + no application-level field allowlist on incoming PATCHes.

**Detection:**
```javascript
// Per database, list collections that look like user/profile/account collections
// without a validator
db.getCollectionInfos().forEach(ci => {
  if (/user|profile|account|member/i.test(ci.name) &&
      (!ci.options.validator || Object.keys(ci.options.validator).length === 0)) {
    print("MG-SH-008 candidate: " + ci.name);
  }
});

// Also sample one document and look for role-like field names
db.getCollection("users").findOne({}, {role:1, isAdmin:1, permissions:1, plan:1})
```

Also static — search for vulnerable Mongoose patterns:
```bash
grep -rE "(findByIdAndUpdate|findOneAndUpdate)\([^,]+,\s*req\.body\)" \
  --include="*.ts" --include="*.js" 2>/dev/null | grep -v node_modules
grep -rE "Model\.update\([^,]+,\s*req\.body\)" \
  --include="*.ts" --include="*.js" 2>/dev/null | grep -v node_modules
```

**Fix:** See [`fix-templates.md`](fix-templates.md) §4 — schema validator with `enum` constraint on `role`; allowlist field names in API layer.

**Source:** MongoDB schema validation docs; OWASP Mass Assignment; vibe-coding study (Tenzai/Ravenna 2025).

---

<a id="mg-sh-009"></a>
## 🟡 MG-SH-009 — Outdated driver / Mongoose CVE chain

| Field | Value |
|-------|-------|
| **ID** | `MG-SH-009` |
| **Severity** | MEDIUM (-5) |
| **Related CVEs** | CVE-2024-53900, CVE-2025-23061, CVE-2025-30706 |

**What happens:** Driver-side vulnerabilities allow query injection or RCE even when the server is fully patched.

- **Mongoose `populate({match})`** — `$where` injection via attacker-controlled match objects. CVE-2024-53900 fixed in Mongoose 8.9.0; CVE-2025-23061 (nested-under-`$or` bypass) fixed in 8.9.5.
- **MongoDB Connector/J** — CVE-2025-30706 (CVSS 7.5) — full system compromise via crafted server response in versions 9.0.0–9.2.0. Patched in 9.2.1.

**Detection:**
```bash
# Node/Mongoose
grep -E '"mongoose":\s*"[^"]*"' package.json
# Flag if version < 8.9.5

# Java
grep -A 1 mongodb-driver pom.xml
# Flag if mongodb-driver-sync < 5.2.x

# Source for $where + populate match pattern
grep -rE 'populate\s*\(\s*\{[^}]*match' --include="*.ts" --include="*.js" 2>/dev/null \
  | grep -v node_modules
```

**Fix:** Upgrade. See [`fix-templates.md`](fix-templates.md) §5 — driver upgrade matrix.

**Source:** HackTricks 2025 entries; Oracle CPU Apr 2025; Mongoose changelog.

---

<a id="mg-sh-010"></a>
## 🟡 MG-SH-010 — Audit log not configured

| Field | Value |
|-------|-------|
| **ID** | `MG-SH-010` |
| **Severity** | MEDIUM (-5) |
| **Edition** | Enterprise / Atlas only |

**What happens:** No record of authentication events, role changes, or schema operations. Forensic dead-end after an incident; impossible to confirm scope of a breach.

**Detection:**
```javascript
db.runCommand({ getCmdLineOpts: 1 }).parsed.auditLog
// Expected: { destination: "file" | "syslog" | "console", path: "...", format: "JSON" }
// Vulnerable: missing
```

**Fix:** Configure `auditLog` in `mongod.conf`. See [`fix-templates.md`](fix-templates.md) §2. Note: Community Edition does not support audit; if Community is in use, document the gap and recommend either Atlas or Enterprise migration for compliance-sensitive workloads.

**Source:** MongoDB Enterprise docs; CIS control 6.x.

---

<a id="mg-sh-011"></a>
## 🟡 MG-SH-011 — `enableTestCommands = 1` in production

| Field | Value |
|-------|-------|
| **ID** | `MG-SH-011` |
| **Severity** | MEDIUM (-5) |

**What happens:** `enableTestCommands` exposes development-only commands (`failpoint`, `sleep`, `configureFailPoint`, etc.) that can crash the server, force latency, or leak internal state. Intended for testing only.

**Detection:**
```javascript
db.adminCommand({ getParameter: 1, enableTestCommands: 1 })
// Vulnerable: { enableTestCommands: 1 }
```

**Fix:** Remove `--setParameter enableTestCommands=1` from launch args; restart.

---

<a id="mg-sh-012"></a>
## 🟡 MG-SH-012 — Replica-set keyfile world-readable

| Field | Value |
|-------|-------|
| **ID** | `MG-SH-012` |
| **Severity** | MEDIUM (-5) |

**What happens:** The shared keyfile that members of a replica set use to authenticate to each other is readable by other users on the host. Any local-user compromise of a replica node yields cluster-membership credentials.

**Detection:** Out-of-band host check — `stat $(grep keyFile mongod.conf | awk '{print $2}')`. Mode must be `0400` or `0600`. Owner must be the mongod user.

**Fix:** `chmod 600 /etc/mongo/keyfile && chown mongodb:mongodb /etc/mongo/keyfile`.

---

<a id="mg-sh-013"></a>
## ℹ️ MG-SH-013 — Driver options without retryWrites/readConcern

| Field | Value |
|-------|-------|
| **ID** | `MG-SH-013` |
| **Severity** | LOW (-2) |

**What happens:** Application connects with weak durability/consistency options. Not directly a security issue, but enables data-corruption and split-brain scenarios that obscure the threat model.

**Detection:** Source scan for `MongoClient(...)` or `mongoose.connect(...)` without `retryWrites: true` and without `readConcern`/`writeConcern`.

**Fix:** Tighten driver options. Connection-string equivalents: `?retryWrites=true&w=majority&readConcernLevel=majority`.

---

<a id="mg-sh-014"></a>
## ℹ️ MG-SH-014 — `mongodump`/`mongorestore` credentials in shell history

| Field | Value |
|-------|-------|
| **ID** | `MG-SH-014` |
| **Severity** | LOW (-2) |

**What happens:** Shell command history (or systemd unit files, or cron jobs) contains `mongodump --password=...`. Anyone with read access to the home directory or the cron config sees the credential.

**Detection:**
```bash
grep -E 'mongo(dump|restore|sh).*--password' \
  ~/.bash_history ~/.zsh_history /etc/cron* 2>/dev/null
```

**Fix:** Use `--config` file with `0600` perms, or `MONGODB_URI` env var sourced from a secret manager.

---

<a id="mg-at-001"></a>
## 🔴 MG-AT-001 — Atlas IP allowlist `0.0.0.0/0`

| Field | Value |
|-------|-------|
| **ID** | `MG-AT-001` |
| **Severity** | CRITICAL (-30) |

**What happens:** Atlas accepts connections from anywhere on the internet. The only barrier is the database-user password, which is often weak or reused. With MongoBleed (`MG-SH-001`) on a vulnerable cluster, no password is needed at all.

**Detection (Terraform):**
```bash
grep -rE 'cidr_block\s*=\s*"0\.0\.0\.0/0"' --include="*.tf" 2>/dev/null
```

**Detection (Atlas Admin API):**
```bash
curl --user "$ATLAS_PUB:$ATLAS_PRIV" --digest -s \
  "https://cloud.mongodb.com/api/atlas/v2/groups/$GID/networkAccessLists" \
  -H "Accept: application/vnd.atlas.2025-03-12+json" \
  | jq '.results[] | select(.cidrBlock=="0.0.0.0/0")'
# Non-empty result = vulnerable
```

**Fix:** Restrict CIDRs to known office/VPN/CI ranges; or move to AWS PrivateLink / Azure Private Endpoint / GCP Private Service Connect. See [`fix-templates.md`](fix-templates.md) §6 — Terraform module with restricted allowlist.

**Source:** Atlas docs; Censys research on exposed Atlas clusters.

---

<a id="mg-at-002"></a>
## 🟠 MG-AT-002 — Atlas Function as direct DB pass-through

| Field | Value |
|-------|-------|
| **ID** | `MG-AT-002` |
| **Severity** | HIGH (-12) |

**What happens:** An Atlas Function exposed as an HTTPS Endpoint takes a client-supplied `filter` object and passes it directly to `collection.find()`. This is NoSQL injection over HTTPS — the attacker controls the query that runs server-side, including `$where` / `$function` / `$or` operators.

**Root cause:** Function body looks like:
```javascript
exports = async function(arg) {
  const collection = context.services.get("mongodb-atlas").db("app").collection("users");
  return await collection.find(arg.filter).toArray();   // attacker controls arg.filter
};
```

This pattern proliferated after the Atlas Data API deprecation (Sept 30 2025) — apps that previously called `/app/{app-id}/endpoint/data/v1/action/find` rotated to bare-bones Atlas Functions without re-architecting auth or input validation. (See `MG-AT-003`.)

**Detection (Atlas Function source review):** look for parameters passed directly into `find`, `findOne`, `aggregate`, `updateMany`. Reject any function where the filter shape is not constrained to a typed allowlist.

**Fix:** Parameterize. See [`fix-templates.md`](fix-templates.md) §7 — typed-input Atlas Function template.

**Source:** Bluefire Redteam Atlas Functions analysis; Softinstigate / MongoDB community forum.

---

<a id="mg-at-003"></a>
## 🟠 MG-AT-003 — Atlas Data API still in code

| Field | Value |
|-------|-------|
| **ID** | `MG-AT-003` |
| **Severity** | HIGH (-12) |

**What happens:** The application still calls deprecated Atlas Data API endpoints. As of Sept 30 2025 these stopped responding entirely; apps that "fixed" the outage by rotating to less-audited Atlas Functions (per `MG-AT-002`) are now in worse security shape than before.

**Detection:**
```bash
grep -rE '/api/atlas/v[0-9.]+/groups/[^/]+/dataAPI|/app/[^/]+/endpoint/data/v1/action/' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.py" 2>/dev/null \
  | grep -v node_modules
```

**Fix:** Migrate to a properly-authed Atlas Function with typed inputs (see `MG-AT-002`), or to Atlas App Services with a real auth provider configured. See [`fix-templates.md`](fix-templates.md) §7.

**Source:** Atlas Data API deprecation notice (MongoDB blog, June 2025).

---

<a id="mg-at-004"></a>
## 🟡 MG-AT-004 — Atlas DB user with Atlas-admin role

| Field | Value |
|-------|-------|
| **ID** | `MG-AT-004` |
| **Severity** | MEDIUM (-5) |

**What happens:** The DB user the application connects with has `atlasAdmin` role. This is `dbAdminAnyDatabase` + `userAdminAnyDatabase` + `readWriteAnyDatabase` rolled up. Application-level NoSQL injection becomes a project-wide compromise.

**Detection:**
```bash
curl --user "$ATLAS_PUB:$ATLAS_PRIV" --digest -s \
  "https://cloud.mongodb.com/api/atlas/v2/groups/$GID/databaseUsers" \
  | jq '.results[] | select(.roles[].roleName=="atlasAdmin")'
```

**Fix:** Replace with `readWrite` scoped to the application database. See [`fix-templates.md`](fix-templates.md) §3.

---

<a id="mg-at-005"></a>
## 🟡 MG-AT-005 — API key with Project Owner

| Field | Value |
|-------|-------|
| **ID** | `MG-AT-005` |
| **Severity** | MEDIUM (-5) |

**What happens:** A programmatic API key (used in CI/CD, Terraform, monitoring) has `Project Owner` role — equivalent to root inside the Atlas project. Key leakage = project takeover.

**Detection:**
```bash
curl --user "$ATLAS_PUB:$ATLAS_PRIV" --digest -s \
  "https://cloud.mongodb.com/api/atlas/v2/orgs/$ORG/apiKeys" \
  | jq '.results[] | select(.roles[].roleName=="ORG_OWNER" or .roles[].roleName=="GROUP_OWNER")'
```

**Fix:** Rotate; reissue with least-privilege role (`Project Read Only` for monitoring; `Project Data Access Read/Write` for app keys; never `Owner`).

---

<a id="mg-at-006"></a>
## ℹ️ MG-AT-006 — Encryption-at-rest using cloud default key

| Field | Value |
|-------|-------|
| **ID** | `MG-AT-006` |
| **Severity** | LOW (-2) |

**What happens:** Atlas uses the cloud provider's default key for encryption-at-rest, not a customer-managed key (CMK). Compliance frameworks (HIPAA, PCI-DSS, FedRAMP) typically require CMK.

**Detection:**
```bash
curl --user "$ATLAS_PUB:$ATLAS_PRIV" --digest -s \
  "https://cloud.mongodb.com/api/atlas/v2/groups/$GID/encryptionAtRest"
# enabled=false, or kmsConfiguration absent → using cloud default
```

**Fix:** Configure CMK. See Atlas docs for AWS KMS / Azure Key Vault / GCP KMS integration.

---

## Pattern-ID conventions

- `MG-SH-NNN` — self-hosted mongod
- `MG-AT-NNN` — Atlas (managed)

If a new pattern applies to both, prefer the `MG-SH-*` ID and note Atlas applicability in the body. Atlas-only patterns (CMK, network access lists, billing-quota DoS) get `MG-AT-*` IDs.

When adding patterns, follow the calibration discipline in `core/scoring.md` §"Calibration discipline."
