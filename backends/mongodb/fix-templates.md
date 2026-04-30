# MongoDB — Fix Templates

Copy-pasteable fixes for every MongoDB pattern in `anti-patterns.md`. Each section maps to the patterns it addresses.

**Delivery contract** (per `core/workflow.md` §5): always offer three modes — write a file, apply now, or walkthrough. The templates below assume "write a file" by default; switch the framing for the other modes.

---

## Table of contents

1. [Version upgrade matrix](#1-version-upgrade-matrix) — `MG-SH-001`
2. [Hardened `mongod.conf`](#2-hardened-mongodconf) — `MG-SH-002` / `003` / `004` / `005` / `006` / `010` / `011`
3. [Least-privilege user creation](#3-least-privilege-user-creation) — `MG-SH-007` / `MG-AT-004`
4. [Schema validators against role escalation](#4-schema-validators-against-role-escalation) — `MG-SH-008`
5. [Driver upgrade matrix](#5-driver-upgrade-matrix) — `MG-SH-009`
6. [Atlas Terraform — restricted access](#6-atlas-terraform--restricted-access) — `MG-AT-001` / `MG-AT-005`
7. [Atlas Function — typed input replacement](#7-atlas-function--typed-input-replacement) — `MG-AT-002` / `MG-AT-003`
8. [Operational hardening — credentials, dumps, keyfiles](#8-operational-hardening) — `MG-SH-012` / `MG-SH-013` / `MG-SH-014`
9. [Migration / rollout template](#9-migration--rollout-template)

---

## 1. Version upgrade matrix

`MG-SH-001` — MongoBleed (CVE-2025-14847)

| Major | Vulnerable range | Patched version | Notes |
|-------|------------------|-----------------|-------|
| 8.2.x | 8.2.0–8.2.2 | **8.2.3** | Upgrade in place |
| 8.0.x | 8.0.0–8.0.16 | **8.0.17** | Upgrade in place |
| 7.0.x | 7.0.0–7.0.27 | **7.0.28** | Upgrade in place; current LTS |
| 6.0.x | 6.0.0–6.0.26 | **6.0.27** | Upgrade in place |
| 5.0.x | 5.0.0–5.0.31 | **5.0.32** | Upgrade in place |
| 4.4.x | 4.4.0–4.4.29 | **4.4.30** | Upgrade in place |
| 4.2 / 4.0 / 3.6 | all | **No patch** | Upgrade major to 6.0.x or 7.0.x |

**Upgrade procedure (in-place, replica set):**

```bash
# Per replica node, in order: secondary → secondary → primary
# 1. drain the node from the application (rolling deploy)
# 2. stop mongod
sudo systemctl stop mongod
# 3. update package
sudo apt-get update && sudo apt-get install -y mongodb-org=7.0.28 \
    mongodb-org-server=7.0.28 mongodb-org-mongos=7.0.28 \
    mongodb-org-tools=7.0.28
# 4. start
sudo systemctl start mongod
# 5. wait for member to rejoin RS as SECONDARY before moving to next node
mongosh --quiet --eval 'rs.status().members.find(m => m.self).stateStr'
```

**If upgrade is blocked this week (compression workaround — same-day mitigation only):**

```yaml
# /etc/mongod.conf — add or modify
net:
  compression:
    compressors: snappy,zstd     # remove zlib from the list
```

Then restart mongod. Verify:
```javascript
db.runCommand({getCmdLineOpts:1}).parsed.net.compression.compressors
// must equal "snappy,zstd" — must NOT include "zlib"
```

This blocks the MongoBleed payload from negotiating but does not fix the underlying bug. Schedule the version upgrade within the same maintenance window.

**Atlas:** auto-patched. No customer action required. Confirm by checking the cluster's MongoDB version in the Atlas UI.

---

## 2. Hardened `mongod.conf`

Single-file template addressing `MG-SH-002` / `003` / `004` / `005` / `006` / `010` / `011`.

```yaml
# /etc/mongod.conf — secure baseline (MongoDB 6.0+)

# Network — bind to private interfaces only, require TLS
net:
  bindIp: 127.0.0.1,10.0.0.10        # comma-separated; or specific private IP
  port: 27017
  tls:
    mode: requireTLS                 # MG-SH-006 fix
    certificateKeyFile: /etc/ssl/mongodb/mongod.pem
    CAFile: /etc/ssl/mongodb/ca.pem
    allowConnectionsWithoutCertificates: false
    disabledProtocols: TLS1_0,TLS1_1
  compression:
    compressors: snappy,zstd          # MG-SH-001 mitigation if upgrade pending

# Auth — required, role-based, no localhost bypass after init
security:
  authorization: enabled              # MG-SH-002 fix
  javascriptEnabled: false            # MG-SH-005 fix
  keyFile: /etc/mongo/keyfile         # MG-SH-012 — chmod 600

setParameter:
  enableLocalhostAuthBypass: false    # MG-SH-004 fix; set after first admin user is created
  enableTestCommands: 0               # MG-SH-011 fix

# Audit — Enterprise / Atlas only
auditLog:                             # MG-SH-010 fix
  destination: file
  format: JSON
  path: /var/log/mongodb/audit.json
  filter: '{ atype: { $in: ["authenticate", "authCheck", "createCollection",
                            "dropCollection", "createUser", "dropUser",
                            "grantRolesToUser", "revokeRolesFromUser",
                            "createRole", "dropRole",
                            "grantPrivilegesToRole", "revokePrivilegesFromRole",
                            "shardCollection", "dropDatabase"] } }'

# Storage / journaling — best-practice baseline (not security per se)
storage:
  dbPath: /var/lib/mongodb
  journal:
    enabled: true

# Process management
processManagement:
  fork: true
  pidFilePath: /var/run/mongodb/mongod.pid
  timeZoneInfo: /usr/share/zoneinfo

# Logging
systemLog:
  destination: file
  path: /var/log/mongodb/mongod.log
  logAppend: true
  verbosity: 0
```

**Apply:** save, validate (`mongod --config /etc/mongod.conf --validate`), restart (`systemctl restart mongod`).

**Validate after restart:**

```javascript
const opts = db.runCommand({getCmdLineOpts:1}).parsed;
print("auth:    " + (opts.security?.authorization === "enabled" ? "OK" : "FAIL"));
print("bindIp:  " + opts.net?.bindIp);
print("tls:     " + (opts.net?.tls?.mode === "requireTLS" ? "OK" : "FAIL"));
print("compr:   " + (opts.net?.compression?.compressors || "default"));
print("js:      " + (opts.security?.javascriptEnabled === false ? "OK (disabled)" : "FAIL"));
```

---

## 3. Least-privilege user creation

`MG-SH-007` / `MG-AT-004`

```javascript
// On admin DB, as a user with userAdmin or userAdminAnyDatabase role
use admin

// Application user — readWrite only on its own database
db.createUser({
  user: "myapp_rw",
  pwd: passwordPrompt(),                    // never inline the password
  roles: [
    { role: "readWrite", db: "myapp" }
  ],
  authenticationRestrictions: [
    {
      clientSource: ["10.0.0.0/16"],         // app subnet only
      serverAddress: ["10.0.0.10", "10.0.0.11", "10.0.0.12"]   // RS members
    }
  ]
})

// Read-only analytics user
db.createUser({
  user: "myapp_ro",
  pwd: passwordPrompt(),
  roles: [
    { role: "read", db: "myapp" }
  ]
})

// Backup user — restoreAndBackup, not root
db.createUser({
  user: "backup_svc",
  pwd: passwordPrompt(),
  roles: [
    { role: "backup", db: "admin" },
    { role: "restore", db: "admin" }
  ]
})
```

**Migration from existing over-privileged user:**

```javascript
// 1. Create the new least-privilege user (as above).
// 2. Update application secret manager / env to use the new credentials.
// 3. Roll out application config; verify connectivity.
// 4. Drop or downgrade the old user:
db.getSiblingDB("admin").updateUser("old_root_user", {
  roles: [ { role: "read", db: "myapp" } ]   // downgrade rather than drop, for emergency rollback
})

// 5. After observation window (e.g., 7 days):
db.getSiblingDB("admin").dropUser("old_root_user")
```

---

## 4. Schema validators against role escalation

`MG-SH-008` — prevent `findByIdAndUpdate(id, req.body)` from setting `role: "admin"`.

```javascript
// Apply to every collection that stores user roles, plans, or permissions
use myapp

db.runCommand({
  collMod: "users",
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["_id", "email"],
      properties: {
        email: { bsonType: "string", pattern: "^[^@]+@[^@]+$" },
        role: { enum: ["user", "editor"] },        // 'admin' explicitly NOT in enum
        plan: { enum: ["free", "pro", "team"] },
        permissions: {
          bsonType: "array",
          items: { enum: ["read", "write"] }       // 'admin' permission not in enum
        },
        balance: { bsonType: ["int", "long", "double"] },
        // Other fields uncontrolled by validator — fine, they're not authority-bearing
      },
      additionalProperties: true
    }
  },
  validationLevel: "strict",                       // applies to all writes, not just new docs
  validationAction: "error"                        // reject — don't just warn
})
```

**To grant admin:** the validator must be temporarily relaxed by an authorized operator using a separate, audited path. Or, preferably, replace the collection-stored role with custom claims in the application's auth provider (Auth0 / Firebase Auth / Supabase Auth) and remove the `role` field entirely.

**For the API layer**, also add an explicit allowlist of fields the user can update on their own profile:

```typescript
// Express + Mongoose example
const ALLOWED_UPDATES = ['displayName', 'avatarUrl', 'preferences'];

app.patch('/users/:id', requireAuth, async (req, res) => {
  if (req.params.id !== req.user.uid) return res.status(403).end();
  const safeUpdate = Object.fromEntries(
    Object.entries(req.body).filter(([k]) => ALLOWED_UPDATES.includes(k))
  );
  await User.findByIdAndUpdate(req.params.id, safeUpdate, { new: true, runValidators: true });
});
```

The validator is defense-in-depth; the API allowlist is the primary fix.

---

## 5. Driver upgrade matrix

`MG-SH-009`

| Driver | Vulnerable | Patched | CVE |
|--------|------------|---------|-----|
| Mongoose (Node) | < 8.9.0 | **8.9.0+** for `populate({match})` $where | CVE-2024-53900 |
| Mongoose (Node) | < 8.9.5 | **8.9.5+** for nested-under-`$or` bypass | CVE-2025-23061 |
| MongoDB Connector/J | 9.0.0–9.2.0 | **9.2.1+** | CVE-2025-30706 (CVSS 7.5) |

```bash
# Node / Mongoose
npm install mongoose@^8.9.5

# Java / Maven
# pom.xml — bump to 5.2.x
<dependency>
  <groupId>org.mongodb</groupId>
  <artifactId>mongodb-driver-sync</artifactId>
  <version>5.2.1</version>
</dependency>
```

**Code-level mitigation if upgrade is blocked** (Mongoose specifically):

```typescript
// Reject any $where / $function in the populate match
import { Document } from 'mongoose';
function safeMatch(match: object): object {
  const json = JSON.stringify(match);
  if (json.includes('$where') || json.includes('$function')) {
    throw new Error('Server-side JS in populate match is not permitted');
  }
  return match;
}

await User.find().populate({ path: 'orders', match: safeMatch(req.body.filter) });
```

---

## 6. Atlas Terraform — restricted access

`MG-AT-001` / `MG-AT-005`

```hcl
# main.tf — Atlas project with strictly-bounded network access

terraform {
  required_providers {
    mongodbatlas = {
      source  = "mongodb/mongodbatlas"
      version = "~> 1.21"
    }
  }
}

variable "atlas_org_id"     { type = string }
variable "atlas_project_id" { type = string }
variable "office_cidrs"     { type = list(string) }   # e.g., ["203.0.113.0/24"]
variable "ci_cidrs"         { type = list(string) }   # GitHub Actions runner egress

# CIDR allowlist — never 0.0.0.0/0
resource "mongodbatlas_project_ip_access_list" "office" {
  for_each   = toset(var.office_cidrs)
  project_id = var.atlas_project_id
  cidr_block = each.value
  comment    = "Office network — managed by Terraform"
}

resource "mongodbatlas_project_ip_access_list" "ci" {
  for_each   = toset(var.ci_cidrs)
  project_id = var.atlas_project_id
  cidr_block = each.value
  comment    = "CI runner egress — managed by Terraform"
}

# Database user — readWrite only on the application database
resource "mongodbatlas_database_user" "app" {
  project_id         = var.atlas_project_id
  username           = "myapp_rw"
  password           = var.atlas_app_user_password   # from secret manager
  auth_database_name = "admin"

  roles {
    role_name     = "readWrite"
    database_name = "myapp"
  }

  # Auth restrictions — IP scope on the user as well as the project
  scopes {
    name = "myapp-cluster"
    type = "CLUSTER"
  }
}

# Programmatic API key — read-only role, never Owner
resource "mongodbatlas_project_api_key" "ci_readonly" {
  project_id  = var.atlas_project_id
  description = "CI read-only — Sentinel audits + monitoring"
  role_names  = ["GROUP_READ_ONLY"]
}
```

**For maximum isolation, use a private endpoint instead of CIDR allowlists:**

```hcl
# AWS PrivateLink for Atlas
resource "mongodbatlas_privatelink_endpoint" "atlas" {
  project_id    = var.atlas_project_id
  provider_name = "AWS"
  region        = "us-east-1"
}

resource "aws_vpc_endpoint" "atlas" {
  vpc_id              = var.app_vpc_id
  service_name        = mongodbatlas_privatelink_endpoint.atlas.endpoint_service_name
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.app_private_subnet_ids
  security_group_ids  = [aws_security_group.atlas_endpoint.id]
}
```

When PrivateLink is configured, drop the office and CI CIDR rules — connectivity goes via the VPC, not the public internet.

---

## 7. Atlas Function — typed input replacement

`MG-AT-002` / `MG-AT-003`

**Anti-pattern (the issue):**

```javascript
// DO NOT DO THIS — direct DB pass-through, NoSQL injection over HTTPS
exports = async function(arg) {
  const collection = context.services.get("mongodb-atlas").db("app").collection("users");
  return await collection.find(arg.filter).toArray();   // attacker controls arg.filter
};
```

**Replacement — typed inputs, no operator pass-through:**

```javascript
// Atlas Function — typed-input search by user ID + optional createdAfter cursor
exports = async function(arg) {
  // 1. Authenticate — App Services should already require auth, but verify
  if (!context.user || !context.user.id) {
    return { error: "unauthorized" };
  }

  // 2. Type-check inputs at the function boundary
  const userId = String(arg.userId || "");
  if (!userId.match(/^[a-zA-Z0-9_-]{1,64}$/)) {
    return { error: "invalid userId" };
  }
  const createdAfter = arg.createdAfter ? new Date(arg.createdAfter) : null;
  const limit = Math.min(50, Math.max(1, Number(arg.limit) || 20));

  // 3. Authorize — the requester can only read their own data
  if (userId !== context.user.id) {
    return { error: "forbidden" };
  }

  // 4. Construct the query server-side; no operator pass-through from arg
  const query = { userId };                                       // not arg.filter
  if (createdAfter) query.createdAt = { $gt: createdAfter };

  const collection = context.services.get("mongodb-atlas").db("app").collection("orders");
  return await collection.find(query)
                          .sort({ createdAt: -1 })
                          .limit(limit)
                          .toArray();
};
```

**Migrating from deprecated Atlas Data API:** apps that called `/app/{app-id}/endpoint/data/v1/action/find` should rewrite to call this Atlas Function, not bypass it.

---

## 8. Operational hardening

### `MG-SH-012` — replica-set keyfile permissions

```bash
sudo chown mongodb:mongodb /etc/mongo/keyfile
sudo chmod 600 /etc/mongo/keyfile
```

### `MG-SH-013` — driver options

Connection-string equivalents to add to `MONGODB_URI`:

```
?retryWrites=true&w=majority&readConcernLevel=majority&authSource=admin
```

### `MG-SH-014` — credentials in shell history

```bash
# Read credentials from a config file with 0600 perms
mongodump --config=/etc/mongodb/backup.cnf --archive=/var/backups/mongo-$(date +%F).archive --gzip

# /etc/mongodb/backup.cnf (chmod 600)
# uri: mongodb://backup_svc:PASSWORD@10.0.0.10:27017/admin?authSource=admin&tls=true
```

Or env-from-secret-manager:
```bash
export MONGODB_URI="$(aws secretsmanager get-secret-value --secret-id mongodb/backup --query SecretString --output text)"
mongodump --uri="$MONGODB_URI" --archive=/var/backups/mongo-$(date +%F).archive --gzip
unset MONGODB_URI
```

Scrub history:
```bash
sed -i '/--password/d' ~/.bash_history
history -c
```

---

## 9. Migration / rollout template

```bash
# migrations/2026-04-30-mongodb-sentinel-fixes.md

## Plan
- [ ] (Day 0) Snapshot — `mongodump --archive=pre-sentinel-$(date +%s).gz --gzip`
- [ ] (Day 0) Apply schema validators on `users`, `accounts` (§4) — non-strict mode for 1 day
- [ ] (Day 0) Verify validator catches no false-positives in app traffic
- [ ] (Day 1) Switch validator to strict mode
- [ ] (Day 1) Create least-privilege application user `myapp_rw` (§3)
- [ ] (Day 1) Update app secret to new credentials
- [ ] (Day 2) Rolling restart with hardened `mongod.conf` (§2) — secondary first
- [ ] (Day 2) Confirm `enableLocalhostAuthBypass: false` on each node post-restart
- [ ] (Day 3) Upgrade to MongoDB 7.0.28 if 7.0 line (§1) — rolling
- [ ] (Day 3) Run Sentinel re-audit; expect score ≥ 80
- [ ] (Day 7) Drop old root-class user

## Rollback
- Each step has an explicit revert. The collMod / createUser / config changes
  are individually reversible via the same commands with old values.
- Major-version DB upgrade (§1) cannot be downgraded in place — use the
  pre-flight snapshot for restore.
```
