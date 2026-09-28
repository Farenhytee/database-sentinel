# MongoDB — End-to-End Test Recipe

Per the implementation plan §Phase 2 task 11, this file documents a deliberately-vulnerable MongoDB test setup that the Sentinel MongoDB workflow can be validated against. Per Q2 default in `DECISIONS.md`, we **document** the recipe rather than spinning it up live in this environment.

Use this when you want to verify a Sentinel change end-to-end before merging.

---

## Setup — vulnerable instance

```yaml
# docker-compose.test-vulnerable.yml
# Deliberately insecure mongod for Sentinel validation. DO NOT use this on a network anyone else can reach.
services:
  mongo:
    image: mongo:7.0.20                        # MG-SH-001 vulnerable: <7.0.28 → MongoBleed
    container_name: sentinel-test-mongo
    command: ["mongod", "--bind_ip_all"]       # MG-SH-003 — internet-bound
    # No --auth flag                           # MG-SH-002 — auth disabled
    # No TLS configuration                     # MG-SH-006 — plaintext
    ports:
      - "127.0.0.1:27017:27017"                # bind to loopback ONLY for local validation
    environment:
      # Intentionally NOT setting MONGO_INITDB_ROOT_USERNAME / PASSWORD
      MONGO_INITDB_DATABASE: testapp
```

```bash
docker compose -f docker-compose.test-vulnerable.yml up -d
```

**Critical safety note:** The `ports` mapping above binds to `127.0.0.1` only. **Never** expose this container on `0.0.0.0` even on a developer laptop. The MongoBleed PoC is public; an exposed instance can be compromised within minutes.

---

## Seed test data

```bash
# Connect (no auth required because of MG-SH-002)
docker exec -it sentinel-test-mongo mongosh \
  --eval '
    use testapp
    db.createCollection("users")
    db.users.insertMany([
      { email: "alice@example.invalid", role: "user", plan: "free" },
      { email: "bob@example.invalid", role: "editor", plan: "pro" }
    ])
    // No JSON schema validator on users — MG-SH-008 surface
    db.createCollection("orders")
    db.orders.insertOne({ userId: "alice", total: 99 })
  '
```

---

## Run Sentinel against this instance

```bash
# From the Sentinel skill directory:
cd /Library/Personal/database-sentinel

# Connect with no credentials — exactly the attacker's view of MG-SH-002
export MONGODB_URI="mongodb://127.0.0.1:27017/testapp"

# 1. Confirm detection picks up MongoDB
grep -rln 'mongodb://' --include="*.env*" 2>/dev/null

# 2. Manually run the introspection bundle from backends/mongodb/introspection.md
docker exec -it sentinel-test-mongo mongosh --quiet --eval '
  print(JSON.stringify({
    version: db.runCommand({buildInfo:1}).version,
    cmdLineOpts: db.runCommand({getCmdLineOpts:1}).parsed,
    parameters: db.adminCommand({
      getParameter: 1,
      enableLocalhostAuthBypass: 1,
      javascriptEnabled: 1,
      enableTestCommands: 1
    })
  }, null, 2))
'

# 3. Confirm an unauthenticated find succeeds — MG-SH-002 active proof
mongosh --quiet --eval 'db.users.findOne()' "$MONGODB_URI"
# Expected: returns the alice document
```

---

## Expected findings

When Sentinel runs against this instance, the report should include:

| Pattern | Severity | Why |
|---------|----------|-----|
| **MG-SH-001** | 🔴 CRITICAL | mongo:7.0.20 < 7.0.28 (MongoBleed); zlib compression enabled by default |
| **MG-SH-002** | 🔴 CRITICAL | `security.authorization` not set; `mongo` image bypassed `mongo_secure_installation` |
| **MG-SH-003** | 🔴 CRITICAL | `--bind_ip_all` on command line; binds 0.0.0.0 |
| **MG-SH-004** | 🟠 HIGH | `enableLocalhostAuthBypass = true` (default) |
| **MG-SH-005** | 🟠 HIGH | `javascriptEnabled = true` (default) |
| **MG-SH-006** | 🟠 HIGH | No TLS configuration |
| **MG-SH-008** | 🟠 HIGH | `users` collection has no validator; role field present |
| **MG-SH-010** | 🟡 MEDIUM | No audit log (Community edition) |

**Score expectation:** with 3 CRITICAL × -30 + 4 HIGH × -12 + 1 MEDIUM × -5 = -143, floored at 0. Headline: **0/100 🔴**.

---

## Add the MongoBleed probe (opt-in)

```bash
# Save the probe script from backends/mongodb/mongobleed-probe.md §"Bash variant"
# to ./scripts/mongobleed-probe.sh, then:

export MONGOBLEED_PROBE_CONFIRM_AUTHORIZED=yes
./scripts/mongobleed-probe.sh 127.0.0.1 27017
echo "exit code: $?"
# Expected on mongo:7.0.20: "vulnerable" + exit 1
```

---

## Apply Sentinel's fixes — verify clean state

```bash
# Stop the vulnerable container
docker compose -f docker-compose.test-vulnerable.yml down

# Apply fixes from backends/mongodb/fix-templates.md:
#   §1 — bump image to mongo:7.0.28 (latest 7.0)
#   §2 — hardened mongod.conf
#   §3 — least-privilege user
#   §4 — schema validator on users

# (See test-recipe-hardened.md companion for the full hardened compose — TBD.)
```

After re-running Sentinel against the hardened instance, the score should be ≥ 80 with at most LOW / INFO findings.

---

## Cleanup

```bash
docker compose -f docker-compose.test-vulnerable.yml down -v
docker volume prune -f
```

---

## CI integration

The `assets/ci/github-action-mongodb.yml` workflow can target a similarly-shaped vulnerable instance via the `services:` block in its live job. For the static-mode validation, commit `docker-compose.test-vulnerable.yml` + a vulnerable Terraform fragment to a test branch and verify the action exits non-zero with the expected `::error` annotations.

---

## Why "document-only" rather than running it live

Per Q2 default in `DECISIONS.md`, this environment runs document-only verification. The recipe above is the contract — when the user wants live validation:

1. Run the setup commands locally.
2. Run the Sentinel workflow per `backends/mongodb/workflow.md`.
3. Confirm findings match the table in §"Expected findings."
4. Tear down.

If any expected finding is missing from the live run, that's a Sentinel bug — file an issue against `backends/mongodb/anti-patterns.md` referencing the specific `MG-SH-NNN` ID.
