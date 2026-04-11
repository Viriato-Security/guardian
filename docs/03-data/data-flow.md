# Data Flow

This document describes how data moves through the entire Guardian system, covering data at
rest, data in transit, every transformation applied to the data, and the specific security
properties (encrypted, signed, plaintext, hashed) of the data at each point in its lifecycle.

---

## Data Lifecycle Overview

```
┌────────────────────────────────────────────────────────────────────────────────┐
│  STAGE           │  DATA FORMAT          │  SECURITY PROPERTY                 │
├────────────────────────────────────────────────────────────────────────────────┤
│  Kernel ring buf │  C struct (binary)    │  In-memory, isolated by BPF verif. │
│  In-process obj  │  Python dataclass     │  In-process memory, no I/O         │
│  pending.jsonl   │  JSONL (plaintext)    │  Signed (HMAC), NOT encrypted      │
│  agent_id file   │  UUID text file       │  NOT secret; stable identity       │
│  gRPC wire       │  Protobuf + TLS 1.3   │  Encrypted + HMAC-signed           │
│  TimescaleDB     │  Platform-managed     │  Platform's responsibility         │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## Data at Rest

### 1. agent_id file

**Path**: `/var/lib/guardian/.agent_id` (production) or `~/.guardian_agent_id` (development).

**Format**: a single UUID4 string followed by a newline, e.g.:
```
f47ac10b-58cc-4372-a567-0e02b2c3d479
```

**Security property**: the `agent_id` is **not a secret**. It is a stable identity used to
correlate events from the same agent across restarts. It is sent in plaintext in every
`EventBatch` proto message and stored openly in the platform's database. It does not need to
be secret because it is authenticated by the HMAC signature (which uses the token, not the
agent_id, as the cryptographic key).

The file should be readable by the user running the guardian process. It does not need to be
protected from read access; however, it should be protected from write access (to prevent
identity spoofing by a local attacker who could overwrite it with a different agent's UUID).
Recommended permissions: `0644` (readable by all, writable only by owner).

**Creation**: the file is created once by `_load_or_create_agent_id()` using `uuid.uuid4()`.
The UUID is a cryptographically random version 4 identifier. It is never regenerated unless
the file is deleted.

---

### 2. pending.jsonl (disk buffer)

**Path**: `~/.guardian/buffer/pending.jsonl` (development default) or
`/var/lib/guardian/buffer/pending.jsonl` (production default), or whatever
`config.agent.buffer_path` specifies.

**Format**: one JSON object per line (JSONL). Each line represents one batch that failed to
be delivered via gRPC:

```json
{"agent_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "signature": "a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2", "events": [{"timestamp": "2026-04-10T14:22:01.123456000Z", "pid": 14832, "process": "python", "syscall": "read", "fd_path": "/var/lib/models/patient-diagnosis-v2/model.pt", "bytes": 32768, "network_addr": "", "return_val": "0", "uid": 1001, "agent_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "model_name": "patient-diagnosis-v2", "container_id": "a3b4c5d6e7f8", "pod_name": "diagnosis-inference-7d9f8c-xkbvp", "namespace": "production", "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000", "this_hash": "7b2c4f8a1e9d3c5f7b2c4f8a1e9d3c5f7b2c4f8a1e9d3c5f7b2c4f8a1e9d3c5"}]}
```

Each line is a complete, self-contained JSON object with three top-level keys:

| Key | Type | Description |
|---|---|---|
| `agent_id` | string | The UUID of this Guardian installation |
| `signature` | string | HMAC-SHA256 hexdigest (64 chars) computed over the event hash list |
| `events` | array | Array of event objects, each with all 16 RawEvent fields |

**Security properties of pending.jsonl**:

- **NOT encrypted**: the file is stored in plaintext. Event content (syscall names, file paths,
  network addresses, model names) is visible to anyone with read access to the buffer directory.
- **Signed**: the `signature` field is the same HMAC-SHA256 that would have been sent over
  gRPC. When buffered batches are replayed, the platform verifies this signature. Any
  modification to the events in a buffered line will cause the signature to fail verification
  on replay.
- **Hash-chained**: each event in `events[]` contains `prev_hash` and `this_hash`. The chain
  is intact at the time of buffering. Modifying any event field in the buffer breaks the chain.
- **Maximum 10,000 lines**: the file is capped at 10,000 lines (`_MAX_BUFFER_LINES = 10_000`).
  Batches that would exceed this cap are dropped.

**Encryption recommendation**: if the `buffer_path` directory is on an unencrypted volume,
use filesystem-level encryption (LUKS on Linux, FileVault on macOS) to protect buffered event
data at rest. The guardian agent itself does not encrypt the buffer.

**Drain semantics**: when a gRPC send succeeds, `_drain_buffer()` reads all lines from
`pending.jsonl`, replays them in order (FIFO — oldest first), and rewrites the file with only
the lines that failed to replay. Successfully replayed lines are not present in the rewritten
file. This means the buffer file shrinks as connectivity is restored.

---

### 3. guardian.yaml

**Path**: one of the three search paths (see [guardian.yaml Reference](guardian-yaml-reference.md)).

**Security property**: the `agent.token` field in `guardian.yaml` is a **secret**. It is the
HMAC signing key used for all batch signatures. It is also sent as a gRPC metadata header.
The file should have permissions `0600` (owner read/write only) in production. It must not be
committed to version control.

The rest of `guardian.yaml` is non-sensitive configuration metadata.

---

## Data in Transit

### gRPC wire format (Guardian → viriato-platform)

All data in transit between the Guardian agent and viriato-platform is sent via gRPC over a
TLS 1.3 connection (except for localhost/development connections, which use plaintext gRPC).

**What is transmitted**: one `EventBatch` proto message per batch flush, containing:
- `agent_id` (top-level, plain)
- `signature` (top-level HMAC-SHA256, 64 hex chars)
- `events` (repeated `Event` proto messages, one per event in the batch)

**TLS encryption**: the entire proto message is encrypted in transit by TLS 1.3. Neither the
event content nor the HMAC signature nor the `agent_id` is visible to a network observer on
a TLS connection.

**gRPC metadata**: the `Authorization: Bearer <token>` header is sent as a gRPC metadata
key-value pair on each stream. This header is also protected by TLS.

**Binary proto encoding**: events are serialised in Protocol Buffers v3 binary wire format, not
JSON. The binary format is more compact (approximately 30–50% smaller than JSON) and is not
human-readable in transit.

**Non-TLS (development)**: when `control_plane` starts with `"localhost"` or `"127."`, or when
`GUARDIAN_INSECURE_GRPC=1` is set, an insecure channel is used. In this case all data
(including the token in gRPC metadata) is transmitted in plaintext. This is acceptable only
in a trusted local network environment.

---

## Data Transformations

The following table traces every transformation applied to the event data from creation to
platform storage.

| Step | Transformation | Input | Output | New security property |
|---|---|---|---|---|
| 1. Generator / kernel | Create RawEvent | None | RawEvent (9 fields) | None |
| 2. Enricher | Add context fields | RawEvent (9 fields) | RawEvent (14 fields) | agent_id added |
| 3. Signer (event) | SHA-256 chain | RawEvent (14 fields) | RawEvent (16 fields) | `this_hash` commits to all 15 other fields |
| 4. Batch accumulate | Append to list | RawEvent (16 fields) | list[RawEvent] | None |
| 5. Signer (batch) | HMAC-SHA256 | list[RawEvent].{prev_hash, this_hash} | signature string | Batch authenticated with token |
| 6. Proto serialise | Protobuf encoding | (list[RawEvent], signature) | EventBatch bytes | Compact binary, schema-validated |
| 7. TLS | Encrypt | EventBatch bytes | Ciphertext | Encrypted for transit |
| 8. Platform receive | TLS decrypt + proto decode | Ciphertext | EventBatch | |
| 9. Platform verify | HMAC re-compute | EventBatch.{signature, events.{prev_hash, this_hash}} | OK / rejected | |
| 10. Platform store | SQL INSERT | EventBatch.events | TimescaleDB rows | Persistent storage |

---

## What is Encrypted vs Signed vs Plaintext

### Encryption

| Data | Encrypted? | By what? |
|---|---|---|
| Events on the gRPC wire | Yes | TLS 1.3 (grpc.ssl_channel_credentials) |
| Events in pending.jsonl | **No** | Filesystem encryption must be applied separately |
| agent_id file | No (not sensitive) | N/A |
| guardian.yaml | No | File permissions (0600) recommended |

### Signing / Hashing

| Data | Signed/Hashed? | By what? | What it proves |
|---|---|---|---|
| Each event's fields | Hashed (SHA-256) | `this_hash` computation | The event was not modified after signing |
| Each event's position in sequence | Chained (SHA-256) | `prev_hash` links | Events were processed in this exact order |
| Each batch | HMAC-SHA256 | token + hash list | The batch came from a known, authenticated agent |
| Buffered batch on disk | HMAC-SHA256 | Same signature as above | Signature verified on replay |

### Plaintext (intentionally)

| Data | Why plaintext is acceptable |
|---|---|
| agent_id | Not a secret; authenticated separately by HMAC |
| model_name, process, syscall in events | These are observability data, not secrets. The HMAC chain ensures they cannot be modified undetected. |
| guardian.yaml (non-token fields) | Configuration metadata; only the token is sensitive |

---

## Data Volume Estimates

At typical rates, the data volumes are:

| Metric | Value |
|---|---|
| Event size (uncompressed JSON) | ~700–900 bytes per event |
| Batch size at 100 ms, 1000 events/sec | ~100 events × 800 bytes ≈ 80 KB |
| Proto batch size (binary, ~40% smaller) | ~48 KB per batch |
| gRPC batches per second | 10 (at 100 ms interval) |
| Wire throughput | ~480 KB/s per agent |
| pending.jsonl max size (10,000 lines) | ~10,000 × 1 KB ≈ 10 MB |

These estimates are for the fake generator's event profile. Real eBPF events may be smaller
(sparser field populations) or larger (longer file paths). The configurable `batch_interval_ms`
is the primary knob for controlling wire throughput.

---

## Cross-Boundary Data Integrity Check

When data crosses from the Guardian agent to viriato-platform, the platform performs three
nested integrity checks:

1. **TLS channel authentication**: the platform's TLS certificate is verified by the gRPC
   client. This ensures the agent is talking to the real viriato-platform and not a MITM.

2. **HMAC batch signature**: the platform recomputes
   `HMAC-SHA256(token, json.dumps([{"prev":e.prev_hash,"this":e.this_hash} for e in events]))`.
   If this does not match `EventBatch.signature`, the batch is rejected with `PERMISSION_DENIED`.

3. **SHA-256 event chain**: the platform verifies that `events[0].prev_hash` links correctly
   to the last stored hash for this `agent_id`, and that each event's `this_hash` is consistent
   with its fields. A broken chain is recorded and flagged for compliance review.

A successful delivery therefore guarantees:
- The data was not modified in transit (TLS).
- The batch came from a known agent (HMAC).
- No individual event was tampered with since the Signer processed it (hash chain).
- The events are in the correct sequence (chain links).

---

## Data Deletion and Retention

Guardian itself does not implement data deletion or retention policies. The agent writes events
to the platform and removes buffered data from `pending.jsonl` after successful delivery.

Data retention on the platform (TimescaleDB) is governed by the viriato-platform's retention
policy, configured separately. EU AI Act Article 12 requires high-risk AI system logs to be
kept for at least 6 months after the system's operation is discontinued. The platform's default
retention is 12 months for compliance-mapped events.

---

## Related Documents

- [Event Schema](event-schema.md) — complete documentation of every RawEvent field.
- [gRPC Contract](grpc-contract.md) — proto message structure for data in transit.
- [Event Pipeline](../02-architecture/event-pipeline.md) — timing and failure modes for each
  transformation step.
- [System Overview](../02-architecture/system-overview.md) — full topology showing where data
  at rest and in transit exists.
- [Design Decisions](../02-architecture/design-decisions.md) — rationale for SHA-256, HMAC,
  JSONL buffer, and TLS choices.
