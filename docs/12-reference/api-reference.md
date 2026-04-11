# API Reference

This document describes the gRPC API between the Guardian agent and viriato-platform.
The schema is defined in `proto/guardian.proto`. All field numbers listed here are
permanent — they must never be reused. See
[proto-changes.md](../10-development/proto-changes.md) for backward-compatibility rules.

---

## Service: GuardianIngest

```protobuf
service GuardianIngest {
  rpc StreamEvents(stream EventBatch) returns (Ack);
}
```

The `GuardianIngest` service has a single method: `StreamEvents`. The agent sends a
stream of `EventBatch` messages (client-streaming RPC). The platform returns a single
`Ack` after the stream closes.

**Endpoint**: `grpc.viriatosecurity.com:443` (TLS, system CA certificates)

**Transport**: HTTP/2 with gRPC framing, TLS 1.2+

**Local/dev endpoint**: `localhost:50051` (insecure channel; auto-detected by Guardian)

---

## Method: StreamEvents

```
StreamEvents(stream EventBatch) returns (Ack)
```

**Type**: Client-streaming RPC. The agent sends zero or more `EventBatch` messages
and then closes the stream. The platform sends a single `Ack` response.

**Usage pattern**: The Guardian agent opens a stream, sends one batch per flush
interval (default 100 ms), and keeps the stream open until the process exits or the
gRPC channel is closed by either side.

---

## Message: EventBatch

The unit of transmission. A signed slice of the event chain.

```protobuf
message EventBatch {
  string           agent_id  = 1;
  string           signature = 2;
  repeated Event   events    = 3;
}
```

| Field | Proto number | Type | Description |
|-------|-------------|------|-------------|
| `agent_id` | 1 | `string` | UUID of the originating Guardian installation. Example: `"a1b2c3d4-e5f6-7890-abcd-ef1234567890"` |
| `signature` | 2 | `string` | HMAC-SHA256 hex string authenticating the batch. 64 lowercase hex characters. See Authentication section below. |
| `events` | 3 | `repeated Event` | The events in this batch. May be empty if the agent is sending a heartbeat. |

---

## Message: Event

Mirrors `agent/generator.py:RawEvent` exactly. All 16 fields correspond to the
same-named fields in the Python dataclass.

```protobuf
message Event {
  string  timestamp    = 1;
  int32   pid          = 2;
  string  process      = 3;
  string  syscall      = 4;
  string  fd_path      = 5;
  int64   bytes        = 6;
  string  return_val   = 7;
  int32   uid          = 8;
  string  prev_hash    = 9;
  string  this_hash    = 10;
  string  agent_id     = 11;
  string  model_name   = 12;
  string  container_id = 13;
  string  pod_name     = 14;
  string  namespace    = 15;
  string  network_addr = 16;
}
```

| Field | Proto # | Type | Required | Description | Example |
|-------|---------|------|----------|-------------|---------|
| `timestamp` | 1 | `string` | Yes | ISO 8601 UTC with 9 nanosecond digits, ending in `Z` | `"2026-04-09T12:00:00.000000000Z"` |
| `pid` | 2 | `int32` | Yes | Linux process ID | `12345` |
| `process` | 3 | `string` | Yes | Process name (from `/proc/<pid>/comm`) | `"python"`, `"torchserve"` |
| `syscall` | 4 | `string` | Yes | Syscall name | `"read"`, `"write"`, `"openat"`, `"sendto"`, `"connect"`, `"execve"` |
| `fd_path` | 5 | `string` | No | File path for file syscalls; empty for network/other | `"/var/lib/models/model.pt"` |
| `bytes` | 6 | `int64` | No | Bytes transferred (read/write/sendto/recvfrom); 0 otherwise | `65536` |
| `return_val` | 7 | `string` | Yes | Syscall return value: `"0"` for success or errno string | `"0"`, `"-13"`, `"-2"` |
| `uid` | 8 | `int32` | Yes | Linux user ID of the process | `1000`, `0` |
| `prev_hash` | 9 | `string` | Yes | SHA-256 of preceding event (chain link); 64 hex chars | `"000...000"` (genesis) or prior `this_hash` |
| `this_hash` | 10 | `string` | Yes | SHA-256 of this event (all fields except `this_hash`); 64 hex chars | `"a3f2..."` |
| `agent_id` | 11 | `string` | Yes | UUID of Guardian installation (redundant per-event for indexing) | `"a1b2c3d4-..."` |
| `model_name` | 12 | `string` | No | AI model name from watch config; `"unknown"` if not matched | `"patient-diagnosis-v2"` |
| `container_id` | 13 | `string` | No | Docker short container ID (12 chars); empty if not in Docker | `"a3f9b2c1d0e8"` |
| `pod_name` | 14 | `string` | No | Kubernetes pod name; empty if not in Kubernetes | `"inference-pod-7d8f"` |
| `namespace` | 15 | `string` | No | Kubernetes namespace; empty if not in Kubernetes | `"production"` |
| `network_addr` | 16 | `string` | No | `host:port` for network syscalls; empty for file/other syscalls | `"10.0.0.1:8080"` |

**Field mutual exclusivity rules:**
- `fd_path` is non-empty for `read`, `write`, `openat` (and `execve`). Empty for network syscalls.
- `network_addr` is non-empty for `connect`, `sendto`, `recvfrom`. Empty for file syscalls.
- `bytes` is non-zero for `read`, `write`, `openat`, `sendto`, `recvfrom`. Zero for `connect`, `socket`, `clone`, `execve`.

---

## Message: Ack

Returned by the platform after the stream closes.

```protobuf
message Ack {
  bool   received      = 1;
  int32  events_stored = 2;
}
```

| Field | Proto # | Type | Description |
|-------|---------|------|-------------|
| `received` | 1 | `bool` | `true` if the platform accepted the batch; `false` on error |
| `events_stored` | 2 | `int32` | Number of events persisted to TimescaleDB. `0` means the events were received but not stored (e.g. duplicate detection or signature failure) |

**`events_stored = 0`**: The platform received the batch but did not store events.
Causes: signature verification failure, duplicate `agent_id` + `this_hash`, or
platform storage error. The agent should log a warning and continue.

---

## Authentication

The `signature` field in `EventBatch` authenticates the batch using HMAC-SHA256.

**Algorithm:**

```python
import hmac
import hashlib
import json

payload = json.dumps(
    [{"prev": event.prev_hash, "this": event.this_hash} for event in events],
    separators=(",", ":"),
)
signature = hmac.new(
    token.encode(),
    payload.encode(),
    hashlib.sha256,
).hexdigest()
```

- `token`: The customer's API token (from `guardian.yaml agent.token`).
- `payload`: A compact JSON array of `{"prev": str, "this": str}` objects, one per
  event, in the same order as `events` in the batch.
- `signature`: 64-character lowercase hex string.

**Why HMAC, not a bare hash?** HMAC-SHA256 is not vulnerable to length extension
attacks. A bare `SHA-256(token || payload)` would be, allowing an attacker who
knows the signature of message M to forge a signature for M + suffix without knowing
the key. HMAC prevents this.

**Platform verification:** The platform recomputes the signature using the stored
token for the `agent_id`. If the computed signature does not match `EventBatch.signature`,
the platform returns `UNAUTHENTICATED` and does not store any events.

---

## gRPC Status Codes

| Status code | Meaning | When returned | Agent action |
|-------------|---------|--------------|--------------|
| `OK` | Success | Normal operation | Increment `total_sent`, drain buffer |
| `UNAUTHENTICATED` | Signature invalid | Token mismatch or corrupted signature | Log error; check token in guardian.yaml |
| `UNAVAILABLE` | Platform overloaded or unreachable | Transient platform issue | Buffer to disk; retry on next interval |
| `INVALID_ARGUMENT` | Batch malformed | Empty batch or missing required fields | Log error; skip batch |
| `RESOURCE_EXHAUSTED` | Rate limit exceeded | Too many events per second | Increase `batch_interval_ms` |

---

## Example Request (JSON representation)

The following is the JSON equivalent of an `EventBatch` with two events. The wire
format is proto3 binary, but this illustrates the structure:

```json
{
  "agent_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "signature": "3f2a1b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1",
  "events": [
    {
      "timestamp": "2026-04-09T12:00:00.000000000Z",
      "pid": 12345,
      "process": "python",
      "syscall": "read",
      "fd_path": "/var/lib/models/patient-diagnosis-v2/model.pt",
      "bytes": 65536,
      "return_val": "0",
      "uid": 1000,
      "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "this_hash": "a3f2b1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2",
      "agent_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "model_name": "patient-diagnosis-v2",
      "container_id": "a3f9b2c1d0e8",
      "pod_name": "inference-pod-7d8f",
      "namespace": "production",
      "network_addr": ""
    },
    {
      "timestamp": "2026-04-09T12:00:00.001000000Z",
      "pid": 12345,
      "process": "python",
      "syscall": "sendto",
      "fd_path": "",
      "bytes": 1024,
      "return_val": "0",
      "uid": 1000,
      "prev_hash": "a3f2b1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2",
      "this_hash": "b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4",
      "agent_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "model_name": "patient-diagnosis-v2",
      "container_id": "a3f9b2c1d0e8",
      "pod_name": "inference-pod-7d8f",
      "namespace": "production",
      "network_addr": "10.0.0.1:8080"
    }
  ]
}
```

## Example Response

```json
{
  "received": true,
  "events_stored": 2
}
```

---

## Proto Field Number Reservation

The following field numbers are reserved and must never be reused:

- `EventBatch`: 1, 2, 3
- `Event`: 1–16
- `Ack`: 1, 2

The next available field number in `Event` is **17**. See
[proto-changes.md](../10-development/proto-changes.md) for the full protocol for
adding new fields.

---

## Related Documents

- [proto-changes.md](../10-development/proto-changes.md)
- [error-codes.md](error-codes.md)
- [glossary.md](glossary.md)
- [../../proto/guardian.proto](../../proto/guardian.proto)
