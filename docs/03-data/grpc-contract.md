# gRPC Contract

This document fully documents the Protocol Buffers v3 schema used by Guardian to transmit
event batches to viriato-platform, explains the design of each message and field, covers
backward-compatibility rules, describes the `scripts/gen_proto.sh` code generation workflow,
and explains why generated stubs are not committed to the repository.

---

## Service Definition

```protobuf
syntax = "proto3";

package guardian;

service GuardianIngest {
  rpc StreamEvents(stream EventBatch) returns (Ack);
}
```

### GuardianIngest service

There is exactly one service, `GuardianIngest`, with exactly one RPC method, `StreamEvents`.

`StreamEvents` is a **client-streaming RPC**: the client (Guardian agent) opens a single
HTTP/2 stream and sends one or more `EventBatch` messages on it before closing the stream.
The server (viriato-platform) sends back a single `Ack` message when it is ready to
acknowledge. In practice, Guardian sends one `EventBatch` per gRPC call (see
`Sender._stub.StreamEvents(iter([batch_proto]))`), making it effectively a unary call wrapped
in the client-streaming envelope. The client-streaming pattern was chosen to allow future
batching of multiple batches in a single HTTP/2 stream without protocol changes.

The `(stream EventBatch)` input parameter means the client can call
`self._stub.StreamEvents(iterator_of_batches)` with an iterator that yields any number of
`EventBatch` messages. The platform processes them in order and returns one `Ack` for the
stream. The `Ack` is not per-batch; it covers the entire stream.

---

## EventBatch Message

```protobuf
message EventBatch {
  string agent_id   = 1;   // UUID4 of the Guardian installation
  string signature  = 2;   // HMAC-SHA256 hexdigest (64 chars)
  repeated Event events = 3; // ordered list of signed events
}
```

### Field 1: agent_id

Type: `string`. The UUID4 identifying the Guardian installation. This is the same value as
`RawEvent.agent_id` for every event in the batch, promoted to the batch envelope to allow the
platform to authenticate and route the batch without deserialising every event. The platform
looks up the customer account by `agent_id` and retrieves the stored token for HMAC
verification.

Sending `agent_id` at the batch level (as well as inside each Event) is intentional: it allows
the platform to reject an unauthorised batch in O(1) without iterating through the `events`
repeated field.

### Field 2: signature

Type: `string`. The HMAC-SHA256 batch signature, computed as:
```python
payload = json.dumps(
    [{"prev": e.prev_hash, "this": e.this_hash} for e in events],
    separators=(',',':'),
)
signature = hmac.new(token.encode(), payload.encode(), hashlib.sha256).hexdigest()
```
The result is a 64-character lowercase hexadecimal string. The platform verifies this
signature by recomputing it with the stored token for the given `agent_id`. If the signature
does not match, the platform rejects the batch with `PERMISSION_DENIED`.

The signature covers only the hash values (not the raw event data), because each `this_hash`
already commits to all event fields. Signing the hash list is cryptographically equivalent to
signing all event data, and produces a compact, fixed-size payload regardless of batch size.

### Field 3: events

Type: `repeated Event`. An ordered list of `Event` messages, one per `RawEvent` in the batch.
The ordering is significant: the platform uses the order to validate the hash chain (each
event's `prev_hash` must match the previous event's `this_hash`). Reordering events in
transmission would break the chain and cause the platform to reject the batch.

In proto3, `repeated` fields serialize as a contiguous sequence of length-delimited records.
The wire size of the `events` field is proportional to the number and size of events.

---

## Event Message

```protobuf
message Event {
  string timestamp    = 1;   // ISO 8601 nanosecond UTC
  int32  pid          = 2;   // Linux process ID
  string process      = 3;   // executable name
  string syscall      = 4;   // syscall name (read, write, openat, ...)
  string fd_path      = 5;   // file path (if applicable)
  int64  bytes        = 6;   // bytes transferred
  string return_val   = 7;   // return value or errno (as string)
  int32  uid          = 8;   // Linux user ID
  string prev_hash    = 9;   // SHA-256 of previous event (or GENESIS_HASH)
  string this_hash    = 10;  // SHA-256 of this event's fields
  string agent_id     = 11;  // UUID4 of Guardian installation
  string model_name   = 12;  // AI model identifier
  string container_id = 13;  // Docker short container ID (12 chars)
  string pod_name     = 14;  // Kubernetes pod name
  string namespace    = 15;  // Kubernetes namespace
  string network_addr = 16;  // "ip:port" for network syscalls
}
```

### Field number rationale

Field numbers 1–8 cover the raw kernel fields in the order they appear in the `RawEvent`
dataclass (minus `network_addr`, which was added later). Field numbers 9–10 are the Signer
fields. Field numbers 11–15 are the Enricher fields. Field 16 is `network_addr`, which was
originally placed after `uid` in the Python dataclass but received the next available proto
field number when the schema was finalised.

**Field numbers are permanent.** In Protocol Buffers, field numbers are part of the wire
format. If field 3 is `process` today, it must always be `process`. Field numbers cannot be
reused or reassigned even if the original field is removed. See "Backward Compatibility Rules"
below.

### Why int32 for pid and uid

On Linux, PIDs are unsigned 32-bit integers (max 4,194,304 on modern kernels). UIDs are also
unsigned 32-bit. Proto3 `int32` is a signed 32-bit integer on the wire, but the values in
the Guardian context will never exceed 2^31 - 1 (~2 billion), so signed vs. unsigned is not
a practical concern. `uint32` would be more semantically correct but `int32` is used for
simplicity and consistency with Python's default integer handling.

### Why string for return_val

Linux syscall return values are `long`, which is 64-bit on 64-bit architectures. Negative
values indicate errno codes. Using `string` avoids any integer overflow issues and preserves
the exact string representation from the kernel (`"-1"`, `"-13"`, etc.) without conversion.

### Why int64 for bytes

File and network I/O byte counts can exceed 2^31 on large transfers. `int64` (signed 64-bit)
allows counts up to ~9.2 exabytes.

---

## Ack Message

```protobuf
message Ack {
  bool  received      = 1;  // true if the batch was accepted
  int32 events_stored = 2;  // number of events written to TimescaleDB
}
```

### Field 1: received

Type: `bool`. `true` means the platform accepted the batch (signature valid, chain valid,
events written). If the platform rejects the batch, it returns a gRPC error status code
(e.g., `PERMISSION_DENIED`, `INVALID_ARGUMENT`) rather than an `Ack { received: false }`.
In proto3, the default value for `bool` is `false`, so an `Ack` with no fields set indicates
failure, while `received: true` explicitly signals success.

### Field 2: events_stored

Type: `int32`. The number of events the platform committed to TimescaleDB. Under normal
operation this equals the number of `Event` messages in the batch. It may differ if the
platform applied deduplication (e.g., a buffered batch was re-sent after a partial store on
a previous attempt). The Guardian agent does not currently inspect this field; it is provided
for future use and for debugging via platform logs.

---

## Backward Compatibility Rules

Protocol Buffers v3 provides strong backward compatibility guarantees if these rules are
followed:

### Adding a new field

Add a new field with the **next available field number**. Never reuse a field number that was
previously assigned (even to a removed field). New fields have zero-value defaults in proto3
(empty string for `string`, 0 for numbers, false for bool), so old clients that do not send
the new field will produce valid messages that the platform can accept with the default value.

Example: adding a `hostname` field to `Event`:
```protobuf
message Event {
  // ... existing fields 1-16 ...
  string hostname = 17;  // CORRECT: next available number
}
```

### Removing a field

Never delete a field definition from the proto file. Instead, mark it as `reserved` to
prevent future reuse of the field number and name:
```protobuf
message Event {
  reserved 5;          // fd_path (removed in v2.0)
  reserved "fd_path";
  // ...
}
```

### Renaming a field

Field numbers are wire-format identifiers; field names are only used in generated code and
JSON serialization. A field can be renamed in the proto file without changing the wire format,
but the rename must be coordinated with any JSON consumers (e.g., the platform's JSON
deserialization of the Ack body). When in doubt, add a new field with the new name and mark
the old name as deprecated.

### Changing a field type

Never change a field's type. `int32` cannot become `string` and vice versa. Type changes
require a new field number.

### Adding a new RPC to GuardianIngest

New RPCs can be added to `GuardianIngest` without affecting existing clients. Old clients will
simply not call the new RPC. The platform must implement all declared RPCs.

---

## gen_proto.sh Walkthrough

The script `scripts/gen_proto.sh` compiles `proto/guardian.proto` into two Python files:
`proto/guardian_pb2.py` (message classes) and `proto/guardian_pb2_grpc.py` (service stub
classes). It requires `grpcio-tools` to be installed (`pip install grpcio-tools`).

```bash
#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTO_DIR="$REPO_ROOT/proto"
PROTO_FILE="$PROTO_DIR/guardian.proto"

python -m grpc_tools.protoc \
  --proto_path="$PROTO_DIR" \
  --python_out="$PROTO_DIR" \
  --grpc_python_out="$PROTO_DIR" \
  "$PROTO_FILE"
```

`--proto_path` sets the import root for `.proto` files. `--python_out` writes the message
class file. `--grpc_python_out` writes the service stub file. Both are written to `proto/`.

After generation, the script fixes an import in the gRPC stub file. `grpc_tools.protoc`
generates:
```python
import guardian_pb2 as guardian__pb2
```
but Guardian's package structure requires:
```python
from proto import guardian_pb2 as guardian__pb2
```

The script uses `sed` to apply this fix:
```bash
if [[ "$(uname)" == "Darwin" ]]; then
  sed -i '' 's/^import guardian_pb2/from proto import guardian_pb2/' "$GRPC_STUB"
else
  sed -i 's/^import guardian_pb2/from proto import guardian_pb2/' "$GRPC_STUB"
fi
```

The `sed -i ''` form is required on macOS (`BSD sed`), while `sed -i` (without the empty
string) is the Linux (`GNU sed`) form. The script detects the OS with `uname` and applies the
correct variant.

The fix is necessary because `grpc_tools.protoc` generates a flat import (`import guardian_pb2`)
that assumes the generated file is importable at the top level of `sys.path`. Guardian's
`sender.py` imports the stubs as `from proto import guardian_pb2_grpc`, meaning the `proto`
directory is a package (it has `proto/__init__.py`) and the stubs must be importable within
that package.

---

## Why Generated Stubs Are Not Committed

The files `proto/guardian_pb2.py` and `proto/guardian_pb2_grpc.py` are listed in `.gitignore`
and should not be committed to the repository. The reasons are:

**Version coupling**: the generated Python code is tightly coupled to the exact version of
`grpcio-tools` used to generate it and to the `grpcio` runtime version installed. Committing
stubs generated with `grpcio-tools 1.62` and then upgrading to `grpcio 1.66` can cause subtle
runtime failures (mismatched descriptor format, different serialisation behaviour). Generating
stubs at install time ensures they always match the installed runtime.

**Git noise**: every `grpcio-tools` version bump would require regenerating and recommitting
the stubs, adding machine-generated diffs to the git history that obscure meaningful changes.

**Standard practice**: the official gRPC documentation recommends generating stubs as part of
the build step. All major gRPC projects (including Google's own) follow this convention.

**Graceful fallback**: the Guardian `Sender` handles missing stubs gracefully. If
`guardian_pb2_grpc` cannot be imported, `_grpc_available` is set to `False` and all batches
are written to the disk buffer. The agent continues running and logging the warning:
```
gRPC not available (ImportError) — disk buffer only. Run: bash scripts/gen_proto.sh
```

The stubs currently present in the working tree as untracked files (`proto/guardian_pb2.py`
and `proto/guardian_pb2_grpc.py`) exist because they were generated during Phase 1 development
and should not be staged or committed.

---

## Wire Format Example

A single-event batch in proto3 binary format. Field numbers appear as left-shifted tags
(field_number << 3 | wire_type). For reference:

```
EventBatch {
  1: "f47ac10b-58cc-4372-a567-0e02b2c3d479"   // agent_id
  2: "a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6..."  // signature (64 hex chars)
  3: {                                          // events[0]
    Event {
      1:  "2026-04-10T14:22:01.123456000Z"      // timestamp
      2:  14832                                  // pid
      3:  "python"                              // process
      4:  "read"                               // syscall
      5:  "/var/lib/models/patient-v2/model.pt" // fd_path
      6:  32768                                 // bytes
      7:  "0"                                  // return_val
      8:  1001                                 // uid
      9:  "0000...0000"                        // prev_hash (GENESIS_HASH for event #0)
      10: "7b2c4f8a..."                        // this_hash
      11: "f47ac10b-58cc-..."                  // agent_id
      12: "patient-diagnosis-v2"              // model_name
      13: "a3b4c5d6e7f8"                       // container_id
      14: "diagnosis-inference-7d9f8c-xkbvp"  // pod_name
      15: "production"                         // namespace
      16: ""                                   // network_addr (empty for read syscall)
    }
  }
}
```

---

## Extending the Schema

The following proto additions are planned for Phase 2 and Phase 3:

- `int64 monotonic_ns = 17` on `Event` — the raw kernel monotonic nanoseconds before
  wall-clock conversion, for precise cross-event timing.
- `string alert_type = 18` on `Event` — inline flag from LocalAlertEngine (avoiding the need
  for a separate alert stream).
- `EventBatch.repeated string alert_ids = 4` — indices of events that triggered local alerts.
- `Ack.string chain_tip = 3` — the platform's current chain tip hash for this agent, enabling
  the agent to validate chain continuity on reconnect.

All additions will use new field numbers (17+) and will not alter existing field numbers.

---

## Related Documents

- [System Overview](../02-architecture/system-overview.md) — where gRPC fits in the topology.
- [Guardian Internals](../02-architecture/guardian-internals.md) — how sender.py uses the stubs.
- [Event Schema](event-schema.md) — full documentation of the 16 RawEvent fields.
- [Data Flow](data-flow.md) — what the wire format looks like and how TLS protects it.
- [Design Decisions](../02-architecture/design-decisions.md) — Decision 4 (gRPC) and Decision 15 (stubs).
