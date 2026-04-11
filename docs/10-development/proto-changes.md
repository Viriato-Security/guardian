# Proto Changes

Guardian uses Protocol Buffers (proto3) for its gRPC transport. The schema is
defined in `proto/guardian.proto` and compiled to Python stubs by
`scripts/gen_proto.sh`. This document explains the backward-compatibility rules,
the shared-contract requirement, and the step-by-step process for making safe
field additions.

---

## Why Proto Changes Are Sensitive

The proto schema is a **shared contract** between two independent deployments:

- **Guardian agent** — running on the customer's infrastructure (possibly hundreds of nodes).
- **viriato-platform** — the SaaS backend that receives and stores events.

A breaking proto change will cause one side to reject or silently misread messages
from the other. In a compliance product this is especially serious: dropped or
corrupted events can invalidate audit evidence.

**Any proto change must be coordinated with the platform team before merging.**

---

## Proto3 Backward Compatibility Rules

### Safe changes (additive)

| Change | Why it is safe |
|--------|----------------|
| Add a new field with a **new field number** | Old parsers ignore unknown fields; new parsers read the new field |
| Add a new message type | Independent of existing messages |
| Add a new enum value | Treated as the default (0) by old parsers |
| Change a field name | Field numbers are the wire format; names are only in generated code |

### Unsafe changes (breaking)

| Change | Why it breaks |
|--------|--------------|
| Remove a field | Old senders still populate it; new receiver may panic or misinterpret reused number |
| Renumber a field | Wire format uses numbers; renumbering corrupts existing serialised data |
| Change a field's type | Wire type mismatch causes parse errors (e.g. `int32` → `string`) |
| Reuse a deleted field number | Extremely dangerous — old data interpreted with wrong semantics |
| Change from `repeated` to singular | Count mismatch causes truncation |

**The golden rule: field numbers are permanent. Never reuse a deleted field number.**

---

## Current Schema

```protobuf
syntax = "proto3";
package guardian;

service GuardianIngest {
  rpc StreamEvents(stream EventBatch) returns (Ack);
}

message EventBatch {
  string           agent_id  = 1;
  string           signature = 2;
  repeated Event   events    = 3;
}

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

message Ack {
  bool   received      = 1;
  int32  events_stored = 2;
}
```

The next available field number in `Event` is **17**. Never reuse 1–16.

---

## How to Add a New Field

The following example adds a `host_name` field (the hostname of the machine running
the agent) to the `Event` message.

### 1. Add the field to guardian.proto

Open `proto/guardian.proto` and add the new field with the next available number:

```protobuf
message Event {
  string  timestamp    = 1;
  // ... existing fields 2–16 unchanged ...
  string  network_addr = 16;
  string  host_name    = 17;   // <-- new field: hostname of the Guardian host
}
```

Rules:
- Use the next sequential number (17 here).
- Add a comment explaining what the field contains.
- Choose the most specific proto3 type (`string`, `int32`, `int64`, `bool`).

### 2. Run gen_proto.sh

Regenerate the Python stubs:

```bash
bash scripts/gen_proto.sh
```

This runs:

```bash
python -m grpc_tools.protoc \
  --proto_path=proto \
  --python_out=proto \
  --grpc_python_out=proto \
  proto/guardian.proto
```

And then fixes the import in the generated stub:

```bash
# On macOS:
sed -i '' 's/^import guardian_pb2/from proto import guardian_pb2/' proto/guardian_pb2_grpc.py

# On Linux:
sed -i 's/^import guardian_pb2/from proto import guardian_pb2/' proto/guardian_pb2_grpc.py
```

The sed fix is necessary because `grpc_tools.protoc` generates a bare
`import guardian_pb2` which does not work as a package-relative import.

### 3. Add the field to RawEvent in agent/generator.py

`RawEvent` is the Python dataclass that mirrors the proto `Event` message exactly.
Add the new field:

```python
@dataclass
class RawEvent:
    timestamp: str = ""
    pid: int = 0
    process: str = ""
    syscall: str = ""
    fd_path: str = ""
    bytes: int = 0
    network_addr: str = ""
    return_val: str = "0"
    uid: int = 0
    agent_id: str = ""
    model_name: str = ""
    container_id: str = ""
    pod_name: str = ""
    namespace: str = ""
    prev_hash: str = ""
    this_hash: str = ""
    host_name: str = ""   # <-- new field
```

Always add new fields at the end of the dataclass to minimise diff noise.

### 4. Populate the field in sender._build_batch_proto()

Open `agent/sender.py` and find `_build_batch_proto()`. Add the new field to the
`guardian_pb2.Event(...)` constructor call:

```python
proto_events = [
    guardian_pb2.Event(
        timestamp=e.timestamp,
        pid=e.pid,
        # ... existing fields ...
        network_addr=e.network_addr,
        host_name=e.host_name,    # <-- add this line
    )
    for e in events
]
```

### 5. Populate the field in the Enricher (if context-derived)

If the field comes from the runtime environment rather than the kernel event,
populate it in `agent/enricher.py`. For `host_name`:

```python
import socket

class Enricher:
    def __init__(self, config: Config) -> None:
        # ...
        self._host_name: str = socket.gethostname()

    def enrich(self, event: RawEvent) -> RawEvent:
        # ... existing enrichment ...
        event.host_name = self._host_name
        return event
```

### 6. Coordinate with the platform team

Open a GitHub issue (or Slack thread) describing the new field **before** merging.
The platform team needs to:

- Add a column to the TimescaleDB `events` table.
- Update the ingest service to read field 17.
- Deploy before the agent version carrying field 17 goes to customers.

**Order of deployment: platform first, then agent.** The platform ignores unknown
fields sent by old agents. New agents sending field 17 to an old platform will have
the field silently dropped — which is acceptable for new optional context fields.

### 7. Update the README schema table

The `README.md` contains a schema table listing all `Event` fields. Add the new
row:

```markdown
| `host_name` | `string` | 17 | Hostname of the machine running Guardian |
```

---

## Why Stubs Are Not Committed

The generated files `proto/guardian_pb2.py` and `proto/guardian_pb2_grpc.py` are
listed in `.gitignore` and must never be committed. Reasons:

1. **Generated from source**: `guardian.proto` is the source of truth. Stubs can
   always be regenerated in seconds.
2. **Platform-specific paths**: The `sed` fix in `gen_proto.sh` bakes in
   `from proto import ...` which assumes the `proto/` directory is importable as
   a package. This may differ across environments.
3. **Reduces merge conflicts**: Generated files change completely on every
   protoc version bump, creating enormous diffs with no semantic content.
4. **CI generates them**: The CI pipeline runs `bash scripts/gen_proto.sh` before
   tests, so contributors do not need to commit stubs.

---

## Versioning and Breaking Changes

Guardian does not yet use protobuf API versioning (e.g. a `v1` package prefix).
When a breaking change is eventually necessary:

1. Create a new message (e.g. `EventV2`) rather than modifying `Event`.
2. Deploy the platform to accept both `EventBatch` (old) and `EventBatchV2` (new).
3. Migrate agents over a defined period (minimum 90 days).
4. Deprecate and remove the old message in a major version release.

For all Phase 1 and Phase 2 development, the rule is: **additive only**.

---

## Related Documents

- [local-setup.md](local-setup.md)
- [adding-a-syscall.md](adding-a-syscall.md)
- [contributing.md](contributing.md)
- [../../docs/12-reference/api-reference.md](../12-reference/api-reference.md)
