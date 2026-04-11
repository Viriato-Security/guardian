# Guardian System Overview

Guardian is the on-premises observability agent produced by Viriato Security. It captures Linux
kernel syscall events from AI inference workloads, enriches and cryptographically chains them,
then streams signed batches to the viriato-platform SaaS backend over mutual-TLS gRPC. This
document describes every component, every connection, and the data formats at each boundary.

---

## Full System Topology

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                        CUSTOMER SERVER (Linux 5.8+, x86-64)                    ║
║                                                                                  ║
║  ┌─────────────────────────────────────────────────────────────┐                ║
║  │                     KERNEL SPACE                            │                ║
║  │                                                             │                ║
║  │   CPU tracepoints                                           │                ║
║  │   sys_enter_read ──┐                                        │                ║
║  │   sys_enter_write ─┤                                        │                ║
║  │   sys_enter_openat─┤                                        │                ║
║  │   sys_enter_sendto─┤─► eBPF probe (guardian.bpf.c)         │                ║
║  │   sys_enter_recvfrom┤   • filter by watched_pids map        │                ║
║  │   sys_enter_connect─┤     (1024 slots, BPF_MAP_TYPE_HASH)   │                ║
║  │   sys_enter_socket ─┤   • populate guardian_event_t struct  │                ║
║  │   sys_enter_clone ──┘   • bpf_ringbuf_submit()              │                ║
║  │                              │                              │                ║
║  │                        BPF ring buffer                      │                ║
║  │                        (256 KB, BPF_MAP_TYPE_RINGBUF)       │                ║
║  └──────────────────────────────┬──────────────────────────────┘                ║
║                                 │  poll() / ring_buffer__poll()                 ║
║                                 ▼                                                ║
║  ┌─────────────────────────────────────────────────────────────┐                ║
║  │                    USER SPACE — Guardian Agent              │                ║
║  │                                                             │                ║
║  │  ┌────────────┐                                             │                ║
║  │  │  EventReader│  Phase 1: FakeEventGenerator               │                ║
║  │  │  (reader.py)│  Phase 2: EbpfLoader polls ring buffer     │                ║
║  │  └─────┬──────┘                                             │                ║
║  │        │ RawEvent (9 kernel fields)                          │                ║
║  │        ▼                                                     │                ║
║  │  ┌────────────┐                                             │                ║
║  │  │  Enricher  │  adds agent_id, model_name,                 │                ║
║  │  │(enricher.py)│  container_id (LRU 512), pod_name,         │                ║
║  │  └─────┬──────┘  namespace                                  │                ║
║  │        │ RawEvent (14 fields)                                │                ║
║  │        ▼                                                     │                ║
║  │  ┌────────────────┐                                          │                ║
║  │  │LocalAlertEngine│  synchronous rule evaluation             │                ║
║  │  │(local_alerts.py)│  sandbox_escape + unexpected_network    │                ║
║  │  └─────┬──────────┘  alerts → stderr JSON + logger.error    │                ║
║  │        │ RawEvent (unchanged) + optional AlertEvent          │                ║
║  │        ▼                                                     │                ║
║  │  ┌────────────┐                                             │                ║
║  │  │   Signer   │  prev_hash chain (SHA-256)                  │                ║
║  │  │  (signer.py)│  this_hash = SHA-256(event dict)           │                ║
║  │  └─────┬──────┘                                             │                ║
║  │        │ RawEvent (16 fields, fully populated)               │                ║
║  │        ▼                                                     │                ║
║  │  ┌─────────────┐  accumulate until batch_interval_ms         │                ║
║  │  │  Batch buf  │  (default 100 ms)                           │                ║
║  │  └─────┬───────┘                                             │                ║
║  │        │ list[RawEvent] + HMAC-SHA256 signature              │                ║
║  │        ▼                                                     │                ║
║  │  ┌────────────┐   success → drain pending.jsonl              │                ║
║  │  │   Sender   │   failure → append to pending.jsonl          │                ║
║  │  │  (sender.py)│  (max 10,000 lines FIFO)                    │                ║
║  │  └─────┬──────┘                                             │                ║
║  └────────┼────────────────────────────────────────────────────┘                ║
║           │                                                                      ║
║  Disk buffer (fallback)                                                         ║
║  ~/.guardian/buffer/pending.jsonl                                                ║
║                                                                                  ║
╚═══════════════════════════════╦════════════════════════════════════════════════╝
                                 │
                     TLS 1.3 / gRPC (port 443)
                     EventBatch proto stream
                     Authorization: Bearer <token> metadata
                                 │
╔════════════════════════════════╩════════════════════════════════════════════════╗
║                        VIRIATO PLATFORM (SaaS)                                  ║
║                                                                                  ║
║  ┌──────────────────────┐    ┌──────────────────────┐   ┌───────────────────┐  ║
║  │  GuardianIngest      │    │  Compliance Engine   │   │  TimescaleDB      │  ║
║  │  gRPC service        │───►│  EU AI Act mapping   │──►│  Hypertable       │  ║
║  │  StreamEvents RPC    │    │  anomaly detection   │   │  event storage    │  ║
║  │  returns Ack         │    │  alert correlation   │   │  time-series idx  │  ║
║  └──────────────────────┘    └──────────────────────┘   └──────────┬────────┘  ║
║                                                                      │           ║
║  ┌──────────────────────────────────────────────────────────────────┘           ║
║  │  REST API (Kotlin + Spring Boot)                                              ║
║  └──────────────────────────────────────────────────────────────────────────┐   ║
║                                                                               │  ║
╚═══════════════════════════════════════════════════════════════════════════════╪══╝
                                                                                │
                                                                   HTTPS / REST │
╔══════════════════════════════════════════════════════════════════╗            │
║  VIRIATO WEB  (viriatosecurity.com)                               ║            │
║  React + TypeScript                                               ║◄───────────┘
║  Compliance dashboards  ·  Alert timeline  ·  Audit export       ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## Data Formats at Each Boundary

### Boundary 1 — BPF ring buffer (kernel → userspace)

The eBPF probe submits a `guardian_event_t` C struct via `bpf_ringbuf_submit()`. The struct
carries the raw kernel context: `pid`, `uid`, `syscall` (as a string copied via
`bpf_probe_read_kernel_str`), `fd_path`, `bytes`, `network_addr`, `return_val`, and a
nanosecond-precision monotonic timestamp converted to wall-clock by userspace. This is an
in-memory zero-copy transfer within the same Linux process memory space.

In Phase 1 the `FakeEventGenerator` produces `RawEvent` Python dataclass instances directly,
bypassing the ring buffer entirely. The schema is identical.

### Boundary 2 — Reader → Enricher (in-process Python objects)

`RawEvent` dataclass, 9 fields populated. The object is mutated in-place by each subsequent
pipeline stage. No serialisation occurs at this boundary.

```
RawEvent(
    timestamp  = "2026-04-10T14:22:01.123456000Z",  # ISO 8601, ns precision, UTC
    pid        = 14832,
    process    = "python",
    syscall    = "read",
    fd_path    = "/var/lib/models/patient-diagnosis-v2/model.pt",
    bytes      = 32768,
    network_addr = "",
    return_val = "0",
    uid        = 1001,
    # remaining 7 fields still empty string / zero
)
```

### Boundary 3 — Enricher → LocalAlertEngine (in-process)

Same `RawEvent` object, now with `agent_id`, `model_name`, `container_id`, `pod_name`, and
`namespace` filled in. Still 14 of 16 fields populated; `prev_hash` and `this_hash` remain
empty until the Signer runs.

### Boundary 4 — Signer → Batch buffer (in-process)

Fully populated 16-field `RawEvent`. The Signer sets `prev_hash` (the `this_hash` of the
previous event, or `GENESIS_HASH = "0" * 64` for the first event of an agent's lifetime) and
`this_hash` (SHA-256 of the JSON-serialised event dict with `this_hash` excluded). Events are
appended to `self._batch: list[RawEvent]`.

### Boundary 5 — Batch → gRPC wire (serialised Protocol Buffers)

When the batch interval elapses (default 100 ms), the Signer computes a batch-level HMAC-SHA256
signature and the Sender serialises events to `guardian.proto` binary format:

```
EventBatch {
    agent_id:  "f47ac10b-58cc-4372-a567-0e02b2c3d479"   // field 1
    signature: "a3f1...d9"                               // field 2, 64 hex chars
    events:    [ Event { ... }, Event { ... } ]          // field 3, repeated
}
```

Each `Event` message carries all 16 `RawEvent` fields (field numbers 1–16). The binary
Protobuf encoding is framed inside a gRPC length-prefixed message envelope and sent over a
TLS 1.3 stream to `grpc.viriatosecurity.com:443`.

The `Authorization: Bearer <token>` gRPC metadata header accompanies every stream.

### Boundary 6 — gRPC → viriato-platform

The `GuardianIngest.StreamEvents` client-streaming RPC receives `EventBatch` messages. The
platform verifies the HMAC signature using the token registered in its database, validates the
hash chain (checking that `events[0].prev_hash` matches the last stored hash for that
`agent_id`), and persists events to TimescaleDB. It returns an `Ack { received: true,
events_stored: N }`.

### Boundary 7 — Disk buffer fallback

When gRPC fails (network down, platform unreachable, stubs not generated), the batch is
serialised as a single JSONL line to `~/.guardian/buffer/pending.jsonl`:

```json
{"agent_id":"f47ac10b-...","signature":"a3f1...","events":[{...},{...}]}
```

On the next successful gRPC send the buffer is drained FIFO (oldest batch first). The file is
capped at 10,000 lines; batches that would exceed the cap are dropped with a warning log entry.

---

## Deployment Topology

### Single-server deployment (typical Phase 1 / Phase 2)

```
[Linux server running AI workloads]
  ├── /etc/guardian/guardian.yaml         ← configuration
  ├── /var/lib/guardian/.agent_id         ← persistent UUID
  ├── /var/lib/guardian/buffer/           ← disk buffer (production path)
  └── guardian agent (systemd service)
        └── python -m agent.main
```

### Kubernetes deployment

```
[Pod: ai-inference]
  ├── container: python/torchserve        ← the monitored workload
  └── container: guardian-agent           ← sidecar
        ├── KUBERNETES_POD_NAME env var   ← injected by Downward API
        ├── KUBERNETES_NAMESPACE env var  ← injected by Downward API
        └── /proc/<pid>/cgroup            ← read to extract container_id
```

In a Kubernetes sidecar deployment the agent shares the PID namespace with the workload
container. The Enricher reads `/proc/<pid>/cgroup` and parses the Docker container ID from the
cgroup path (12-character short ID). The LRU cache (512 slots) prevents repeated `/proc` reads
for the same PID.

---

## Security Boundaries

| Boundary | Mechanism | What it protects |
|---|---|---|
| Kernel → ring buffer | BPF verifier, CAP_BPF | Prevents unsafe kernel code |
| Agent → platform (wire) | TLS 1.3 (grpc.ssl_channel_credentials) | Confidentiality and server auth in transit |
| Batch authenticity | HMAC-SHA256 (token as key) | Proves batch came from a known agent |
| Event integrity | SHA-256 hash chain (prev/this) | Detects any post-capture tampering |
| Agent identity | UUID4 persisted at /var/lib/guardian/.agent_id | Stable identity across restarts |
| Local alerting | In-process, no network | Fires immediately, not bypassed by network failure |
| Config token | guardian.yaml (0600 permissions recommended) | Protects the HMAC signing key |

The agent does **not** encrypt events at rest in the disk buffer (pending.jsonl is plaintext
JSON). Filesystem-level encryption (LUKS, dm-crypt) should be applied separately if the buffer
directory is on an unencrypted volume. The hash chain and HMAC signature still detect any
tampering with buffered events before re-transmission.

---

## Component Inventory

| Component | Language | File(s) | Phase |
|---|---|---|---|
| eBPF probe | C (libbpf, BTF) | probe/guardian.bpf.c, probe/guardian.h | 2 (stub in 1) |
| EbpfLoader | Python | agent/loader.py | 2 (stub) |
| FakeEventGenerator | Python | agent/generator.py | 1 (complete) |
| EventReader | Python | agent/reader.py | 1 (complete) |
| Enricher | Python | agent/enricher.py | 1 (complete) |
| LocalAlertEngine | Python | agent/local_alerts.py | 1 (complete) |
| Signer | Python | agent/signer.py | 1 (complete) |
| Sender | Python | agent/sender.py | 1 (complete) |
| Config loader | Python | agent/config.py | 1 (complete) |
| Agent entrypoint | Python | agent/main.py | 1 (complete) |
| Proto definition | Protobuf | proto/guardian.proto | 1 (complete) |
| viriato-platform | Kotlin + Spring Boot | private repo | SaaS |
| viriato-web | React + TypeScript | private repo | SaaS |

---

## Related Documents

- [Three-Layer Platform](three-layer-platform.md) — how Guardian, viriato-platform, and
  viriato-web relate to each other and why they are separate.
- [Guardian Internals](guardian-internals.md) — deep-dive into the agent daemon's internal
  structure, stateful vs stateless components, and module dependencies.
- [Event Pipeline](event-pipeline.md) — step-by-step journey of a single syscall event from
  kernel capture to platform storage.
- [Event Schema](../03-data/event-schema.md) — full documentation of all 16 RawEvent fields.
- [gRPC Contract](../03-data/grpc-contract.md) — complete proto documentation.
- [Data Flow](../03-data/data-flow.md) — what data is encrypted, signed, or plaintext at each
  stage.
