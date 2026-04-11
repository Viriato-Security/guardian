# Solution Architecture

Guardian solves the AI observability problem through a three-layer architecture that cleanly separates capture, transport, and interpretation. Each layer has a single responsibility, a well-defined interface, and can be scaled or replaced independently.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│  LAYER 1: CAPTURE (Guardian Agent — this repository)                    │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Kernel Space                                                    │   │
│  │                                                                  │   │
│  │   ┌────────────────┐    ring buffer     ┌───────────────────┐   │   │
│  │   │  AI Model      │ ─────syscalls────► │  BPF Program      │   │   │
│  │   │  Process       │                   │  (guardian.bpf.c) │   │   │
│  │   │  (python /     │                   │                   │   │   │
│  │   │   torchserve)  │                   │  Tracepoints:     │   │   │
│  │   └────────────────┘                   │  read, openat,    │   │   │
│  │                                        │  execve (+more    │   │   │
│  │                                        │   in Phase 2)     │   │   │
│  │                                        └─────────┬─────────┘   │   │
│  └──────────────────────────────────────────────────┼─────────────┘   │
│                                                      │ ring buffer read │
│  ┌───────────────────────────────────────────────────▼─────────────┐   │
│  │  User Space Pipeline                                             │   │
│  │                                                                  │   │
│  │  EventReader → Enricher → LocalAlertEngine → Signer → Sender    │   │
│  │                                                                  │   │
│  │  EventReader:   kernel events (eBPF) or generated (--fake)      │   │
│  │  Enricher:      agent_id, model_name, container_id, pod_name    │   │
│  │  AlertEngine:   sandbox_escape, unexpected_network (local only) │   │
│  │  Signer:        SHA-256 hash chain per event                    │   │
│  │  Sender:        batch + HMAC, gRPC/TLS, offline buffer          │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Config: guardian.yaml  |  State: ~/.guardian/  |  ID: /var/lib/guardian│
└─────────────────────────────────────────────────────┬───────────────────┘
                                                      │
                                              gRPC / TLS
                                        StreamEvents(EventBatch)
                                                      │
┌─────────────────────────────────────────────────────▼───────────────────┐
│  LAYER 2: PLATFORM (viriato-platform)                                   │
│                                                                         │
│   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────────┐  │
│   │  Event Ingest   │   │  Anomaly        │   │  Policy Engine      │  │
│   │  & Storage      │   │  Detection      │   │  (EU AI Act rules)  │  │
│   └────────┬────────┘   └────────┬────────┘   └──────────┬──────────┘  │
│            │                     │                        │             │
│            └─────────────────────┴────────────────────────┘             │
│                                         │                               │
│                               Compliance API                            │
└─────────────────────────────────────────┼───────────────────────────────┘
                                          │
                                    HTTPS / API
                                          │
┌─────────────────────────────────────────▼───────────────────────────────┐
│  LAYER 3: WEB INTERFACE (viriato-web)                                   │
│                                                                         │
│   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────────┐  │
│   │  Compliance     │   │  Audit          │   │  Alert              │  │
│   │  Dashboards     │   │  Timelines      │   │  Management         │  │
│   └─────────────────┘   └─────────────────┘   └─────────────────────┘  │
│                                                                         │
│   Users: compliance officers, auditors, security teams                 │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Layer 1: The Guardian Agent (Capture)

The agent is the only component that runs on the customer's infrastructure. Everything else is either Viriato-operated or accessed via the web interface.

### The Pipeline

The agent pipeline is a linear sequence of stages. Each stage receives an event (or batch of events), does one thing to it, and passes it on. There is no branching, no feedback loop, and no shared state between stages (except the hash chain maintained by the Signer).

```
EventReader
    │  RawEvent (kernel + uid fields filled)
    ▼
Enricher
    │  RawEvent (+ agent_id, model_name, container_id, pod_name, namespace)
    ▼
LocalAlertEngine
    │  RawEvent (unchanged; alerts are side effects, not transformations)
    ▼
Signer
    │  RawEvent (+ prev_hash, this_hash)
    ▼
[batch accumulation — GuardianAgent collects events for batch_interval_ms]
    │
    ▼
Sender
    │  EventBatch (agent_id, HMAC signature, list of Events)
    ▼
gRPC → viriato-platform
```

### EventReader

The reader is the source abstraction. It decides where events come from:

- If `--fake` is passed or `GUARDIAN_FAKE_EVENTS=1` is set, events come from `FakeEventGenerator`.
- If none of those apply but the eBPF loader is available (Linux + `/sys/kernel/btf/vmlinux` + `bcc` importable), events come from the eBPF ring buffer.
- Otherwise, the fake generator is used with a warning logged.

This design means the pipeline from Enricher onwards is identical regardless of whether the source is real kernel events or generated events. Tests, demos, and CI all use the fake generator. Production uses eBPF. The pipeline code never knows the difference.

### Enricher

The enricher adds identity context that the kernel does not provide:

- **`agent_id`**: A UUID stable across restarts. Stored at `/var/lib/guardian/.agent_id` in production, falling back to `~/.guardian_agent_id` for development. Created on first run.
- **`model_name`**: Resolved by matching `event.process` against the `watch` list in `guardian.yaml`. Returns `'unknown'` for unrecognised processes.
- **`container_id`**: Extracted from `/proc/<PID>/cgroup` using a regex that matches the 64-character Docker container ID and truncates to 12 characters. Results are cached in an LRU cache with 512 slots to avoid repeated file reads for the same PID.
- **`pod_name`** and **`namespace`**: Read from `KUBERNETES_POD_NAME` and `KUBERNETES_NAMESPACE` environment variables. Empty string if not running in Kubernetes.

### LocalAlertEngine

The alert engine is the only place in Guardian where any evaluation of event content occurs. It performs exactly two checks:

1. **Sandbox escape**: Was the syscall `execve`, and was the path one of `/bin/bash`, `/bin/sh`, `/usr/bin/bash`, or `/usr/bin/sh`? If so, fire an alert. A model process spawning a shell is a strong indicator of a sandbox escape attempt.

2. **Unexpected network**: Was the syscall `connect` or `sendto`, and is the destination not in the `network_allowlist` from `guardian.yaml`? If the allowlist is empty (the default), no restriction is applied.

These two checks exist in the agent because they require immediate local action — a `log_and_alert` action should be taken within milliseconds of the event occurring, not after a round-trip to the platform. All other alerting logic lives in the platform tier.

### Signer

The signer maintains a cryptographic hash chain across all events processed in a session. For each event:

1. `prev_hash` is set to the `this_hash` of the previous event (or `"0" * 64` for the first event — the genesis hash).
2. `this_hash` is computed as `SHA-256(json.dumps(asdict(event) - this_hash field, sort_keys=True))`.

This means each event's hash commits to its content and its position in the chain. Altering any event (changing a timestamp, a byte count, a network address) invalidates that event's hash. Reordering events breaks the chain links. Inserting a fake event requires computing a hash that chains correctly, which requires knowing the private state of the signer at insertion time.

At the batch level, the signer computes `HMAC-SHA256(token, json.dumps([{prev_hash, this_hash} for event in batch]))`. This binds the batch to the agent's authentication token, preventing a batch from being replayed by a different agent.

The signer is explicitly **not thread-safe**. The pipeline is single-threaded by design (for Phase 1), which makes this safe.

### Sender

The sender wraps the gRPC client and manages the offline buffer:

- Events are accumulated for `batch_interval_ms` milliseconds (default: 100ms) and then dispatched as a single `StreamEvents` call.
- If the endpoint is `localhost` or `127.x.x.x`, or `GUARDIAN_INSECURE_GRPC=1` is set, the connection is made without TLS. This is the development default.
- On any send failure, events are written to `~/.guardian/buffer/pending.jsonl` (one JSON object per line), up to a maximum of 10,000 lines. Older entries are dropped when the limit is reached.
- On the next successful send, the buffer is drained: all pending events are sent before any new events.

---

## Layer 2: The Platform (Interpretation)

The platform receives the signed event stream from Guardian agents and is responsible for everything that requires context beyond a single event:

- **Storage and indexing**: Events are stored with their full hash chain intact, enabling later verification.
- **Anomaly detection**: Statistical baselines, behavioural clustering, and outlier detection. These algorithms require historical data and cannot run in the agent.
- **Policy evaluation**: Rules that encode EU AI Act compliance requirements (e.g., "does this system have logging for all high-risk decisions?"). Policy rules require knowledge of the full event history and organisational context.
- **Compliance API**: An API consumed by the web interface for dashboard data, audit export, and compliance status.

The platform is not part of this repository. Its gRPC interface is defined in `proto/guardian.proto`.

---

## Layer 3: The Web Interface (Presentation)

The web interface is where compliance officers and auditors interact with the event data. It presents derived views of the raw event stream: timelines, summaries, risk indicators, and exportable audit reports.

The web interface never interacts directly with Guardian agents or with raw event data. It consumes only the platform's compliance API.

---

## Why Three Layers, Not One Monolith

A single monolithic system — "agent captures, analyses, and reports" — would have several serious problems:

**Resource contention on the model host.** If the agent ran anomaly detection algorithms on the model host, it would compete for CPU and memory with the model process. This is unacceptable for latency-sensitive inference workloads.

**Contextual blindness.** The agent sees only the events from the processes it watches on a single host. Anomaly detection across multiple agents, or policy evaluation that requires knowing the full deployment history of a model version, cannot be done at the agent level.

**Auditability requirements.** The compliance record must be stored in a system with access controls, retention policies, and audit trails on the storage itself. A flat file on the model host does not satisfy these requirements.

**Separation of duty.** The team that operates Guardian (customer DevOps) is different from the team that reads compliance reports (compliance officers). The three-layer architecture enforces this separation at the system level: DevOps has access to the agent configuration and host, compliance officers have access to the web interface. Neither needs access to the other's layer.

**Upgradability.** The platform's interpretation algorithms can be improved — new anomaly detection models, updated policy rules, new compliance frameworks — without touching the agent. Customers always run the same, stable capture agent; Viriato can iterate on the intelligence layer.

---

## Data Flow Summary

| Stage | Input | Output | Who provides |
|-------|-------|--------|--------------|
| eBPF / Generator | kernel syscalls | `RawEvent` (9 kernel fields) | Guardian |
| Enricher | `RawEvent` (9 fields) | `RawEvent` (14 fields) | Guardian |
| LocalAlertEngine | `RawEvent` (14 fields) | `RawEvent` (14 fields) + side-effect alerts | Guardian |
| Signer | `RawEvent` (14 fields) | `RawEvent` (16 fields, with hashes) | Guardian |
| Sender | `RawEvent` list + HMAC | `EventBatch` gRPC message | Guardian |
| Platform ingest | `EventBatch` | stored, indexed events | viriato-platform |
| Platform analysis | stored events | anomaly scores, policy results | viriato-platform |
| Web | API responses | dashboards, reports | viriato-web |

---

## Configuration Surface

The entire agent is configured by a single `guardian.yaml` file. The agent has no database, no environment-specific secrets beyond the authentication token, and no runtime configuration API. The complete configuration surface is:

- `agent.token` — authentication token for the platform
- `agent.control_plane` — gRPC endpoint address
- `agent.batch_interval_ms` — batching window
- `agent.buffer_path` — local buffer directory
- `watch[]` — list of `{process, model_name}` mappings
- `syscalls[]` — list of syscall names to capture
- `local_alerts[]` — list of alert rules (type + condition + action)
- `network_allowlist[]` — allowed outbound network destinations
- `compliance.organization` — organisation name for compliance metadata
- `compliance.data_categories[]` — data categories handled by the AI systems
- `compliance.articles[]` — EU AI Act articles the deployment is targeting

---

## Related Documents

- [What Is Guardian](what-is-guardian.md) — The design philosophy
- [Problem Statement](problem-statement.md) — The problems this architecture solves
- [EU AI Act Context](eu-ai-act-context.md) — The regulatory context
- [Pipeline Walk-Through](../05-components/pipeline.md) — Detailed pipeline component documentation
- [RawEvent Schema](../03-data/raw-event-schema.md) — The 16-field event structure
- [Proto Reference](../12-reference/proto-reference.md) — The gRPC interface definition
- [Signing & Chain of Custody](../04-security/signing.md) — Hash chain mechanics
