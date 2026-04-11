# Three-Layer Platform Architecture

Viriato Security's product is composed of three discrete layers that communicate via well-defined
APIs. Each layer has a single responsibility, can be deployed and upgraded independently, and
degrades gracefully when the layers above or below it are unavailable.

---

## Layer Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 3: viriato-web                                                │
│  React + TypeScript                                                  │
│  viriatosecurity.com                                                 │
│                                                                      │
│  Compliance dashboards · Alert timelines · Audit export (PDF/CSV)   │
│  EU AI Act article summaries · Model risk scoring UI                │
└────────────────────────────┬────────────────────────────────────────┘
                              │ HTTPS REST (JSON)
                              │ authenticated with session token
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 2: viriato-platform                                           │
│  Kotlin + Spring Boot (private repo)                                 │
│  TimescaleDB (PostgreSQL hypertable extension)                       │
│                                                                      │
│  • GuardianIngest gRPC service (receives EventBatch from agents)    │
│  • Verifies HMAC batch signature + hash chain continuity            │
│  • Persists events in time-series hypertable                        │
│  • Compliance Engine: maps events to EU AI Act articles             │
│  • Anomaly Detection: statistical baselines per model/agent         │
│  • Alert Correlation: deduplicates + enriches local agent alerts    │
│  • REST API: serves viriato-web and customer integrations           │
└────────────────────────────┬────────────────────────────────────────┘
                              │ gRPC over TLS 1.3
                              │ EventBatch proto stream (port 443)
                              │ HMAC-SHA256 signed, SHA-256 hash chain
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 1: Guardian (this repo)                                       │
│  Python 3.12+ agent                                                  │
│  Runs on customer's Linux server (or macOS for Phase 1 / dev)       │
│                                                                      │
│  • Captures kernel syscall events (Phase 2: eBPF / Phase 1: fake)  │
│  • Enriches with environment context (container, pod, model)        │
│  • Evaluates local alert rules (no network required)                │
│  • Cryptographically chains and signs events                        │
│  • Buffers to disk when platform unreachable                        │
│  • Streams signed batches to Layer 2 via gRPC                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Guardian (this repository)

### What it is

Guardian is an open-source (BUSL-1.1), on-premises agent that runs inside the customer's
infrastructure. It is the only layer that touches the customer's kernel and the customer's AI
workload processes directly. The customer installs it, configures it with a `guardian.yaml` file,
and starts it as a systemd service or Kubernetes sidecar. The agent has no database, no web
server, and no persistent state beyond a single UUID file and an optional disk buffer.

### What it does

Guardian runs a six-stage pipeline: EventReader produces RawEvent objects (9 kernel/synthetic
fields), the Enricher adds 5 context fields (agent_id, model_name, container_id, pod_name,
namespace), the LocalAlertEngine evaluates two synchronous rules (sandbox_escape and
unexpected_network), the Signer chains and hashes events, the in-memory batch accumulates
events for up to 100 ms, and the Sender transmits signed EventBatch messages to Layer 2.

Every event carries a cryptographic hash chain. If any event is tampered with in transit or
at rest, the chain breaks and Layer 2 will detect it on ingestion.

### Why it is separate from Layer 2

The agent runs on the customer's server. The customer may be in a regulated industry
(healthcare, finance) and unwilling to send raw kernel events anywhere without first confirming
that the data is signed and attested. Keeping the capture and signing logic on-premises — and
open source — allows customers and auditors to inspect exactly what is collected and how it is
protected before it leaves the server.

There is also a practical network-resilience reason: the agent can buffer events locally for
extended periods (up to 10,000 batches in `pending.jsonl`) and replay them once connectivity to
Layer 2 is restored, without losing observability data.

---

## Layer 2: viriato-platform (private)

### What it is

The viriato-platform is a private SaaS backend operated by Viriato Security. It is written in
Kotlin with the Spring Boot framework. Its primary storage engine is TimescaleDB — the
PostgreSQL extension for time-series data — which stores incoming events in a hypertable
partitioned by `timestamp` and indexed on `agent_id`, `model_name`, and `syscall`.

### What it does

On the ingest side the platform runs a gRPC service (`GuardianIngest`) that accepts
`StreamEvents` client-streaming calls. For each received `EventBatch` it:

1. Looks up the customer account by `agent_id`.
2. Verifies the HMAC-SHA256 `signature` against the stored token.
3. Checks that the hash chain is internally consistent and that the first event's `prev_hash`
   links correctly to the last stored event for that agent.
4. Persists all events to the hypertable.
5. Returns an `Ack { received: true, events_stored: N }`.

On the analysis side the platform runs a Compliance Engine that maps events to EU AI Act
articles, an Anomaly Detection module that builds per-model syscall baselines and fires alerts
on deviations, and an Alert Correlation engine that deduplicates and enriches the alerts
generated by Layer 1's LocalAlertEngine.

The REST API layer (served over HTTPS) provides authenticated endpoints for Layer 3 to fetch
dashboards, timelines, export audit reports, and configure alert thresholds.

### Why it is separate from Layer 1

Layer 2 requires persistent storage, multi-tenant data isolation, compliance computation, and
a hosted API. These concerns do not belong on the customer's server. Separating them means the
customer's server only runs the lightweight Guardian agent (a few MB of Python code), while
all the compute-intensive analysis runs in Viriato Security's managed infrastructure.

Upgrading the compliance engine, adding new EU AI Act article mappings, or changing the anomaly
detection algorithm requires no change to the customer's installed agent.

---

## Layer 3: viriato-web (private)

### What it is

The viriato-web frontend is a React + TypeScript single-page application served from
viriatosecurity.com. It is the primary interface through which customers interact with their
AI observability data. It is entirely stateless with respect to event data — all data is fetched
from Layer 2's REST API.

### What it does

- **Compliance dashboards**: shows which EU AI Act articles are covered by the events captured
  from each model, with evidence links.
- **Alert timeline**: displays LocalAlertEngine alerts (sandbox_escape, unexpected_network)
  correlated and enriched by the platform, in chronological order with full event context.
- **Audit export**: allows compliance officers to download event logs and compliance summaries
  as PDF or CSV for regulator submission.
- **Model risk scoring**: renders per-model risk scores computed by the Anomaly Detection module.
- **Agent management**: shows the status (online/offline/buffering) of each registered Guardian
  agent, identified by `agent_id`.

### Why it is separate from Layer 2

Keeping the UI separate from the API layer is standard web architecture. It allows the frontend
to be served from a global CDN (viriatosecurity.com) independently of the API backend, enables
future mobile or third-party integrations against the same REST API, and means the frontend can
be iterated on rapidly without any risk of destabilising the ingest pipeline.

---

## Failure Mode Analysis

Understanding what happens when each layer goes down is important for designing operational
runbooks and SLAs.

### If Layer 3 (viriato-web) goes down

Impact: Customers cannot access dashboards or export audit reports. No data is lost. Ingest is
unaffected. The Guardian agent continues streaming to Layer 2 normally. Layer 2 continues
storing events, running compliance analysis, and generating alerts. Alerts generated by Layer 1
(LocalAlertEngine) still fire immediately on the customer's server via stderr and logger.error,
regardless of Layer 3 availability.

Recovery: Restoring or redeploying viriato-web is sufficient. No data backfill is needed.

### If Layer 2 (viriato-platform) goes down

Impact: The Guardian agent cannot deliver event batches via gRPC. The Sender catches the
`RpcError` and falls back to writing batches as JSONL lines to
`~/.guardian/buffer/pending.jsonl` (or `/var/lib/guardian/buffer/pending.jsonl` in production).
The buffer can hold up to 10,000 batch lines. At the default batch interval of 100 ms with
typical event rates, this represents several minutes to hours of buffer capacity depending on
event volume.

Layer 1 local alerting (sandbox_escape, unexpected_network) continues to function without any
dependency on Layer 2. Cryptographic signing and hash chaining continue normally, so the
integrity of buffered events is preserved.

When Layer 2 recovers, the agent's next successful gRPC send triggers `_drain_buffer()`, which
replays buffered batches in FIFO order (oldest first). If the buffer exceeds 10,000 lines while
Layer 2 is down, the oldest pending batches are dropped, and a warning is logged. This is a
deliberate design choice: unbounded buffer growth on a customer's production server poses a
greater operational risk (disk exhaustion) than the loss of excess events.

Recovery: When gRPC connectivity to Layer 2 is restored, drain is automatic. No manual
intervention is required unless the buffer overflowed.

### If Layer 1 (Guardian agent) goes down

Impact: No new kernel events are captured or transmitted to Layer 2. The existing data in
Layer 2 and Layer 3 is unaffected. The hash chain pauses at the last event sent before the
outage. When the agent restarts it reads its persistent `agent_id` and resumes chaining from
`GENESIS_HASH` for the new session. The platform records a gap in the event sequence that
compliance auditors can identify.

Layer 2 and Layer 3 remain fully operational, serving existing data and dashboards.

Recovery: Restart the Guardian systemd service. The agent recovers automatically; no manual
configuration is needed. If events were buffered to disk before shutdown, they are replayed on
the first successful connection.

---

## API Contracts Between Layers

| From | To | Protocol | Format | Auth |
|---|---|---|---|---|
| Layer 1 (Guardian agent) | Layer 2 (GuardianIngest) | gRPC over TLS 1.3 | Protocol Buffers (EventBatch) | Bearer token in gRPC metadata |
| Layer 3 (viriato-web) | Layer 2 (REST API) | HTTPS | JSON | Session token / API key |
| Customer tooling | Layer 2 (REST API) | HTTPS | JSON | API key |

The gRPC contract between Layer 1 and Layer 2 is defined in `proto/guardian.proto` and is
documented fully in [gRPC Contract](../03-data/grpc-contract.md). Changes to that contract are
made under strict backward-compatibility rules (never re-use field numbers, never change field
types, always use reserved for removed fields).

---

## Licensing Note

Guardian (Layer 1) is licensed under BUSL-1.1. This licence grants customers the right to run
the agent on their own servers for production observability purposes. It prohibits third parties
from creating competing commercial products directly derived from Guardian's source code.
Layers 2 and 3 are proprietary and not open source.

---

## Related Documents

- [System Overview](system-overview.md) — full ASCII topology and data formats at each boundary.
- [Guardian Internals](guardian-internals.md) — deep-dive into the Layer 1 agent pipeline.
- [Event Pipeline](event-pipeline.md) — step-by-step journey of one event through all layers.
- [gRPC Contract](../03-data/grpc-contract.md) — the Layer 1 ↔ Layer 2 API contract.
- [Design Decisions](design-decisions.md) — why each architectural and technology choice was made.
