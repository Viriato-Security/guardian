# Guardian Documentation

Guardian is a kernel-level eBPF observability agent for AI systems, built by Viriato Security. This documentation covers everything from first principles to production operations.

---

## Reading Paths

### New to the Project

If you are encountering Guardian for the first time, work through these documents in order:

1. [What Is Guardian](01-overview/what-is-guardian.md) — The one-paragraph explanation, the design philosophy, and what the agent produces
2. [Problem Statement](01-overview/problem-statement.md) — Why this tool exists and what gap it fills at business, technical, and operational levels
3. [Solution Architecture](01-overview/solution-architecture.md) — The three-layer architecture and why the system is split the way it is
4. [EU AI Act Context](01-overview/eu-ai-act-context.md) — The regulatory backdrop that drives the compliance requirements
5. [RawEvent Schema](03-data/raw-event-schema.md) — The central data structure every other component produces or consumes
6. [Pipeline Walk-Through](05-components/pipeline.md) — How reader → enricher → alert engine → signer → batch → sender fit together
7. [Installation](09-operations/installation.md) — Getting Guardian running for the first time
8. [guardian.yaml Reference](12-reference/config-reference.md) — Every configuration key explained

### Specific Question

Jump directly to the section that matches your question.

| I want to...                                      | Go to                                                                   |
|---------------------------------------------------|-------------------------------------------------------------------------|
| Understand what Guardian captures                 | [RawEvent Schema](03-data/raw-event-schema.md)                          |
| Understand the hash chain                         | [Signing & Chain of Custody](04-security/signing.md)                    |
| Configure watched processes                       | [guardian.yaml Reference](12-reference/config-reference.md)             |
| Write a guardian.yaml from scratch                | [Configuration Guide](09-operations/configuration.md)                   |
| Run Guardian without a real kernel                | [Fake Event Generator](05-components/generator.md)                      |
| Understand the gRPC contract                      | [Proto Reference](12-reference/proto-reference.md)                      |
| See what eBPF probes are implemented              | [eBPF Probes](06-ebpf/probes.md)                                        |
| Understand Phase 2 plans                          | [Roadmap](07-phases/roadmap.md)                                         |
| Run the test suite                                | [Testing Guide](08-testing/testing.md)                                  |
| Understand the network buffer / offline mode      | [Sender & Buffering](05-components/sender.md)                           |
| Understand local alert rules                      | [Local Alert Engine](05-components/local-alerts.md)                     |
| Understand what EU AI Act articles require        | [EU AI Act Context](01-overview/eu-ai-act-context.md)                   |
| Compare Guardian to Falco or auditd               | [Alternatives](11-alternatives/comparison.md)                           |
| Understand container/pod enrichment               | [Enricher](05-components/enricher.md)                                   |
| Set up Guardian in Kubernetes                     | [Kubernetes Deployment](09-operations/kubernetes.md)                    |
| Contribute to Guardian                            | [Development Guide](10-development/contributing.md)                     |
| Understand the license                            | [License & BUSL](12-reference/license.md)                               |

---

## Sections

### 01 — Overview

The why and the what. Start here if you are new to Guardian or need to explain it to someone else.

| File | Description |
|------|-------------|
| [what-is-guardian.md](01-overview/what-is-guardian.md) | One-page executive summary: design philosophy, users, outputs, non-goals |
| [problem-statement.md](01-overview/problem-statement.md) | The three-level problem: business, technical, operational |
| [solution-architecture.md](01-overview/solution-architecture.md) | Three-layer design with ASCII diagram and rationale |
| [eu-ai-act-context.md](01-overview/eu-ai-act-context.md) | Articles 12, 13, 15, 17, 72 mapped to Guardian capabilities |

### 02 — Architecture

Deep dives into system design decisions.

| File | Description |
|------|-------------|
| [system-design.md](02-architecture/system-design.md) | Full component diagram, data flow, and concurrency model |
| [decisions.md](02-architecture/decisions.md) | Architecture Decision Records (ADRs) for major design choices |

### 03 — Data

The schema layer — what data Guardian produces and how it flows.

| File | Description |
|------|-------------|
| [raw-event-schema.md](03-data/raw-event-schema.md) | All 16 RawEvent fields, their sources, and types |
| [event-lifecycle.md](03-data/event-lifecycle.md) | How a kernel syscall becomes a signed, batched, sent event |
| [data-categories.md](03-data/data-categories.md) | Data sensitivity, PII handling, and compliance tagging |

### 04 — Security

How Guardian maintains tamper evidence and protects the event stream.

| File | Description |
|------|-------------|
| [signing.md](04-security/signing.md) | SHA-256 hash chain per event, HMAC-SHA256 batch signatures |
| [trust-model.md](04-security/trust-model.md) | What Guardian protects against and what it explicitly does not |
| [token-management.md](04-security/token-management.md) | API token lifecycle, rotation, and the dev-test-token warning |

### 05 — Components

Per-module reference for every Python file in `agent/`.

| File | Description |
|------|-------------|
| [pipeline.md](05-components/pipeline.md) | The full reader→enricher→alert→signer→batch→sender pipeline |
| [reader.md](05-components/reader.md) | Source selection: eBPF vs generator, env var and flag overrides |
| [generator.md](05-components/generator.md) | Fake event generation, syscall weights, execve injection |
| [enricher.md](05-components/enricher.md) | Agent ID, model name, container ID, pod name, namespace |
| [local-alerts.md](05-components/local-alerts.md) | Sandbox escape and unexpected network detection |
| [signer.md](05-components/signer.md) | Hash chain mechanics, genesis block, verify_chain() |
| [sender.md](05-components/sender.md) | gRPC transport, insecure mode, offline buffer, drain logic |

### 06 — eBPF

The kernel instrumentation layer.

| File | Description |
|------|-------------|
| [probes.md](06-ebpf/probes.md) | Implemented tracepoints: read, openat, execve. Phase 2 TODO list |
| [kernel-struct.md](06-ebpf/kernel-struct.md) | guardian_event C struct, ring buffer, watched_pids map |
| [bcc-vs-libbpf.md](06-ebpf/bcc-vs-libbpf.md) | Why libbpf was chosen and Phase 3 Aya/Rust migration plan |

### 07 — Phases

Roadmap and phase definitions.

| File | Description |
|------|-------------|
| [roadmap.md](07-phases/roadmap.md) | Phase 1 (complete), Phase 2 (real eBPF), Phase 3 (Rust+Aya) |
| [phase1-scope.md](07-phases/phase1-scope.md) | What was delivered in Phase 1 and what was explicitly deferred |

### 08 — Testing

How to run and extend the test suite.

| File | Description |
|------|-------------|
| [testing.md](08-testing/testing.md) | Running the 63-test suite, coverage, test module breakdown |
| [test-strategy.md](08-testing/test-strategy.md) | Testing philosophy, fake-first design, what is not tested |

### 09 — Operations

Getting Guardian deployed and kept running.

| File | Description |
|------|-------------|
| [installation.md](09-operations/installation.md) | Dependencies, install script, first run |
| [configuration.md](09-operations/configuration.md) | Step-by-step guardian.yaml construction |
| [kubernetes.md](09-operations/kubernetes.md) | DaemonSet deployment, env vars, RBAC |
| [monitoring.md](09-operations/monitoring.md) | Watching buffer size, sent/buffered counters, log levels |

### 10 — Development

Contributing to Guardian.

| File | Description |
|------|-------------|
| [contributing.md](10-development/contributing.md) | Branch model, PR process, code style |
| [local-dev.md](10-development/local-dev.md) | Running in --fake mode, dev UI, proto regeneration |
| [adding-a-probe.md](10-development/adding-a-probe.md) | Step-by-step guide for adding a new eBPF tracepoint in Phase 2 |

### 11 — Alternatives

Positioning Guardian in the existing landscape.

| File | Description |
|------|-------------|
| [comparison.md](11-alternatives/comparison.md) | Guardian vs Falco, auditd, Tetragon, Pixie, OpenTelemetry |

### 12 — Reference

Quick-reference material.

| File | Description |
|------|-------------|
| [config-reference.md](12-reference/config-reference.md) | Every guardian.yaml key with type, default, and example |
| [proto-reference.md](12-reference/proto-reference.md) | GuardianIngest service, EventBatch, Event, Ack definitions |
| [cli-reference.md](12-reference/cli-reference.md) | All CLI flags: --fake, --dry-run, --config, --log-level |
| [license.md](12-reference/license.md) | BUSL-1.1 explained: what is and is not permitted |

---

## Quick Answers

Common questions and where to find the answers.

**Q: What syscalls does Guardian capture?**
Guardian captures `read`, `write`, `openat`, `sendto`, `recvfrom`, `connect`, `execve`, `clone`, and `socket`. The full list is configurable in `guardian.yaml`. See [guardian.yaml Reference](12-reference/config-reference.md).

**Q: Does Guardian modify AI model code?**
No. Guardian operates entirely at the kernel layer via eBPF. No instrumentation library, SDK, or agent is injected into the monitored process. See [What Is Guardian](01-overview/what-is-guardian.md).

**Q: How does Guardian identify which model generated a syscall?**
By matching the process name (e.g., `python`, `torchserve`) against the `watch` list in `guardian.yaml`. The mapping is one process name → one model name. See [Enricher](05-components/enricher.md).

**Q: Can I run Guardian without a Linux kernel?**
Yes. Use `--fake` or set `GUARDIAN_FAKE_EVENTS=1`. The fake generator produces statistically realistic events without requiring eBPF. See [Fake Event Generator](05-components/generator.md).

**Q: How does Guardian prove events have not been tampered with?**
Each event carries a SHA-256 hash of its content chained to the previous event's hash. Each batch carries an HMAC-SHA256 signature over all hashes in the batch. See [Signing & Chain of Custody](04-security/signing.md).

**Q: What happens if the control plane is unreachable?**
Events are buffered to `~/.guardian/buffer/pending.jsonl` (up to 10,000 lines). The buffer is drained on the next successful connection. See [Sender & Buffering](05-components/sender.md).

**Q: Does Guardian do any ML or anomaly detection itself?**
No. Guardian captures facts and signs them. Interpretation, anomaly detection, and report generation happen in the viriato-platform. See [What Is Guardian](01-overview/what-is-guardian.md).

**Q: Which EU AI Act articles does Guardian help with?**
Articles 12 (logging), 13 (transparency), 15 (accuracy and robustness), 17 (quality management), and 72 (general-purpose AI obligations). See [EU AI Act Context](01-overview/eu-ai-act-context.md).

**Q: Is the gRPC connection encrypted?**
TLS is used by default. The connection is deliberately insecure only when the endpoint is `localhost` or `127.x.x.x`, or when `GUARDIAN_INSECURE_GRPC=1` is set. See [Sender & Buffering](05-components/sender.md).

**Q: What is the agent ID and where is it stored?**
A UUID that uniquely identifies a Guardian installation. Stored at `/var/lib/guardian/.agent_id` (production) or `~/.guardian_agent_id` (development fallback). See [Enricher](05-components/enricher.md).

**Q: What does the `--dry-run` flag do?**
The pipeline runs normally (events are read, enriched, signed) but nothing is sent to the control plane and nothing is written to the buffer. Useful for configuration validation. See [CLI Reference](12-reference/cli-reference.md).

**Q: How does container detection work?**
The enricher reads `/proc/<PID>/cgroup` and extracts a 12-character Docker short container ID using a regex. Results are cached in an LRU cache with 512 slots. See [Enricher](05-components/enricher.md).

**Q: How is Guardian licensed?**
Business Source License 1.1 (BUSL-1.1). Production use requires a commercial license. Development and testing use is permitted. See [License](12-reference/license.md).

**Q: What Python version is required?**
Python 3.12 or higher. See [Installation](09-operations/installation.md).

**Q: What are the key dependencies?**
`grpcio` (transport), `pyyaml` (config parsing), `cryptography` (signing), and `rich` (terminal output). See [Installation](09-operations/installation.md).

**Q: How do I add a new watched process?**
Add an entry under `watch:` in `guardian.yaml` with a `process` and `model_name`. No restart needed if Guardian is configured to watch for config changes. See [Configuration Guide](09-operations/configuration.md).

**Q: What is the genesis hash?**
The first event in a chain has no predecessor. Its `prev_hash` is set to 64 zeros (`"0" * 64`). See [Signing & Chain of Custody](04-security/signing.md).

**Q: Can I add custom alert handlers?**
Yes. `LocalAlertEngine.set_custom_handler()` replaces the default log output with any callable. See [Local Alert Engine](05-components/local-alerts.md).

**Q: What eBPF tracepoints are implemented today?**
`sys_enter_read`, `sys_enter_openat`, and `sys_enter_execve`. Full syscall coverage is planned for Phase 2. See [eBPF Probes](06-ebpf/probes.md).

**Q: What is Phase 2?**
Real eBPF kernel attachment replacing the fake generator. The `EbpfLoader` stub in `agent/loader.py` will be implemented. See [Roadmap](07-phases/roadmap.md).

**Q: What is the batch interval?**
Events are batched and sent every `batch_interval_ms` milliseconds (default: 100ms = 0.1s). Configurable via `guardian.yaml`. See [guardian.yaml Reference](12-reference/config-reference.md).

**Q: How do I verify that a chain of events is valid?**
Call `Signer.verify_chain(events)`. It checks the genesis hash, each event's SHA-256 hash against its content, and that each event's `prev_hash` matches the prior event's `this_hash`. See [Signing & Chain of Custody](04-security/signing.md).

---

## About

Guardian is developed and maintained by [Viriato Security](https://viriato.io). Phase 1 (pipeline scaffold, fake generator, full test suite) is complete on `main`. Phase 2 (real eBPF kernel attachment) is in active development.

For security disclosures, see [SECURITY.md](../SECURITY.md).
For contribution guidelines, see [CONTRIBUTING.md](../CONTRIBUTING.md).
