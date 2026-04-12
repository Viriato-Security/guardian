# Guardian

**Guardian is a kernel-level eBPF observability agent for AI systems.**

Built by [Viriato Security](https://viriatosecurity.com) — the EU AI Act compliance platform.
Guardian sits on your Linux server, captures every syscall made by your AI processes at kernel level,
signs the telemetry cryptographically, and streams it to the Viriato platform for compliance analysis.

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **Python 3.12+** | Required for the userspace agent |
| **Linux 5.8+ with BTF** | Required for real eBPF probe (Phase 2+). Phase 1 runs on macOS and Linux in fake-event mode. |
| **gRPC / protobuf** | Installed via `requirements.txt` — no manual steps |
| **Root / `CAP_BPF`** | Required for loading eBPF programs (Phase 2+). Not needed for Phase 1 dry-run. |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Customer Server                          │
│                                                                 │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│   │  AI Process  │    │  eBPF Probe  │    │  Guardian Agent  │  │
│   │  (python /   │───▶│  (kernel)    │───▶│  (userspace)     │  │
│   │  torchserve) │    │  guardian    │    │  enrich + sign   │  │
│   └──────────────┘    │  .bpf.c      │    │  + local alerts  │  │
│                        └──────────────┘    └────────┬─────────┘  │
└────────────────────────────────────────────────────│────────────┘
                                                      │ gRPC / TLS
                                         ┌────────────▼────────────┐
                                         │   viriato-platform      │
                                         │   TimescaleDB           │
                                         │   EU AI Act compliance  │
                                         │   anomaly detection     │
                                         └─────────────────────────┘
```

Guardian is **dumb by design** — it captures syscall facts and signs them.
All intelligence (anomaly detection, compliance mapping, report generation) lives in viriato-platform.

---

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| **1** | ✅ Done | Python agent + fake event generator. Full pipeline on macOS/CI. |
| **2** | Planned | Real eBPF probe on Linux 5.8+ with BTF. `probe/guardian.bpf.c`. |
| **3** | Planned | Rewrite agent in Rust for minimal footprint and zero-copy ring buffer reads. |

---

## Repository Layout

```
guardian/
├── agent/              # Userspace agent (Python)
│   ├── main.py         # Entry point — orchestrates the pipeline
│   ├── config.py       # guardian.yaml loader and schema
│   ├── reader.py       # eBPF / fake event source selection
│   ├── generator.py    # Fake event generator (Phase 1)
│   ├── loader.py       # eBPF loader stub (Phase 2)
│   ├── enricher.py     # Adds agent_id, model_name, container_id, pod metadata
│   ├── local_alerts.py # Offline sandbox-escape and network alerts
│   ├── signer.py       # SHA-256 hash chain + HMAC-SHA256 batch signatures
│   └── sender.py       # gRPC transport + offline disk buffer
├── probe/              # eBPF C kernel probe (Phase 2)
│   ├── guardian.bpf.c  # Tracepoints: read, openat, execve
│   └── guardian.h      # Shared C structs (guardian_event, ring buffer)
├── proto/              # gRPC contract
│   └── guardian.proto  # GuardianIngest service, EventBatch, Event, Ack
├── tests/              # pytest test suite (63 tests)
├── tools/              # Developer tooling
│   ├── dev_server.py   # Local dev UI server (stdlib only)
│   ├── dev_ui.html     # Browser UI: run agent, test gRPC, verify chains
│   ├── dev.sh          # One-command launcher for the dev UI
│   └── demo.py         # Rich terminal demo for presentations
├── scripts/
│   └── gen_proto.sh    # Regenerate gRPC stubs from guardian.proto
├── docs/               # Full technical documentation (12 sections)
├── guardian.yaml.example
└── install.sh          # Bootstrap script
```

---

## Documentation

Full technical docs live in [`docs/`](docs/README.md), covering architecture, data schema, security model, eBPF probes, operations, and more.

| I want to... | Go to |
|---|---|
| Understand what Guardian captures | [RawEvent Schema](docs/03-data/event-schema.md) |
| Understand the hash chain | [Signing & Chain of Custody](docs/04-security/batch-signing.md) |
| Configure watched processes | [guardian.yaml Reference](docs/12-reference/api-reference.md) |
| Run without a real kernel | [Fake Event Generator](docs/05-components/event-generator.md) |
| Compare to Falco / auditd | [Alternatives](docs/11-alternatives/alternatives-considered.md) |

---

## Quickstart

```bash
# 1. Clone
git clone https://github.com/Viriato-Security/guardian.git
cd guardian

# 2. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Bootstrap (installs deps, generates gRPC stubs, copies guardian.yaml.example)
bash install.sh

# 4. Run — no token required for fake + dry-run mode
python3 -m agent.main --fake --dry-run --log-level DEBUG
```

Press `Ctrl+C` to stop. Guardian flushes the in-flight batch and logs a shutdown summary.

> **To send real events to the platform:** edit `guardian.yaml`, set `agent.token` to your token from [viriatosecurity.com](https://viriatosecurity.com), then run without `--fake` and `--dry-run`.

---

## Configuration Reference

`guardian.yaml` — all fields:

| Field | Type | Description |
|-------|------|-------------|
| `agent.token` | string | API token from [viriatosecurity.com](https://viriatosecurity.com) |
| `agent.control_plane` | string | gRPC endpoint (default: `grpc.viriatosecurity.com:443`) |
| `agent.batch_interval_ms` | int | Flush interval in milliseconds (default: `100`) |
| `agent.buffer_path` | string | Disk buffer directory (default: `/var/lib/guardian/buffer`) |
| `watch[].process` | string | Process name to monitor (e.g. `python`, `torchserve`) |
| `watch[].model_name` | string | Human-readable AI model name for this process |
| `syscalls[]` | list[string] | Syscalls to capture |
| `local_alerts[].type` | string | `sandbox_escape` or `unexpected_network` |
| `local_alerts[].condition` | string | Human-readable condition description |
| `local_alerts[].action` | string | `log_and_alert` |
| `network_allowlist[]` | list[string] | Allowed `IP:port` pairs (empty = no restriction) |
| `compliance.organization` | string | Your organisation name for reports |
| `compliance.data_categories[]` | list[string] | Data types processed (e.g. `medical_records`, `PII`) |
| `compliance.articles[]` | list[int] | EU AI Act articles you are targeting |

---

## Event Schema

Every event captured by Guardian contains exactly these 16 fields:

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `timestamp` | string | probe/generator | ISO 8601 nanosecond precision, UTC, ends in `Z` |
| `pid` | int | probe/generator | Process ID |
| `process` | string | probe/generator | Process name (`python`, `torchserve`, …) |
| `syscall` | string | probe/generator | Syscall name (`read`, `write`, `execve`, …) |
| `fd_path` | string | probe/generator | File path for file syscalls, empty otherwise |
| `bytes` | int | probe/generator | Bytes read/written |
| `network_addr` | string | probe/generator | `IP:port` for network syscalls, empty otherwise |
| `return_val` | string | probe/generator | `"0"` for success or errno string e.g. `"-13"` |
| `uid` | int | probe/generator | Linux user ID |
| `agent_id` | string | enricher | UUID of this Guardian installation |
| `model_name` | string | enricher | From `guardian.yaml` watch list |
| `container_id` | string | enricher | Docker short ID (12 chars) from `/proc/PID/cgroup` |
| `pod_name` | string | enricher | From `KUBERNETES_POD_NAME` env var |
| `namespace` | string | enricher | From `KUBERNETES_NAMESPACE` env var |
| `prev_hash` | string | signer | SHA-256 of previous event (GENESIS_HASH for first) |
| `this_hash` | string | signer | SHA-256 of this event |

---

## Local Alerts

Guardian fires alerts **without any network call** — even when viriato-platform is unreachable.

| Alert type | Trigger | Action |
|-----------|---------|--------|
| `sandbox_escape` | `execve` to `/bin/bash`, `/bin/sh`, `/usr/bin/bash`, `/usr/bin/sh` | `logger.error` + JSON to stderr |
| `unexpected_network` | `connect`/`sendto` to address not in `network_allowlist` (when list is non-empty) | `logger.error` + JSON to stderr |

---

## Cryptographic Integrity

**Event chaining** — tamper-evident log:
```
event[0].prev_hash = "0000...0000"  (GENESIS_HASH, 64 zeros)
event[0].this_hash = SHA-256(all fields except this_hash)
event[1].prev_hash = event[0].this_hash
event[1].this_hash = SHA-256(all fields except this_hash)
...
```
Any deletion, insertion, reordering, or field mutation breaks the chain.

**Batch signing** — HMAC-SHA256 over the chain hashes:
```
payload   = json([{"prev": e.prev_hash, "this": e.this_hash} for e in batch])
signature = HMAC-SHA256(api_token, payload)
```

---

## Running Tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

All tests should pass.

---

## Developer Tools

Guardian ships a browser-based dev UI for testing the pipeline without touching
the terminal.

```bash
bash tools/dev.sh
# Opens http://localhost:8765 automatically
```

Or start the server manually:

```bash
python tools/dev_server.py
```

The UI has three tabs:

| Tab | What it does |
|-----|-------------|
| **Run Agent** | Start/stop the agent subprocess and stream live log output. ALERT lines are highlighted red, batch-ready lines green. Supports dry-run and live modes. |
| **Test gRPC** | Generate N fake events for a chosen syscall, sign them with `dev-test-token`, and send the batch to any endpoint. Shows the Ack response and full signed batch JSON. Events are auto-loaded into the Verify tab. |
| **Verify Chain** | Paste a JSON event array (or full EventBatch) and verify the SHA-256 event chain client-side in the browser. Per-event green ✓ / red ✗ with overall CHAIN INTACT or CHAIN BROKEN verdict. |

The server (`tools/dev_server.py`) uses only Python's standard library plus the
packages already in `requirements.txt`. No extra dependencies.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

---

## License

[BUSL-1.1](LICENSE) — Business Source License.
Free for development and evaluation. Contact [hello@viriatosecurity.com](mailto:hello@viriatosecurity.com) for production licensing.

© 2026 Viriato Security Lda., Lisbon, Portugal.
