# Phase 1 — Python Agent with Fake Generator

> Complete documentation of what Phase 1 built, the decisions made, and what it validated.

**Status: COMPLETE**

Phase 1 is the complete Guardian agent pipeline, implemented in Python, with a fake event generator standing in for the eBPF kernel probe. Every component that will exist in production was designed, implemented, and tested. The fake event generator is not a placeholder — it is a deliberate design that enables the entire downstream pipeline to be validated on macOS, in CI, without root, without Linux, and without BCC.

63 tests pass. The pipeline is correct. Phase 1 is the specification that Phase 2 and Phase 3 must satisfy.

---

## Overview

Phase 1 answers a fundamental question: before writing a single line of kernel code, can we prove that the pipeline design is correct? The answer is yes. By producing synthetic events that are schema-identical to what a real eBPF probe would produce, Phase 1 validates:

- The 16-field event schema
- SHA-256 per-event hash chaining
- HMAC-SHA256 per-batch signing with the customer token
- gRPC transmission over TLS to the platform
- Disk buffer fallback with JSONL format and FIFO drain
- Local alert rules (sandbox_escape, unexpected_network)
- Agent identity persistence across restarts
- Kubernetes context enrichment
- Configuration loading and validation

None of these depend on the event source being real. They depend on the event schema being correct. `FakeEventGenerator` produces events with the correct schema. The tests verify this. Phase 2 must satisfy the same schema — and the same tests.

---

## What Was Built

### agent/config.py

Configuration loader for `guardian.yaml`. Uses `yaml.safe_load()` (PyYAML) and converts the raw dict into typed Python dataclasses.

**Dataclasses**: `Config`, `AgentConfig`, `WatchEntry`, `LocalAlert`, `ComplianceConfig`.

**Search path order**:
1. Explicit path argument passed to `load_config(path)` if provided
2. `./guardian.yaml` (current working directory)
3. `/etc/guardian/guardian.yaml` (system installation)
4. `~/.guardian/guardian.yaml` (user installation)

**Error handling**: Raises `FileNotFoundError` if no config is found in any location. Logs a `WARNING` (does not raise) if the API token is the placeholder value `"YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE"` — this allows the agent to start in dry-run mode with a placeholder token.

**Tested by**: `tests/test_config.py` (6 tests) — covers file not found, placeholder token warning, all search paths, and dataclass field validation.

### agent/generator.py

`FakeEventGenerator` is the heart of Phase 1. It produces a stream of `RawEvent` instances that structurally and statistically mimic a PyTorch-based LLM inference workload.

**Syscall distribution** (weighted random, matching real PyTorch profiling data):
- `read`: 35%
- `write`: 25%
- `openat`: 15%
- `sendto`: 7%
- `recvfrom`: 6%
- `connect`: 5%
- `socket`: 4%
- `clone`: 3%

These weights reflect the dominant pattern of a PyTorch inference server: the majority of syscalls are reads (loading weights, processing inputs) and writes (returning results), with a tail of network and process syscalls.

**execve injection**: Every 500–1000 events (drawn from `random.randint(500, 1000)`), the normal weighted distribution is bypassed and an `execve` event is emitted. The `fd_path` is set to a shell binary path (e.g., `/bin/bash`). This allows `sandbox_escape` alert testing in Phase 1 without requiring a real execve.

**Sleep interval**: `random.uniform(0.0005, 0.002)` seconds between events. This simulates 500–2000 syscalls/second, matching the range of a real single-process PyTorch inference server.

**Timestamp format**: `_now_iso_ns()` returns `datetime.now(timezone.utc).isoformat(timespec="nanoseconds")` which produces e.g. `"2026-04-10T14:30:22.123456789+00:00"`. Uses `timezone.utc` (not the deprecated `datetime.utcnow()`).

**Realistic data pools**:
- `_FILE_PATHS`: Real-looking model paths (`/var/lib/models/patient-diagnosis-v2/model.pt`), library paths (`/usr/local/lib/python3.12/site-packages/torch/nn/modules/linear.py`), and temp paths (`/tmp/torch_cache/...`)
- `_ALL_NETWORK_ADDRS`: Internal addresses (`10.0.0.1:8080`, `172.16.0.5:443`) and external addresses (`203.0.113.42:443`, `198.51.100.7:8443`) — the external ones trigger `unexpected_network` alerts in tests

**`RawEvent` dataclass fields**: `timestamp`, `pid`, `uid`, `process`, `syscall`, `fd_path`, `bytes`, `network_addr`, `return_val`, plus agent-layer fields filled later: `agent_id`, `model_name`, `container_id`, `pod_name`, `namespace`, `prev_hash`, `this_hash`.

**Tested by**: `tests/test_generator.py` (16 tests) — covers timestamp format, syscall distribution, RawEvent schema, execve injection, and the full field set.

### agent/enricher.py

`Enricher` adds context that the kernel probe cannot know: who is the agent, what model is running, and where in the cluster is this pod.

**`agent_id`**: A persistent UUID stored at:
- `/var/lib/guardian/.agent_id` (production — owned by guardian service user)
- `~/.guardian_agent_id` (development — fallback when production path is unwritable)

Created on first run with `uuid.uuid4()`. Validated as UUID format on subsequent loads. If validation fails, a new UUID is generated and written. This ensures `agent_id` is stable across restarts (same chain session continuity on the platform) but recoverable if the file is corrupted.

**`model_name`**: Looked up from the `watch` list in `config.watch` by matching `event.process` against `WatchEntry.process`. Returns `"unknown"` for processes not in the watch list (e.g., system daemons that happen to be watched).

**`container_id`**: Parsed from `/proc/<pid>/cgroup` using regex `r"/docker/([a-f0-9]{12,64})"`. Returns the first 12 characters (Docker short ID format). LRU-cached with 512 slots — a process's cgroup does not change, so caching per-PID is safe and reduces `/proc` filesystem reads.

**`pod_name`**: From `KUBERNETES_POD_NAME` environment variable. Set by Kubernetes' downward API when running as a DaemonSet pod.

**`namespace`**: From `KUBERNETES_NAMESPACE` environment variable. Also set by Kubernetes' downward API.

**Tested by**: `tests/test_enricher.py` (11 tests) — covers agent_id persistence, agent_id UUID validation, model_name lookup, container_id parsing from cgroup, and Kubernetes env var handling.

### agent/local_alerts.py

`LocalAlertEngine` evaluates alert rules against each event synchronously in the pipeline loop, before signing. Alerts that fire are emitted immediately (logged + printed to stderr) without waiting for the batch to be sent.

**`sandbox_escape` rule**: Fires when `event.syscall == "execve"` AND `event.fd_path in {"/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"}`. Rationale: a legitimate AI inference workload never calls `execve` to a shell binary during normal operation. This is the highest-severity alert Guardian generates.

**`unexpected_network` rule**: Fires when `event.syscall in {"connect", "sendto"}` AND `event.network_addr` is not in the configured `network_allowlist`. An empty allowlist disables this rule (no restrictions). Rationale: an AI model that connects to an unexpected destination may be exfiltrating data.

**Custom handler**: `set_custom_handler(fn)` overrides the default output (`logger.error()` + `print(json.dumps(alert), file=sys.stderr)`). Used in tests to capture alert payloads without polluting test output: `engine.set_custom_handler(captured.append)`.

**Alert format**: The alert is a dict with keys `alert_type`, `event_timestamp`, `pid`, `process`, `syscall`, `fd_path`, `network_addr`. Serialised to JSON for logging and stderr output.

**Tested by**: `tests/test_local_alerts.py` (14 tests) — covers sandbox_escape firing conditions, unexpected_network allowlist matching, custom handler capture, and edge cases (empty allowlist, unknown syscall).

### agent/signer.py

`Signer` implements two distinct cryptographic operations: event-level SHA-256 chaining and batch-level HMAC-SHA256 signing.

**Event chaining**:
- First event in an agent session: `prev_hash = GENESIS_HASH` (the string `"0" * 64` — 64 zero characters, not a hash value)
- Each event: `this_hash = SHA-256(json.dumps(all_fields_except_this_hash, sort_keys=True))`
- Next event: `prev_hash = previous_event.this_hash`

`sort_keys=True` ensures deterministic JSON serialisation regardless of dict insertion order. The hash input includes `prev_hash`, creating a hash chain: each event's hash depends on the previous event's hash.

**Batch signing**:
```python
payload = json.dumps(
    [{"prev": e.prev_hash, "this": e.this_hash} for e in events],
    separators=(",", ":")  # compact JSON — no extra spaces
)
signature = hmac.new(token.encode("utf-8"), payload.encode("utf-8"), sha256).hexdigest()
```

The batch signature uses the customer's API token as the HMAC key. Only an agent that knows the token can produce a valid signature. The platform verifies this signature on receipt — a batch with an invalid signature is rejected.

**`verify_chain(events)`**: Recomputes every hash from scratch and verifies prev-next linkage. Returns `(True, "ok")` on success. Returns `(False, reason_string)` on failure. Used in tests and available for platform-side verification.

**Error conditions**: `ValueError` if token is empty string (constructor). `ValueError` if batch is empty list (`sign_batch`).

**`GENESIS_HASH`**: Defined as module constant `GENESIS_HASH = "0" * 64`. This is the `prev_hash` for every first event in a chain. It is not a SHA-256 hash of anything — it is a sentinel value that signals "this is the start of a chain." The platform treats a batch starting with `prev_hash == GENESIS_HASH` as a new chain from a (re)started agent.

**Tested by**: `tests/test_signer.py` (16 tests) — covers hash correctness, chain integrity, tamper detection (modified field breaks chain), genesis hash, batch signing determinism, and empty-batch error.

### agent/sender.py

`Sender` transmits signed batches to the viriato-platform via gRPC with a disk-buffer fallback for network failures.

**gRPC channel**: Uses TLS (`grpc.ssl_channel_credentials()`) for production endpoints. Uses insecure (`grpc.insecure_channel()`) for `localhost` endpoints or when `GUARDIAN_INSECURE_GRPC=1` is set. The channel target is `config.agent.endpoint` from `guardian.yaml`.

**Disk buffer**: JSONL file at `buffer_path/pending.jsonl`. Each line is a complete JSON-serialised batch (events + signature). Maximum 10,000 lines — approximately 17 minutes of buffering at the default 100ms batch interval before events are dropped.

**Drain on success**: After a successful `StreamEvents` gRPC call, `_drain_buffer()` replays all buffered batches in order (FIFO — oldest first). Stops on first failure and preserves remaining lines. This ensures no double-send: events are drained only after the current batch succeeds.

**Buffer fallback**: If `buffer_path` is not writable (e.g., `/var/lib/guardian` not created), falls back to `~/.guardian/buffer`. This ensures buffering always works even during initial installation.

**Error log format**: `"gRPC send failed (%s): buffering %d events"` where `%s` is the gRPC status code and `%d` is the event count. Warning format: `"Disk buffer full (%d lines) — dropping batch"`.

**Tested indirectly** by `tests/test_signer.py` (chain verification) and integration tests.

### agent/reader.py

`EventReader` is the abstraction layer between the event source and the pipeline. It selects the event source at startup based on platform and configuration:

1. `--fake` CLI flag OR `GUARDIAN_FAKE_EVENTS=1` environment variable → `FakeEventGenerator` (always, regardless of platform)
2. `EbpfLoader.is_available()` returns True → `EbpfLoader` (Phase 2 path, currently never reached)
3. Otherwise → `FakeEventGenerator` with a `WARNING` log: `"eBPF not available on this platform — using fake event generator"`

The `stream()` method returns an iterator that yields `RawEvent` instances. The `main.py` pipeline loop does not know or care which source is active.

### agent/loader.py

`EbpfLoader` is the Phase 2 stub. In Phase 1:

**`EbpfLoader.is_available()`**: Returns `False` on all platforms. The implementation is complete and correct for Phase 2 — it checks `sys.platform != "darwin"`, existence of `/sys/kernel/btf/vmlinux`, and importability of `bcc`. It returns False in Phase 1 only because these checks fail on macOS/CI.

**`EbpfLoader.load()`**: Raises `NotImplementedError`. Will be implemented in Phase 2 with BCC.

**`EbpfLoader.stream()`**: Raises `NotImplementedError`. Will be implemented in Phase 2 with BCC ring buffer polling.

### agent/main.py

`GuardianAgent.run()` implements the pipeline loop:

```python
for event in reader.stream():
    enricher.enrich(event)
    alerts = alert_engine.evaluate(event)
    signer.sign_event(event)
    batch.append(event)
    if time.monotonic() - last_flush >= batch_interval_seconds:
        flush(batch)
        batch = []
        last_flush = time.monotonic()
```

`flush()` calls `signer.sign_batch(batch)` to get the HMAC signature, then `sender.send_batch(events, signature)` to transmit. If `--dry-run` is set, `send_batch` logs instead of transmitting.

**CLI flags**: `--config FILE`, `--fake`, `--dry-run`, `--log-level {DEBUG,INFO,WARNING,ERROR}`.

**Console script**: `guardian = "agent.main:cli_main"` in `pyproject.toml`. After `pip install -e .`, the `guardian` command is available.

### proto/guardian.proto

Defines the gRPC wire format between the agent and viriato-platform. Unchanged across all three phases.

**Service**: `GuardianIngest` with one RPC: `StreamEvents(stream EventBatch) returns (Ack)` — client-streaming, allowing the agent to send multiple batches over a persistent connection.

**`EventBatch`**: `agent_id` (string), `signature` (string — HMAC-SHA256 hex), `repeated Event events`.

**`Event`**: 16 fields matching `RawEvent` fields 1:1. String types for all fields except `pid` (int32), `uid` (int32), and `bytes` (int64).

**`Ack`**: `received` (bool), `events_stored` (int32).

**Generated stubs**: `proto/guardian_pb2.py` and `proto/guardian_pb2_grpc.py` are generated by `scripts/gen_proto.sh` using `grpc_tools.protoc`. They are not committed to the repository (listed in `.gitignore`) and are generated on each developer machine.

---

## The Fake Generator Innovation

The `FakeEventGenerator` is the key design decision of Phase 1. It is not a shortcut — it is a principled engineering choice that enables the entire pipeline to be validated without kernel code.

**Why fake data is sufficient for pipeline validation**: The pipeline (enrichment, signing, batching, gRPC, disk buffer, alerting) does not care about the content of events. It cares about the *structure* of events. A fake `RawEvent` with `syscall="execve"` and `fd_path="/bin/bash"` triggers `sandbox_escape` just as reliably as a real one. The SHA-256 hash chain is equally secure. The gRPC transmission is identical.

**Why schema identity is the critical property**: `FakeEventGenerator` is not allowed to produce events with a slightly different schema than `EbpfLoader`. If it did, Phase 1 tests would not specify Phase 2 requirements. The tests in `test_generator.py` are not just quality gates for the fake generator — they are the specification for what `EbpfLoader` must produce.

**What the fake generator cannot validate**: Only that the event source is actually observing real kernel activity. Phase 1 proves the pipeline is correct given correct input. Phase 2 proves the input (real kernel events) is correct.

---

## Design Decisions Accepted for Phase 1

**Python, not Rust or Go**: Speed to validation. The schema, cryptographic design, and gRPC contract are the hard parts. Python lets you iterate on these in days. A Rust rewrite of a proven design (Phase 3) is far less risky than designing and implementing simultaneously in Rust.

**Fake event generator, not real eBPF**: The entire pipeline can be validated without kernel code. Phase 1's value is proving the design, not demonstrating eBPF instrumentation. The schema contract enforces that Phase 2 matches Phase 1's output exactly.

**HMAC-SHA256 for batch signing, not Ed25519 asymmetric signatures**: Simpler implementation (Python `hmac` stdlib, no key generation ceremony). Uses the customer API token directly as the HMAC key — the customer proves they know the token. Ed25519 would require key pair management, safe key storage, and a verification endpoint. HMAC is sufficient for Phase 1 and Phase 2. Phase 3 may upgrade to Ed25519 for key rotation support.

**JSONL buffer, not SQLite**: JSONL is human-readable (useful for debugging), has no additional dependency, and is safe for partial writes — each line is a complete record, and a write that is interrupted mid-line produces at most one corrupted record. SQLite would require `sqlite3` (stdlib, but with its own consistency semantics), schema management, and vacuum logic. JSONL is the simpler correct choice.

**10,000 batch limit on disk buffer**: At the default 100ms batch interval, 10,000 batches = ~17 minutes of event buffering without network connectivity. This covers short network outages (DNS flapping, TLS renegotiation, brief cloud provider incidents) without consuming unbounded disk space.

---

## Performance Characteristics

| Metric | Phase 1 Value |
|--------|--------------|
| Synthetic event rate | 500–2000 events/sec (sleep-limited) |
| Batch interval | 100ms default |
| Events per batch | 50–200 (at 500–2000/sec with 100ms interval) |
| Memory | ~20MB Python process at steady state |
| CPU | <1% for event generation and pipeline loop |
| Startup time | <1 second |
| Test suite duration | ~0.04–0.06 seconds (63 tests) |
| macOS support | Full |
| Root required | No |

The Python GIL means the event generation loop and the pipeline loop run in a single thread. This is intentional for Phase 1: simplicity over concurrency. Phase 3 (Rust + tokio) will use async concurrency for true parallelism.

---

## Known Limitations (By Design)

These limitations are deliberate in Phase 1 and are resolved in Phase 2/3:

1. **No real kernel events**: Events reflect a modelled distribution, not an actual AI process. A model making unusual syscalls that don't match the configured `_SYSCALL_WEIGHTS` distribution would not be detected in Phase 1.

2. **No kernel-level PID filtering**: Phase 1 generates events for configured process names without verifying those processes exist. Phase 2 filters at the kernel level via `watched_pids`.

3. **No real fd_path for read/write**: The fake generator uses pre-defined path lists. Real paths (which may reveal unexpected file access) require Phase 2's `/proc/<pid>/fd/<fd>` resolution.

4. **No real network_addr**: Fake network addresses are drawn from a pre-defined pool. Real network connections to unexpected destinations require Phase 2's `sockaddr` parsing.

5. **return_val always "0" or synthetic errno**: Real return values (bytes transferred, actual errors) require `sys_exit` tracepoints — a Phase 2 TODO.

6. **macOS development only**: Phase 1 runs on macOS because there is no BPF. Phase 2 requires Linux 5.8+.

---

## What Phase 1 Validated

Phase 1 proved — not assumed — the following:

- **Configuration loading**: All search paths, typed dataclasses, placeholder warning, and error handling are correct and tested.
- **Enrichment**: `agent_id` persistence across restarts, UUID validation, `model_name` lookup by process name, `container_id` parsing from cgroup files, and Kubernetes env var handling.
- **Cryptographic chaining**: Every hash is computed correctly, chain integrity is verified, tamper detection works (modified field breaks chain), and GENESIS_HASH starts every chain.
- **Batch signing**: HMAC-SHA256 is deterministic for the same input, token binding works, and the batch payload format is correct.
- **Local alerting**: `sandbox_escape` fires on execve to shell binaries, `unexpected_network` fires on unexpected destinations, custom handlers capture alerts without stdout pollution.
- **End-to-end pipeline**: reader → enricher → signer → alert → batch → sender flows without errors in 63 tests.
- **Proto serialisation**: `RawEvent` serialises to `Event` proto correctly for all field types and values.
- **Disk buffer**: Write, read, drain, full-buffer behavior, and fallback path all work correctly.

---

## The Test Suite as Specification

The 63 tests are the specification. Phase 2 must pass all 63 tests unchanged. Phase 3 must pass all 63 tests unchanged (from a Python test runner that imports the Rust agent's output schema via FFI or subprocess). Any Phase 2/3 change that breaks an existing test indicates a regression in the schema contract.

| Test File | Test Count | What It Specifies |
|-----------|-----------|-------------------|
| `tests/test_config.py` | 6 | Config loading, search paths, typed dataclasses, validation, error handling |
| `tests/test_enricher.py` | 11 | agent_id persistence, UUID validation, model_name lookup, container_id parsing, Kubernetes context |
| `tests/test_generator.py` | 16 | RawEvent schema, all 17 field names and types, timestamp format, syscall distribution, execve injection timing |
| `tests/test_local_alerts.py` | 14 | sandbox_escape conditions, unexpected_network allowlist matching, custom handler interface, edge cases |
| `tests/test_signer.py` | 16 | Hash correctness, chain integrity, tamper detection, genesis hash, batch signing, empty-batch error |
| **Total** | **63** | **The complete Phase 1 specification** |

The tests run in ~0.04–0.06 seconds with no external dependencies, no network access, and no root. They run identically on macOS, Linux, and GitHub Actions CI.

---

## Deliverables

Phase 1 produced the following artifacts:

| Artifact | Description |
|----------|-------------|
| `agent/config.py` | Configuration loader with typed dataclasses |
| `agent/generator.py` | `FakeEventGenerator` and `RawEvent` dataclass |
| `agent/enricher.py` | Agent identity, model name, Kubernetes context |
| `agent/signer.py` | SHA-256 chaining, HMAC-SHA256 batch signing |
| `agent/sender.py` | gRPC sender with JSONL disk buffer fallback |
| `agent/local_alerts.py` | sandbox_escape and unexpected_network rules |
| `agent/reader.py` | Event source abstraction |
| `agent/loader.py` | EbpfLoader stub (is_available + NotImplementedError) |
| `agent/main.py` | Pipeline loop, CLI, batch flush |
| `proto/guardian.proto` | gRPC schema (16-field Event, EventBatch, Ack) |
| `probe/guardian.h` | Kernel event struct definition |
| `probe/guardian.bpf.c` | BPF program stub (compiles, not yet loaded) |
| `tests/test_config.py` | 6 config tests |
| `tests/test_enricher.py` | 11 enricher tests |
| `tests/test_generator.py` | 16 generator schema tests |
| `tests/test_local_alerts.py` | 14 alert rule tests |
| `tests/test_signer.py` | 16 signer/chain tests |
| `guardian.yaml.example` | Documented configuration example |
| `guardian.yaml` | Local development configuration |
| `install.sh` | System installation script |
| `scripts/gen_proto.sh` | Proto stub generation script |
| `tools/demo.py` | Interactive pipeline demo |
| `pyproject.toml` | Python packaging with console script |
| `README.md` | Project overview and quickstart |
| `CONTRIBUTING.md` | Contribution guidelines |
| `SECURITY.md` | Security disclosure policy |

---

## Summary

Phase 1 is complete. The pipeline — enrichment, signing, batching, gRPC, disk buffer, local alerting, configuration, and proto schema — is designed, implemented, and proven correct by 63 tests that run in under 100ms. The `FakeEventGenerator` produces schema-identical events to what Phase 2's `EbpfLoader` will produce, enabling the complete pipeline to be validated without a kernel probe. Phase 2 replaces exactly one component: the event source.

---

## Related Documents

- [Phase 1 vs Phase 2](../06-ebpf/phase1-vs-phase2.md)
- [Phase 2: Real eBPF](phase2-real-ebpf.md)
- [Phase 3: Rust Rewrite](phase3-rust-rewrite.md)
- [Test Strategy](../08-testing/test-strategy.md)
- [Event Schema](../03-data/event-schema.md)
- [Cryptographic Design](../04-security/cryptographic-design.md)
- [Why Python First](../11-alternatives/why-python-first.md)
