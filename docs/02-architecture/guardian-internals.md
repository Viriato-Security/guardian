# Guardian Internals

This document describes the internal architecture of the Guardian agent daemon in detail: how
its two major components (the eBPF probe and the agent daemon) communicate, the processing
pipeline stage by stage, which components are stateful versus stateless, and the dependency
graph between Python modules.

---

## Two Major Components

Guardian has a clean two-component architecture: a kernel-space eBPF probe and a userspace
Python agent daemon. In Phase 1 the kernel probe is replaced by a Python fake event generator
that produces events with an identical schema.

```
┌──────────────────────────────────────────────────────────────────┐
│  COMPONENT 1: eBPF Probe  (Phase 2, probe/guardian.bpf.c)        │
│  Runs inside the Linux kernel                                     │
│  Language: C (libbpf, BTF-based CO-RE)                           │
│  Lifecycle: loaded by EbpfLoader.load(), unloaded on agent exit  │
│                                                                   │
│  Tracepoints attached:                                            │
│    sys_enter_read, sys_enter_write, sys_enter_openat,            │
│    sys_enter_sendto, sys_enter_recvfrom, sys_enter_connect,      │
│    sys_enter_socket, sys_enter_clone                             │
│                                                                   │
│  BPF Maps:                                                        │
│    events      BPF_MAP_TYPE_RINGBUF  256 KB                      │
│    watched_pids BPF_MAP_TYPE_HASH    1024 slots                  │
└──────────────────────────────┬───────────────────────────────────┘
                                │
         BPF ring buffer        │  ring_buffer__poll()
         (shared memory,        │  (Phase 2: Python ctypes/bcc)
          zero-copy)            │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  COMPONENT 2: Agent Daemon  (agent/)                              │
│  Runs in userspace                                                │
│  Language: Python 3.12+                                          │
│  Lifecycle: started by `python -m agent.main`, stopped by        │
│             SIGTERM or SIGINT                                     │
│                                                                   │
│  Modules: config, reader, generator, loader, enricher,           │
│           local_alerts, signer, sender, main                     │
└──────────────────────────────────────────────────────────────────┘
```

---

## eBPF Probe Internals (Phase 2)

The probe is written in C using the libbpf library with BTF-based Compile Once — Run Everywhere
(CO-RE) support. CO-RE means the probe binary is compiled once and can run on any kernel that
exposes BTF type information, without needing to recompile against each kernel's headers.

### Maps

**events** (`BPF_MAP_TYPE_RINGBUF`, 256 KB): the primary data channel. When a monitored syscall
fires, the probe allocates a `guardian_event_t` entry in this ring buffer via
`bpf_ringbuf_reserve()`, populates its fields from kernel context (using `bpf_get_current_pid_tgid()`,
`bpf_get_current_uid_gid()`, `bpf_probe_read_user_str()`, etc.), and submits it via
`bpf_ringbuf_submit()`. The userspace agent drains the ring buffer using `ring_buffer__poll()`.

**watched_pids** (`BPF_MAP_TYPE_HASH`, 1024 slots): a hash map from `u32` PID to `u8` presence
sentinel. The eBPF handler for each tracepoint checks whether the triggering PID is in this map
before doing any other work. If the PID is absent, the handler returns immediately with no
memory allocation or ring buffer write. This is the primary performance gate. Userspace
populates this map after loading the probe by iterating the configured `watch` entries and
resolving their PIDs from `/proc`.

### guardian_event_t struct (probe/guardian.h)

```c
struct guardian_event_t {
    __u64  timestamp_ns;   // bpf_ktime_get_boot_ns() — converted to wall-clock by userspace
    __u32  pid;
    __u32  uid;
    char   process[64];    // bpf_get_current_comm()
    char   syscall[16];    // set per-tracepoint: "read", "write", etc.
    char   fd_path[256];   // bpf_probe_read_user_str() from filename arg
    __s64  bytes;          // count arg for read/write; 0 for others
    char   network_addr[48]; // formatted "ip:port" from connect/sendto args
    __s64  return_val;     // set in sys_exit handler; 0 initially
};
```

---

## Agent Daemon Pipeline

The agent daemon runs a single-threaded, synchronous pipeline driven by a `for event in
self._reader.stream()` generator loop in `agent/main.py`. Each event passes through every stage
sequentially before the loop body completes and the next event is consumed.

### Stage 0: Configuration (agent/config.py)

`load_config()` is called once at startup. It searches for `guardian.yaml` in three locations
(see [guardian.yaml reference](../03-data/guardian-yaml-reference.md)) and parses it into a
typed `Config` dataclass. All subsequent stages receive a reference to this immutable `Config`
object. If no config file is found, the agent raises `FileNotFoundError` immediately.

### Stage 1: EventReader (agent/reader.py)

`EventReader.stream()` is a generator that selects exactly one event source at startup and
yields `RawEvent` instances indefinitely. Source selection (evaluated once, in order):

1. `force_fake=True` (from `--fake` CLI flag) **or** `GUARDIAN_FAKE_EVENTS=1` env var → use
   `FakeEventGenerator`.
2. `EbpfLoader.is_available()` is `True` (Linux + `/sys/kernel/btf/vmlinux` exists + `bcc`
   importable) → use `EbpfLoader`.
3. Otherwise → use `FakeEventGenerator` with a warning logged.

The source is recorded in `EventReader.source` (the string `"generator"` or `"ebpf"`).

### Stage 2: Enricher (agent/enricher.py)

`Enricher.enrich(event)` mutates the `RawEvent` in-place:

- `event.agent_id`: the persistent UUID loaded from `/var/lib/guardian/.agent_id` or
  `~/.guardian_agent_id`. Created on first run.
- `event.model_name`: looked up by calling `config.model_name_for_process(event.process)`,
  which scans the `watch` list. Returns `"unknown"` if the process is not in the list.
- `event.container_id`: result of `_container_id(event.pid)`, which reads
  `/proc/<pid>/cgroup`, applies the regex `r"/docker/([a-f0-9]{12,64})"`, and returns the
  first 12 characters of the match. Returns `""` if not in a container or if the file cannot
  be read. This call is LRU-cached with 512 slots.
- `event.pod_name`: from `KUBERNETES_POD_NAME` environment variable (empty string if absent).
- `event.namespace`: from `KUBERNETES_NAMESPACE` environment variable (empty string if absent).

### Stage 3: LocalAlertEngine (agent/local_alerts.py)

`LocalAlertEngine.evaluate(event)` runs two rule checks synchronously and returns a (possibly
empty) `list[AlertEvent]`:

**sandbox_escape**: fires when `event.syscall == "execve"` and `event.fd_path` is in the set
`{"/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"}`. This detects AI workload processes
attempting to spawn a shell, which is a strong indicator of a sandbox escape or prompt injection
attack.

**unexpected_network**: fires when `event.syscall` is `"connect"` or `"sendto"` and
`event.network_addr` is not in `config.network_allowlist`. This rule is a no-op if the
allowlist is empty (all addresses are allowed). When the allowlist is non-empty, any outbound
connection to an address not on the list is flagged as potentially exfiltrating model outputs
or system prompts.

When an `AlertEvent` fires, it is output to stderr as a JSON line and logged at `ERROR` level.
The RawEvent continues through the pipeline unchanged; alerting does not interrupt flow.

### Stage 4: Signer (agent/signer.py)

`Signer.sign_event(event)` implements the per-event hash chain:

```python
event.prev_hash = self._prev_hash          # "0"*64 for event #0, else previous this_hash
event.this_hash = self._hash_event(event)  # SHA-256(json.dumps(event dict, excluding this_hash))
self._prev_hash = event.this_hash
```

The hash input is computed as:
```python
d = asdict(event)
d.pop("this_hash", None)
json.dumps(d, sort_keys=True, separators=(',',':'), default=str)
```

`sort_keys=True` ensures the serialisation is deterministic regardless of dict insertion order.
`default=str` handles any non-serialisable types defensively. `separators=(',',':')` produces
compact (no-whitespace) JSON, ensuring the hash is independent of formatting choices.

### Stage 5: Batch accumulation (agent/main.py)

The pipeline loop appends each signed `RawEvent` to `self._batch`. A time-based flush is
triggered whenever `time.monotonic() - last_flush >= config.batch_interval_seconds`. The
default is 100 ms (`batch_interval_ms: 100` in config). The flush also fires unconditionally
in the `finally` block when the agent shuts down, ensuring the last partial batch is not lost.

### Stage 6: Sender (agent/sender.py)

`_flush()` in `main.py` calls `self._signer.sign_batch(events)` to compute the batch-level
HMAC-SHA256 signature, then calls `self._sender.send_batch(events, signature)`.

`send_batch()` attempts to serialize events to a `guardian_pb2.EventBatch` proto message and
call `self._stub.StreamEvents(iter([batch_proto]))`. On success it triggers `_drain_buffer()`.
On any exception (gRPC `RpcError`, `ImportError` if stubs are missing) it calls
`_buffer_batch(events, signature)` to write the batch as a JSONL line to `pending.jsonl`.

---

## Stateful vs Stateless Components

Understanding what state each component holds is important for reasoning about restarts,
multi-instance deployments, and test isolation.

| Module | Stateful? | State held | Survives restart? |
|---|---|---|---|
| config.py | No | Reads config on call | N/A |
| reader.py | Minimal | Source selection (set once) | No |
| generator.py | Yes | `_events_generated`, `_next_execve_in`, weighted pool | No |
| loader.py | Yes (Phase 2) | BPF prog fd, ring buffer fd | No |
| enricher.py | Yes | `agent_id`, LRU cache (512 slots), pod/ns env | `agent_id` survives (persisted to file); cache does not |
| local_alerts.py | Yes | `alert_count` | No |
| signer.py | Yes | `_prev_hash` (current chain tip), `_events_signed` | No — restarts at GENESIS_HASH |
| sender.py | Yes | gRPC channel, `total_sent`, `total_buffered` | `pending.jsonl` survives; channel does not |
| main.py | Yes | `_batch`, `_stats`, `_running` | No |

The most significant stateful boundary is the Signer's `_prev_hash`. When the agent restarts,
the chain always resets to `GENESIS_HASH`. The platform records a discontinuity in the sequence,
which is expected and does not constitute a security violation (it simply marks a restart
boundary). An attacker cannot forge a seamlessly continued chain across restarts because they
do not hold the HMAC token.

The persistent state that does survive restarts is:

- **agent_id** (`/var/lib/guardian/.agent_id` or `~/.guardian_agent_id`): ensures the agent
  is consistently identified to the platform across reboots.
- **pending.jsonl** (`~/.guardian/buffer/pending.jsonl` or `/var/lib/guardian/buffer/`):
  batches that were not yet delivered are replayed after restart.

---

## Module Dependency Diagram

```
agent/main.py
    ├── agent/config.py          (Config, load_config)
    │       └── yaml
    ├── agent/reader.py          (EventReader)
    │       ├── agent/generator.py  (FakeEventGenerator, RawEvent)
    │       │       └── agent/config.py
    │       └── agent/loader.py     (EbpfLoader)
    ├── agent/enricher.py        (Enricher)
    │       ├── agent/generator.py  (RawEvent)
    │       └── agent/config.py
    ├── agent/local_alerts.py    (LocalAlertEngine, AlertEvent)
    │       └── agent/generator.py  (RawEvent)
    ├── agent/signer.py          (Signer, GENESIS_HASH, verify_chain)
    │       └── agent/generator.py  (RawEvent)
    └── agent/sender.py          (Sender)
            ├── agent/generator.py  (RawEvent)
            ├── proto/guardian_pb2.py       (generated, lazy import)
            └── proto/guardian_pb2_grpc.py  (generated, lazy import)

Standard library: argparse, dataclasses, datetime, hashlib, hmac,
                  functools, json, logging, os, pathlib, re, signal,
                  sys, time, uuid
Third-party:      yaml (PyYAML), grpc (grpcio), google.protobuf
```

`agent/generator.py` defines `RawEvent` and is the central type used throughout the pipeline.
Every other module imports `RawEvent` from it. This means there is no circular import
dependency: `generator.py` itself imports only from `agent/config.py` and the standard library.

`proto/guardian_pb2.py` and `proto/guardian_pb2_grpc.py` are lazy-imported inside
`sender._init_grpc()` and `sender._build_batch_proto()` with `ImportError` caught. This design
means the agent can run in `--dry-run` mode or buffer-only mode without the proto stubs being
present. The stubs are generated by running `bash scripts/gen_proto.sh` and are git-ignored
(they contain machine-generated code tied to the installed protobuf runtime version).

---

## Signal Handling

The agent registers `SIGTERM` and `SIGINT` handlers in `GuardianAgent.run()`:

```python
signal.signal(signal.SIGTERM, self._handle_shutdown)
signal.signal(signal.SIGINT, self._handle_shutdown)
```

Both handlers set `self._running = False`. The generator loop checks `self._running` at the top
of each iteration and breaks when it is `False`. The `finally` block then calls `self._flush()`
(sending or buffering the last partial batch) and `self._shutdown()` (closing the gRPC channel
and logging final statistics).

This ensures that systemd `ExecStop` (which sends SIGTERM) results in a clean final flush.
No events that passed the Signer are silently discarded on graceful shutdown.

---

## Concurrency Model

The agent is deliberately single-threaded. There are no threads, asyncio tasks, or
multiprocessing. This simplicity eliminates an entire class of race conditions around the Signer
state (`_prev_hash`) and the Sender's buffer file. The trade-off is that the gRPC send (which
is a blocking network call) occurs in the same thread as event processing, causing the event
loop to pause briefly during each batch flush. At the default 100 ms batch interval and typical
event rates (500–2000 events/sec synthetic, lower for real eBPF) this pause is negligible.

Phase 3 (Rust + Aya) will use an async runtime (tokio) to make the gRPC send non-blocking, but
this is not a concern for Phase 1.

---

## Related Documents

- [System Overview](system-overview.md) — end-to-end topology including kernel and platform.
- [Event Pipeline](event-pipeline.md) — step-by-step trace of a single event through these stages.
- [Design Decisions](design-decisions.md) — rationale for single-threaded model, Python, SHA-256, etc.
- [Event Schema](../03-data/event-schema.md) — full documentation of the RawEvent dataclass fields.
- [gRPC Contract](../03-data/grpc-contract.md) — proto definitions consumed by the Sender.
