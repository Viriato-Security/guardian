# Event Pipeline

This document traces the exact journey of a single syscall event from its moment of creation
to its final storage in viriato-platform's TimescaleDB. Each step is numbered, its inputs and
outputs are described precisely, failure modes and their consequences are listed, and timing
characteristics are given.

---

## Overview

```
Step 1: Kernel capture (eBPF tracepoint fires / generator produces event)
    │
    ▼  RawEvent: 9 fields (timestamp, pid, process, syscall, fd_path,
    │             bytes, network_addr, return_val, uid)
Step 2: Source selection and delivery to reader
    │
    ▼  RawEvent: same 9 fields (yielded by reader.stream())
Step 3: Enrichment (Enricher.enrich)
    │
    ▼  RawEvent: 14 fields (+agent_id, model_name, container_id, pod_name, namespace)
Step 4: Local alert evaluation (LocalAlertEngine.evaluate)
    │
    ▼  RawEvent: unchanged 14 fields + optional AlertEvent(s) to stderr
Step 5: Cryptographic signing (Signer.sign_event)
    │
    ▼  RawEvent: 16 fields (+prev_hash, this_hash)
Step 6: Batch accumulation
    │
    ▼  list[RawEvent] grows in memory
Step 7: Batch flush — HMAC signing (Signer.sign_batch)
    │
    ▼  (list[RawEvent], signature: str)
Step 8: gRPC transmission (Sender.send_batch)
    │
    ├─ success ─► drain pending.jsonl ─► EventBatch sent to platform
    └─ failure ─► append to pending.jsonl
    │
    ▼
Step 9: Platform ingestion (viriato-platform GuardianIngest)
    │
    ▼  Ack { received: true, events_stored: N }  ─► TimescaleDB
```

---

## Step 1: Kernel Capture

### Phase 2 (Linux, eBPF)

The eBPF probe attaches to the `sys_enter_*` tracepoints for the syscalls listed in
`guardian.yaml` under `syscalls`. When the monitored process (matched by PID in the
`watched_pids` BPF hash map, 1024 slots) executes one of these syscalls, the BPF handler fires
in the kernel context of that process.

The handler calls `bpf_ringbuf_reserve()` to allocate a `guardian_event_t` slot in the 256 KB
ring buffer, fills it from the syscall arguments using `bpf_probe_read_user_str()` and
`bpf_get_current_pid_tgid()`, then calls `bpf_ringbuf_submit()`. The total time in kernel
context is on the order of 1–3 microseconds per event.

Timing: the `timestamp` field is set by `bpf_ktime_get_boot_ns()` in the kernel, then
converted to a UTC ISO 8601 string by the userspace agent when it reads the event from the ring
buffer. Nanosecond precision is preserved; the wall-clock offset is calibrated once at loader
start.

### Phase 1 (macOS / CI / --fake)

`FakeEventGenerator._make_event()` constructs a `RawEvent` directly using
`datetime.now(timezone.utc)` for the timestamp. The generator sleeps
`random.uniform(0.0005, 0.002)` seconds between events (simulating 500–2000 events/sec). An
`execve` event is injected every 500–1000 events to exercise local alert rules.

**Failure modes:**
- Phase 2: if the ring buffer fills faster than the agent drains it, new events are dropped by
  the kernel with `bpf_ringbuf_discard()`. The agent logs a warning. No crash occurs.
- Phase 1: the generator runs indefinitely; no failure mode at this step.

---

## Step 2: Source Selection and Reader Delivery

`EventReader.stream()` yields the event into the pipeline loop in `main.py`. Source selection
is performed exactly once when `stream()` is first called; the source is fixed for the agent's
lifetime.

Selection priority (first match wins):
1. `force_fake=True` (from `--fake`) or `GUARDIAN_FAKE_EVENTS=1` → generator.
2. `EbpfLoader.is_available()` (`not darwin` + `/sys/kernel/btf/vmlinux` exists + `bcc`
   importable) → eBPF.
3. Fallback → generator with `logger.warning(...)`.

The yielded object is the `RawEvent` dataclass. At this point the following fields are
populated: `timestamp`, `pid`, `process`, `syscall`, `fd_path`, `bytes`, `network_addr`,
`return_val`, `uid`. The remaining seven fields (`agent_id`, `model_name`, `container_id`,
`pod_name`, `namespace`, `prev_hash`, `this_hash`) are empty strings or zero.

**Failure modes:**
- If `EbpfLoader.load()` raises `NotImplementedError` (Phase 1 stub), the agent crashes at
  startup. This cannot happen in Phase 1 because `is_available()` returns `False` on macOS
  and when `bcc` is not installed.
- If the generator raises an unhandled exception, it propagates to the `try` block in
  `GuardianAgent.run()`, logs the error, and triggers a final flush before exit.

---

## Step 3: Enrichment

`Enricher.enrich(event)` mutates the `RawEvent` object in-place and returns it. This step adds
the five environment-context fields.

- **agent_id**: read once at `Enricher.__init__()` from the persistent UUID file. Never changes
  during the agent's lifetime.
- **model_name**: `config.model_name_for_process(event.process)`. O(n) scan of the `watch`
  list; typically 1–5 entries. Returns `"unknown"` on miss.
- **container_id**: `_container_id(event.pid)` — reads `/proc/<pid>/cgroup`, applies the regex
  `r"/docker/([a-f0-9]{12,64})"`, returns the first 12 characters. This method is
  `@functools.lru_cache(maxsize=512)`, so subsequent events from the same PID skip the
  filesystem read.
- **pod_name**: from `os.environ.get("KUBERNETES_POD_NAME", "")` — read once at init.
- **namespace**: from `os.environ.get("KUBERNETES_NAMESPACE", "")` — read once at init.

Timing: for a cached PID, this step takes on the order of 1 microsecond. For an uncached PID
(first event from a new process), it involves a single `/proc/<pid>/cgroup` read, typically
under 10 microseconds.

**Failure modes:**
- If `/proc/<pid>/cgroup` does not exist (process already exited), `OSError` is caught and
  `container_id` is set to `""`. The event continues through the pipeline normally.
- If the LRU cache is full (>512 unique PIDs), the oldest entry is evicted. The evicted PID's
  next event will trigger a fresh `/proc` read.
- If neither UUID file path is writable on first run, an ephemeral UUID is used and logged as a
  warning. This UUID will not survive agent restarts.

---

## Step 4: Local Alert Evaluation

`LocalAlertEngine.evaluate(event)` runs synchronously without any I/O. It evaluates the
sandbox_escape and unexpected_network rules and returns a `list[AlertEvent]`.

The event RawEvent is **not modified** by this step. If one or more `AlertEvent` objects are
generated, `_fire()` is called for each, which:
1. Increments `self._alert_count`.
2. Calls `logger.error("ALERT %s: %s", alert.alert_type, alert.detail)`.
3. Prints a JSON payload to `sys.stderr`.

The pipeline continues to Step 5 immediately after `evaluate()` returns, regardless of whether
alerts fired.

Timing: approximately 1 microsecond per event. No I/O, no blocking operations.

**Failure modes:**
- This stage cannot block or crash unless Python itself crashes. It is the most reliable stage
  in the pipeline precisely because it has no external dependencies.
- If `network_allowlist` is empty, the `unexpected_network` rule is a no-op (no false positives
  for unconfigured deployments).

---

## Step 5: Cryptographic Signing (per-event)

`Signer.sign_event(event)` sets the two remaining fields on the `RawEvent`:

```python
event.prev_hash = self._prev_hash
# For event #0 of this agent session: self._prev_hash == "0" * 64 (GENESIS_HASH)
# For event #N: self._prev_hash == events[N-1].this_hash

event.this_hash = Signer._hash_event(event)
# = hashlib.sha256(
#       json.dumps(
#           asdict(event_without_this_hash),
#           sort_keys=True,
#           separators=(',',':'),
#           default=str
#       ).encode()
#   ).hexdigest()

self._prev_hash = event.this_hash
```

The event is now fully populated with all 16 fields. `this_hash` commits to every other field
value; any subsequent modification to any field (timestamp, syscall, uid, etc.) will change
the hash, breaking the chain and making tampering detectable.

Timing: a single SHA-256 over approximately 500–800 bytes of JSON. On modern x86-64 hardware
with SHA-NI instructions this takes under 5 microseconds.

**Failure modes:**
- `sign_event()` does not raise exceptions under normal conditions.
- If `asdict(event)` raises (which would require a non-dataclass object to reach the Signer),
  it propagates to the pipeline loop's `except` block in `main.py`.

---

## Step 6: Batch Accumulation

The signed `RawEvent` is appended to `self._batch` (a plain Python list in `GuardianAgent`).
No serialisation occurs at this step. The batch grows in memory until the flush condition is met.

**Flush condition**: `time.monotonic() - last_flush >= config.batch_interval_seconds`. With the
default `batch_interval_ms: 100`, this is 0.1 seconds. The check is performed after every event
is processed (at the bottom of the `for event in self._reader.stream()` loop body).

This means that at 1000 events/sec, a batch will contain approximately 100 events. At 500
events/sec approximately 50. At 2000 events/sec approximately 200. The batch size is not
capped by count — only by time. Very high event rates will produce larger batches, which are
more efficient for gRPC serialisation.

**Shutdown flush**: When `self._running` becomes `False` (from SIGTERM or SIGINT), the loop
breaks. The `finally:` block calls `self._flush()` unconditionally. This ensures that even a
partial batch accumulated after the last timed flush is sent or buffered before the agent exits.

**Failure modes:**
- If the agent is killed with SIGKILL (not SIGTERM/SIGINT), the `finally` block does not run
  and the current in-memory batch is lost. Events that had already been flushed and sent are
  unaffected.
- If the process runs out of memory while accumulating a very large batch (which would require
  a very high event rate with no successful gRPC flushes for extended periods), Python raises
  `MemoryError`. This is caught by the `except Exception` in `run()` and triggers the `finally`
  flush.

---

## Step 7: Batch-Level HMAC Signing

When `_flush()` fires, it calls `self._signer.sign_batch(events)`:

```python
payload = json.dumps(
    [{"prev": e.prev_hash, "this": e.this_hash} for e in events],
    separators=(',',':'),
)
signature = hmac.new(
    token.encode(),          # the customer's API token
    payload.encode(),
    hashlib.sha256,
).hexdigest()               # 64-character lowercase hex string
```

The signature covers only the hash values (not the full event data). This is intentional: since
each `this_hash` already commits to all event fields, the HMAC over the hash list commits
transitively to all event data. The payload is compact (each `{"prev":..., "this":...}` entry
is 140 bytes), making the HMAC fast regardless of event count.

**Failure modes:**
- `sign_batch([])` raises `ValueError("sign_batch requires at least one event.")`. The `_flush()`
  method guards against this with an early return if `self._batch` is empty.
- If `token` is empty, the `Signer.__init__()` raises `ValueError` at agent startup, before any
  events are processed.

---

## Step 8: gRPC Transmission and Buffer Fallback

`Sender.send_batch(events, signature)` attempts the following:

1. Build a `guardian_pb2.EventBatch` proto message with `agent_id`, `signature`, and a repeated
   `Event` field for each RawEvent.
2. Call `self._stub.StreamEvents(iter([batch_proto]))` — a unary client-streaming call that
   sends one batch and waits for an `Ack`.
3. On success: call `_drain_buffer()` to replay any previously buffered batches.
4. On any exception (including `grpc.RpcError`, network timeout, or `ImportError` if stubs are
   not generated): call `_buffer_batch(events, signature)`.

**Buffer write format** (`_buffer_batch`):
```python
line = json.dumps({
    "agent_id": self._agent_id,
    "signature": signature,
    "events": [asdict(e) for e in events],
})
# appended to pending.jsonl with a trailing newline
```

The buffer file is `~/.guardian/buffer/pending.jsonl` by default, or whatever
`config.agent.buffer_path` specifies. Before writing, the current line count is checked; if it
is at or above 10,000, the batch is dropped with a warning log and the method returns.

**Buffer drain** (`_drain_buffer`): reads all lines from `pending.jsonl`, attempts to re-send
each in order. On the first failure, remaining lines are written back to `pending.jsonl` and
drain stops. Fully drained lines are removed from the file.

**Insecure channel**: if `control_plane` starts with `"localhost"`, `"127."`, or
`GUARDIAN_INSECURE_GRPC=1` is set, `grpc.insecure_channel()` is used. Otherwise
`grpc.secure_channel(..., grpc.ssl_channel_credentials())` is used (TLS 1.3).

Timing: a typical gRPC round-trip to `grpc.viriatosecurity.com:443` with TLS over a UK or EU
datacenter connection is approximately 5–30 ms. The batch flush runs at most every 100 ms, so
in the steady state the sender spends ~10–30% of its time in blocking gRPC calls.

**Failure modes:**
- `grpc.RpcError` (network down, platform unavailable): caught, batch buffered.
- `ImportError` (stubs not generated): caught in `_init_grpc`, `_grpc_available` set to False,
  all subsequent sends go directly to the buffer with a warning logged.
- `PermissionError` writing to buffer directory: `_resolve_buffer_dir()` tries the fallback
  path `~/.guardian/buffer`. If both fail, the batch is dropped with an error log.
- Buffer full (10,000 lines): batch is dropped with a warning log.

---

## Step 9: Platform Ingestion

The viriato-platform's `GuardianIngest.StreamEvents` RPC receives the `EventBatch`. The platform:

1. Authenticates the request using the `Authorization: Bearer <token>` gRPC metadata header.
2. Verifies the HMAC-SHA256 `signature` by recomputing it with the stored token.
3. Validates the hash chain: checks internal consistency and that `events[0].prev_hash` links
   to the last stored hash for this `agent_id`.
4. Writes all events to the TimescaleDB hypertable.
5. Returns `Ack { received: true, events_stored: N }`.

If the HMAC verification fails, the platform returns a gRPC `PERMISSION_DENIED` status. If the
hash chain is broken, the platform stores the events with a `chain_broken=true` flag and raises
an alert for the compliance team.

The `Ack` is received by the Sender's `StreamEvents` call. The Sender does not inspect the
`events_stored` field; it only distinguishes success (no exception) from failure (exception).

**Failure modes:**
- If the platform rejects the batch (HMAC failure): `grpc.RpcError` with `PERMISSION_DENIED`,
  the batch is **buffered locally**. This is a security feature: buffered events still contain
  the correct hashes and can be replayed once the token issue is resolved.
- If the platform's database is temporarily unavailable, it returns `UNAVAILABLE`. The batch
  is buffered locally.

---

## Complete Timing Budget

| Step | Typical time | Cumulative |
|---|---|---|
| 1. Kernel capture | ~2 µs (eBPF) / ~1 µs (fake) | 2 µs |
| 2. Reader yield | ~1 µs | 3 µs |
| 3. Enrichment (cached PID) | ~1 µs | 4 µs |
| 4. Local alert evaluation | ~1 µs | 5 µs |
| 5. SHA-256 hash (per event) | ~3 µs | 8 µs |
| 6. Append to batch list | < 1 µs | 9 µs |
| 7. HMAC sign batch (per flush, not per event) | ~5 µs | — |
| 8. gRPC send (per flush, blocking) | ~5–30 ms | — |
| 9. Platform ingestion + DB write | ~10–50 ms | — |

Steps 1–6 run per event (O(1) per event, approximately 10 µs total). Steps 7–9 run per batch
(every ~100 ms). At 1000 events/sec the per-event overhead is approximately 10 µs/event, which
is negligible relative to the syscall overhead the kernel is already incurring.

---

## Related Documents

- [Guardian Internals](guardian-internals.md) — architecture, state, and module dependencies.
- [System Overview](system-overview.md) — full topology and security boundaries.
- [Event Schema](../03-data/event-schema.md) — detailed documentation of each RawEvent field.
- [Data Flow](../03-data/data-flow.md) — encryption, signing, and plaintext at each stage.
- [gRPC Contract](../03-data/grpc-contract.md) — proto definition for Step 8.
