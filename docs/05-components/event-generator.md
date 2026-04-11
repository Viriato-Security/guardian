# Event Generator (`agent/generator.py`)

## Overview

`agent/generator.py` serves two roles in the Guardian codebase:

1. **It defines `RawEvent`**, the central data structure that flows through the entire pipeline — from source (eBPF or fake generator) through enrichment, signing, and transmission.
2. **It implements `FakeEventGenerator`**, a synthetic event stream that mimics a PyTorch-based AI inference workload for use on macOS, in CI, and in any environment where the Phase 2 eBPF loader is not yet available.

The Phase 1 contract that makes this architecture work is: **the schema produced by `FakeEventGenerator` must be identical to the schema that the Phase 2 eBPF loader will produce**. This means all other pipeline stages — `Enricher`, `Signer`, `Sender`, `LocalAlertEngine` — are already Phase-2-ready without modification.

---

## `RawEvent` Dataclass

```python
@dataclass
class RawEvent:
    # Set by generator/loader (Phase 1/2)
    timestamp: str = ""
    pid: int = 0
    process: str = ""
    syscall: str = ""
    fd_path: str = ""
    bytes: int = 0
    network_addr: str = ""
    return_val: str = "0"
    uid: int = 0
    # Set by enricher.py
    agent_id: str = ""
    model_name: str = ""
    container_id: str = ""
    pod_name: str = ""
    namespace: str = ""
    # Set by signer.py
    prev_hash: str = ""
    this_hash: str = ""
```

### Field Reference

| Field | Type | Set by | Description |
|---|---|---|---|
| `timestamp` | `str` | Generator / eBPF | ISO 8601 UTC with nanosecond precision (see `_now_iso_ns()`). |
| `pid` | `int` | Generator / eBPF | Process ID of the process that made the syscall. |
| `process` | `str` | Generator / eBPF | Name of the process (basename of the executable). |
| `syscall` | `str` | Generator / eBPF | Name of the syscall (`"read"`, `"execve"`, `"connect"`, etc.). |
| `fd_path` | `str` | Generator / eBPF | Path argument for file-related syscalls (`read`, `write`, `openat`, `execve`). Empty for network-only syscalls. |
| `bytes` | `int` | Generator / eBPF | Number of bytes transferred. Relevant for `read`, `write`, `sendto`, `recvfrom`. Zero for others. |
| `network_addr` | `str` | Generator / eBPF | `"host:port"` for network syscalls (`connect`, `sendto`, `recvfrom`). Empty for file-only syscalls. |
| `return_val` | `str` | Generator / eBPF | Syscall return value as a string (e.g. `"0"` for success, `"-13"` for `EACCES`). Stored as string to accommodate 64-bit signed values without int overflow risk. |
| `uid` | `int` | Generator / eBPF | UID of the process making the syscall. |
| `agent_id` | `str` | `Enricher` | UUID of this Guardian installation. |
| `model_name` | `str` | `Enricher` | Model name from `watch` config, or `"unknown"`. |
| `container_id` | `str` | `Enricher` | Docker short container ID (12 chars), or empty if not in a container. |
| `pod_name` | `str` | `Enricher` | Kubernetes pod name from `KUBERNETES_POD_NAME` env var, or empty. |
| `namespace` | `str` | `Enricher` | Kubernetes namespace from `KUBERNETES_NAMESPACE` env var, or empty. |
| `prev_hash` | `str` | `Signer` | SHA-256 of the previous event's canonical form, or `GENESIS_HASH` for the first event. |
| `this_hash` | `str` | `Signer` | SHA-256 of this event's canonical form (excluding `this_hash` itself). |

The three groups (generator fields, enricher fields, signer fields) are set in pipeline order. An event passed to `Signer.sign_event()` without enrichment will have empty `agent_id`, `model_name`, etc., and those empty values will be included in the hash computation.

---

## `_now_iso_ns()` Function

```python
def _now_iso_ns() -> str:
    now = datetime.now(timezone.utc)
    us = now.microsecond
    ns_str = f"{us:06d}000"  # 6 µs digits + 3 trailing zeros → 9 digits
    return now.strftime("%Y-%m-%dT%H:%M:%S") + f".{ns_str}Z"
```

**Purpose:** Produce a UTC timestamp string with exactly 9 fractional-second digits (nanosecond precision format), which matches the format that the Phase 2 eBPF loader will produce from kernel `ktime_get_real_ns()` values.

**Format:** `"%Y-%m-%dT%H:%M:%S.{9-digit-ns}Z"`

**Example output:** `"2026-04-10T12:00:01.234567000Z"`

**Why not `datetime.utcnow()`:** That method is deprecated in Python 3.12+. `datetime.now(timezone.utc)` is the modern equivalent and is timezone-aware.

**Precision note:** Python's `datetime` only provides microsecond precision. The last three digits of the 9-digit fractional part are always `"000"` — this is a known Phase 1 limitation. Phase 2 will read actual kernel nanosecond timestamps.

---

## `FakeEventGenerator` Class

```python
class FakeEventGenerator:
    def __init__(self, config: Config) -> None:
```

### Construction

The generator initialises from the loaded `Config`:

- `_syscall_pool`: list of syscall names from `config.syscalls`, or the built-in `_SYSCALL_WEIGHTS` keys if `config.syscalls` is empty.
- `_watch_entries`: the `config.watch` list, used to generate process names matching the watch configuration.
- `_events_generated`: counter, starts at `0`.
- `_next_execve_in`: set to `random.randint(500, 1000)` at construction. This is the event count at which the first injected `execve` will occur.
- `_weighted_syscalls`: a flat list where each syscall appears a number of times equal to its weight (see table below).

### Syscall Weight Table

The generator mimics a PyTorch inference workload where memory-mapped file reads and tensor writes dominate.

| Syscall | Weight | Approximate frequency |
|---|---|---|
| `read` | 35 | 35% |
| `write` | 25 | 25% |
| `openat` | 15 | 15% |
| `sendto` | 7 | 7% |
| `recvfrom` | 6 | 6% |
| `connect` | 5 | 5% |
| `socket` | 4 | 4% |
| `clone` | 3 | 3% |

Syscalls not in `_SYSCALL_WEIGHTS` but present in `config.syscalls` receive a default weight of `1`.

### `execve` Injection Mechanism

The `execve` syscall is not in the normal weighted pool. It is injected periodically using a separate counter mechanism:

```python
if self._events_generated >= self._next_execve_in:
    self._next_execve_in = self._events_generated + random.randint(500, 1000)
    return self._make_execve_event()
```

**Initial trigger:** `_next_execve_in = random.randint(500, 1000)` — the first `execve` fires between event 500 and event 1000.

**Subsequent triggers:** After each `execve`, the next trigger is set to `current_count + random.randint(500, 1000)`.

This produces an `execve` approximately every 500–1000 events, which at the default stream rate (500–2000 events/sec) means roughly every 0.25–2 seconds.

The injected `execve` always targets a random shell path from `_SHELL_PATHS`:
```python
_SHELL_PATHS = ["/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"]
```

This ensures `sandbox_escape` alerts fire during development and testing without requiring manual trigger.

### `stream()` Method

```python
def stream(self) -> Iterator[RawEvent]:
    while True:
        event = self._make_event()
        self._events_generated += 1
        yield event
        time.sleep(random.uniform(0.0005, 0.002))
```

The generator yields events indefinitely. Between each event, it sleeps for a random interval between 0.5 ms and 2 ms, simulating 500–2000 syscalls/second. This rate is intentionally lower than real kernel rates to avoid overwhelming single-threaded test pipelines.

The `events_generated` property tracks the running total:

```python
@property
def events_generated(self) -> int:
    return self._events_generated
```

---

## Realistic Data Pools

The generator draws from fixed data pools to produce events that resemble real PyTorch inference workloads:

**File paths (`_FILE_PATHS`):**
```python
[
    "/var/lib/models/patient-diagnosis-v2/model.pt",
    "/var/lib/models/fraud-detection-v1/config.json",
    "/tmp/torch_cache/hub/checkpoints/model.bin",
    "/tmp/torch_cache/hub/checkpoints/tokenizer.json",
    "/proc/self/status",
    "/proc/self/maps",
    "/dev/urandom",
    "/etc/ld.so.cache",
    "/usr/lib/libpython3.12.so",
]
```

**Internal network addresses (`_INTERNAL_ADDRS`):**
```python
["10.0.0.1:8080", "10.0.1.45:5000", "10.1.2.3:9090", "172.16.0.5:6379"]
```

**External network addresses (`_EXTERNAL_ADDRS`):**
```python
["203.0.113.42:443", "198.51.100.7:80", "93.184.216.34:443"]
```

External addresses are drawn from the TEST-NET-3 (`203.0.113.0/24`) and TEST-NET-2 (`198.51.100.0/24`) blocks reserved by IANA for documentation, ensuring they are never routable in production.

**Error injection:** Approximately 3% of events have a non-zero `return_val` drawn from `["-1", "-2", "-13", "-22"]` (EPERM, ENOENT, EACCES, EINVAL).

---

## Phase 1 Contract: Schema Identity

The fundamental guarantee of `generator.py` is that `RawEvent` instances produced by `FakeEventGenerator.stream()` are schema-identical to what `EbpfLoader.stream()` will produce in Phase 2. Specifically:

1. All `RawEvent` fields are present and have the correct types (`str`, `int`).
2. `timestamp` uses the exact nanosecond ISO 8601 format that the eBPF loader will produce.
3. `fd_path` and `network_addr` follow the same conventions (empty string when not applicable, not `None`).
4. `return_val` is a string, not an integer.
5. `agent_id`, `model_name`, `container_id`, `pod_name`, `namespace`, `prev_hash`, `this_hash` are empty strings at the time the generator yields them — they are filled in by later pipeline stages.

Violating this contract in Phase 1 would mean that Phase 2 integration requires changes to Enricher, Signer, LocalAlertEngine, and Sender — all of which were designed and tested against this schema.

---

## Related Documents

- `docs/05-components/reader.md` — `EventReader` wraps `FakeEventGenerator` with source selection logic
- `docs/05-components/loader.md` — `EbpfLoader` will replace `FakeEventGenerator` in Phase 2
- `docs/05-components/enricher.md` — fills the enricher fields on `RawEvent`
- `docs/05-components/signer.md` — fills `prev_hash` and `this_hash` on `RawEvent`
