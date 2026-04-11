# Phase 1 vs Phase 2 — Fake Generator vs Real eBPF

> A precise comparison of what changes and what stays identical between the fake-generator Phase 1 and the real-eBPF Phase 2.

The most important architectural decision in Guardian is that Phase 1 and Phase 2 share an identical event schema and identical downstream pipeline. Only the event source changes. This document makes that boundary explicit and precise.

---

## Overview

Guardian is built in phases for good reason: the hardest part of the system is not the eBPF probe — it is the pipeline (schema design, cryptographic integrity, gRPC transport, disk buffer, local alerting) that runs downstream of the event source. Phase 1 validated the entire pipeline in Python, running on macOS, without requiring Linux 5.8+, BCC, or root privileges. Phase 2 replaces the single component that Phase 1 faked: the event source.

The key insight is that `FakeEventGenerator` and `EbpfLoader` are interchangeable at the `reader.py` interface. Both produce `RawEvent` dataclass instances with identical field names, types, and semantics. Everything downstream of `reader.py` — `enricher.py`, `signer.py`, `sender.py`, `local_alerts.py`, `main.py` — is completely unaware of which source produced the events.

---

## Status

| Phase | Status | Platform | Event Source |
|-------|--------|----------|-------------|
| Phase 1 | COMPLETE | macOS, Linux, CI | `FakeEventGenerator` (Python) |
| Phase 2 | PLANNED | Linux 5.8+ (OrbStack for macOS dev) | `EbpfLoader` (BCC/Python → BPF C) |
| Phase 3 | PLANNED | Linux 5.8+ | Aya/Rust agent + BPF Rust program |

---

## Comparison Table

This table covers every dimension of the two phases. "Identical" means byte-for-byte compatible at the `RawEvent` interface.

| Dimension | Phase 1 | Phase 2 |
|-----------|---------|---------|
| Event source | `FakeEventGenerator` Python class | `EbpfLoader` reading from 256KB ring buffer |
| Kernel involvement | None — pure Python | BPF program running in kernel context |
| macOS support | Full — runs on macOS natively | No — Linux 5.8+ only for real eBPF |
| Root required | No | Yes — `CAP_BPF` or `CAP_SYS_ADMIN` |
| Event rate | 500–2000 synthetic events/sec (sleep-limited) | Kernel-limited — 10,000–100,000/sec for real AI workloads |
| CPU overhead | <1% Python event generation loop | 1–3% BPF tracepoints at 100,000 syscalls/sec |
| Memory overhead | ~20MB Python process | ~25MB Python process + BPF maps |
| `fd_path` for openat | Random from pre-defined list (`_FILE_PATHS`) | Real kernel path from `bpf_probe_read_user_str()` |
| `fd_path` for read | Random from pre-defined list | Resolved via `os.readlink(/proc/PID/fd/FD)` |
| `network_addr` | Random from pre-defined addresses | Real `sockaddr` formatted as `"IP:port"` |
| `pid` | `random.randint(1000, 65535)` | Real TGID from `bpf_get_current_pid_tgid() >> 32` |
| `uid` | `random.randint(0, 1000)` | Real effective UID from `bpf_get_current_uid_gid()` |
| `timestamp` | `datetime.now(timezone.utc)` in Python | Converted from `bpf_ktime_get_real_ns()` nanoseconds |
| `process` | Random choice from watch list | Real `task_comm` from `bpf_get_current_comm()` |
| `syscall` | Weighted random (read=35%, write=25%, ...) | Derived from real `syscall_nr` via lookup table |
| `return_val` | `"0"` or occasional errno string | `str(guardian_event.return_val)` (from sys_exit TODO) |
| PID filtering | Not applicable — all events are synthetic | `watched_pids` BPF map — kernel-level filtering |
| execve injection | Every 500–1000 events (for alert testing) | Real execve from watched processes |
| Event schema (`RawEvent`) | Defined by `FakeEventGenerator` | Identical — `EbpfLoader` must match exactly |
| Proto schema | Unchanged | Unchanged |
| guardian.yaml schema | Unchanged | Unchanged |
| 63 existing tests | All pass | All still pass — same interface |

---

## The Schema Contract

The `FakeEventGenerator` produces `RawEvent` dataclass instances. The `EbpfLoader` (Phase 2) must produce `RawEvent` instances with **identical field types and semantics**. This contract is enforced at three levels:

**Level 1 — Shared dataclass**: Both `FakeEventGenerator` and `EbpfLoader` return instances of `agent.generator.RawEvent`. The dataclass is defined once and used by both. The Phase 2 loader imports and instantiates it. A field type mismatch is a Python `TypeError` at construction time.

**Level 2 — Test suite**: `tests/test_generator.py` defines 16 tests that specify the exact schema of `RawEvent` output. Every field name, type constraint, and format requirement is tested. Phase 2 adds equivalent tests (`tests/test_loader_translate.py`) that verify the same constraints on `EbpfLoader` output. Both test files run in CI.

**Level 3 — Proto serialisation**: `agent/sender.py` serialises every `RawEvent` to a `proto/guardian.proto` `Event` message. If any field is missing or has the wrong type, `grpc_sender.py` raises a `ValueError` at serialisation time. This is the ultimate schema enforcement — a Phase 2 event that cannot be serialised to proto cannot be sent.

### RawEvent Field Sources

| Field | Phase 1 Source | Phase 2 Source |
|-------|---------------|----------------|
| `timestamp` | `datetime.now(timezone.utc).isoformat(timespec="nanoseconds")` | `datetime.fromtimestamp(ev.timestamp_ns / 1e9, tz=timezone.utc).isoformat()` |
| `pid` | `random.randint(1000, 65535)` | `ev.pid` (TGID from BPF) |
| `uid` | `random.randint(0, 1000)` | `ev.uid` (effective UID from BPF) |
| `process` | Random choice from configured watch entry process names | `ev.process.decode("utf-8", errors="replace").rstrip("\x00")` |
| `syscall` | Weighted random from `_SYSCALL_WEIGHTS` | `_SYSCALL_NR_TO_NAME.get(ev.syscall_nr, f"syscall_{ev.syscall_nr}")` |
| `fd` | Not in `RawEvent` (internal BPF field only) | `ev.fd` (used for fd_path resolution) |
| `fd_path` | Random from `_FILE_PATHS` list | For openat/execve: `ev.fd_path` decoded; for read/write: `os.readlink(/proc/{pid}/fd/{fd})` |
| `bytes` | `random.randint(512, 65536)` | `ev.bytes` (count argument from syscall) |
| `network_addr` | Random from `_ALL_NETWORK_ADDRS` | `ev.network_addr.decode("utf-8", errors="replace").rstrip("\x00")` |
| `return_val` | `"0"` or occasional errno string | `str(ev.return_val)` |
| `agent_id` | Filled by `Enricher.enrich()` | Same |
| `model_name` | Filled by `Enricher.enrich()` | Same |
| `container_id` | Filled by `Enricher.enrich()` | Same |
| `pod_name` | Filled by `Enricher.enrich()` | Same |
| `namespace` | Filled by `Enricher.enrich()` | Same |
| `prev_hash` | Filled by `Signer.sign_event()` | Same |
| `this_hash` | Filled by `Signer.sign_event()` | Same |

---

## What Changes in Phase 2

Phase 2 has exactly two files with substantive changes:

### agent/loader.py (primary change)

`EbpfLoader.is_available()` currently returns `False` on all platforms (Phase 1 stub). In Phase 2:

```python
@staticmethod
def is_available() -> bool:
    if sys.platform == "darwin":
        return False
    if not os.path.exists("/sys/kernel/btf/vmlinux"):
        return False
    try:
        import bcc
    except ImportError:
        return False
    return True
```

`EbpfLoader.load()` currently raises `NotImplementedError`. Phase 2 implements it with BCC:
- Load `guardian.bpf.c` via `BPF(src_file="probe/guardian.bpf.c")`
- Attach tracepoints: `bpf.attach_tracepoint(tp="syscalls:sys_enter_read", fn_name="handle_read")` and similarly for openat, execve
- Populate `watched_pids` by scanning `/proc` for matching process names
- Start background thread for PID re-discovery every 5 seconds

`EbpfLoader.stream()` currently raises `NotImplementedError`. Phase 2 implements it:
- Open ring buffer: `bpf["events"].open_ring_buffer(callback)`
- Poll loop: `bpf.ring_buffer_poll(timeout=100)`
- Translate `guardian_event` C struct → `RawEvent` Python dataclass in `_translate()`

### probe/guardian_bcc.c (new file in Phase 2)

A BCC-style variant of `guardian.bpf.c` that uses BCC's Python-compatible C conventions:
- Uses `PERF_OUTPUT` or `BPF_RINGBUF` depending on BCC version
- Uses BCC's `bpf_probe_read()` macros (slightly different from libbpf's)
- Defines the same `guardian_event` struct

Alternatively, Phase 2 may use `guardian.bpf.c` directly with BCC if BCC's Python loader supports the libbpf-style map definition syntax (`__uint(type, ...)`) on the target BCC version. This is a Phase 2 implementation detail.

---

## What Does Not Change in Phase 2

These modules are **completely unchanged** between Phase 1 and Phase 2. The list is not aspirational — it is the architectural invariant:

**`agent/main.py`**: The pipeline loop iterates over `reader.stream()` and calls enricher, alert engine, signer, and sender in order. It does not know whether events come from fake generation or real eBPF. The `--fake` flag is still supported in Phase 2 for testing and rollback.

**`agent/enricher.py`**: Enriches `RawEvent` with `agent_id`, `model_name`, `container_id`, `pod_name`, and `namespace`. Reads from `RawEvent.process` and `RawEvent.pid`. These fields have the same semantics in both phases.

**`agent/signer.py`**: Computes `prev_hash` and `this_hash` from `RawEvent` fields using SHA-256. The hash inputs are identical regardless of event source. The `GENESIS_HASH = "0" * 64` starts every new agent run.

**`agent/sender.py`**: Serialises `RawEvent` to `proto/guardian.proto` `Event` messages and sends via gRPC. The proto fields are identical in both phases.

**`agent/config.py`**: Parses `guardian.yaml`. The configuration schema is unchanged. No Phase 2-specific configuration keys are added.

**`agent/local_alerts.py`**: Evaluates `sandbox_escape` and `unexpected_network` rules against `RawEvent`. The rules look at `syscall` and `fd_path` / `network_addr` fields — identical in both phases. In Phase 2, `sandbox_escape` fires on real `execve` events, not just injected fake ones.

**`agent/reader.py`**: The `EventReader` class already contains the Phase 2 logic path: if `EbpfLoader.is_available()` returns True, use `EbpfLoader`. Otherwise, fall back to `FakeEventGenerator`. No code changes needed — the `is_available()` return value changes from False to True.

**`agent/generator.py`**: `FakeEventGenerator` continues to work unchanged in Phase 2. It is used when `--fake` is specified or when `GUARDIAN_FAKE_EVENTS=1` is set. This is the rollback mechanism.

**`proto/guardian.proto`**: The wire format is the schema contract between the agent and viriato-platform. It does not change in Phase 2. The platform receives identical gRPC messages.

**`guardian.yaml` schema**: All configuration keys (agent, watch, syscalls, local_alerts, network_allowlist, compliance) are unchanged. A `guardian.yaml` that works in Phase 1 works in Phase 2 without modification.

**All 63 existing tests**: The tests verify the schema contract that Phase 2 must satisfy. They run without modification in Phase 2. Phase 2 adds new tests — it does not break existing ones.

---

## OrbStack Development Workflow

Phase 2 requires Linux 5.8+ with BTF and BCC. On macOS, the recommended development environment is OrbStack.

**Why OrbStack**: OrbStack provides a lightweight Linux VM on macOS with a recent Linux kernel (5.15+) with BTF enabled by default. It is significantly faster than Docker Desktop (no VM hypervisor overhead for filesystem access) and more convenient than a full VM (shared filesystem with macOS, `orb` CLI for one-command shell access).

**Setup:**

```bash
# Install OrbStack from https://orbstack.dev (macOS)
brew install orbstack

# Create a Ubuntu 22.04 machine named guardian-dev
orb create ubuntu:22.04 guardian-dev

# Open a shell in the VM
orb shell guardian-dev
```

**In the OrbStack VM:**

```bash
# Install prerequisites
sudo apt-get update
sudo apt-get install -y clang-14 libelf-dev libbpf-dev bpftool python3-bcc

# Verify BTF is available
ls /sys/kernel/btf/vmlinux  # must exist

# Verify Python BCC
python3 -c "import bcc; print(bcc.__version__)"

# Run Phase 2 agent
cd /path/to/guardian
sudo python3 -m agent.main --config guardian.yaml --log-level DEBUG
```

**Development split**: Edit agent Python code on macOS (your IDE, linters, formatters). Test Phase 2 eBPF loading in the OrbStack VM (requires Linux). Run the 63 existing tests on macOS (no root needed). Run Phase 2 integration tests in the VM (requires root).

```bash
# On macOS:
pytest tests/  # 63 tests, ~0.05 seconds, no root needed

# In OrbStack VM:
sudo pytest tests/                     # existing 63 tests
sudo pytest tests/integration/        # new Phase 2 integration tests
```

---

## Performance Expectations

| Metric | Phase 1 | Phase 2 |
|--------|---------|---------|
| Synthetic event rate | 500–2000/sec (sleep-limited by `random.uniform(0.0005, 0.002)`) | Kernel-limited — real workload dependent |
| Real event rate | N/A | 10,000–100,000/sec for PyTorch inference server |
| BPF kernel overhead | None | 1–3% CPU at 100,000 syscalls/sec |
| Python pipeline overhead | <1% CPU | <1% CPU (pipeline unchanged) |
| Memory | ~20MB Python process | ~25MB Python + BPF maps |
| Startup time | <1s | 3–7s (BCC compiles guardian.bpf.c at load time) |
| Root required | No | Yes |
| CI compatibility | Full — runs on GitHub Actions, macOS, Linux | CI on Linux runners only; macOS tests skip eBPF loading |

---

## Testing for Phase 2

Phase 2 adds tests in addition to the existing 63. The existing 63 tests continue to pass unchanged — they test the schema contract, not the event source.

**New Phase 2 unit tests:**

`tests/test_loader.py` — Tests `EbpfLoader.is_available()` with mock filesystem:
- Mocking `/sys/kernel/btf/vmlinux` present/absent
- Mocking `bcc` importable/not importable
- Verifying `False` on macOS (`sys.platform == "darwin"`)

`tests/test_loader_translate.py` — Tests `EbpfLoader._translate()` with synthetic C structs:
- Verifying `timestamp_ns` → ISO 8601 conversion
- Verifying `syscall_nr` → syscall name mapping
- Verifying null-terminated string decoding

**New Phase 2 integration tests (Linux + root required):**

`tests/integration/test_ebpf_loading.py` — Verifies that the BPF object loads without verifier errors.

`tests/integration/test_real_syscalls.py` — Starts a real Python process, verifies Guardian detects its `read` and `openat` syscalls with correct field values.

`tests/integration/test_schema_parity.py` — Verifies that `EbpfLoader.stream()` and `FakeEventGenerator.stream()` produce `RawEvent` instances with identical field sets.

---

## Summary

Phase 1 and Phase 2 differ in exactly one component: the event source. `FakeEventGenerator` (Phase 1) and `EbpfLoader` (Phase 2) are interchangeable implementations of the same interface. The `RawEvent` schema is the contract between them. Everything downstream — enricher, signer, sender, local alerts, gRPC transport, disk buffer, proto schema, guardian.yaml format, and all 63 tests — is identical in both phases.

When Phase 2 ships: change `agent/loader.py` to implement `load()` and `stream()` with BCC. Everything else continues working unchanged.

---

## Related Documents

- [What Is eBPF](what-is-ebpf.md)
- [Guardian Probe Architecture](probe-architecture.md)
- [Phase 1: Python Agent](../07-phases/phase1-python-agent.md)
- [Phase 2: Real eBPF](../07-phases/phase2-real-ebpf.md)
- [BCC vs libbpf vs Aya](bcc-vs-libbpf-vs-aya.md)
- [Migration Guide](../07-phases/migration-guide.md)
- [EbpfLoader Component](../05-components/loader.md)
