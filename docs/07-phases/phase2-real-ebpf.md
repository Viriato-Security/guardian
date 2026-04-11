# Phase 2 — Real eBPF Probe on Linux

> Specification for Phase 2, which replaces the fake generator with a real kernel eBPF probe.

**Status: PLANNED**

Phase 2 is the first version of Guardian that observes actual AI process behavior at the kernel level. It replaces the single fake component from Phase 1 — the `FakeEventGenerator` — with a real BPF program attached to Linux syscall tracepoints. The event schema, the downstream pipeline, and the gRPC contract are all unchanged.

---

## Overview

Phase 1 validated everything except the event source. Phase 2 validates the event source. The BPF probe (`probe/guardian.bpf.c`) is attached to `sys_enter_read`, `sys_enter_openat`, and `sys_enter_execve`. Real kernel events flow through the ring buffer into the existing Python pipeline. The chain integrity, batch signing, local alerting, gRPC transport, and disk buffer all work identically — they do not know or care that the events are now real.

The key implementation change is `agent/loader.py`. Everything else is unchanged.

Phase 2 requires Linux 5.8+ with BTF, BCC Python bindings, and root or `CAP_BPF` privileges. On macOS, development uses OrbStack to provide a Linux 5.15+ VM.

---

## Prerequisites

### System Requirements

**Linux 5.8+**: Required for `BPF_MAP_TYPE_RINGBUF`. The ring buffer map type was introduced in this kernel version. Earlier kernels would require falling back to `BPF_MAP_TYPE_PERF_EVENT_ARRAY` — a viable fallback but not what the probe currently implements.

**`/sys/kernel/btf/vmlinux` must be present**: This file contains the kernel's BTF type information. Its presence indicates the kernel was compiled with `CONFIG_DEBUG_INFO_BTF=y`. On Ubuntu 22.04+ and Fedora 35+, this is enabled by default. `EbpfLoader.is_available()` checks for this file as a prerequisite.

**`clang 14+`**: Required to compile `probe/guardian.bpf.c` to BPF bytecode. BCC triggers this compilation at load time. Install on Ubuntu: `sudo apt-get install clang-14`.

**`libbpf 1.x` headers**: Required for the BPF helper function signatures used in `guardian.bpf.c`. Install on Ubuntu: `sudo apt-get install libbpf-dev`.

**`bcc` Python package**: BCC provides the Python bindings that Phase 2 uses in `agent/loader.py`. Install: `sudo apt-get install python3-bcc` or `pip install bcc`. The system package is preferred because BCC requires kernel header access.

**Root or `CAP_BPF` + `CAP_SYS_ADMIN`**: Loading BPF programs requires elevated privilege. On Linux 5.8+, `CAP_BPF` is the dedicated capability. In practice, running as root is the simplest path for Phase 2.

### Python Requirements

Python 3.12+ (same as Phase 1). All Phase 1 requirements (`grpcio`, `protobuf`, `PyYAML`) remain. Add `bcc` to the requirements.

### Verifying Prerequisites

```bash
# Check kernel version — must be 5.8+
uname -r

# Check BTF availability
ls -la /sys/kernel/btf/vmlinux

# Check clang version — must be 14+
clang --version

# Check libbpf headers
ls /usr/include/bpf/bpf_helpers.h

# Check BCC Python bindings
python3 -c "import bcc; print('BCC version:', bcc.__version__)"

# Verify EbpfLoader.is_available() returns True
python3 -c "from agent.loader import EbpfLoader; print(EbpfLoader.is_available())"
```

### Development Environment on macOS

On macOS, use OrbStack to provide a Linux VM:

```bash
# Install OrbStack (macOS only)
brew install orbstack

# Create an Ubuntu 22.04 VM
orb create ubuntu:22.04 guardian-dev

# Open a shell in the VM
orb shell guardian-dev

# Inside the VM: install prerequisites
sudo apt-get update
sudo apt-get install -y \
    clang-14 \
    libelf-dev \
    libbpf-dev \
    bpftool \
    python3-bcc \
    python3-pip

# Install Python requirements
pip3 install grpcio protobuf PyYAML
```

OrbStack VMs run Linux 5.15+ with BTF enabled by default. They are faster than Docker Desktop for filesystem-intensive operations and require no HyperKit overhead.

---

## What Changes: agent/loader.py

`agent/loader.py` is the only file with substantive changes in Phase 2. Every other file is unchanged.

### EbpfLoader.is_available()

The Phase 1 stub already implements the correct logic. In Phase 2, it returns True on Linux 5.8+ with BTF and BCC:

```python
@staticmethod
def is_available() -> bool:
    if sys.platform == "darwin":
        return False
    if not os.path.exists("/sys/kernel/btf/vmlinux"):
        return False
    try:
        import bcc  # noqa: F401
    except ImportError:
        return False
    return True
```

This check is fast (filesystem stat + Python import), idempotent, and has no side effects. It is called by `agent/reader.py` at startup to determine the event source.

### EbpfLoader.load()

Phase 2 implementation using BCC:

```python
def load(self) -> None:
    from bcc import BPF
    # BCC compiles guardian.bpf.c using clang at load time (1-5s startup)
    self._bpf = BPF(src_file="probe/guardian.bpf.c")
    # Attach implemented tracepoints
    self._bpf.attach_tracepoint(tp="syscalls:sys_enter_read",   fn_name="handle_read")
    self._bpf.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="handle_openat")
    self._bpf.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="handle_execve")
    # Populate watched_pids map with current PIDs of watched processes
    self._discover_and_update_pids()
    # Start background thread for periodic PID re-discovery
    self._start_pid_discovery_thread()
```

BCC triggers `clang -target bpf` compilation of `guardian.bpf.c` at this point. The 1–5 second compilation latency is acceptable for Phase 2. Phase 3 (Aya) eliminates this by embedding pre-compiled BPF bytecode.

### PID Discovery Algorithm

The `watched_pids` BPF map must be populated with the PIDs of processes to monitor. The discovery algorithm scans `/proc`:

```python
def _discover_and_update_pids(self) -> None:
    watch_comms = {entry.process for entry in self._config.watch}
    new_pids: set[int] = set()

    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            comm_path = f"/proc/{entry.name}/comm"
            comm = open(comm_path).read().strip()
            if comm in watch_comms:
                new_pids.add(int(entry.name))
        except OSError:
            # Process may have exited between scandir and open — ignore
            continue

    # Add new PIDs to the BPF map
    watched_map = self._bpf["watched_pids"]
    for pid in new_pids - self._known_pids:
        watched_map[ctypes.c_uint32(pid)] = ctypes.c_uint8(1)

    # Remove PIDs that no longer exist
    for pid in self._known_pids - new_pids:
        try:
            del watched_map[ctypes.c_uint32(pid)]
        except KeyError:
            pass  # Already removed

    self._known_pids = new_pids
```

This runs at startup and every 5 seconds in a background daemon thread. The 5-second interval means a newly started AI process is monitored within 5 seconds. Events from the first 5 seconds of a new process are missed — acceptable for Phase 2, improvable in Phase 3 via `execve` tracepoint to detect process creation.

**Why `/proc/<pid>/comm`**: The `comm` file contains exactly the `task_comm` string — the same value that `bpf_get_current_comm()` reads in the BPF program. Matching `comm` in userspace ensures the PID filtering is consistent with what the BPF program sees as the process name.

### EbpfLoader.stream()

Phase 2 implementation reading from the ring buffer:

```python
def stream(self) -> Iterator[RawEvent]:
    self._queue: queue.Queue[RawEvent] = queue.Queue(maxsize=10000)

    def callback(cpu: int, data, size: int) -> None:
        # Called by BCC in the ring buffer drain loop
        event = self._bpf["events"].event(data)
        raw = self._translate(event)
        try:
            self._queue.put_nowait(raw)
        except queue.Full:
            logger.warning("Event queue full — dropping event")

    self._bpf["events"].open_ring_buffer(callback)

    while True:
        # Poll the ring buffer — calls callback for each pending event
        self._bpf.ring_buffer_poll(timeout=100)  # 100ms timeout
        # Yield all events accumulated since last poll
        while not self._queue.empty():
            try:
                yield self._queue.get_nowait()
            except queue.Empty:
                break
```

The `ring_buffer_poll(timeout=100)` call blocks for at most 100ms, then returns. Any events available in the ring buffer during that 100ms are delivered via `callback`. The `queue` decouples the BCC callback thread from the generator's caller (the `main.py` pipeline loop).

### Translating guardian_event to RawEvent

The `_translate()` method converts from the C `guardian_event` struct (as BCC presents it via ctypes) to a Python `RawEvent` dataclass:

```python
# Syscall number to name mapping for x86-64
_SYSCALL_NR_TO_NAME: dict[int, str] = {
    0:  "read",
    1:  "write",
    41: "socket",
    42: "connect",
    44: "sendto",
    45: "recvfrom",
    56: "clone",
    59: "execve",
    257: "openat",
}

def _translate(self, ev) -> RawEvent:
    syscall_name = _SYSCALL_NR_TO_NAME.get(ev.syscall_nr, f"syscall_{ev.syscall_nr}")
    fd_path = ev.fd_path.decode("utf-8", errors="replace").rstrip("\x00")

    # For read/write, fd_path is empty from BPF — resolve via /proc
    if not fd_path and ev.syscall_nr in (0, 1):  # read, write
        fd_path = self._resolve_fd_path(ev.pid, ev.fd)

    return RawEvent(
        timestamp=_ns_to_iso(ev.timestamp_ns),
        pid=ev.pid,
        uid=ev.uid,
        process=ev.process.decode("utf-8", errors="replace").rstrip("\x00"),
        syscall=syscall_name,
        fd_path=fd_path,
        bytes=ev.bytes,
        network_addr=ev.network_addr.decode("utf-8", errors="replace").rstrip("\x00"),
        return_val=str(ev.return_val),
    )
```

`_ns_to_iso(ns: int) -> str` converts nanoseconds since epoch to ISO 8601 with microsecond precision:
```python
def _ns_to_iso(ns: int) -> str:
    dt = datetime.fromtimestamp(ns / 1e9, tz=timezone.utc)
    return dt.isoformat(timespec="microseconds")
```

### fd_path Resolution for Read/Write

For `read` and `write` events, the BPF program fills `fd_path` with empty bytes — the path is not available from the syscall arguments. The Phase 2 userspace resolver fills it from `/proc`:

```python
def _resolve_fd_path(self, pid: int, fd: int) -> str:
    if fd < 0:
        return ""
    try:
        return os.readlink(f"/proc/{pid}/fd/{fd}")
    except OSError:
        return ""
```

`os.readlink()` resolves the symlink at `/proc/<pid>/fd/<fd>` to the full path of the open file. For regular files, this is the absolute path. For sockets, it is `socket:[inode]`. For pipes, it is `pipe:[inode]`. For anonymous inodes, it is `anon_inode:[type]`.

### network_addr Resolution

For `connect`, `sendto`, and `recvfrom`, the BPF program reads the `struct sockaddr` argument and formats it as `"IP:port"`. The Phase 2 BPF implementation (in `guardian.bpf.c`):

```c
// For connect: ctx->args[1] is the struct sockaddr *
struct sockaddr_in addr_in;
bpf_probe_read_user(&addr_in, sizeof(addr_in), (void *)ctx->args[1]);
if (addr_in.sin_family == AF_INET) {
    // Format IPv4 address
    __u32 ip = addr_in.sin_addr.s_addr;
    __u16 port = __bpf_ntohs(addr_in.sin_port);
    bpf_snprintf(e->network_addr, sizeof(e->network_addr),
                 "%d.%d.%d.%d:%d",
                 ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, ip >> 24,
                 port);
}
```

---

## What Changes: guardian_bcc.c (New File)

A BCC-compatible variant of the BPF program may be needed if the BCC version on the target does not support all libbpf-style map definition macros. `guardian_bcc.c` uses BCC's alternative macro syntax for map definitions while keeping the same tracepoint logic as `guardian.bpf.c`.

In practice, BCC 0.26+ supports libbpf-style map definitions, so `guardian.bpf.c` can often be loaded directly by BCC. This is a Phase 2 implementation detail to be resolved during development.

---

## What Does NOT Change

Every module except `agent/loader.py` is completely unchanged between Phase 1 and Phase 2. This is not an aspiration — it is the architectural invariant that Phase 1 was designed to enable.

| Module | Phase 2 Status | Reason Unchanged |
|--------|---------------|-----------------|
| `agent/config.py` | Unchanged | Configuration schema has no eBPF-specific keys |
| `agent/enricher.py` | Unchanged | Reads from `RawEvent.process` and `RawEvent.pid` — same fields, same types |
| `agent/signer.py` | Unchanged | Hashes `RawEvent` fields — field names and types are identical |
| `agent/sender.py` | Unchanged | Serialises `RawEvent` to proto — proto is unchanged |
| `agent/main.py` | Unchanged | Iterates `reader.stream()` — stream interface is identical |
| `agent/reader.py` | Unchanged | Already has the Phase 2 code path (`EbpfLoader.is_available()`) |
| `agent/generator.py` | Unchanged | Still used for `--fake` and CI |
| `agent/local_alerts.py` | Unchanged | Alert rules evaluate `RawEvent.syscall` and `RawEvent.fd_path` |
| `proto/guardian.proto` | Unchanged | Wire format is the invariant schema contract |
| `guardian.yaml` schema | Unchanged | No new configuration needed for real eBPF |
| All 63 existing tests | Still pass | Schema contract is maintained |

---

## OrbStack Development Workflow

The recommended development workflow splits work between macOS (code editing, unit tests) and an OrbStack VM (Phase 2 eBPF testing):

**On macOS (no root, no Linux required):**
```bash
cd /Users/radeshgovind/Viriato-Security/guardian

# Run all 63 existing tests — fast, no root needed
pytest tests/ -v

# Edit agent code, run linters
ruff check agent/
mypy agent/
```

**In OrbStack VM (Linux + root, for Phase 2 testing):**
```bash
# Open VM shell
orb shell guardian-dev

# The guardian repo is accessible via OrbStack's shared filesystem
cd /Users/radeshgovind/Viriato-Security/guardian  # same path via OrbStack mount

# Generate vmlinux.h for the VM's kernel
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > probe/vmlinux.h

# Build the BPF probe (verifies it compiles)
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I/usr/include/bpf -I./probe \
    -c probe/guardian.bpf.c -o probe/guardian.bpf.o

# Verify EbpfLoader.is_available() returns True
python3 -c "from agent.loader import EbpfLoader; print(EbpfLoader.is_available())"
# Expected: True

# Run the full agent with real eBPF
sudo python3 -m agent.main --config guardian.yaml --log-level DEBUG

# Run existing tests (still pass)
sudo pytest tests/ -v

# Run Phase 2 integration tests (new)
sudo pytest tests/integration/ -v
```

**Development cycle**: Edit Python code on macOS (fast feedback from unit tests). Test eBPF-specific behavior in the OrbStack VM. The shared filesystem means no `scp` or `rsync` — the same files are used in both environments.

---

## PID Discovery Algorithm in Depth

The PID discovery algorithm is critical for Phase 2 correctness. It must:
1. Find all existing instances of watched processes at startup
2. Detect new instances within a bounded time (5-second interval)
3. Clean up PIDs of processes that have exited
4. Be race-condition safe (processes may exit during the scan)

The implementation uses `os.scandir("/proc")` to enumerate PID directories and reads `/proc/<pid>/comm` for each. The `try/except OSError` block handles the race condition where a process exits between `scandir()` and `open(comm)`.

The 5-second discovery interval is a deliberate trade-off:
- Shorter intervals (1 second): More CPU overhead, more `/proc` reads
- Longer intervals (30 seconds): Longer window of missed events for new processes
- 5 seconds: Standard for process discovery in monitoring agents (matches Prometheus's scrape cycle concept)

---

## Performance Expectations

At typical AI inference workloads running on Linux:

| Metric | Expected Value |
|--------|---------------|
| Real kernel event rate (PyTorch inference) | 10,000–100,000 syscalls/sec per process |
| BPF tracepoint overhead per syscall | ~200–500 nanoseconds |
| CPU overhead at 100,000 syscalls/sec | 1–3% |
| Ring buffer drain interval | 100ms |
| Events per drain cycle | 1,000–10,000 |
| Memory for BPF maps | ~5MB (ring buffer + watched_pids) |
| Memory for Python agent | ~20–25MB (same as Phase 1) |
| PID discovery scan interval | 5 seconds |
| Startup time (BCC compilation) | 3–7 seconds |

The ring buffer at 256KB holds approximately 682 events. At 100,000 syscalls/sec, the userspace drain loop must run at least every 682/100,000 = 6.8ms to avoid drops. The 100ms drain interval is insufficient at this rate — Phase 2 tuning will reduce it to 10ms or use `epoll` for event-driven draining rather than polling.

---

## Testing Strategy for Phase 2

### Existing Tests (All Unchanged)

All 63 Phase 1 tests continue to pass. They test the pipeline, not the event source. Running them in Phase 2 (even under `sudo`) confirms no regressions.

### Phase 2 Unit Tests (New)

`tests/test_loader.py` — Tests `EbpfLoader.is_available()` without loading BPF:
- Mocked `/sys/kernel/btf/vmlinux` present → True on Linux
- Mocked `/sys/kernel/btf/vmlinux` absent → False
- `sys.platform == "darwin"` → False (tested in CI on macOS)
- `bcc` not importable → False

`tests/test_loader_translate.py` — Tests `EbpfLoader._translate()` with synthetic ctypes structs:
- `timestamp_ns` → ISO 8601 conversion accuracy
- `syscall_nr` → syscall name lookup for all known syscalls
- Null-terminated string decoding (e.g., `b"python3\x00\x00\x00..."` → `"python3"`)
- `fd_path` empty for read → triggers `_resolve_fd_path` call (mocked)

### Phase 2 Integration Tests (Linux + root required)

`tests/integration/test_ebpf_loading.py`:
```python
def test_bpf_loads_without_error():
    """Verify guardian.bpf.c loads and attaches without verifier rejection."""
    loader = EbpfLoader(config)
    loader.load()  # Should not raise
    loader.cleanup()
```

`tests/integration/test_real_syscalls.py`:
```python
def test_python_process_read_events_detected():
    """Start a real Python process, verify Guardian detects its read syscalls."""
    # Start a Python subprocess that reads a file repeatedly
    proc = subprocess.Popen(["python3", "-c",
        "while True: open('/etc/hostname').read(); time.sleep(0.01)"])
    loader = EbpfLoader(config_watching_python)
    loader.load()
    events = list(itertools.islice(loader.stream(), 10))
    assert any(e.syscall == "read" and e.pid == proc.pid for e in events)
    proc.terminate()
```

`tests/integration/test_schema_parity.py`:
```python
def test_ebpf_rawevent_schema_matches_fake():
    """Verify EbpfLoader and FakeEventGenerator produce RawEvents with identical fields."""
    fake_event = next(FakeEventGenerator(config).stream())
    real_event = next(EbpfLoader(config).stream())
    assert set(asdict(fake_event).keys()) == set(asdict(real_event).keys())
```

`tests/integration/test_sandbox_escape_real.py`:
```python
def test_real_execve_fires_sandbox_escape_alert():
    """Verify that a real execve to /bin/bash fires the sandbox_escape alert."""
    # This test runs the full pipeline with real eBPF and a real execve
    alerts = []
    engine.set_custom_handler(alerts.append)
    # Trigger a real execve in a watched process...
    assert any(a["alert_type"] == "sandbox_escape" for a in alerts)
```

---

## Rollback to Phase 1

If Phase 2 introduces a regression, rolling back to Phase 1 behavior requires one flag change:

```bash
# Option 1: --fake flag
sudo python3 -m agent.main --config guardian.yaml --fake

# Option 2: environment variable
GUARDIAN_FAKE_EVENTS=1 sudo python3 -m agent.main --config guardian.yaml

# Option 3: systemd override
systemctl edit guardian  # Add: Environment=GUARDIAN_FAKE_EVENTS=1
systemctl restart guardian
```

The `--fake` flag bypasses `EbpfLoader.is_available()` and forces `FakeEventGenerator`. The pending JSONL buffer is preserved across the restart and drained when the agent reconnects to the platform.

---

## Status

Phase 2 is planned for after Phase 1's pipeline design is validated with the first customer deployment. The implementation scope is small: approximately 150 lines of new Python in `agent/loader.py`, plus Phase 2 integration tests and a possible `guardian_bcc.c` variant. The BPF probe (`guardian.bpf.c`) already compiles and is waiting to be loaded.

---

## Summary

Phase 2 replaces `FakeEventGenerator` with a real BPF probe, delivering actual kernel syscall events from watched AI processes. The change is confined to `agent/loader.py`. Every other component — enricher, signer, sender, local alerts, main, proto, config, and all 63 tests — is unchanged. Phase 2 delivers the first production-ready version of Guardian for Linux 5.8+ environments.

---

## Related Documents

- [Phase 1: Python Agent](phase1-python-agent.md)
- [Phase 1 vs Phase 2](../06-ebpf/phase1-vs-phase2.md)
- [Phase 3: Rust Rewrite](phase3-rust-rewrite.md)
- [Guardian Probe Architecture](../06-ebpf/probe-architecture.md)
- [BCC vs libbpf vs Aya](../06-ebpf/bcc-vs-libbpf-vs-aya.md)
- [Migration Guide](migration-guide.md)
- [EbpfLoader Component](../05-components/loader.md)
