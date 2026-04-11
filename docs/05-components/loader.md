# eBPF Loader (`agent/loader.py`)

## Overview

`agent/loader.py` defines `EbpfLoader`, the Phase 2 stub for the kernel eBPF event source. In Phase 1, this class exists primarily to give `EventReader` a stable interface against which to check platform availability and to structure the work that Phase 2 must deliver.

All methods that would actually interact with the kernel (`load()`, `stream()`, and the implicit `unload()` via garbage collection) raise `NotImplementedError`. The agent handles this gracefully by falling back to `FakeEventGenerator` automatically.

---

## Phase 1 Status

`EbpfLoader` is a **stub**. Its public API surface is complete and will not change in Phase 2, but all kernel interaction is unimplemented. The class raises `NotImplementedError` with a descriptive message on every method call except `is_available()`.

**Why include a stub in Phase 1?**

1. `EventReader` can be written and tested against the final interface without waiting for Phase 2 implementation.
2. `is_available()` is a pure platform check that works today and gives `EventReader` the information it needs to decide which source to use.
3. The stub documents the expected Phase 2 API as executable code that will be validated by the test suite.
4. Operators deploying on qualifying Linux hosts get a clear error message (`"eBPF loader not yet implemented (Phase 2)..."`) rather than an import error or attribute error.

---

## `EbpfLoader` Class

```python
class EbpfLoader:
    """Loads and manages the guardian eBPF probe.

    .. note::
        Phase 2 stub — raises NotImplementedError on all platforms.
    """
```

The class has no `__init__` arguments. Construction is always safe (no side effects).

---

## `is_available()` — Static Method

```python
@staticmethod
def is_available() -> bool:
```

The only method that executes real logic in Phase 1. Returns `True` only if all three eBPF runtime requirements are satisfied simultaneously.

### Requirement 1: Not macOS

```python
if sys.platform == "darwin":
    return False
```

eBPF is a Linux-only technology. macOS uses a different kernel (XNU) and has no `/sys` filesystem. This check short-circuits early on every macOS development machine, routing directly to `FakeEventGenerator` without any I/O.

### Requirement 2: BTF Support Present

```python
if not os.path.exists("/sys/kernel/btf/vmlinux"):
    return False
```

BTF (BPF Type Format) is required for CO-RE (Compile Once, Run Everywhere) eBPF programs that can attach to arbitrary kernel functions without being compiled for a specific kernel version. The file `/sys/kernel/btf/vmlinux` contains the type information for the running kernel and is present only on Linux 5.8 and later with `CONFIG_DEBUG_INFO_BTF=y` (the default in most modern distributions since Ubuntu 20.04 and Debian 11).

On older kernels, containers, or minimal Linux images without BTF, this check returns `False` and the agent falls back to the generator.

### Requirement 3: BCC Importable

```python
try:
    import bcc  # noqa: F401
except ImportError:
    return False
return True
```

BCC (BPF Compiler Collection) provides the Python bindings used to compile and load the eBPF C program (`probe/guardian.bpf.c`). If BCC is not installed, the loader cannot function.

Installation varies by distribution:
- Ubuntu/Debian: `apt install python3-bcc`
- Fedora/RHEL: `dnf install bcc-tools python3-bcc`
- Alpine: `apk add py3-bcc`

BCC has a large dependency footprint (LLVM, kernel headers). For deployment environments where minimising the image size is important, the Phase 2 loader may be refactored to use the lighter `bpf` (pure Python libbpf bindings) or a pre-compiled BPF object file.

### `is_available()` Truth Table

| Platform | `/sys/kernel/btf/vmlinux` | `bcc` importable | Return value |
|---|---|---|---|
| macOS | N/A | N/A | `False` |
| Linux (any), no BTF | `False` | any | `False` |
| Linux 5.8+, BTF, no BCC | `True` | `False` | `False` |
| Linux 5.8+, BTF, BCC installed | `True` | `True` | `True` |

---

## `load()` — Phase 2 Planned

```python
def load(self) -> None:
    raise NotImplementedError(
        "eBPF loader not yet implemented (Phase 2). "
        "Use --fake or set GUARDIAN_FAKE_EVENTS=1 to run with the fake generator."
    )
```

**Phase 1:** Always raises `NotImplementedError`.

**Phase 2 plan:** Compile `probe/guardian.bpf.c` using BCC, attach the compiled program to the kernel tracepoints listed in `config.syscalls`, and open a perf event buffer for event retrieval.

Expected implementation outline for Phase 2:

```python
def load(self) -> None:
    from bcc import BPF
    self._bpf = BPF(src_file="probe/guardian.bpf.c")
    self._bpf.attach_tracepoint(
        tp="syscalls:sys_enter_execve",
        fn_name="trace_execve",
    )
    # ... attach other syscall tracepoints
    self._bpf["events"].open_perf_buffer(self._handle_event)
```

---

## `stream()` — Phase 2 Planned

```python
def stream(self):
    raise NotImplementedError("eBPF stream not yet implemented (Phase 2).")
```

**Phase 1:** Always raises `NotImplementedError`.

**Phase 2 plan:** Poll the BPF perf event buffer in a loop, parse each raw kernel event into a `RawEvent` object (using the same schema as `FakeEventGenerator`), and yield it. The loop also handles perf buffer overflow by logging dropped event counts.

Expected implementation outline for Phase 2:

```python
def stream(self) -> Iterator[RawEvent]:
    while True:
        self._bpf.perf_buffer_poll(timeout=10)
        while self._event_queue:
            yield self._event_queue.popleft()
```

---

## `unload()` — Phase 2 Planned

There is no explicit `unload()` method in the Phase 1 stub. Phase 2 will need to detach tracepoints and close BPF maps on shutdown to avoid kernel resource leaks. This will be implemented as either a `close()` method (matching `Sender`) or as a context manager (`__enter__`/`__exit__`).

Expected Phase 2 cleanup:

```python
def unload(self) -> None:
    if self._bpf is not None:
        self._bpf.cleanup()
        self._bpf = None
```

---

## Why `loader.py` Exists in Phase 1

There are three reasons to include `EbpfLoader` in Phase 1 even though it does nothing:

### 1. Stable `EventReader` interface

`EventReader.stream()` calls `EbpfLoader.is_available()` to decide the event source. If `loader.py` did not exist, `EventReader` would need a conditional import or a try/except block. With the stub, `EventReader` imports `EbpfLoader` unconditionally and `is_available()` returns `False` on non-qualifying platforms — clean and testable.

### 2. Executable API contract

The Phase 2 implementation must provide `load()`, `stream()`, and `is_available()` with exactly the signatures defined in `loader.py`. The existing stub acts as the interface specification. The Phase 1 test suite verifies that `NotImplementedError` is raised on all methods, which will change to testing real behaviour in Phase 2.

### 3. Clear operator messaging

When `is_available()` returns `True` (which can only happen today if an operator has BCC installed on a qualifying Linux host), calling `load()` produces a descriptive error:

```
NotImplementedError: eBPF loader not yet implemented (Phase 2).
Use --fake or set GUARDIAN_FAKE_EVENTS=1 to run with the fake generator.
```

This is far clearer than `AttributeError` or `ImportError` would be.

---

## Phase 2 Timeline and Prerequisites

Phase 2 eBPF implementation requires:

1. `probe/guardian.bpf.c` — the eBPF C program that attaches to kernel tracepoints. The `probe/` directory already exists in the repository.
2. BCC or libbpf Python bindings installed in the deployment environment.
3. A Linux 5.8+ kernel with BTF enabled (standard in Ubuntu 22.04, Debian 12, RHEL 9, Amazon Linux 2023).
4. The `scripts/gen_proto.sh` script is already in place for proto generation; Phase 2 will add a `scripts/build_bpf.sh` for BPF compilation.

---

## Related Documents

- `docs/05-components/reader.md` — `EventReader` calls `is_available()` to select the source
- `docs/05-components/event-generator.md` — the Phase 1 fallback that `EbpfLoader` will replace
- `docs/06-ebpf/` — eBPF program design, tracepoint selection, and perf buffer architecture (Phase 2)
- `docs/07-phases/` — Phase 1 vs Phase 2 feature matrix and delivery plan
