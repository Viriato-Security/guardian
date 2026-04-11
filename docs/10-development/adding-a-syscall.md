# Adding a New Syscall

This guide walks through every change needed to add a new syscall to Guardian.
The example syscall is **`mmap`** — used by PyTorch to memory-map model weight files.
Apply the same pattern for any other syscall.

---

## Overview of Changes

| Step | File | What changes |
|------|------|-------------|
| 1 | `guardian.yaml.example` | Add syscall to the `syscalls` list |
| 2 | `agent/generator.py` | Add weight to `_SYSCALL_WEIGHTS` |
| 3 | `agent/generator.py` | Handle field population in `_make_syscall_event()` |
| 4 | `tests/test_generator.py` | Add tests for the new syscall |
| 5 | `probe/guardian_bcc.c` | Add BCC tracepoint stub (Phase 2) |
| 6 | `probe/guardian.bpf.c` | Add libbpf tracepoint (Phase 3) |
| 7 | `agent/local_alerts.py` | Add an alert if needed |

---

## Step 1 — Add to guardian.yaml.example

Open `guardian.yaml.example` and add the syscall to the `syscalls` list.
This list controls which syscalls the fake generator and the eBPF probe pay attention to.

**Before:**

```yaml
syscalls:
  - read
  - write
  - openat
  - sendto
  - recvfrom
  - connect
  - execve
  - clone
  - socket
```

**After:**

```yaml
syscalls:
  - read
  - write
  - openat
  - sendto
  - recvfrom
  - connect
  - execve
  - clone
  - socket
  - mmap
```

Also update your local `guardian.yaml` the same way.

---

## Step 2 — Add Weight to _SYSCALL_WEIGHTS

Open `agent/generator.py`. The `_SYSCALL_WEIGHTS` dict controls how often each
syscall appears in the fake event stream. Higher weight = more frequent.
The existing weights are:

```python
_SYSCALL_WEIGHTS = {
    "read": 35,
    "write": 25,
    "openat": 15,
    "sendto": 7,
    "recvfrom": 6,
    "connect": 5,
    "socket": 4,
    "clone": 3,
}
```

`mmap` is less frequent than reads but present in every model load. Add it with
weight `2`:

```python
_SYSCALL_WEIGHTS = {
    "read": 35,
    "write": 25,
    "openat": 15,
    "sendto": 7,
    "recvfrom": 6,
    "connect": 5,
    "socket": 4,
    "clone": 3,
    "mmap": 2,      # <-- add this line
}
```

Note: `execve` is NOT in this dict. It is injected separately every 500–1000 events
via `_make_execve_event()`, regardless of this weight table.

---

## Step 3 — Handle Field Population in _make_syscall_event()

The `_make_syscall_event()` method in `FakeEventGenerator` decides which fields
to populate on a `RawEvent` based on the syscall type. The rules are:

- File syscalls (`read`, `write`, `openat`): set `fd_path` and `bytes`
- Network syscalls (`sendto`, `recvfrom`, `connect`): set `network_addr` (plus `bytes` for `sendto`/`recvfrom`)
- Other syscalls (`socket`, `clone`): no additional fields

For `mmap`, the kernel maps a file into memory. The relevant fields are:
- `bytes`: the length argument (size of the mapping), random in `[4096, 134217728]` (4 KB to 128 MB)
- `fd_path`: the file being mapped (empty string for anonymous mappings; use a model path for realism)
- `network_addr`: empty (mmap is not a network call)

**Current structure of `_make_syscall_event()` (excerpt):**

```python
def _make_syscall_event(self, syscall: str) -> RawEvent:
    process, pid, uid = self._random_process()
    ev = RawEvent(
        timestamp=_now_iso_ns(),
        pid=pid,
        process=process,
        syscall=syscall,
        return_val="0",
        uid=uid,
    )

    if syscall in ("read", "write", "openat"):
        ev.fd_path = random.choice(_FILE_PATHS)
        ev.bytes = random.randint(512, 65536)

    elif syscall in ("sendto", "recvfrom", "connect"):
        ev.network_addr = random.choice(_ALL_NETWORK_ADDRS)
        if syscall in ("sendto", "recvfrom"):
            ev.bytes = random.randint(64, 4096)

    elif syscall == "socket":
        pass  # no additional fields

    elif syscall == "clone":
        pass  # no additional fields

    ...
    return ev
```

**After adding `mmap`:**

```python
    elif syscall == "socket":
        pass  # no additional fields

    elif syscall == "clone":
        pass  # no additional fields

    elif syscall == "mmap":
        ev.fd_path = random.choice(_FILE_PATHS)          # file being mapped
        ev.bytes = random.randint(4096, 134_217_728)     # 4 KB – 128 MB
        # network_addr stays empty — mmap is not a network call
```

This placement keeps all `elif` branches together and makes it easy to see the
pattern at a glance.

---

## Step 4 — Add Tests in test_generator.py

Add the following test to `tests/test_generator.py`. The pattern follows the
existing tests for other syscalls.

```python
def test_mmap_events_have_fd_path_and_bytes() -> None:
    """mmap events must have a non-empty fd_path and bytes > 0."""
    cfg = _make_config(syscalls=["mmap"])
    gen = FakeEventGenerator(cfg)
    gen._next_execve_in = 10_000   # suppress execve injection
    gen._events_generated = 0
    found = 0
    for _ in range(50):
        e = gen._make_event()
        gen._events_generated += 1
        if e.syscall == "mmap":
            assert e.fd_path, f"Expected non-empty fd_path for mmap, got {e.fd_path!r}"
            assert e.bytes > 0, f"Expected bytes > 0 for mmap, got {e.bytes}"
            assert e.network_addr == "", (
                f"mmap should have empty network_addr, got {e.network_addr!r}"
            )
            found += 1
    assert found > 0, "No mmap events generated in 50 iterations"
```

Also add a test confirming `mmap` appears in a mixed event stream:

```python
def test_mmap_appears_in_mixed_stream() -> None:
    """mmap should appear when included in the syscall list."""
    cfg = _make_config(syscalls=["read", "write", "mmap"])
    gen = FakeEventGenerator(cfg)
    gen._next_execve_in = 10_000
    gen._events_generated = 0
    syscalls_seen: set[str] = set()
    for _ in range(200):
        e = gen._make_event()
        gen._events_generated += 1
        syscalls_seen.add(e.syscall)
    assert "mmap" in syscalls_seen, (
        f"mmap never appeared in 200 events. Seen: {syscalls_seen}"
    )
```

Run the new tests:

```bash
python -m pytest tests/test_generator.py -v -k mmap
```

Both tests must pass before proceeding.

---

## Step 5 — BCC Tracepoint Stub (Phase 2)

Phase 2 uses BCC (BPF Compiler Collection) to attach to kernel tracepoints.
Open `probe/guardian_bcc.c` and add a tracepoint handler for `mmap`.

The `mmap` syscall corresponds to the `sys_enter_mmap` tracepoint. Add:

```c
TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!should_trace(pid)) return 0;

    struct event_t ev = {};
    ev.pid     = pid;
    ev.uid     = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev.syscall = SYSCALL_MMAP;          // add SYSCALL_MMAP to the enum
    ev.bytes   = args->len;             // mmap length argument
    // fd_path: args->fd >= 0 means file-backed; resolve in userspace
    ev.fd      = args->fd;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
```

Add `SYSCALL_MMAP` to the syscall enum and map it to the string `"mmap"` in the
Python-side BCC event handler.

---

## Step 6 — libbpf Tracepoint (Phase 3)

Phase 3 uses libbpf with CO-RE (Compile Once, Run Everywhere). Open
`probe/guardian.bpf.c` and add:

```c
// TODO Phase 3: attach to sys_enter_mmap tracepoint
// SEC("tracepoint/syscalls/sys_enter_mmap")
// int handle_mmap(struct trace_event_raw_sys_enter *ctx) {
//     // read ctx->args[1] (len), ctx->args[4] (fd)
//     // submit to ring buffer
// }
```

Leave it as a comment stub in Phase 1 so the intent is documented. Implement in
the Phase 3 sprint.

---

## Step 7 — Consider If a New Alert Is Needed

Ask yourself: does `mmap` of a specific file path warrant an alert?

For example, if a process `mmap`s `/etc/shadow`, that would be suspicious.
If you want an alert, follow the [adding-an-alert.md](adding-an-alert.md) guide
and create a `_check_sensitive_file_mmap()` method in `LocalAlertEngine`.

For standard model weight file mapping, no alert is needed — that is expected
behaviour for AI inference workloads.

---

## Checklist

- [ ] `guardian.yaml.example` updated
- [ ] `_SYSCALL_WEIGHTS` updated
- [ ] `_make_syscall_event()` updated with correct field logic
- [ ] Tests added and passing
- [ ] BCC stub added (Phase 2) or noted
- [ ] libbpf stub added (Phase 3) or noted
- [ ] Alert considered and documented

---

## Related Documents

- [adding-an-alert.md](adding-an-alert.md)
- [local-setup.md](local-setup.md)
- [contributing.md](contributing.md)
- [../../docs/05-components/generator.md](../05-components/)
