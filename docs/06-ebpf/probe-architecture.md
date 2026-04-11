# eBPF Probe Architecture

> How Guardian's kernel probe is structured — the maps, tracepoints, and data flow between kernel and userspace.

> **Phase note**: The probe is compiled and loaded in Phase 2 and Phase 3. In Phase 1, the Python `FakeEventGenerator` produces events with an identical schema. The probe C code exists in the repository as a Phase 2 stub. All data structures documented here are exact — they define the schema contract between the kernel and the entire upstream pipeline.

---

## Overview

The Guardian kernel probe consists of two files that together define everything the kernel-side observer does:

```
probe/
  guardian.h        # Shared header: constants and struct guardian_event
  guardian.bpf.c    # BPF program: map definitions, tracepoint handlers
```

The design follows a deliberate minimalism principle: the kernel probe does as little as possible. It captures raw syscall arguments, fills a fixed-size struct, and submits it to a ring buffer. All enrichment (model name, container ID, pod name), all correlation (prev_hash, this_hash, agent_id), and all path resolution for read/write file descriptors happen in userspace. This keeps the BPF verifier happy (less code = simpler verification) and keeps the kernel-side complexity minimal.

The probe is pure C for the BPF target. It does not include Python, Go, or Rust. It is compiled with `clang`, not `gcc`, because only clang supports `-target bpf` and BPF-specific intrinsics.

---

## guardian.h: The Shared Header

`guardian.h` is the contract between the kernel-side BPF program and the userspace loader. It is included by `guardian.bpf.c` and will be used by the Phase 2 Python loader (via BCC's auto-generated ctypes bindings) and the Phase 3 Rust loader (via Aya's shared types crate).

Every field and every constant in `guardian.h` is a constraint on the downstream pipeline: the Python `RawEvent` dataclass field names, the `proto/guardian.proto` field definitions, and the enricher's struct handling all depend on this header being stable.

### Constants

```c
#define GUARDIAN_PROCESS_LEN   16    // task_comm length (kernel comm max)
#define GUARDIAN_FD_PATH_LEN  256    // resolved file path
#define GUARDIAN_NETADDR_LEN   64    // "IP:port" string
```

**`GUARDIAN_PROCESS_LEN = 16`**: The Linux kernel limits `task->comm` (the process name field in `task_struct`) to exactly 16 bytes, including the null terminator. The BPF helper `bpf_get_current_comm(buf, size)` writes at most `size` bytes. Setting `GUARDIAN_PROCESS_LEN` to 16 matches the kernel's internal limit exactly — no process name can be longer than 15 visible characters. Setting it larger wastes ring buffer space on zero bytes. Setting it smaller truncates process names.

The 15-character limit is a known Linux constraint. Process names longer than 15 characters are silently truncated by the kernel itself (e.g., `python3.12.0-dev` becomes `python3.12.0-de`). The `Enricher` in userspace resolves the full process name from `/proc/PID/cmdline` when needed for model_name mapping.

**`GUARDIAN_FD_PATH_LEN = 256`**: File paths are resolved in userspace (not the BPF program) for read/write syscalls, and read directly from the syscall argument for `openat` and `execve`. 256 bytes covers the vast majority of paths relevant to AI workloads: model weight paths like `/var/lib/models/patient-diagnosis-v2/weights/model.safetensors` (64 characters), Python library paths like `/usr/local/lib/python3.12/site-packages/torch/nn/modules/linear.py` (70 characters), and temporary paths like `/tmp/torch_cache/20240410_143022_model_cache_shard_0001.bin` (57 characters).

Linux `PATH_MAX` is 4096 bytes. Using 4096 per event would increase the per-event struct size from ~376 bytes to ~4216 bytes, reducing ring buffer capacity from ~680 events to ~60 events at 256KB. 256 bytes is the engineering compromise that covers real AI workload paths without wasting ring buffer capacity.

**`GUARDIAN_NETADDR_LEN = 64`**: Network addresses are formatted as `"IP:port"` strings. The longest possible IPv6 address with port is `[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:65535` = 47 characters. 64 provides comfortable margin for any valid address format.

### struct guardian_event

The event struct is the atomic unit of data that flows from kernel to userspace through the ring buffer. Its total size determines how many events fit in the 256KB ring buffer simultaneously.

```c
struct guardian_event {
    __u64  timestamp_ns;                        // ktime_get_real_ns() at syscall entry
    __u32  pid;                                 // tgid (userspace PID)
    __u32  uid;                                 // effective UID
    __s32  syscall_nr;                          // syscall number from pt_regs
    __s32  fd;                                  // file descriptor (-1 if N/A)
    __s64  bytes;                               // bytes requested (count argument)
    __s64  return_val;                          // syscall return value (0 at sys_enter)
    char   process[GUARDIAN_PROCESS_LEN];       // task_comm, NUL-terminated (16 bytes)
    char   fd_path[GUARDIAN_FD_PATH_LEN];       // resolved path for file syscalls (256 bytes)
    char   network_addr[GUARDIAN_NETADDR_LEN];  // "IP:port" for network syscalls (64 bytes)
};
```

**Size calculation**: 8 + 4 + 4 + 4 + 4 + 8 + 8 + 16 + 256 + 64 = **376 bytes** per event. With 8 bytes of ring buffer overhead per slot, each event occupies ~384 bytes. The 256KB ring buffer holds approximately 682 events simultaneously — more than 3 full batches at the default 100ms batch interval.

**Field-by-field notes:**

`timestamp_ns`: Written by `bpf_ktime_get_real_ns()`, which returns nanoseconds since the Unix epoch (equivalent to `clock_gettime(CLOCK_REALTIME)` in userspace). The Phase 1 `FakeEventGenerator` mirrors this as ISO 8601 with 9-digit nanosecond precision: `"2026-04-10T14:30:22.123456789Z"`. The Phase 2 loader converts via `datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).isoformat()`.

`pid`: Populated as `bpf_get_current_pid_tgid() >> 32`. The right-shift extracts the upper 32 bits, which are the TGID (thread group ID). In Linux, TGID is what userspace calls a "PID" — the identifier shared by all threads in a process. The lower 32 bits (the actual kernel thread ID) would differ between threads of the same process and is not useful for AI workload monitoring.

`uid`: Populated as `bpf_get_current_uid_gid() & 0xFFFFFFFF`. The low 32 bits are the effective UID; the high 32 bits are the effective GID. AI workloads running as non-root users will have a UID > 0. Root processes have UID = 0.

`syscall_nr`: The raw syscall number from the syscall table. On x86-64: `__NR_read` = 0, `__NR_write` = 1, `__NR_openat` = 257, `__NR_execve` = 59, `__NR_clone` = 56, `__NR_connect` = 42, `__NR_sendto` = 44, `__NR_recvfrom` = 45, `__NR_socket` = 41. The Phase 2 loader translates these to human-readable strings via a lookup table.

`fd`: The file descriptor argument. For `read(fd, buf, count)`, this is `fd`. For `openat(dirfd, pathname, flags)`, this is `dirfd` (usually `AT_FDCWD` = -100). For syscalls with no fd argument, set to -1.

`bytes`: For `read` and `write`, this is the `count` argument (bytes requested), not the actual bytes transferred. Actual bytes transferred come from the return value, which requires a `sys_exit` tracepoint (Phase 2 TODO). For `sendto` and `recvfrom`, this is the `len` argument.

`return_val`: Set to 0 at `sys_enter` time. The Phase 2 implementation will add `sys_exit` tracepoints to fill this field with the actual return value — the number of bytes transferred for read/write, the new socket fd for socket(), or a negative errno for failures.

`process`: Written by `bpf_get_current_comm(e->process, sizeof(e->process))`. Contains the process's `comm` string — typically the executable name (e.g., `"python3"`, `"python"`, `"gunicorn"`). Used by the Phase 2 `EbpfLoader` to match against the `watched_pids` map (which was populated by looking up these comm strings in `/proc`).

`fd_path`: For `openat` and `execve`, filled by `bpf_probe_read_user_str(e->fd_path, sizeof(e->fd_path), filename_ptr)` where `filename_ptr` is `ctx->args[1]` for `openat` and `ctx->args[0]` for `execve`. For `read` and `write`, left empty in the BPF program — resolved in userspace via `/proc/<pid>/fd/<fd>` readlink (Phase 2).

`network_addr`: Filled for `connect`, `sendto`, and `recvfrom` by reading the `struct sockaddr` argument via `bpf_probe_read_user()` and formatting as `"IP:port"`. IPv4: `inet_ntop()` equivalent in BPF. IPv6: bracket notation. Left empty for non-network syscalls.

**Agent-layer fields not in this struct**: `agent_id`, `model_name`, `container_id`, `pod_name`, `namespace`, `prev_hash`, and `this_hash` are NOT in `guardian_event`. They are added by `enricher.py` (for the first four) and `signer.py` (for the hash fields) in userspace after reading from the ring buffer. The kernel probe stays minimal — it knows nothing about models, containers, or cryptography.

---

## guardian.bpf.c: Program Structure

The BPF program includes these headers in order:

```c
#include "vmlinux.h"          // BTF-derived kernel type definitions (auto-generated)
#include <bpf/bpf_helpers.h>  // BPF helper functions (bpf_get_current_pid_tgid, etc.)
#include <bpf/bpf_tracing.h>  // Tracepoint macros (SEC, PT_REGS_*)
#include <bpf/bpf_core_read.h>// CO-RE read macros (BPF_CORE_READ)
#include "guardian.h"          // Guardian constants and guardian_event struct
```

`vmlinux.h` is generated from the running kernel's BTF data:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > probe/vmlinux.h
```

It replaces the traditional kernel headers (`linux/sched.h`, `linux/fs.h`, etc.) with a single auto-generated file that contains all kernel type definitions correctly offset for the specific kernel that generated it. When used with CO-RE macros, the compiled BPF object works across kernel versions.

`vmlinux.h` is not committed to the repository — it is kernel-specific and must be generated on the target system. The `.gitignore` excludes it.

---

## The Ring Buffer Map

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB = 262,144 bytes
} events SEC(".maps");
```

**Why 256KB?** The ring buffer must be sized to absorb burst syscall traffic without dropping events during the gap between userspace drain calls. The calculation:

- Each `guardian_event` occupies ~384 bytes in the ring buffer (376 bytes data + 8 bytes overhead).
- 262,144 / 384 ≈ 682 events fit simultaneously.
- At the maximum Phase 1 simulation rate of 2,000 events/second, a 100ms drain interval produces at most 200 events between drains.
- 682 slots provides more than 3 drain intervals of headroom — sufficient to absorb bursts.
- At Phase 2 real kernel rates (10,000–100,000 syscalls/sec for a real PyTorch inference server), the drain interval may need reduction or the buffer size may need increase. This is a Phase 2 tuning item.

**Power-of-two page-size-multiple requirement**: The ring buffer implementation requires `max_entries` to be a power of two and a multiple of the system page size (4KB). 256 × 1024 = 262,144 = 64 × 4096. This satisfies both constraints.

**Linux 5.8+ required**: `BPF_MAP_TYPE_RINGBUF` was introduced in Linux 5.8. Earlier kernels require `BPF_MAP_TYPE_PERF_EVENT_ARRAY`, which has higher overhead and requires a separate fd and mmap per CPU. Guardian requires Linux 5.8+ specifically because of this map type.

---

## The watched_pids Map

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u32);   // pid (tgid) — userspace process ID
    __type(value, __u8);    // 1 = present (the value is a sentinel)
} watched_pids SEC(".maps");
```

**Purpose**: The BPF program does not emit events for every process on the system — only processes whose PID is present in this map. This is kernel-level filtering: events for unwanted PIDs are dropped before they ever reach the ring buffer or userspace.

Without `watched_pids`, Guardian would generate events for every process on the host — the web server, the SSH daemon, Prometheus, the container runtime, and every other Linux process. Filtering 999 processes to find 1 AI workload in userspace would waste CPU and ring buffer capacity. Filtering at the kernel level via `watched_pids` costs one hash lookup per syscall — approximately 50 nanoseconds.

**How it is populated (Phase 2)**: The userspace agent scans `/proc` for processes matching the configured `watch` list. For each match, it writes the PID to the map using `bpf_map_update_elem()` via the BCC `bpf["watched_pids"]` interface. A background thread re-scans `/proc` every 5 seconds to catch newly started processes.

**max_entries 1024**: Supports up to 1,024 concurrent monitored processes. A typical AI inference server runs a small number of Python worker processes (4–32, matching CPU core count). Even at 32 workers × 32 threads each (max Linux processes for a typical pool), this ceiling is not reached. For very large Kubernetes nodes with many model replicas, Phase 2 tuning may increase this.

**Value type `__u8`**: The value is semantically unused — only key presence matters. Using `__u8` (1 byte) minimises per-entry memory: 1,024 entries × (4-byte key + 1-byte value + BPF hash overhead) ≈ 40KB. An `__u64` value would use 1,024 × (4 + 8) = 12KB more for no benefit.

---

## The is_watched() Helper Function

Every tracepoint handler begins with a PID check:

```c
static __always_inline bool is_watched(void) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *val = bpf_map_lookup_elem(&watched_pids, &pid);
    return val != NULL;
}
```

`__always_inline` is required because BPF programs (before Linux 5.10) could not make non-inlined function calls to helper functions with complex types. Inlining avoids this restriction and is verified by the verifier as if the code were written inline.

`bpf_get_current_pid_tgid()` returns a 64-bit value: upper 32 bits = TGID (userspace PID), lower 32 bits = kernel thread ID. The right-shift extracts the TGID.

`bpf_map_lookup_elem()` performs a hash lookup. If the TGID is in the map, it returns a non-null pointer. If not, it returns NULL. The handler checks `val != NULL` — if False, it returns 0 immediately, dropping the event with minimal overhead.

---

## The Reserve-Fill-Submit Pattern

Every tracepoint handler follows the same three-step atomic protocol:

```c
// Step 1: Reserve a slot in the ring buffer
struct guardian_event *e = bpf_ringbuf_reserve(&events,
                               sizeof(struct guardian_event), 0);
if (!e)
    return 0;  // Buffer full — event dropped silently

// Step 2: Fill the reserved slot in-place
e->timestamp_ns = bpf_ktime_get_real_ns();
e->pid          = bpf_get_current_pid_tgid() >> 32;
e->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
e->syscall_nr   = ctx->id;
e->fd           = (int)ctx->args[0];   // for read
e->bytes        = (long)ctx->args[2];  // for read
e->return_val   = 0;                   // filled by sys_exit (Phase 2 TODO)
bpf_get_current_comm(e->process, sizeof(e->process));
// fd_path and network_addr filled by syscall-specific logic

// Step 3: Submit — makes the slot visible to userspace
bpf_ringbuf_submit(e, 0);
return 0;
```

**Why this pattern is safer than alternatives:**

`bpf_ringbuf_reserve()` atomically claims a slot. The returned pointer `e` points directly into the ring buffer's shared memory. Writing to `e->field` writes directly to that memory — there is no intermediate stack buffer, no copy operation. The BPF verifier sees a single contiguous write to a known, bounded region.

If `reserve()` returns NULL (buffer full), calling `return 0` is the correct response — the kernel's tracepoint infrastructure treats a non-zero return as an error. The event is silently dropped. Phase 2 will add a `drop_counter` map to track accumulated drops and emit them as synthetic events.

`bpf_ringbuf_submit(e, 0)` advances the producer position, making the slot visible to the userspace consumer's `epoll` or `poll` call. The second argument is flags — 0 means wake up any sleeping consumer.

The alternative, `bpf_ringbuf_output()`, copies from a stack buffer to the ring buffer. This requires the data to exist twice — once on the BPF stack (512 byte limit!) and once in the ring buffer. For `guardian_event` (376 bytes), this would consume 74% of the entire BPF stack. The reserve-fill-submit pattern avoids the stack copy entirely.

---

## Implemented Tracepoints

### sys_enter_read

**Attachment**: `tracepoint/syscalls/sys_enter_read`

**Fires at**: Every `read(fd, buf, count)` syscall entry from a watched PID.

**Captured fields**:
- `timestamp_ns`: Current time via `bpf_ktime_get_real_ns()`
- `pid`: TGID from `bpf_get_current_pid_tgid() >> 32`
- `uid`: Effective UID from `bpf_get_current_uid_gid() & 0xFFFFFFFF`
- `syscall_nr`: 0 (x86-64 `__NR_read`)
- `fd`: `ctx->args[0]` — the file descriptor being read
- `bytes`: `ctx->args[2]` — the `count` argument (bytes requested)
- `process`: Current task comm via `bpf_get_current_comm()`

**Not captured by BPF**: `fd_path` for read requires resolving the fd to a path via `/proc/<pid>/fd/<fd>` readlink. This cannot be done efficiently in kernel context and is performed by the Phase 2 userspace loader after receiving the event.

### sys_enter_openat

**Attachment**: `tracepoint/syscalls/sys_enter_openat`

**Fires at**: Every `openat(dirfd, pathname, flags, mode)` syscall entry from a watched PID.

**Captured fields**: Base fields plus:
- `syscall_nr`: 257 (x86-64 `__NR_openat`)
- `fd`: `ctx->args[0]` — the `dirfd` argument (usually `AT_FDCWD` = -100 for relative-to-cwd opens)
- `fd_path`: Read from `ctx->args[1]` (the `pathname` userspace pointer) via `bpf_probe_read_user_str(e->fd_path, sizeof(e->fd_path), pathname_ptr)`. This captures the file path being opened before the syscall executes.

**Why `openat` and not `open`?**: Modern Linux (glibc 2.26+) always uses `openat` with `AT_FDCWD` instead of `open`. The `open` syscall is deprecated on 64-bit systems. Monitoring only `openat` captures all file opens on modern Linux kernels.

### sys_enter_execve

**Attachment**: `tracepoint/syscalls/sys_enter_execve`

**Fires at**: Every `execve(pathname, argv, envp)` syscall entry from a watched PID.

**Captured fields**: Base fields plus:
- `syscall_nr`: 59 (x86-64 `__NR_execve`)
- `fd_path`: Read from `ctx->args[0]` (the binary path) via `bpf_probe_read_user_str()`

**Why `execve` is special**: The `execve` handler is the kernel-side trigger for the `sandbox_escape` local alert. When the Phase 2 `EbpfLoader` receives an `execve` event with `fd_path` matching `/bin/bash`, `/bin/sh`, `/usr/bin/bash`, or `/usr/bin/sh`, the `LocalAlertEngine` fires a `sandbox_escape` alert. This happens synchronously in the `main.py` pipeline loop before the event is signed or batched.

---

## Phase 2 TODO Tracepoints

The following tracepoints are stubbed out in `guardian.bpf.c` with comments indicating Phase 2 implementation:

| Tracepoint | Syscall nr | What it captures | Implementation challenge |
|-----------|-----------|-----------------|------------------------|
| `sys_enter_write` | 1 | `fd`, `bytes` (count argument) | Same as read — fd_path resolved in userspace |
| `sys_enter_connect` | 42 | `fd`, `network_addr` from `struct sockaddr *` | IPv4/IPv6 union, `bpf_probe_read_user()` of `sockaddr` struct |
| `sys_enter_sendto` | 44 | `fd`, `bytes`, `network_addr` | Same as connect, plus bytes (len argument) |
| `sys_enter_recvfrom` | 45 | `fd`, `bytes`, source `network_addr` | Source address in separate `struct sockaddr *` argument |
| `sys_enter_clone` | 56 | `flags` (in `bytes` field) | No path resolution needed — flags are the diagnostic data |
| `sys_enter_socket` | 41 | `domain`, `type` packed into `fd` and `bytes` | Socket type reveals protocol intent |

The network address tracepoints (`connect`, `sendto`, `recvfrom`) require the most careful BPF implementation because they must:
1. Read a userspace pointer (`struct sockaddr *`) without page faults (`bpf_probe_read_user()`)
2. Determine whether it's `struct sockaddr_in` (AF_INET) or `struct sockaddr_in6` (AF_INET6) from the `sa_family` field
3. Extract address bytes and port
4. Format as `"IP:port"` string using BPF string operations (no `sprintf` available)

---

## fd_path Resolution in Userspace

For `read` and `write` syscalls, the BPF program captures `fd` but not the path (the path is not a syscall argument for these calls — only the fd is). The path is resolved in userspace by the Phase 2 agent using the Linux `/proc` filesystem:

```python
import os

def resolve_fd_path(pid: int, fd: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/fd/{fd}")
    except OSError:
        return ""
```

`/proc/<pid>/fd/<fd>` is a symlink created and maintained by the kernel. `os.readlink()` resolves it to the full path of the open file. This works for:
- Regular files: `/var/lib/models/gpt2/model.safetensors`
- Sockets: `socket:[12345]` (where 12345 is the inode number)
- Pipes: `pipe:[67890]`
- Anonymous inodes: `anon_inode:[eventfd]`, `anon_inode:[timerfd]`

This resolution is performed after the event is received from the ring buffer, in the `_translate()` method of `EbpfLoader`. The `pid` and `fd` fields from `guardian_event` are used directly.

**Why not in the BPF program?** The BPF verifier prohibits complex operations (string formatting, directory traversal) in kernel context. `/proc` fd resolution requires traversing the kernel's file descriptor table and VFS path — operations that take microseconds and cannot be done from an interrupt-context BPF program. Userspace resolution adds a few hundred nanoseconds of latency per event, which is acceptable.

---

## Build Requirements and Command

### Requirements

- **Linux 5.8+**: Required for `BPF_MAP_TYPE_RINGBUF`. Guardian's `EbpfLoader.is_available()` checks for `/sys/kernel/btf/vmlinux` as a proxy for this requirement.
- **clang 14+**: BPF target support (`-target bpf`), CO-RE helper macros, and full C11 support.
- **libbpf 1.x**: Headers at `/usr/include/bpf/`. Provides `bpf_helpers.h`, `bpf_tracing.h`, `bpf_core_read.h`.
- **vmlinux.h**: Generated from the target kernel's BTF. Must be regenerated when the kernel changes.

### Generate vmlinux.h

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > probe/vmlinux.h
```

### Build Command

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I/usr/include/bpf -I./probe \
    -c probe/guardian.bpf.c -o probe/guardian.bpf.o
```

**Flag-by-flag explanation:**

`-O2`: Optimization is required. The BPF verifier rejects many unoptimized code patterns — for example, unoptimized code may have reachable code after a return statement, which the verifier treats as dead code paths with potentially uninitialized registers.

`-g`: Embeds BTF type information in the output ELF. Required for CO-RE relocations and for `bpftool` inspection. Without `-g`, the compiled object works but loses CO-RE portability and debuggability.

`-target bpf`: Compile to BPF bytecode instead of native x86-64 machine code.

`-D__TARGET_ARCH_x86`: Enables architecture-specific macros in `vmlinux.h` and `bpf_tracing.h`. Required for x86-64 tracepoint argument access (`ctx->args[N]`). For arm64 targets, use `-D__TARGET_ARCH_arm64`.

`-I/usr/include/bpf`: Adds the libbpf header directory. Provides `bpf_helpers.h`, `bpf_tracing.h`, and `bpf_core_read.h`.

`-I./probe`: Adds the `probe/` directory to the include path. Allows `#include "guardian.h"` and `#include "vmlinux.h"` to resolve correctly.

The output `probe/guardian.bpf.o` is an ELF file containing BPF bytecode and BTF metadata. It is loaded by the Phase 2 Python agent via BCC or by the Phase 3 Rust agent via Aya.

---

## Data Flow: Kernel to Userspace

The complete path from an AI process making a syscall to a signed `guardian_event` arriving at the platform:

```
AI Process (e.g., python3 running PyTorch inference)
  │
  │  read(fd=5, buf, 65536)
  ▼
Linux Kernel: syscall dispatch
  │
  │  Kernel fires: tracepoint/syscalls/sys_enter_read
  ▼
BPF Tracepoint Handler (guardian.bpf.c: handle_read)
  │
  ├─ is_watched(pid)?  →  lookup watched_pids map
  │    └─ No: return 0 immediately (< 50ns overhead, event dropped)
  │    └─ Yes: continue
  │
  ├─ bpf_ringbuf_reserve(&events, sizeof(guardian_event), 0)
  │    └─ Returns NULL if buffer full: return 0, event dropped
  │    └─ Returns *e: pointer into ring buffer shared memory
  │
  ├─ Fill guardian_event fields in-place:
  │    timestamp_ns = bpf_ktime_get_real_ns()
  │    pid          = bpf_get_current_pid_tgid() >> 32
  │    uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF
  │    syscall_nr   = 0  (__NR_read)
  │    fd           = ctx->args[0]
  │    bytes        = ctx->args[2]
  │    bpf_get_current_comm(e->process, 16)
  │    // fd_path: left empty for read (resolved in userspace)
  │
  └─ bpf_ringbuf_submit(e, 0)
       │  (makes slot visible to userspace consumer)
       ▼
events ring buffer (256KB, kernel-owned, mmap'd to userspace)
  │
  │  Phase 2 EbpfLoader.stream():
  │  bpf["events"].open_ring_buffer(callback)
  │  bpf.ring_buffer_poll(timeout=100ms)
  ▼
EbpfLoader._translate(guardian_event) → RawEvent (Python dataclass)
  │  (includes fd_path resolution via /proc/PID/fd/FD)
  ▼
agent/main.py pipeline loop:
  ├─ Enricher.enrich(event)        → adds agent_id, model_name, container_id, pod_name
  ├─ LocalAlertEngine.evaluate(event) → fires sandbox_escape / unexpected_network alerts
  ├─ Signer.sign_event(event)      → adds prev_hash, this_hash
  └─ batch.append(event)
       │  (every 100ms:)
  ├─ Signer.sign_batch(batch)      → HMAC-SHA256 batch signature
  └─ Sender.send_batch(events, sig) → gRPC EventBatch to viriato-platform
```

---

## Summary

The Guardian probe is a two-file design: `guardian.h` defines the shared contract (3 constants, 1 struct, 10 fields), and `guardian.bpf.c` implements the kernel observer (2 maps, 3 implemented tracepoints, 6 planned). The ring buffer provides zero-copy, lock-free event delivery. The `watched_pids` map provides kernel-level PID filtering. The reserve-fill-submit pattern enables atomic, crash-safe event emission. Every downstream component — enricher, signer, sender, platform — depends only on the `guardian_event` schema defined in `guardian.h`.

---

## Related Documents

- [What Is eBPF](what-is-ebpf.md)
- [Why eBPF for AI Observability](why-ebpf-for-ai.md)
- [Phase 1 vs Phase 2](phase1-vs-phase2.md)
- [BCC vs libbpf vs Aya](bcc-vs-libbpf-vs-aya.md)
- [Phase 2: Real eBPF](../07-phases/phase2-real-ebpf.md)
- [Event Schema](../03-data/event-schema.md)
- [EbpfLoader Component](../05-components/loader.md)
