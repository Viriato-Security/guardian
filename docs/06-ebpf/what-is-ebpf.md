# What Is eBPF?

> A primer on extended Berkeley Packet Filter — what it is, how it works, and why it is relevant to Guardian.

eBPF (extended Berkeley Packet Filter) is a technology that allows programs to run sandboxed inside the Linux kernel without changing kernel source code or loading kernel modules. It is the foundation of Guardian's observability approach, enabling the agent to observe every syscall made by AI workloads with near-zero overhead and no instrumentation required in the application itself.

---

## Overview

eBPF has become one of the most important technologies in modern Linux systems engineering. What began as a simple mechanism for filtering network packets in the early 1990s has evolved into a general-purpose programmable kernel interface used by major observability, security, and networking tools including Cilium, Falco, Pixie, and Meta's production infrastructure monitoring.

For Guardian, eBPF provides three things that no other approach can simultaneously deliver: complete visibility (every syscall, including those from third-party code), negligible overhead (JIT-compiled programs running in kernel context with no context switches per event), and safety guarantees (the kernel verifier rejects any program that could crash the system before it ever runs).

Understanding eBPF well enough to reason about what Guardian can and cannot observe is important for users, operators, and contributors. This document provides that foundation.

---

## History: From BPF to eBPF

### 1992 — Berkeley Packet Filter

BPF was introduced in a 1992 USENIX paper by Steven McCanne and Van Jacobson at Lawrence Berkeley National Laboratory. The goal was straightforward: allow `tcpdump` to filter network packets efficiently inside the kernel. Before BPF, every packet on a network interface was copied to userspace before filtering could occur. BPF inverted this: a small filter program ran inside the kernel, and only matching packets were copied to userspace.

The original BPF was a minimal virtual machine with two registers (an accumulator and an index register), a small instruction set (load, store, arithmetic, branches), and read-only access to packet memory. Programs were statically verified before loading to ensure they always terminated and never accessed invalid memory.

The performance improvement over userspace filtering was dramatic. For high-traffic interfaces, BPF reduced CPU usage by orders of magnitude. Tools like `tcpdump`, `libpcap`, and Wireshark rely on BPF to this day.

### 2014 — Extended BPF (Linux 3.18)

Alexei Starovoitov at Facebook rewrote BPF for Linux 3.18, submitted in 2014. The result — retroactively called "classic BPF" for the original and "eBPF" or simply "BPF" for the extended version — was an entirely different technology that happened to share the same name:

- **11 64-bit registers** instead of 2, matching the x86-64 calling convention and enabling efficient JIT compilation
- **A 512-byte stack** per program invocation for local variables
- **Maps**: persistent kernel data structures (hash maps, arrays, ring buffers) that survive across program invocations and are accessible from both BPF programs and userspace
- **Helper functions**: a stable, versioned API for calling kernel services from BPF code without accessing kernel internals directly
- **A richer instruction set** including function calls, BPF-to-BPF calls, and tail calls
- **JIT compilation** to native machine code on x86-64, arm64, s390x, MIPS, and other architectures
- **Expanded attachment points** far beyond networking: tracepoints, kprobes, uprobes, and more

The extended BPF was so different from the original that it effectively created a new platform for kernel-level programmability while maintaining the safety invariants of the original design.

### 2016–Present — Modern eBPF and Linux 5.x

From Linux 4.1 onward, eBPF gained attachment points throughout the kernel. The ecosystem grew rapidly:

- **Linux 4.7** (2016): Tracepoints — stable, versioned kernel instrumentation points. Guardian's tracepoints (`sys_enter_read`, `sys_enter_openat`, `sys_enter_execve`) use this.
- **Linux 4.9** (2016): Hardware performance counters accessible from BPF.
- **Linux 5.2** (2019): BTF (BPF Type Format) — embedded kernel type information that enables CO-RE.
- **Linux 5.8** (2020): `BPF_MAP_TYPE_RINGBUF` — the ring buffer map type Guardian uses for zero-copy event delivery.
- **Linux 5.13** (2021): `CAP_BPF` — a dedicated capability for loading BPF programs, replacing the coarser `CAP_SYS_ADMIN`.

Today, eBPF is the foundation of major production infrastructure at companies including Meta, Google, Cloudflare, Netflix, and Microsoft. Kubernetes networking via Cilium, security monitoring via Falco, and CPU profiling via Parca all run on eBPF.

---

## How eBPF Programs Run

eBPF programs go through a well-defined lifecycle: write, compile, load+verify, JIT compile, and attach. Understanding this lifecycle explains both the capabilities and the constraints of eBPF programs.

### Step 1: Write

You write a BPF program in restricted C (or Rust with the Aya framework). The restrictions are significant: no arbitrary function calls, no unbounded loops, no global mutable state outside of maps, no dynamic memory allocation. BPF helper functions provide a stable API for interacting with the kernel: `bpf_get_current_pid_tgid()`, `bpf_ktime_get_real_ns()`, `bpf_map_lookup_elem()`, `bpf_ringbuf_reserve()`, and so on.

Programs use `SEC()` annotations to declare their type and attachment point:

```c
SEC("tracepoint/syscalls/sys_enter_read")
int handle_read(struct trace_event_raw_sys_enter *ctx) {
    // program body
    return 0;
}
```

The `SEC()` macro places the function in a named ELF section. When the loader loads the BPF object, it uses the section name to determine where to attach the program.

### Step 2: Compile to BPF Bytecode

You compile using clang with `-target bpf`:

```bash
clang -O2 -g -target bpf -c program.bpf.c -o program.bpf.o
```

The output is an ELF file containing BPF bytecode — a portable intermediate representation, not native machine code for any specific CPU. The `-g` flag embeds BTF (type information) in the object file, enabling CO-RE.

### Step 3: Load and Verify

When the BPF object is loaded via the `bpf()` syscall, the kernel's **BPF verifier** performs static analysis on the bytecode. This is the most important step in the lifecycle: it is what makes eBPF safe. The verifier checks:

- **Termination**: Every possible path through the program must terminate. The verifier traces all branches; back edges (which would create loops) are rejected unless they can be proven to terminate (Linux 5.3+ added bounded loops).
- **Memory safety**: All memory accesses are bounds-checked. Reading from a map value pointer requires a null check first. The verifier tracks pointer types and rejects type confusion.
- **Stack bounds**: Stack usage must not exceed 512 bytes across all paths.
- **Initialisation**: Memory passed to helper functions must be initialised. Uninitialized stack reads are rejected.
- **Helper function arguments**: Every argument to every helper function is type-checked and range-checked.
- **Complexity limit**: Programs with more than 1 million verified instructions are rejected to prevent DoS via complex verification.

If the verifier rejects a program, the `bpf()` syscall returns `-EACCES` with a detailed diagnostic log that identifies the offending instruction and the reason.

### Step 4: JIT Compilation

After verification, the BPF bytecode is JIT-compiled to native machine code for the host architecture. On x86-64, each BPF instruction typically maps to 1–3 native instructions. The compiled code is placed in kernel memory marked executable.

JIT compilation means eBPF programs run at near-native speed. There is no interpretation overhead per instruction at runtime.

### Step 5: Attachment

The compiled program is attached to an event source. For tracepoints, attachment means: every time the kernel fires that tracepoint, execute this BPF program synchronously in the calling process's context (interrupts disabled, no sleeping allowed).

Attachment is managed through a file descriptor held in userspace. When the userspace process exits, the program is automatically detached. This prevents orphaned BPF programs from accumulating in the kernel.

---

## Program Types

eBPF supports many program types, each with different capabilities, attachment points, and context structures:

**`BPF_PROG_TYPE_TRACEPOINT`** — Attaches to stable kernel tracepoints defined in `/sys/kernel/debug/tracing/events/`. These are stable across kernel versions (unlike kprobes, which attach to specific kernel function addresses that may change). Guardian Phase 2 uses tracepoints at `tracepoint/syscalls/sys_enter_read`, `sys_enter_openat`, and `sys_enter_execve`.

**`BPF_PROG_TYPE_KPROBE`** — Attaches to the entry or return of any kernel function. More powerful than tracepoints (any function is hookable) but less stable (kernel function signatures can change between versions). Used by tools like `bpftrace` and custom deep-dive debugging.

**`BPF_PROG_TYPE_XDP`** — Attaches at the earliest point in the network receive path, in the network driver, before the kernel's network stack processes the packet. Used by Cloudflare and Meta for high-performance packet processing (DDoS mitigation, load balancing).

**`BPF_PROG_TYPE_SOCKET_FILTER`** — The original BPF program type. Attaches to a socket and filters incoming packets. Still used by `libpcap` for packet capture.

**`BPF_PROG_TYPE_LSM`** — Attaches to Linux Security Module hooks. Used by security tools to enforce mandatory access control policies programmatically. Can return a deny decision to block the operation.

**`BPF_PROG_TYPE_CGROUP_SKB`** — Attaches to cgroup network hooks. Used by Cilium for per-container network policy enforcement in Kubernetes.

**`BPF_PROG_TYPE_PERF_EVENT`** — Attaches to hardware performance events (CPU cycles, cache misses, branch mispredictions) or software perf events. Used by profilers like Parca and Pixie.

---

## Maps: Kernel-Userspace Communication

BPF maps are kernel data structures that persist across program invocations. They are the primary mechanism for:

1. **BPF → userspace communication**: The BPF program writes events to a map; userspace reads them.
2. **Userspace → BPF communication**: Userspace writes configuration to a map; the BPF program reads it.
3. **BPF → BPF shared state**: Multiple BPF programs can share a map.

Maps are created by userspace before loading the BPF program. They are referenced by file descriptor in userspace and by name (resolved to a file descriptor at load time via the BPF object's ELF sections) in BPF programs.

**`BPF_MAP_TYPE_HASH`** — A hash map with O(1) average lookup, insert, and delete. Guardian uses this for `watched_pids`: the key is a `__u32` process ID; the value is a `__u8` sentinel (1 = present). Userspace writes the PIDs to monitor; the BPF program looks up each event's PID to decide whether to emit it. Maximum 1,024 entries.

**`BPF_MAP_TYPE_ARRAY`** — A fixed-size array indexed by integer. O(1) access. Used when the key space is small and dense (e.g., per-CPU counters).

**`BPF_MAP_TYPE_RINGBUF`** — The ring buffer, introduced in Linux 5.8. The BPF program reserves a slot, fills it in-place, and submits. Userspace reads via `epoll` or polling. Guardian's primary output channel: the `events` map with 256KB capacity. Zero-copy from kernel to userspace.

**`BPF_MAP_TYPE_PERF_EVENT_ARRAY`** — The predecessor to `RINGBUF`. Works via perf events. Higher overhead, more complex userspace API. Still widely used in older tools. Guardian uses `RINGBUF`, not `PERF_EVENT_ARRAY`.

**`BPF_MAP_TYPE_LRU_HASH`** — Like `HASH` but evicts the least-recently-used entry when full, instead of returning an error. Useful for caches.

**`BPF_MAP_TYPE_PERCPU_HASH`** — A per-CPU hash map. No lock contention between CPUs. Used for high-frequency counters.

---

## The Ring Buffer in Detail

`BPF_MAP_TYPE_RINGBUF` (Linux 5.8+) is designed specifically for high-frequency event streams from BPF to userspace. Guardian's `events` map is defined as:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB capacity
} events SEC(".maps");
```

Key properties of the ring buffer:

**Reserve-Fill-Submit protocol**: The BPF program calls `bpf_ringbuf_reserve(&events, sizeof(struct guardian_event), 0)` to atomically claim a slot. The returned pointer points directly into the ring buffer's shared memory. The program fills the struct fields in-place, then calls `bpf_ringbuf_submit(e, 0)` to make the slot visible to userspace. If reserve fails (buffer full), the program calls `bpf_ringbuf_discard()` and the event is dropped with zero overhead.

**Zero-copy delivery**: The ring buffer is backed by memory-mapped memory. Userspace reads a pointer into the same memory region. No data copy occurs during delivery. This is the key performance advantage over `PERF_EVENT_ARRAY`, which copies data twice.

**Single-producer, single-consumer**: The BPF program (producer) and the userspace drain loop (consumer) share the ring buffer with a lock-free protocol. Multiple BPF programs can share one ring buffer using the `BPF_RB_NO_WAKEUP` and `BPF_RB_FORCE_WAKEUP` flags.

**Power-of-two size requirement**: The ring buffer size must be a power-of-two multiple of the system page size (4KB on most systems). Guardian's 256KB = 64 × 4KB satisfies this constraint.

**Why not perf event array?**: The `PERF_EVENT_ARRAY` requires a separate file descriptor per CPU, separate mmap per CPU, separate drain loop per CPU, and copies data twice. The ring buffer simplifies all of this with a single map and single drain loop.

---

## BTF: BPF Type Format

BTF (BPF Type Format) is a compact binary metadata format that describes types (structs, unions, enums, typedefs, functions). It is embedded in:

1. **The kernel itself**: Available at `/sys/kernel/btf/vmlinux` (Linux 5.2+). Contains type information for every struct in the kernel.
2. **BPF object files**: Emitted by clang when compiled with `-g`. Contains type information for the BPF program's types and maps.

BTF enables **CO-RE (Compile Once, Run Everywhere)**. Without CO-RE, a BPF program hardcodes the byte offset of every struct field it reads. Since kernel struct layouts differ between kernel versions, the compiled BPF object only works on the exact kernel it was compiled for (or one with an identical struct layout). This is why BCC must compile on the target: it reads `/proc/kallsyms` and regenerates offsets for the running kernel.

With CO-RE, instead of hardcoding an offset, the BPF program uses a relocation record: "I want the field `pid` from type `task_struct`". At load time, libbpf resolves the offset from the running kernel's BTF data in `/sys/kernel/btf/vmlinux`. The same compiled `.bpf.o` works on Linux 5.8, 5.15, 6.1, and any future version, as long as the field exists.

Guardian Phase 3 (Rust/Aya) uses CO-RE: compile once on a developer machine, run on any Linux 5.8+ kernel. Guardian Phase 2 (Python/BCC) does not use CO-RE: it compiles on the target at load time.

To generate `vmlinux.h` (the C header version of the kernel's BTF data, used in Phase 2/3 probe compilation):

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > probe/vmlinux.h
```

`EbpfLoader.is_available()` checks for the existence of `/sys/kernel/btf/vmlinux` as a prerequisite for Phase 2 loading.

---

## Safety Guarantees

The BPF verifier provides the following safety guarantees. These are hard guarantees enforced before any BPF code runs, not soft recommendations:

**No kernel panics**: A buggy BPF program is rejected at load time, never at runtime. The verifier's static analysis ensures that every possible execution path is safe. An `oops` or kernel panic from a BPF program is a verifier bug (extremely rare, patched promptly when found).

**Memory isolation**: BPF programs access kernel memory only through approved mechanisms: map lookups, helper functions, and CO-RE reads via `BPF_CORE_READ()`. Arbitrary kernel pointer arithmetic is rejected. Reading from an untrusted pointer without a null check is rejected.

**No blocking or sleeping**: BPF programs attached to tracepoints run in atomic context. They cannot sleep, acquire locks (beyond spinlocks), or perform I/O. This ensures that a BPF program cannot stall a CPU.

**Bounded resource usage**: Stack is limited to 512 bytes. Map sizes are declared at creation with an upper bound. Program complexity is bounded by the 1-million-instruction limit on the verifier.

**Privilege control**: Loading BPF programs requires `CAP_BPF` (Linux 5.8+) or `CAP_SYS_ADMIN`. Unprivileged BPF is possible with significant restrictions (no tracepoints, no kprobes, limited map types). Guardian requires elevated privilege for Phase 2 and Phase 3.

---

## Performance

eBPF programs are JIT-compiled to native code and run in kernel context. For tracepoint programs specifically:

**Overhead per syscall**: Typically 200–500 nanoseconds per syscall event (including map lookup, struct fill, ring buffer reserve, and submit). This translates to 1–3% CPU overhead at 100,000 syscalls/second — a high-throughput AI inference workload.

**No context switch**: eBPF runs in the kernel. There is no userspace/kernel boundary crossing per event. The ring buffer drain in userspace is triggered by `epoll`, adding minimal overhead.

**Comparison to alternatives**:
- `ptrace` (strace): Two context switches per syscall (stop traced process → tracer wakes → inspects registers → resumes). 10–100x slower than eBPF for the same syscall stream. Unacceptable for production monitoring.
- `auditd`: Kernel to userspace copy via a separate audit netlink socket. Lock contention at high event rates. No zero-copy.
- LD_PRELOAD: Zero kernel overhead but misses direct syscalls, statically linked binaries, and vDSO-based syscalls.

eBPF achieves observability that is simultaneously complete (all syscalls, all processes) and production-safe (1–3% overhead).

---

## eBPF vs Kernel Modules

A natural question when first learning about eBPF: why not write a kernel module?

| Property | Kernel Module | eBPF |
|----------|--------------|------|
| Safety | Can crash the kernel — no verifier | Verifier prevents crashes before load |
| Deployment | Requires matching kernel headers and build tools on target | CO-RE: one compiled binary for all 5.8+ kernels |
| Privilege | Requires `CAP_SYS_MODULE` — very high privilege | `CAP_BPF` — scoped privilege |
| Stability | Breaks on every major kernel version | Stable helper function API |
| Hot reload | Requires `rmmod` + `insmod` — disrupts state | Atomic file descriptor swap |
| Distribution | Signed kernel modules required on secure boot | BPF programs verified in userspace |
| Debugging | Difficult — `printk` only, no userspace debugger | `bpf_trace_printk()`, `bpftool`, rich tooling |

For observability workloads like Guardian, eBPF is strictly superior to kernel modules in every dimension that matters for production: safety, portability, and debuggability.

---

## Summary

eBPF is a Linux kernel technology that enables safe, efficient, programmable instrumentation without kernel modification. It evolved from the 1992 BPF packet filter into a general-purpose kernel programmability platform. Guardian uses eBPF in Phase 2 and Phase 3 to observe AI process syscalls via tracepoints, communicate events to userspace via the ring buffer, and control which processes are monitored via the `watched_pids` hash map.

The key facts for Guardian specifically:

- Ring buffer (`BPF_MAP_TYPE_RINGBUF`): 256KB capacity, zero-copy, Linux 5.8+ required
- `watched_pids` hash map: `BPF_MAP_TYPE_HASH`, 1,024 entries, key `__u32` PID, value `__u8`
- Tracepoints implemented in Phase 2: `sys_enter_read`, `sys_enter_openat`, `sys_enter_execve`
- Reserve-fill-submit pattern: `bpf_ringbuf_reserve()` → fill fields → `bpf_ringbuf_submit()`
- BTF at `/sys/kernel/btf/vmlinux`: prerequisite for Phase 2 loading
- Overhead: 1–3% CPU at 100,000 syscalls/second

---

## Related Documents

- [Why eBPF for AI Observability](why-ebpf-for-ai.md)
- [Guardian Probe Architecture](probe-architecture.md)
- [Phase 1 vs Phase 2](phase1-vs-phase2.md)
- [BCC vs libbpf vs Aya](bcc-vs-libbpf-vs-aya.md)
- [Phase 2: Real eBPF](../07-phases/phase2-real-ebpf.md)
- [Phase 3: Rust Rewrite](../07-phases/phase3-rust-rewrite.md)
