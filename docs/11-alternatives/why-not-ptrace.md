# Why Not ptrace

**Status: DECIDED — not using ptrace. eBPF is the correct tool for production
syscall observation.**

ptrace is the classic Linux interface for intercepting and inspecting process
syscalls. It is how `strace`, `gdb`, and many debuggers work. This document
explains why it is unsuitable for Guardian and what eBPF provides instead.

---

## What ptrace Does

`ptrace(2)` is a Linux system call that allows one process (the tracer) to observe
and control another process (the tracee). Debuggers use it to implement breakpoints,
single-stepping, and memory inspection. Security tools have used it to intercept
syscalls.

The basic loop for syscall tracing:

```c
// Attach to a process
ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);

// Wait for the process to stop
waitpid(target_pid, &status, 0);

// Set it to stop at every syscall entry and exit
ptrace(PTRACE_SYSCALL, target_pid, NULL, NULL);

// The process is now stopped at syscall entry
// Read registers to identify the syscall
struct user_regs_struct regs;
ptrace(PTRACE_GETREGS, target_pid, NULL, &regs);
// rax = syscall number, rdi/rsi/rdx = arguments

// Resume until the next syscall stop
ptrace(PTRACE_SYSCALL, target_pid, NULL, NULL);
```

`strace` is the most familiar user of this interface:

```bash
strace -p <pid>   # shows all syscalls made by <pid>
```

---

## The Performance Problem

The fundamental issue with `PTRACE_SYSCALL` is that it stops the traced process
**twice for every syscall** — once on entry and once on exit:

1. **Syscall entry**: The kernel interrupts the process and switches to the tracer.
2. **Tracer reads event**: The tracer (e.g. Guardian) reads registers, inspects
   arguments, and records the event.
3. **Tracer resumes**: The tracer calls `PTRACE_SYSCALL` again.
4. **Kernel runs the syscall**: The actual `read()` or `write()` executes.
5. **Syscall exit**: The kernel interrupts the process again and switches to the tracer.
6. **Tracer reads return value**: The tracer reads the return value from registers.
7. **Tracer resumes**: The tracer calls `PTRACE_SYSCALL` again.
8. **Process continues**.

That is **two context switches per syscall** (entry + exit), plus the overhead of
the tracer reading register state via additional ptrace calls.

### Quantified overhead

A PyTorch inference workload performing 1,000 syscalls per second with ptrace
overhead:

| Metric | Without ptrace | With ptrace |
|--------|---------------|-------------|
| Context switches per second | baseline | +2,000 |
| Estimated added latency per syscall | ~0 | ~5–50 µs |
| Total added latency at 1,000 syscalls/sec | ~0 ms | ~5–50 ms per second |
| Suitable for production AI inference | Yes | No |

The 10–100x overhead estimate (compared to eBPF) comes from kernel measurements
and is widely cited in operating systems literature. For a production AI serving
deployment where inference latency SLAs are in the 10–200 ms range, adding 5–50 ms
of systematic overhead is not acceptable.

---

## Why strace Uses ptrace: Designed for Debugging, Not Production

`strace` is designed for one-off debugging sessions, not continuous production
monitoring. The typical use pattern is:

```bash
strace -p <pid> -o /tmp/trace.txt   # run for a few seconds, then Ctrl-C
```

The kernel developers explicitly warn against using ptrace for production
monitoring. It was never designed for that use case.

---

## Why seccomp-bpf Is Also Not the Right Tool

`seccomp-bpf` (Secure Computing Mode with BPF filters) is often mentioned as an
alternative to ptrace for syscall interception. It is not suitable for Guardian
for a different reason: **it is enforcement, not observation**.

seccomp-bpf installs a BPF filter that runs on every syscall and decides whether
to **allow, deny, or kill** the process. It is designed to restrict what syscalls
a process can make — used in container runtimes (Docker, Kubernetes) to harden
workloads.

Key limitations for Guardian:

- **Cannot capture event content**: A seccomp filter receives the syscall number
  and arguments but cannot write them anywhere. It can only return a decision.
- **No return value access**: The filter runs before the syscall executes, so it
  cannot observe what was read from a file or written to a socket.
- **Enforcement-only**: Guardian needs to observe silently, not enforce. Installing
  a seccomp policy risks breaking the monitored workload if a rule is wrong.
- **No chain context**: seccomp has no concept of event history, hashing, or
  chaining.

seccomp-bpf is a valuable hardening tool for production containers, but it is the
wrong tool for compliance evidence collection.

---

## eBPF as the Successor

eBPF (Extended Berkeley Packet Filter) solves both problems:

| Property | ptrace | seccomp-bpf | eBPF |
|----------|--------|-------------|------|
| Overhead | 10–100x | Minimal (enforcement) | ~1% |
| Process interruption | Yes (stops on entry + exit) | Yes (stops on entry) | No |
| Captures event content | Yes | No | Yes |
| Captures return value | Yes | No | Yes |
| Silent observation | No | No | Yes |
| Production-safe | No | Only for enforcement | Yes |
| Kernel JIT-compiled | No | Partial | Yes |

eBPF programs are JIT-compiled by the kernel and run in a sandboxed in-kernel
environment with no process interruption. A kprobe or tracepoint handler attaches
to a kernel function and executes in kernel context, reading the syscall arguments
and return value, then submitting the data to a perf buffer or ring buffer that
is read by userspace (Guardian's Python pipeline).

The typical overhead of an eBPF tracepoint handler is measured in nanoseconds per
syscall — orders of magnitude less than ptrace.

---

## Phase 1: Fake Generator Instead of ptrace

In Phase 1, Guardian runs on macOS and in CI where neither ptrace nor eBPF is
available. Rather than using ptrace as a cross-platform fallback, Guardian uses a
**fake event generator** (`agent/generator.py`) that synthesises realistic events
matching the exact `RawEvent` schema that the Phase 2 eBPF loader will produce.

This means:

- The entire pipeline (enricher → alert engine → signer → sender) runs in Phase 1
  with real code, just with synthetic events.
- The transition to Phase 2 is a pure swap of the event source, not a pipeline change.
- No ptrace dependency is ever introduced.

---

## Summary

| Question | Answer |
|----------|--------|
| Does ptrace work for syscall observation? | Yes, functionally |
| Is ptrace suitable for production AI workloads? | No — 10–100x overhead, process interruption |
| What does strace use? | ptrace (designed for debugging, not production) |
| Can seccomp-bpf be used for observation? | No — enforcement only, no event content |
| What does Guardian use? | eBPF (Phase 2+), fake generator (Phase 1) |

---

## Related Documents

- [alternatives-considered.md](alternatives-considered.md)
- [why-not-falco.md](why-not-falco.md)
- [why-python-first.md](why-python-first.md)
- [../../docs/06-ebpf/](../06-ebpf/)
