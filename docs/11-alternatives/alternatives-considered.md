# Alternatives Considered

This document records every significant alternative that was evaluated before (or
during) building Guardian and the reason each was not chosen. The purpose is to
prevent future re-proposals of already-decided questions and to give new contributors
the context to understand why Guardian is built the way it is.

**Decision records here are final for the current phase.** If you believe a decision
should be revisited, open a GitHub issue with new evidence rather than re-raising
the original argument.

---

## Summary Table

| Alternative | Category | Key reason rejected | What we chose instead |
|-------------|----------|--------------------|-----------------------|
| Falco | Runtime security tool | Compliance layer would be as much work as Guardian; constrained by Falco's data model; no crypto chaining | Build Guardian directly on eBPF |
| OpenTelemetry (OTel) | Observability framework | Application-level; requires code changes; eBPF operator not production-ready | eBPF syscall capture in kernel space |
| ptrace | Syscall interception | 10–100x overhead; stops process on every syscall; unacceptable for AI inference | eBPF (~1% overhead, no interruption) |
| seccomp-bpf | Kernel enforcement | Enforcement not observation; cannot capture event content | eBPF kprobes/tracepoints |
| auditd | Linux audit subsystem | High-volume noise, flat text format, no crypto chaining, complex rule language | eBPF with structured events |
| Go for agent | Language choice | No mature BCC Python bindings; slower iteration in Phase 1 | Python Phase 1, Rust Phase 3 |
| Rust for Phase 1 | Language choice | Steeper learning curve; Phase 1 goal is validation speed | Python Phase 1, Rust Phase 3 |
| MIT license | License choice | Competitors could fork agent and build competing platform without contributing back | BUSL-1.1 |
| AGPL license | License choice | Enterprise legal teams flag copyleft; slows enterprise adoption | BUSL-1.1 |
| SQLite buffer | Disk buffer format | Extra dependency; JSONL is simpler, introspectable, and dependency-free | JSONL (`pending.jsonl`) |
| Per-batch chaining | Chain granularity | Less granular than per-event; hides intra-batch tampering | Per-event SHA-256 chain |
| Ed25519 signing | Batch signature | Requires key pair management; HMAC token already held by both sides | HMAC-SHA256 with customer token |
| BLAKE3 hashing | Event hash function | Not yet in Python stdlib; SHA-256 is sufficient and needs no extra dep | SHA-256 (hashlib) |
| Kafka transport | Event transport | Adds broker dependency; gRPC streaming is bidirectional and latency-appropriate | gRPC streaming |
| REST transport | Event transport | Per-event HTTP overhead; batching workarounds are complex | gRPC streaming with batching |

---

## Key Decision Clusters

The alternatives fall into four clusters. Understanding the cluster helps understand
the individual decisions.

### Event capture mechanism

The central question: how do we capture kernel syscall events from a running process
with no code changes to that process and minimal overhead?

- **ptrace**: Works but 10–100x overhead. Process stops on every syscall. Ruled out
  for production AI workloads.
- **seccomp-bpf**: Enforcement not observation. Cannot read event content. Wrong tool.
- **auditd**: Linux audit subsystem. Produces high-volume flat-text events, no
  structured fields, no crypto chaining. Complex rule language. Performance degrades
  under high syscall rates. Ruled out.
- **eBPF**: ~1% overhead, kernel JIT-compiled, no process interruption, structured
  events, can attach to any tracepoint. Chosen.

### Tooling layer (build on top of vs. build from scratch)

Could we build Guardian on top of an existing tool and inherit its eBPF collection?

- **Falco**: Production-ready but designed for real-time alerting, not compliance
  evidence. No crypto chaining. Data model mismatch. Building a compliance layer on
  top would be as much work as Guardian itself.
- **OpenTelemetry**: Application-level. Requires code changes. eBPF Operator is
  experimental and captures HTTP traces, not raw syscalls.
- **Build directly on eBPF**: Chosen. More work upfront but full control over data
  model, chaining, and transport.

### Language and implementation

What language to write the agent pipeline in?

- **Go**: Good gRPC, single binary, popular in cloud-native. No mature BCC bindings.
  Team not fluent. Slower Phase 1 iteration.
- **Rust Phase 1**: Safety, Aya framework. Steeper learning curve. Phase 1 is
  validation speed, not production performance.
- **Python Phase 1**: Team fluency, pytest, fast iteration, BCC bindings available.
  GIL and memory footprint are Phase 3 concerns.
- **Python Phase 1, Rust Phase 3**: Chosen. Pipeline design is language-agnostic.

### Cryptography and transport

How to authenticate events and transport them?

- **Per-batch chaining**: Less granular. Intra-batch deletions undetectable.
- **Per-event SHA-256 chain**: Chosen. Any gap is detectable.
- **Ed25519**: Asymmetric. Requires key distribution. Token already shared.
- **HMAC-SHA256**: Chosen. Simpler, no key management, immune to length extension.
- **BLAKE3**: Faster than SHA-256. Not in Python stdlib. SHA-256 is sufficient.
- **Kafka**: Adds broker dependency. No intrinsic benefit for compliance streaming.
- **REST**: Per-event HTTP overhead. Batching is awkward.
- **gRPC streaming**: Chosen. Bidirectional, efficient, first-class proto support.

---

## The Principle: Document Rejections to Prevent Re-proposals

Every engineering team wastes time re-debating settled questions. This document
exists so that when someone asks "why not use Falco?" or "why not AGPL?", the
answer is written down and the team does not have to reconstruct the reasoning
from memory.

When a decision is genuinely worth revisiting (new evidence, changed requirements,
new technology), open a GitHub issue and link to this document. If the issue
produces new consensus, update this document and the relevant detail file.

---

## Detail Files

Each row in the summary table has (or will have) a dedicated document with
fuller context:

- [why-not-falco.md](why-not-falco.md)
- [why-not-opentelemetry.md](why-not-opentelemetry.md)
- [why-not-ptrace.md](why-not-ptrace.md)
- [why-python-first.md](why-python-first.md)
- [why-busl-not-mit.md](why-busl-not-mit.md)

---

## Related Documents

- [why-not-falco.md](why-not-falco.md)
- [why-not-opentelemetry.md](why-not-opentelemetry.md)
- [why-not-ptrace.md](why-not-ptrace.md)
- [why-python-first.md](why-python-first.md)
- [why-busl-not-mit.md](why-busl-not-mit.md)
- [../../docs/02-architecture/](../02-architecture/)
