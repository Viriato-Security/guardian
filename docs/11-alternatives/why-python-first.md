# Why Python First

**Status: DECIDED — Python for Phase 1 and Phase 2, Rust for Phase 3 rewrite.**

Guardian's pipeline (reader → enricher → signer → sender) is implemented in Python.
Two alternatives were seriously evaluated: Go and Rust. This document records why
both were rejected for Phase 1 and what the Phase 3 migration plan is.

---

## The Phase 1 Goal

Phase 1 is a **validation sprint**, not a production performance build. The
objectives are:

1. Validate the cryptographic chain design (SHA-256 per-event, HMAC-SHA256 per-batch).
2. Validate the proto schema against the viriato-platform team.
3. Validate the gRPC transport and disk-buffer fallback.
4. Validate the local alert rules with real compliance teams.
5. Ship a working demo to early customers.

The goal is to answer "does this design work?" as fast as possible, not to achieve
maximum runtime performance. Language choice should optimise for iteration speed
in Phase 1.

---

## The Argument for Go

Go was the first alternative considered. The case for Go:

- **Single static binary**: No runtime dependency; easy to deploy as a DaemonSet
  with a small container image.
- **Good gRPC support**: `google.golang.org/grpc` is the reference implementation
  and is excellent.
- **Popularity in infrastructure tooling**: The cloud-native ecosystem (Kubernetes,
  Prometheus, Falco) is predominantly Go.
- **Performance**: ~10x better throughput than Python for CPU-bound work; much
  lower memory footprint.
- **Strong concurrency**: goroutines are well-suited to the pipeline pattern.

### Why Go was rejected

**No mature BCC Python bindings for Go.** The Python BCC library
(`from bcc import BPF`) is the standard way to write Phase 2 eBPF programs with
Python-side event handling. There is no equivalent Go library that is as mature.
The Go eBPF ecosystem (`cilium/ebpf`) is good but oriented toward static BPF
object files compiled separately — which is a Phase 3 (Rust + libbpf/Aya) concern,
not a Phase 1/2 concern.

**Team background.** The Guardian team's Python expertise is deep. Go is not a
language where the team has equivalent fluency. For a validation sprint where the
goal is speed, using an unfamiliar language adds risk without commensurate benefit.

**Iteration speed.** Python's interactive debugging, pytest, and dataclasses make
the pipeline easy to iterate on. The type system (with mypy strict mode) provides
safety without the overhead of a full compile step.

---

## The Argument for Rust Phase 1

Rust was also considered for Phase 1. The case for Rust:

- **Safety**: No memory unsafety, no data races; highly desirable for kernel-adjacent code.
- **Aya framework**: Rust's [Aya](https://aya-rs.dev/) library allows writing both
  the eBPF kernel program and the userspace consumer in the same language. This
  avoids the Python/C split in Phase 2.
- **Performance**: Similar to C; appropriate for high-throughput event processing.
- **Phase 3 target**: Guardian's Phase 3 plan is a Rust rewrite. Starting in Rust
  would avoid a language migration.

### Why Rust Phase 1 was rejected

**Steeper learning curve.** Rust's ownership model, borrow checker, and async
runtime (Tokio) impose a significant cognitive overhead that slows initial
iteration. For a validation sprint, this is the wrong trade-off.

**Phase 1 goal is validation, not production performance.** There is no technical
reason to incur the Rust learning overhead in Phase 1 when the design may change.
Shipping a working prototype in Python in 2 weeks is more valuable than shipping
a slower Rust prototype in 6 weeks.

**Aya for Phase 2 requires kernel object compilation.** Aya eBPF programs must be
compiled separately (cross-compiled for the target kernel). Setting up the Aya
toolchain (LLVM, cross-compilation targets, BTF generation) is non-trivial and
would consume time better spent validating the design.

---

## Why Not Stay Python Forever

Python has real limitations for a production kernel-adjacent agent:

**GIL (Global Interpreter Lock).** CPython's GIL limits true parallelism. At high
syscall rates (>100,000 events/sec on a busy AI GPU server), the GIL becomes a
bottleneck in the event processing pipeline.

**Memory footprint.** A Python process with gRPC stubs, protobuf libraries, and
dataclasses loaded has a baseline memory footprint of ~40–60 MB. A Rust binary
with statically linked libraries would be ~5–10 MB.

**Deployment complexity.** Python requires a runtime environment (venv or container)
and dependency management. A static Rust binary requires nothing.

**JIT startup latency.** Python's import time for grpcio and protobuf is measurable
(~500 ms on a cold start). Not critical for a daemon that runs continuously, but
noticeable in test feedback loops.

These limitations do not affect Phase 1 or Phase 2 (where the bottleneck is the
eBPF probe and the kernel, not the Python pipeline). They become relevant at Phase 3
scale.

---

## The Key Insight: Pipeline Design is Language-Agnostic

The Guardian pipeline — `reader → enricher → signer → sender` — is a clean
functional design with clear interfaces. Each stage takes a `RawEvent` or list of
`RawEvent` objects and produces a transformed output. The interfaces are:

- `reader.stream()` → `Iterator[RawEvent]`
- `enricher.enrich(event)` → `RawEvent`
- `signer.sign_event(event)` → `RawEvent`, `signer.sign_batch(events)` → `str`
- `sender.send_batch(events, signature)` → `bool`

This design is language-agnostic. Phase 3 is a **rewrite**, not a **redesign**. The
Rust implementation will implement the same interfaces with the same semantics —
but compiled to a static binary, using Tokio for async I/O, Aya for eBPF, and
prost for proto serialisation.

The Python codebase in Phase 1/2 serves as the **reference implementation** and
the **test oracle** for Phase 3. The same test scenarios (known input events →
known hash chains) can be run against both implementations to verify correctness.

---

## Phase Roadmap

| Phase | Language | Event source | Goal |
|-------|----------|-------------|------|
| Phase 1 | Python | Fake generator | Validate design, schema, transport |
| Phase 2 | Python + BCC | Linux eBPF (BCC) | Real events, kernel-level |
| Phase 3 | Rust | libbpf / Aya | Production performance, static binary |

---

## Summary

| Question | Answer |
|----------|--------|
| Why not Go? | No mature BCC bindings; team not fluent in Go; slower Phase 1 iteration |
| Why not Rust Phase 1? | Steeper learning curve; Aya toolchain overhead; Phase 1 is validation not perf |
| Why not Python forever? | GIL, memory footprint, deployment complexity at Phase 3 scale |
| What is Phase 3? | Rust rewrite using same pipeline design; Aya for eBPF; Tokio for async |

---

## Related Documents

- [alternatives-considered.md](alternatives-considered.md)
- [why-not-ptrace.md](why-not-ptrace.md)
- [../../docs/07-phases/](../07-phases/)
