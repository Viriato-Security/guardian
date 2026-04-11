# BCC vs libbpf vs Aya — eBPF Userspace Library Comparison

> A detailed comparison of the three eBPF userspace libraries and why Guardian uses each for a different phase.

Guardian uses three different eBPF toolchains across its three phases. This is not indecision — it is a deliberate progression that prioritises speed to validation in Phase 1, speed to real kernel events in Phase 2, and long-term production excellence in Phase 3. This document explains each toolchain in depth, the trade-offs involved, and why the progression makes sense.

---

## Overview

The eBPF toolchain stack has three layers:

1. **The kernel-side BPF program**: Written in C (classic) or Rust (Aya). Compiled to BPF bytecode. Defines maps, tracepoint handlers.
2. **The BPF loader library**: Loads the bytecode into the kernel, performs CO-RE relocations, attaches programs to events, exposes map access to userspace.
3. **The userspace application**: Reads events from maps, enriches them, and does something useful.

BCC, libbpf, and Aya are different choices at layer 2 (and optionally layer 3). Guardian's `guardian.bpf.c` is written in libbpf-style C and is compatible with both BCC and libbpf. Phase 3 replaces it with Aya-style Rust.

---

## BCC (BPF Compiler Collection)

BCC was created at Plumgrid in 2015 and is now maintained as an open-source project with major contributions from Brendan Gregg (Netflix), Facebook, and Red Hat. It is the toolchain that made eBPF accessible to a broad audience through its Python bindings and included suite of observability tools (`execsnoop`, `opensnoop`, `tcptop`, `profile`, and hundreds more).

### How BCC Works

BCC ships BPF C source code alongside the userspace application. At runtime, BCC calls the LLVM/clang compiler (which must be installed on the target machine) to compile the C to BPF bytecode. The compiled bytecode is then loaded into the kernel. This runtime compilation is what makes BCC easy (no pre-compile step, no architecture mismatch) and costly (requires clang on every target, slow startup).

### Strengths

**Python bindings that just work**: BCC's Python API is the most ergonomic eBPF interface available. Attaching a tracepoint is three lines: `bpf = BPF(src_file="prog.bpf.c")`, `bpf.attach_tracepoint(tp="syscalls:sys_enter_read", fn_name="handle_read")`, done. Map access is dict-like: `bpf["watched_pids"][ctypes.c_uint32(pid)] = ctypes.c_uint8(1)`.

**Runtime compilation means flexible prototyping**: Change the BPF C source, restart the application — the new code is compiled and loaded automatically. No build step. For exploratory development (finding the right tracepoints, debugging event fields), this is invaluable.

**Large community and examples**: The BCC repository contains hundreds of reference implementations for exactly the syscall tracing patterns Guardian needs. Phase 2 benefits from being able to reference `opensnoop.py`, `execsnoop.py`, and `bpf_trace.py` directly.

**No pre-compilation required**: The userspace developer does not need to run `clang -target bpf` manually. BCC handles compilation transparently.

### Weaknesses

**LLVM/clang as a runtime dependency**: BCC requires clang and the LLVM libraries on every machine where it runs — approximately 100–300MB of additional packages (`libclang`, `libLLVM`, kernel headers). For a Kubernetes DaemonSet that should be a minimal container image, this is prohibitive.

**Slow startup due to runtime compilation**: BCC compiles the BPF C source at load time. For `guardian.bpf.c` (approximately 300 lines), this takes 1–5 seconds on a typical server. During this time, no events are captured. For production monitoring that should start instantly, this delay is unacceptable.

**Compile errors surface at runtime, not build time**: A syntax error in `guardian.bpf.c` is not caught until BCC tries to compile it at process startup. In a CI pipeline, BCC compilation requires a Linux machine with clang — tests cannot run on macOS without the eBPF compiler. libbpf and Aya compile BPF code offline, catching errors in CI.

**Harder to distribute**: Shipping a BCC application requires ensuring clang and kernel headers are installed on the target, or including them in the container image. This adds operational complexity.

**CO-RE support is an afterthought**: BCC was designed before CO-RE existed. CO-RE support was added later and is less complete than libbpf's implementation. Some BTF-dependent features work differently between BCC and libbpf versions.

### Guardian Use: Phase 2

Phase 2 chooses BCC because it is the **fastest path to real kernel events from the existing Python codebase**. The entire Phase 1 agent is Python. BCC provides Python bindings for BPF. The Phase 2 change is adding 50 lines of BCC Python to `agent/loader.py`. No language change, no new build system, no learning curve beyond the BCC API.

The costs of BCC (clang on target, slow startup) are acceptable in Phase 2 because:
- This is a development and validation phase, not production at scale
- OrbStack VMs have clang available
- The goal is to validate that real kernel events match the Phase 1 schema — startup time is irrelevant for this validation
- Phase 3 replaces BCC before production deployment

---

## libbpf (C Library)

libbpf is the canonical C library for eBPF programs. It was extracted from the Linux kernel's `tools/lib/bpf/` directory and is now maintained as a standalone library. It is the foundation of CO-RE and the standard for modern production eBPF tooling.

### How libbpf Works

You compile BPF C to BPF bytecode offline using clang: `clang -O2 -g -target bpf -c prog.bpf.c -o prog.bpf.o`. The `.bpf.o` file contains BPF bytecode and BTF metadata. You ship this pre-compiled object. At runtime, libbpf loads the object, performs CO-RE relocations (patching field offsets for the running kernel using the kernel's BTF data at `/sys/kernel/btf/vmlinux`), and attaches programs.

### Strengths

**No compiler on target**: The `.bpf.o` file is pre-compiled. Only libbpf (a small shared library, ~300KB) is required on the target. No clang, no LLVM, no kernel headers.

**CO-RE is first-class**: libbpf invented CO-RE. The `BPF_CORE_READ()` macro, BTF relocation processing, and the compatibility checks are all implemented in libbpf. Programs compiled with libbpf-style CO-RE annotations run on any Linux 5.2+ kernel with BTF.

**Low overhead**: No startup compilation. The pre-compiled object loads in milliseconds. Ideal for production environments where startup time matters.

**Generates skeleton headers**: `bpftool gen skeleton prog.bpf.o > prog.skel.h` generates a C header with type-safe accessors for every map and program in the object. Userspace code uses the skeleton instead of raw `bpf_map_lookup_elem()` calls — significantly reducing boilerplate and type errors.

**Field-tested at scale**: libbpf is used by Cilium (Kubernetes CNI), Katran (Facebook load balancer), and the Linux kernel's own BPF test suite. It is the production standard.

**Guardian's probe is already libbpf-style**: `guardian.bpf.c` uses libbpf-style map definitions (`__uint(type, ...)`, `__type(key, ...)`, `SEC(".maps")`), CO-RE read macros, and libbpf helper function signatures. This is intentional — the probe is designed for libbpf/Aya Phase 3 from the start.

### Weaknesses

**C API only**: libbpf has no official Python or Rust bindings. Third-party Python bindings exist (`python-libbpf`) but are not widely used. Integrating libbpf with Python requires either CGo-style wrapping or subprocess execution — both complex.

**C expertise required**: Writing a libbpf-based loader requires fluent C and familiarity with BPF skeleton patterns. Error handling is C-style (return codes, not exceptions). Memory management is manual.

**Separate build artifact**: The `.bpf.o` file must be compiled separately and shipped alongside the binary. CI pipelines must include a BPF compilation step. Docker images must include the pre-compiled object.

### Guardian Use: Phase 3 reference design

Guardian's `guardian.bpf.c` is written in libbpf style, but the Python Phase 2 uses BCC to load it (BCC can load libbpf-style C). Phase 3 uses Aya, which provides similar CO-RE support to libbpf but in Rust. libbpf itself is not used directly in any phase — it is the style that `guardian.bpf.c` follows, and Aya uses libbpf under the hood for some platforms.

---

## Aya (Rust eBPF Framework)

Aya is an open-source Rust library for writing eBPF programs and their userspace counterparts entirely in Rust. It was created by Alessandro Decina and is actively maintained by the Aya community, with significant contributions from Red Hat and Microsoft.

### How Aya Works

The BPF program itself is written in Rust using the `aya-ebpf` crate. It compiles to BPF bytecode using `rustc` with the `bpfel-unknown-none` target (little-endian BPF). The userspace component is standard Rust using the `aya` crate. The BPF bytecode is embedded in the userspace binary at compile time via `include_bytes!()`. At runtime, Aya loads the embedded bytecode, performs CO-RE relocations, and attaches programs — all from pure Rust with no external dependencies.

### Strengths

**Single language for kernel and userspace**: The BPF program and the userspace application are both Rust. Type definitions can be shared between them via a common types crate. No C/Rust FFI boundary for the BPF program itself.

**Rust safety in the userspace loader**: The Aya userspace API uses Rust's ownership system for resource management. A `Program` that goes out of scope is automatically detached. Map access is typed — `HashMap<u32, u8>` for `watched_pids`, not `bpf_map_lookup_elem(&map, &key)`.

**CO-RE built-in**: Aya supports BTF-based CO-RE for Rust BPF programs. The compiled Rust BPF binary includes BTF metadata and CO-RE relocations just like a libbpf-compiled C program.

**Single binary output**: The BPF bytecode is embedded in the Rust binary via `include_bytes!()` at compile time (`cargo build`). The result is a single statically linked binary. No `.bpf.o` file to manage, no Python runtime, no clang on the target machine.

**Async-friendly with tokio**: Aya's `aya-tokio` crate integrates the ring buffer drain loop with tokio's async runtime. The event consumer is a tokio task that `await`s ring buffer events. This enables true concurrent event processing without threads.

**Strong typing across the kernel-userspace boundary**: The shared types crate defines `GuardianEvent` in Rust. The BPF program uses it. The userspace loader uses it. Type mismatches are caught at compile time, not at runtime.

### Weaknesses

**Younger project with smaller community**: Aya is approximately 4 years old vs BCC's 10 years. There are fewer Stack Overflow answers, fewer tutorials, and fewer reference implementations for specific tracepoint patterns. Debugging obscure BPF verifier errors in Rust requires understanding both the verifier and Aya's code generation.

**Aya-specific patterns to learn**: Writing BPF in Rust with Aya requires learning Aya's attribute macros (`#[tracepoint]`, `#[map]`), the `aya-ebpf` helper function API (analogous to but different from libbpf's C helpers), and the Aya CO-RE read macros.

**Rust + BPF toolchain setup**: Requires `rustup` with `nightly` toolchain (for some unstable features used by `aya-ebpf`), the `bpfel-unknown-none` target, and `cargo-generate` for the Aya project template. This is more setup than `pip install bcc`.

**Ecosystem still maturing**: Some advanced BPF features (certain program types, newer map types) may not yet have Aya bindings. The list of supported types grows with each release.

### Guardian Use: Phase 3

Phase 3 rewrites the entire agent in Rust with Aya. This is the production target: single binary, <10MB, <100ms startup, <20MB memory, 1–2% CPU overhead at 100,000 syscalls/sec. Kubernetes DaemonSet deployment becomes trivial — one container image under 30MB (distroless base + single binary).

---

## Comparison Table

| Property | BCC | libbpf | Aya |
|----------|-----|--------|-----|
| Language (userspace) | Python | C | Rust |
| Language (BPF program) | C | C | Rust (or C via raw bytes) |
| Compilation model | Runtime (on target) | Offline (pre-compile) | Offline (embedded in binary) |
| Requires clang on target | Yes (~200MB) | No | No |
| Requires Python on target | Yes | No | No |
| Startup latency | 1–5s (BPF compilation) | <100ms | <100ms |
| CO-RE support | Limited/afterthought | First-class | First-class |
| Single binary output | No | No (separate .bpf.o) | Yes |
| Memory footprint (rough) | ~150MB (Python + clang) | ~5–10MB | ~10–15MB |
| Type safety (userspace) | Python typing | C (manual) | Rust ownership + generics |
| Async runtime integration | Limited | Manual epoll | tokio native |
| Community maturity | High (10 years, ~200 tools) | High (kernel-blessed) | Growing (4 years) |
| Guardian phase | Phase 2 | BPF C style (not loaded directly) | Phase 3 |
| CI support | Linux only | Any (offline compilation) | Any (offline compilation) |
| Container image impact | +200MB (clang+python) | +300KB (libbpf SO) | +0 (embedded) |

---

## Why This Progression Makes Sense

### Phase 1: No eBPF at All

The pipeline — enrichment, signing, batching, gRPC, disk buffer, local alerts — was validated without any eBPF. This was the critical design decision: the schema and cryptographic design are the hardest parts to get right. eBPF is "just" the event source. 63 tests pass. The pipeline is proven correct. Building this in Python, without eBPF, took days rather than weeks.

### Phase 2: BCC Because It Is the Fastest Path

Phase 2 needs real kernel events. The existing codebase is Python. BCC provides Python bindings for BPF. The Phase 2 change is adding ~50 lines to `agent/loader.py`. The existing agent, existing tests, existing proto schema, and existing platform integration work unchanged. This is the fastest possible path from "fake events" to "real events."

The BCC costs (clang on target, slow startup) are future problems. Phase 2 is a development and validation phase. The goal is to prove that the schema contract holds with real kernel events, that the `sandbox_escape` alert fires on a real `execve`, and that the chain integrity holds across thousands of real kernel events. BCC is the right tool for this validation.

### Phase 3: Aya for Production

Phase 3 comes after Phase 2 validates the probe design in production. At that point, the eBPF program is known-correct (tracepoints, maps, and field capture are validated). The Rust rewrite implements a proven design rather than inventing a new one.

Aya delivers what production requires: single binary, no runtime dependencies, sub-100ms startup, minimal memory footprint, strong typing, and tokio async integration that enables future parallelism improvements without Python GIL constraints.

---

## Why Not Start With Aya?

The obvious question: if Aya is the production target, why not start there?

**Validation velocity**: Proving the pipeline design (schema, crypto, gRPC, alerting) in Python took approximately one week of focused development. In Rust, the same design would take 3–6 weeks — not because Rust is harder, but because Aya adds a new learning curve on top of an already novel design space. Phase 1 validated the hard parts first.

**Risk sequencing**: The hardest unsolved problems at the start of the project were protocol design questions: which fields? which crypto? which gRPC schema? what alert rules? These were solved in Phase 1. The implementation language is a separate and lower-risk decision.

**Debugging BPF in Rust vs Python**: When a tracepoint fires and produces garbage data, debugging in Python (with `print()`, BCC's `bpf_trace_printk()`, and direct map inspection via `bpf["map"].items()`) is significantly easier than debugging in Rust. Phase 2 catches and fixes probe design bugs in a more debuggable environment. Phase 3 reimplements the validated design in Rust.

**Team familiarity and solo development**: A founder building alone must minimize unknowns. Adding Rust + Aya + new eBPF tracepoints + new proto schema + new cryptographic design simultaneously is too much risk. Python first, then real eBPF in Python, then Rust for production — each phase adds one major new element.

---

## Why Not libbpf Directly?

libbpf is the right choice if you are writing a C userspace application. Guardian is not:

- Phase 1/2 are Python. Bridging libbpf to Python requires CGo or subprocess execution — both complex, both fragile.
- Phase 3 is Rust. In the Rust world, Aya is the equivalent of libbpf — it uses libbpf under the hood on some platforms or provides its own loader. Writing a Rust application that FFI-calls libbpf C is possible but replicates what Aya already does.

libbpf's value shows up in `guardian.bpf.c`: the probe is written in libbpf-style C (`__uint(type, ...)` map definitions, `SEC()` annotations, CO-RE macros). This makes it compatible with both BCC (Phase 2) and Aya (Phase 3). libbpf is the style, not the loader.

---

## The Proto Schema Works Identically Across All Three Phases

The most important architectural invariant: `proto/guardian.proto` is the contract between Guardian and the viriato-platform. It is unchanged across all three phases.

```protobuf
message Event {
    string  timestamp    = 1;
    int32   pid          = 2;
    int32   uid          = 3;
    string  process      = 4;
    string  syscall      = 5;
    string  fd_path      = 6;
    int64   bytes        = 7;
    string  network_addr = 8;
    string  return_val   = 9;
    string  agent_id     = 10;
    string  model_name   = 11;
    string  container_id = 12;
    string  pod_name     = 13;
    string  namespace    = 14;
    string  prev_hash    = 15;
    string  this_hash    = 16;
}
```

Phase 1 (Python `FakeEventGenerator`) → serialises `RawEvent` to this proto via `guardian_pb2`.
Phase 2 (Python BCC `EbpfLoader`) → serialises `RawEvent` (from real kernel events) to the same proto.
Phase 3 (Rust Aya agent) → serialises Rust `Event` struct to the same proto via `prost`.

The platform receives byte-for-byte identical protobuf wire format in all three cases. A customer migrating from Phase 1 to Phase 2 to Phase 3 sees no change in the platform UI, no change in the API, and no change in the alert rules.

---

## Summary

Guardian uses BCC for Phase 2 (fastest path to real events from existing Python codebase), and Aya for Phase 3 (best production properties: single binary, memory safety, CO-RE, async). libbpf directly is not used as a loader — but `guardian.bpf.c` is written in libbpf style for maximum compatibility. The proto schema is the invariant that makes this progression work: same wire format, same platform, same compliance evidence, regardless of which library loaded the BPF program.

---

## Related Documents

- [What Is eBPF](what-is-ebpf.md)
- [Guardian Probe Architecture](probe-architecture.md)
- [Phase 1 vs Phase 2](phase1-vs-phase2.md)
- [Phase 2: Real eBPF](../07-phases/phase2-real-ebpf.md)
- [Phase 3: Rust Rewrite](../07-phases/phase3-rust-rewrite.md)
- [gRPC Contract](../03-data/grpc-contract.md)
