# Phase 3 — Rust Agent with Aya eBPF

> The plan for rewriting the Guardian agent in Rust for production-grade performance and deployment simplicity.

**Status: PLANNED (after first revenue)**

Phase 3 rewrites the Guardian agent entirely in Rust using the Aya eBPF framework. The result is a single statically linked binary: no Python runtime, no BCC compiler, no LLVM on the target machine. The same `guardian.yaml` configuration, the same `proto/guardian.proto` wire format, and the same event field schema are preserved unchanged. Only the implementation language changes.

---

## Overview

Phase 2 proves that Guardian works on Linux with real kernel events. Phase 3 makes it production-grade: minimal footprint, single binary, sub-100ms startup, and Rust's memory safety guarantees in a privileged process.

The timing — after first revenue — reflects the right sequencing of technical investment. Phase 1 validated the design. Phase 2 validates eBPF instrumentation in production. Phase 3 implements a proven design in the production-optimal language. Attempting Phase 3 before the design was validated would have been premature optimisation.

No Rust code has been written for Phase 3. This document describes the design intent and technology choices. The proto schema, configuration format, and cryptographic algorithms validated in Phase 1 and Phase 2 ensure that Phase 3 can be implemented against a known specification.

---

## Why Rust

### Memory Safety in a Privileged Process

Guardian runs with `CAP_BPF` and `CAP_SYS_ADMIN` — effectively root-equivalent privileges. Memory safety vulnerabilities in a privileged process are critical security issues. A use-after-free or buffer overflow in a root process can lead to privilege escalation, system compromise, or kernel panic.

Rust's ownership system eliminates at compile time:
- **No use-after-free**: The borrow checker prevents using a value after it has been moved or freed
- **No data races**: Rust's ownership rules prevent unsynchronised shared mutable access — compile-time guarantee, not a runtime check
- **No null pointer dereferences**: `Option<T>` forces explicit handling of nullable values via pattern matching
- **No buffer overflows**: Slice indexing is bounds-checked; fixed-size arrays are encoded in types
- **No uninitialized reads**: Variables must be initialized before use — enforced by the compiler

In Python (Phase 1/2), these classes of bugs are prevented by runtime checks and the interpreter's memory management. In Rust, they are prevented at compile time with zero runtime overhead.

### Performance: No GIL, Zero-Cost Abstractions

Python's Global Interpreter Lock (GIL) means only one thread executes Python bytecode at a time. The Phase 1/2 pipeline loop runs in a single thread. For Phase 2's real kernel event rates (100,000+ syscalls/sec), the GIL becomes a bottleneck as event processing, PID discovery, and gRPC transmission compete for the interpreter.

Rust has no GIL. Threads are truly parallel. Async tasks on tokio run on a thread pool without contention. The Phase 3 architecture runs:
- Event drain loop on its own tokio task (CPU-bound, reads from Aya's ring buffer)
- Enrichment + signing on another tokio task (CPU-bound, but fast)
- gRPC sender on a third tokio task (I/O-bound, awaits network)

These run concurrently without the coordination overhead of Python threads.

Rust's "zero-cost abstractions" mean that high-level code (iterators, closures, generics, futures) compiles to machine code equivalent to handwritten C — no hidden allocation, no virtual dispatch unless explicitly requested, no garbage collection pauses.

### Deployment: Single Binary, No Runtime

Phase 2 requires on every target machine: Python 3.12+, BCC, clang/LLVM (~200MB), libbpf-dev, and Python package dependencies. A Kubernetes DaemonSet container image weighs approximately 400MB.

Phase 3 produces a single statically linked binary. The BPF bytecode is embedded in the binary at compile time via `include_bytes!()`. On the target machine: nothing except the binary is required. The container image is a distroless base (~15MB) + the guardian binary (~10MB) = ~25MB total. A 94% reduction from Phase 2's image size.

Deployment becomes: `COPY guardian /usr/local/bin/guardian`. No package management, no runtime installation, no version conflicts.

---

## Technology Stack

### Aya (eBPF Framework)

Aya is the primary eBPF library for Rust. It is actively maintained with significant contributions from Red Hat and Microsoft.

**`aya` crate (userspace)**: BPF object loader, program attachment, map management, ring buffer consumer. Provides typed map access: `HashMap::<u32, u8>::try_from(bpf.map_mut("watched_pids")?)?`.

**`aya-ebpf` crate (kernel/BPF side)**: Replaces the C BPF program. Tracepoints are Rust functions with `#[tracepoint]` attribute:
```rust
#[tracepoint(name = "sys_enter_read")]
pub fn handle_read(ctx: TracePointContext) -> u32 {
    match try_handle_read(ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}
```

**`aya-log` / `aya-log-ebpf` crates**: Structured logging from BPF programs to userspace. Used for development debugging — log messages appear in userspace without a separate communication channel.

The BPF program written with `aya-ebpf` compiles to BPF bytecode using `rustc --target bpfel-unknown-none`. The `bpf-linker` tool links and strips the BPF ELF. The `aya-build` crate handles this in `build.rs`.

### tonic (gRPC)

`tonic` is the canonical async gRPC library for Rust, built on `tokio` and `prost`. It replaces `grpcio` (the C-extension-based Python gRPC library used in Phase 1/2).

**`proto/guardian.proto` is unchanged**. The Rust agent generates Rust types from it at compile time via `build.rs`:

```rust
// build.rs
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/guardian.proto")?;
    Ok(())
}
```

This generates `guardian.rs` containing `Event`, `EventBatch`, `Ack`, and the `GuardianIngestClient` stub. The generated code is included via `include!(concat!(env!("OUT_DIR"), "/guardian.rs"))`.

**Cargo.toml dependencies:**
```toml
[dependencies]
tonic = "0.11"
prost = "0.12"
tokio = { version = "1", features = ["full"] }
```

The gRPC client code in Rust is equivalent to the Python `Sender` class — TLS by default, insecure for localhost. The disk buffer JSONL format is identical.

### serde (Serialisation)

`serde` with `serde_json` handles disk buffer serialisation, replacing Python's `json.dumps()` / `json.loads()`. The `pending.jsonl` format is identical between Phase 2 (Python) and Phase 3 (Rust) — JSON is language-agnostic.

```toml
[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

The `RawEvent` equivalent in Rust derives `Serialize` and `Deserialize`:
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct RawEvent {
    pub timestamp: String,
    pub pid: u32,
    pub uid: u32,
    pub process: String,
    pub syscall: String,
    pub fd_path: String,
    pub bytes: i64,
    pub network_addr: String,
    pub return_val: String,
    pub agent_id: String,
    pub model_name: String,
    pub container_id: String,
    pub pod_name: String,
    pub namespace: String,
    pub prev_hash: String,
    pub this_hash: String,
}
```

### hmac + sha2 (Cryptography)

The Phase 3 cryptography is identical in algorithm to Phase 1/2: SHA-256 for event hashing, HMAC-SHA256 for batch signing. The hash values are byte-for-byte identical for the same input, regardless of the implementing language.

```toml
[dependencies]
hmac = "0.12"
sha2 = "0.10"
hex = "0.4"
```

This means a chain started in Phase 2 (Python) and continued in Phase 3 (Rust) would produce consistent hashes — the same `this_hash` for the same event fields. In practice, chains restart on agent restart (new GENESIS_HASH), but the algorithmic compatibility is an important correctness property.

### tokio (Async Runtime)

`tokio` is the async runtime that replaces Python's single-threaded event loop. Phase 3's pipeline is structured as concurrent async tasks:

```rust
#[tokio::main]
async fn main() {
    tokio::select! {
        _ = event_drain_task() => {},
        _ = pipeline_task() => {},
        _ = sender_task() => {},
        _ = signal::ctrl_c() => {},
    }
}
```

The ring buffer drain uses `aya-tokio`'s async ring buffer: `AsyncRingBuf::try_from(bpf.take_map("events")?)?.next().await?`.

### ring-channel or crossbeam (Event Delivery)

The BPF event drain task produces `GuardianEvent` structs. The pipeline task (enricher + signer) consumes them. A bounded channel connects the two:

```rust
use tokio::sync::mpsc;
let (tx, rx) = mpsc::channel::<GuardianEvent>(10_000);
```

The channel size (10,000) provides backpressure: if the pipeline falls behind, the drain task pauses, which allows the ring buffer to fill, which causes the BPF program to drop events rather than overwhelming the pipeline.

---

## What Stays the Same

This is the most important section of the Phase 3 document. The proto schema, configuration format, and cryptographic algorithms are the invariant core. They do not change.

### proto/guardian.proto

The proto file is completely unchanged. `prost-build` generates Rust types from the same `.proto` file. The platform receives byte-for-byte identical protobuf wire format. No platform changes required for Phase 3.

### guardian.yaml Schema

The configuration schema — `agent`, `watch`, `syscalls`, `local_alerts`, `network_allowlist`, `compliance` sections — is unchanged. The Rust agent parses the same YAML file using `serde_yaml`:

```toml
[dependencies]
serde_yaml = "0.9"
```

A `guardian.yaml` file that works with the Phase 2 Python agent works unchanged with the Phase 3 Rust binary.

### Event Field Names and Types

The 16 event fields (`timestamp`, `pid`, `uid`, `process`, `syscall`, `fd_path`, `bytes`, `network_addr`, `return_val`, `agent_id`, `model_name`, `container_id`, `pod_name`, `namespace`, `prev_hash`, `this_hash`) are identical in all three phases. The Rust `RawEvent` struct has the same fields as the Python `RawEvent` dataclass.

### Cryptographic Design

SHA-256 chaining and HMAC-SHA256 batch signing algorithms are identical:
- `GENESIS_HASH = "0".repeat(64)` — same sentinel value
- `this_hash = sha256(json_serialize_sorted_keys(event_without_this_hash))` — same computation
- `signature = hmac_sha256(token, json_serialize([(prev, this) for event in batch]))` — same payload format

### Disk Buffer Format

The `pending.jsonl` format is JSON, language-agnostic. The Phase 3 Rust agent reads JSONL files written by Phase 2 Python and vice versa. Cross-phase migration is safe: a system running Phase 2 that has buffered events can be upgraded to Phase 3, and Phase 3 will drain the buffer written by Phase 2.

---

## What Changes

### The Entire agent/ Directory

All Python code under `agent/` is replaced by Rust. The Rust project structure:

```
guardian-agent/          # new top-level Rust workspace
  Cargo.toml             # workspace definition
  guardian/              # userspace agent binary
    Cargo.toml
    build.rs             # proto compilation (tonic_build) + BPF embedding
    src/
      main.rs            # entry point, CLI (clap), tokio::main
      config.rs          # YAML configuration loading (serde_yaml)
      enricher.rs        # agent_id persistence, model_name, container_id
      signer.rs          # SHA-256 chaining + HMAC-SHA256
      sender.rs          # gRPC sender (tonic), JSONL disk buffer (serde_json)
      local_alerts.rs    # sandbox_escape, unexpected_network rules
      loader.rs          # Aya BPF loader, ring buffer consumer (aya-tokio)
      reader.rs          # event source abstraction (same concept as reader.py)
  guardian-ebpf/         # BPF-side Rust program
    Cargo.toml
    src/
      main.rs            # BPF program: maps, tracepoint handlers
  guardian-common/       # shared types between BPF and userspace
    Cargo.toml
    src/
      lib.rs             # GuardianEvent struct, constants
```

The `guardian-common` crate is the Rust equivalent of `guardian.h`: it defines `GuardianEvent` and the constants (`PROCESS_LEN = 16`, `FD_PATH_LEN = 256`, `NETADDR_LEN = 64`) in Rust, shared between the BPF program and the userspace loader.

### probe/guardian.bpf.c → guardian-ebpf/src/main.rs

The C BPF program is superseded by a Rust BPF program using `aya-ebpf`:

```rust
// guardian-ebpf/src/main.rs
use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};
use guardian_common::GuardianEvent;

#[map(name = "events")]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map(name = "watched_pids")]
static WATCHED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[tracepoint(name = "sys_enter_read")]
pub fn handle_read(ctx: TracePointContext) -> u32 {
    match try_handle_read(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}
```

The old `probe/guardian.bpf.c` and `probe/guardian.h` remain in the repository for historical reference but are not compiled in Phase 3.

### Binary Distribution

Phase 1/2: `pip install guardian` or `python3 -m agent.main`.

Phase 3: single static binary `guardian`, distributed as:

- **GitHub Releases**: `guardian-linux-x86_64`, `guardian-linux-aarch64` binaries attached to each release tag
- **Container image**: `viriatosecurity/guardian:3.x` on Docker Hub — distroless base (~15MB) + guardian binary (~10MB) = ~25MB total
- **Kubernetes DaemonSet YAML**: Includes the container image reference, required capabilities (`CAP_BPF`, `CAP_SYS_ADMIN`), volume mounts for `/sys/kernel/btf/vmlinux` and `/proc`, and the `guardian.yaml` ConfigMap reference
- **Package manager**: RPM and DEB packages for major Linux distributions

### Cargo.toml Replaces pyproject.toml

The Python packaging (`pyproject.toml`, `requirements.txt`) is replaced by Cargo's workspace manifest. Python dependencies disappear entirely.

---

## CO-RE: Compile Once Run Everywhere

Phase 2 (BCC) compiles `guardian.bpf.c` on the target machine at load time. This requires clang and kernel headers on every target. Phase 3 (Aya with CO-RE) eliminates this requirement.

The Phase 3 Aya BPF program uses BTF-based CO-RE: instead of hardcoding struct field offsets, it uses `bpf_core_read!()` macros that record relocation entries in the compiled BPF bytecode. At load time, Aya's userspace loader reads `/sys/kernel/btf/vmlinux` and patches the offsets to match the running kernel.

The compiled guardian binary contains the BPF bytecode (with relocation entries) and the userspace loader. On the target machine: copy the binary, run it. No compilation, no clang, no kernel headers. The same binary runs on Ubuntu 22.04 (Linux 5.15), Fedora 40 (Linux 6.8), and RHEL 9 (Linux 5.14) — any Linux 5.8+ kernel with BTF.

This is the fundamental deployment advantage of Phase 3 over Phase 2.

---

## Binary Size and Performance Targets

| Metric | Phase 2 (Python + BCC) | Phase 3 (Rust + Aya) Target |
|--------|------------------------|------------------------------|
| Executable size | N/A (Python scripts) | <10MB (statically linked) |
| Install footprint | ~400MB (Python + clang + BCC) | <10MB (single binary) |
| Container image | ~400MB | <30MB (distroless + binary) |
| Startup time | 3–7 seconds (BCC compilation) | <100ms (embedded BPF, fast Aya load) |
| Memory at steady state | ~25MB (Python + BPF maps) | <20MB (Rust + BPF maps) |
| CPU overhead at 100k syscalls/sec | ~3–5% (Python pipeline + BPF) | ~1–2% (Rust pipeline + BPF) |
| Event processing latency | ~1ms (Python GIL, batching) | ~0.1ms (Rust async, tokio) |

These targets are based on comparable Rust eBPF agents in production (Cilium, Katran, custom internal tools at Meta/Google). They are achievable with straightforward Rust implementation.

---

## Migration Path

See the Migration Guide for full step-by-step instructions. Summary:

**Step 1 — Deploy Phase 3 alongside Phase 2:**
```bash
# Run Phase 3 in dry-run to verify events match
sudo /usr/local/bin/guardian-v3 --config guardian.yaml --dry-run --log-level debug
```

**Step 2 — Verify schema parity:**
Compare events from Phase 2 Python agent and Phase 3 Rust agent on the same host. Field names, types, and chain structure must be identical. The platform UI shows both chains for the same `agent_id`.

**Step 3 — Verify disk buffer compatibility:**
If Phase 2 has buffered events in `pending.jsonl`, Phase 3 must drain them correctly. The JSONL format is language-agnostic JSON — Rust's `serde_json` reads Python-generated JSON correctly.

**Step 4 — Stop Phase 2, start Phase 3:**
```bash
sudo systemctl stop guardian
# Update systemd ExecStart to use guardian-v3 binary
sudo systemctl start guardian
```

**Step 5 — Verify and clean up:**
After 24 hours of Phase 3 running correctly, remove Phase 2 dependencies (Python, BCC, clang) if no longer needed.

**Step 6 — Remove Python agent:**
```bash
sudo apt-get remove python3-bcc clang-14
# Optionally remove Python if not needed for other tools
```

A chain restart (new GENESIS_HASH) on Phase 3 startup is expected and is not an error.

---

## Status

Phase 3 is planned for after Phase 2 is validated in production and the first revenue milestone is reached. The timeline depends on Phase 2 deployment success and customer feedback.

At the start of Phase 3 implementation, the following are already known and proven:
- The exact 16-field event schema (from Phase 1 tests and the proto definition)
- The cryptographic algorithm (SHA-256 + HMAC-SHA256, constants defined)
- The gRPC wire format (unchanged proto)
- The correct eBPF tracepoints and their argument layouts (from Phase 2 validation)
- The configuration file format (guardian.yaml schema)
- The disk buffer format (JSONL, JSON-agnostic)

Phase 3 is implementing a proven design in a better language, not designing a new system. This makes it lower risk than it might appear.

---

## Summary

Phase 3 rewrites the Guardian agent in Rust using Aya, producing a single binary with no runtime dependencies, sub-100ms startup, and memory safety in a privileged process. The proto schema, configuration format, event field schema, and cryptographic algorithms are all unchanged from Phase 1. Phase 3 is the production deployment target: a <30MB container image, 1–2% CPU overhead, and full CO-RE portability across Linux 5.8+ kernels.

---

## Related Documents

- [BCC vs libbpf vs Aya](../06-ebpf/bcc-vs-libbpf-vs-aya.md)
- [Phase 2: Real eBPF](phase2-real-ebpf.md)
- [Migration Guide](migration-guide.md)
- [Guardian Probe Architecture](../06-ebpf/probe-architecture.md)
- [Cryptographic Design](../04-security/cryptographic-design.md)
- [gRPC Contract](../03-data/grpc-contract.md)
