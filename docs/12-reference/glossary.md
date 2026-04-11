# Glossary

Alphabetical definitions of every term used in Guardian's codebase, documentation,
and architecture. If a term appears in a doc or in code and is not defined here,
that is a bug — open an issue.

---

## A

**agent_id**
A UUID (version 4) that uniquely identifies a single Guardian installation. Generated
on first run and persisted to `/var/lib/guardian/.agent_id` (production Linux) or
`~/.guardian_agent_id` (development / macOS). Included in every event and every
`EventBatch` so the platform can correlate events to a specific node. If neither
path is writable, an ephemeral UUID is used for the session only.

**AlertEvent**
A Python dataclass (`agent/local_alerts.py`) emitted by `LocalAlertEngine` when a
rule matches. Fields: `alert_type`, `pid`, `process`, `syscall`, `detail`,
`timestamp`, `agent_id`, `model_name`. Distinct from a `RawEvent` — an `AlertEvent`
is a derived summary, not a raw kernel observation.

**allowlist**
See `network_allowlist`.

**Aya**
A Rust framework for writing eBPF programs. Aya allows both the eBPF kernel program
and the userspace consumer to be written in Rust, using cargo as the build system.
Guardian's Phase 3 rewrite will use Aya. See [why-python-first.md](../11-alternatives/why-python-first.md).

---

## B

**batch**
A collection of `RawEvent` objects flushed together to the platform on a configurable
interval (`batch_interval_ms`, default 100 ms). Each batch is signed as a unit with
an HMAC-SHA256 signature before being sent in an `EventBatch` proto message.

**batch_interval_ms**
Configuration key (`agent.batch_interval_ms`) controlling how often the pipeline
flushes accumulated events to the sender. Default: 100 ms. Lower values reduce
latency to the platform; higher values improve batching efficiency.

**BCC**
BPF Compiler Collection. A toolkit for writing eBPF programs in C with a Python
userspace API. Guardian Phase 2 uses BCC to attach tracepoint probes to the kernel
and receive events in Python via a perf buffer. Not needed in Phase 1 (fake
generator) or Phase 3 (Rust/Aya).

**BPF**
Berkeley Packet Filter. The original (classic) BPF was designed for network packet
filtering. Extended BPF (eBPF) generalises this to arbitrary kernel instrumentation.
See `eBPF`.

**BPFTRACE**
A high-level tracing language built on eBPF, similar to DTrace syntax. Useful for
ad-hoc kernel investigation but not suitable for continuous structured event
collection. Guardian uses raw eBPF (via BCC or libbpf), not bpftrace.

**BTF**
BPF Type Format. Kernel debug information embedded in the kernel image that allows
eBPF programs to access kernel data structures in a type-safe way. Required for
CO-RE. Enabled by `CONFIG_DEBUG_INFO_BTF=y` in the kernel build configuration.
Linux 5.2+ supports BTF; Guardian Phase 2 requires Linux 5.8+ for ring buffer support.

**buffer_path**
Configuration key (`agent.buffer_path`) specifying the directory for the disk buffer
(`pending.jsonl`). Default in development: `~/.guardian/buffer`. Default in
production Linux: `/var/lib/guardian/buffer`. If the configured path is not writable,
Guardian falls back to `~/.guardian/buffer` automatically.

**BUSL-1.1**
Business Source License version 1.1. Guardian's license. Source-available (not OSI
open source); production use requires a commercial license; automatically converts
to Apache 2.0 four years after each release date. See
[why-busl-not-mit.md](../11-alternatives/why-busl-not-mit.md).

---

## C

**CAP_BPF**
A Linux capability (since kernel 5.8) that grants permission to load and attach eBPF
programs without requiring full `CAP_SYS_ADMIN`. Guardian Phase 2 requires either
`CAP_BPF + CAP_PERFMON` or `CAP_SYS_ADMIN` depending on the kernel version.

**chain integrity**
The property that the sequence of events cannot be silently reordered, deleted, or
modified. Guardian implements chain integrity via a per-event SHA-256 hash chain:
each event's `prev_hash` equals the `this_hash` of the preceding event. The first
event's `prev_hash` is `GENESIS_HASH` (64 zeros). See `this_hash`, `prev_hash`.

**CO-RE**
Compile Once, Run Everywhere. A libbpf / BTF feature that allows eBPF programs
compiled on one kernel version to run correctly on different kernel versions by
using BTF type information to adjust memory offsets at load time. Guardian Phase 3
will use CO-RE via Aya.

**compliance mapping**
The association between Guardian events and specific EU AI Act articles. Configured
in `guardian.yaml` under `compliance.articles` (e.g. `[12, 13, 15, 17, 72]`).
The platform uses these article numbers to generate compliance reports.

**container_id**
A 12-character Docker short container ID. Extracted by the `Enricher` from
`/proc/<pid>/cgroup` using a regex match on the Docker cgroup path. Empty string
if the process is not running in a Docker container.

**control_plane**
The `host:port` of the viriato-platform gRPC endpoint. Default:
`grpc.viriatosecurity.com:443`. Set in `guardian.yaml` under `agent.control_plane`.
For local development, use `localhost:50051` with an insecure channel.

---

## D

**DaemonSet**
A Kubernetes resource that ensures exactly one pod runs on every node in a cluster.
Guardian Phase 2 is deployed as a DaemonSet so every node's syscall events are
captured. See the Phase 2 deployment documentation.

**Downward API (Kubernetes)**
A Kubernetes mechanism that exposes pod metadata (pod name, namespace, labels) as
environment variables or volume files inside the pod. Guardian reads
`KUBERNETES_POD_NAME` and `KUBERNETES_NAMESPACE` environment variables injected
by the Downward API to populate `pod_name` and `namespace` on each event.

---

## E

**eBPF**
Extended Berkeley Packet Filter. A Linux kernel subsystem that allows sandboxed
programs to run in kernel space in response to kernel events (syscalls, tracepoints,
kprobes, network packets). eBPF programs are JIT-compiled by the kernel and verified
by the eBPF verifier for safety. Guardian Phase 2 uses eBPF to capture syscall
events with approximately 1% overhead. See
[why-not-ptrace.md](../11-alternatives/why-not-ptrace.md).

**enricher**
The `Enricher` class in `agent/enricher.py`. Mutates each `RawEvent` in-place to
add context that is not available at the kernel level: `agent_id`, `model_name`
(looked up from the `watch` config by process name), `container_id` (from
`/proc/<pid>/cgroup`), `pod_name`, and `namespace` (from environment variables).

**EU AI Act**
The European Union's Artificial Intelligence Act (Regulation 2024/1689). Guardian
is designed to produce compliance evidence for high-risk AI systems under this
regulation. Key articles include: Article 12 (record keeping), Article 13
(transparency), Article 15 (accuracy and robustness), Article 17 (quality
management), Article 72 (post-market monitoring).

**EventBatch**
The proto3 message transmitted from Guardian to viriato-platform in each gRPC
stream chunk. Fields: `agent_id` (field 1), `signature` (field 2), `events`
(field 3, repeated `Event`). The `signature` is an HMAC-SHA256 over the hash
pairs of all events in the batch.

**EventReader**
The `EventReader` class in `agent/reader.py`. Abstracts over the fake event
generator (Phase 1) and the eBPF loader (Phase 2). Source selection: `--fake`
flag or `GUARDIAN_FAKE_EVENTS=1` → generator; `EbpfLoader.is_available()` → eBPF;
otherwise → generator with a warning.

**execve**
The Linux syscall for executing a new program. `execve("/bin/bash", args, env)`
replaces the calling process with a new bash instance. Guardian's `sandbox_escape`
alert fires when `execve` is called with a shell binary path
(`/bin/bash`, `/bin/sh`, `/usr/bin/bash`, `/usr/bin/sh`).

---

## F

**fd_path**
A `RawEvent` field containing the filesystem path for file-related syscalls
(`read`, `write`, `openat`). Empty string for network and other syscalls. In Phase 1
(fake generator), chosen from a pool of realistic model paths. In Phase 2 (eBPF),
resolved from the file descriptor table via `/proc/<pid>/fd/<fd>`.

**FakeEventGenerator**
The `FakeEventGenerator` class in `agent/generator.py`. Generates synthetic
`RawEvent` instances with the exact schema that the Phase 2 eBPF loader will
produce. Used on macOS, in CI, and in dry-run mode. Injects `execve` events every
500–1000 events for local alert testing.

---

## G

**GENESIS_HASH**
The `prev_hash` value for the first event in a chain: `"0" * 64` (64 zero
characters). Defined in `agent/signer.py`. Acts as a sentinel so verifiers know
where the chain begins.

**gRPC**
Google Remote Procedure Call. A high-performance RPC framework using HTTP/2 and
Protocol Buffers. Guardian uses gRPC client streaming (`StreamEvents`) to send
`EventBatch` messages to viriato-platform. The `grpcio` and `grpcio-tools` Python
packages provide the client library and proto compiler integration.

**guardian.yaml**
The configuration file for the Guardian agent. Searched in order:
`./guardian.yaml`, `/etc/guardian/guardian.yaml`, `~/.guardian/guardian.yaml`.
Contains agent credentials, process watch list, syscall list, local alert rules,
network allowlist, and compliance metadata. Must never be committed to version
control (it contains the API token).

---

## H

**HMAC**
Hash-based Message Authentication Code. A construction that uses a secret key and
a cryptographic hash function to produce a message authentication code. Guardian
uses HMAC-SHA256 to sign each `EventBatch`: `HMAC(token, json([{prev, this} for
each event]))`. HMAC is not vulnerable to length extension attacks, unlike bare
SHA-256 of `(secret || message)`.

---

## J

**JIT compiler**
Just-In-Time compiler. The Linux kernel's eBPF JIT compiler translates verified
eBPF bytecode into native machine code before execution. This gives eBPF programs
performance close to natively compiled kernel modules, with the safety guarantees
of the eBPF verifier.

---

## K

**kernel space**
The privileged memory region where the Linux kernel and kernel extensions (including
eBPF programs) execute. Guardian's Phase 2 eBPF probes run in kernel space; the
Python pipeline runs in userspace.

**kprobe**
A kernel probing mechanism that attaches a handler to the entry or exit of any
kernel function. More flexible than tracepoints (can attach to any function, not
just stable trace event points) but less stable across kernel versions. Guardian
Phase 2 uses tracepoints for stability; kprobes may be used for functions without
stable tracepoints.

---

## L

**libbpf**
A C library for loading and interacting with eBPF programs. The successor to BCC
for production eBPF deployments. Used in Phase 3 via the Aya Rust bindings. Unlike
BCC, libbpf programs are compiled ahead-of-time (not at runtime), which eliminates
the LLVM/Clang dependency at deployment time.

**local alert**
An alert evaluated synchronously on each event by `LocalAlertEngine` before the
event is signed or sent. Does not require network access. Current alert types:
`sandbox_escape` (execve to a shell binary) and `unexpected_network` (connect/sendto
to an address not in the allowlist). Alerts are logged to stderr as JSON.

**LRU cache**
Least Recently Used cache. The `Enricher._container_id()` method uses a
`functools.lru_cache(maxsize=512)` to avoid reading `/proc/<pid>/cgroup` on every
event for the same PID. The 512-slot limit prevents unbounded memory growth.

---

## M

**model_name**
The name of the AI model being monitored. Populated by the `Enricher` by looking
up the event's `process` name in the `watch` configuration. For example, if
`watch` maps `python` → `patient-diagnosis-v2`, then all events from `python`
processes have `model_name = "patient-diagnosis-v2"`. Defaults to `"unknown"` if
the process is not in the watch list.

---

## N

**namespace**
The Kubernetes namespace of the pod running Guardian. Read from the
`KUBERNETES_NAMESPACE` environment variable, which is injected by the Kubernetes
Downward API. Empty string in non-Kubernetes deployments.

**network_allowlist**
A list of `host:port` strings specifying permitted outbound network addresses.
Configured in `guardian.yaml` under `network_allowlist`. An empty list means no
restriction. A non-empty list enables the `unexpected_network` alert, which fires
when `connect` or `sendto` targets an address not in the list.

---

## O

**OrbStack**
A macOS application providing lightweight Linux VMs with a modern kernel. Recommended
for Guardian Phase 2 development on macOS, where eBPF is not available natively.
OrbStack VMs have BTF-enabled kernels and integrate with the macOS filesystem.

---

## P

**perf buffer**
A kernel ring buffer used by eBPF programs (via `BPF_MAP_TYPE_PERF_EVENT_ARRAY`) to
send data to userspace. Guardian Phase 2 uses a perf buffer (or ring buffer) to
receive events from the eBPF probe. Events are submitted from kernel space and
consumed by the Python pipeline in userspace.

**pending.jsonl**
The disk buffer file at `{buffer_path}/pending.jsonl`. Each line is a JSON object
containing `agent_id`, `signature`, and a list of serialised events. Written when
the gRPC send fails; read and replayed on the next successful connection. Capped at
10,000 lines to prevent unbounded disk usage.

**PID**
Process ID. A unique integer assigned by the Linux kernel to each process. Included
in every `RawEvent` and `Event`. Used by the `Enricher` to look up the container
ID from `/proc/<pid>/cgroup`.

**prev_hash**
A `RawEvent` field containing the `this_hash` of the preceding event in the chain.
For the first event, `prev_hash = GENESIS_HASH`. Enables chain integrity verification:
any deletion or reordering of events breaks the chain and is detectable.

**proto3**
Protocol Buffers version 3. Google's interface description language and binary
serialisation format. Guardian's event schema is defined in `proto/guardian.proto`.
All fields default to zero values; `required` does not exist in proto3.

---

## R

**RawEvent**
The Python dataclass (`agent/generator.py`) that represents a single kernel event
as captured (or synthesised) before enrichment and signing. All fields have zero
defaults. `Enricher` adds context fields; `Signer` adds `prev_hash` and
`this_hash`. Maps 1:1 to the proto3 `Event` message.

**ring buffer**
A lock-free, memory-efficient kernel buffer (`BPF_MAP_TYPE_RINGBUF`) introduced in
Linux 5.8. Superior to perf buffers for high-throughput event collection. Guardian
Phase 2 targets ring buffers where available.

---

## S

**sandbox escape**
A `LocalAlertEngine` alert type. Fires when a monitored process calls `execve` with
a shell binary path: `/bin/bash`, `/bin/sh`, `/usr/bin/bash`, or `/usr/bin/sh`.
Indicates a potentially exploited container escape or unexpected shell execution
within an AI workload.

**signer**
The `Signer` class in `agent/signer.py`. Responsible for two operations: (1)
setting `prev_hash` and computing `this_hash` on each event (per-event SHA-256
chain), and (2) computing the HMAC-SHA256 batch signature over the chain hashes.
Stateful — holds `_prev_hash` across events.

**syscall**
A kernel interface call made by a userspace program to request a kernel service
(e.g. `read()`, `write()`, `connect()`). Guardian monitors specific syscalls to
build a compliance record of what a process reads, writes, and connects to.

---

## T

**this_hash**
A `RawEvent` field containing the SHA-256 hash of the event's own data (all fields
except `this_hash` itself, JSON-serialised with sorted keys). Computed by
`Signer.sign_event()`. Serves as the `prev_hash` for the subsequent event.

**TimescaleDB**
A PostgreSQL extension for time-series data. viriato-platform stores events in
TimescaleDB, partitioned by time and `agent_id`, enabling efficient range queries
for audit reports.

**TLS**
Transport Layer Security. The gRPC channel to `grpc.viriatosecurity.com:443` uses
TLS with system CA certificates (`grpc.ssl_channel_credentials()`). Insecure
channels are only used for `localhost` or `127.*` addresses, or when
`GUARDIAN_INSECURE_GRPC=1` is set.

**token**
The customer API token from the Viriato Security console. Set in `guardian.yaml`
under `agent.token`. Used as the HMAC key for batch signing. Must be kept secret.
If the token is the placeholder value `YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE`, a
warning is logged and events are buffered locally but not sent.

**tracepoint**
A stable kernel instrumentation point with a defined, version-stable interface.
Tracepoints are preferred over kprobes for Guardian because their argument types
are stable across kernel versions. Defined under `TRACE_EVENT` in kernel source and
exposed as `tracepoint/syscalls/sys_enter_<name>` for syscall entry points.

---

## U

**unexpected_network**
A `LocalAlertEngine` alert type. Fires when a `connect` or `sendto` syscall targets
an address not in `network_allowlist`. Only active when `network_allowlist` is
non-empty (an empty allowlist disables this alert by design — it would fire on every
network call).

**userspace**
The unprivileged memory region where application code (including the Guardian Python
pipeline) runs. Contrast with `kernel space`. eBPF programs run in kernel space and
submit events to userspace via perf/ring buffers.

---

## V

**viriato-platform**
The Viriato Security SaaS backend. Receives `EventBatch` messages from Guardian
agents via the `GuardianIngest` gRPC service, verifies HMAC signatures, stores
events in TimescaleDB, and provides compliance dashboards, EU AI Act article
mapping, and audit report generation.

---

## W

**watched_pids**
Informal term for the set of process IDs whose syscalls Guardian monitors. In Phase 1
(fake generator), the process names come from the `watch` configuration. In Phase 2
(eBPF), the eBPF probe filters by process name using a BPF map of watched process
names. `watched_pids` as a runtime concept refers to the set of active PIDs matching
watched process names at any given moment.

---

## Related Documents

- [faq.md](faq.md)
- [api-reference.md](api-reference.md)
- [error-codes.md](error-codes.md)
- [../../docs/02-architecture/](../02-architecture/)
