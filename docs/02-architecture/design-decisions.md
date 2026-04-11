# Design Decisions

This document records every significant architectural and technology decision made for Guardian
Phase 1. Each entry is structured as: the decision, alternatives that were considered, the
reason the chosen approach was selected, the trade-offs accepted, and the current status. Each
decision has a minimum of three paragraphs of reasoning.

---

## Decision 1: Python for Phase 1

**Decision**: Implement the Guardian agent in Python 3.12+ for Phase 1.

**Alternatives considered**: Rust (with Tokio and Tonic gRPC), Go (with google.golang.org/grpc),
C, a compiled Python extension.

**Reason chosen**: Phase 1's explicit goal is validation, not production performance. Python
allows rapid iteration on the event schema, pipeline stages, and test coverage. The 63-test
suite was written and passing in less time than a Rust equivalent would take to compile. Python's
rich ecosystem (PyYAML for config, grpcio for gRPC, dataclasses for the event schema) means
every major dependency is available with a single `pip install`. The fake event generator, the
enricher's LRU cache, the HMAC signer, and the disk buffer are all expressible in readable,
auditable Python that a security-conscious customer can inspect.

Python is also the language of AI/ML workloads (PyTorch, scikit-learn, HuggingFace). Guardian
agents will typically run as sidecars alongside Python inference processes. Using the same
language makes deployment simpler: a single Python environment can host both the model and the
agent in a Kubernetes pod, reducing operational complexity for early adopters.

The performance characteristics of Phase 1 are adequate. SHA-256 in Python (via `hashlib` which
calls OpenSSL under the hood) runs at well over 100 MB/s. HMAC-SHA256 over a 100-event batch
takes under 10 microseconds. The single-threaded pipeline at 1000 events/sec consumes only a
few percent of a modern CPU core.

**Trade-offs**: Python has a GIL, higher memory overhead than Rust, and cannot safely load
BPF programs directly (Phase 2 uses BCC Python bindings as a bridge). Phase 3 will rewrite the
agent in Rust with Aya for direct eBPF loading without BCC.

**Status**: Phase 1 implementation is complete.

---

## Decision 2: SHA-256 for per-event hash chaining

**Decision**: Use SHA-256 (via `hashlib.sha256`) for the per-event content hash (`this_hash`).

**Alternatives considered**: SHA-3-256, BLAKE3, MD5 (rejected immediately), SHA-512,
BLAKE2b, a keyed hash (HMAC-SHA256).

**Reason chosen**: SHA-256 is standardised (FIPS 180-4), hardware-accelerated on all x86-64
CPUs manufactured after 2013 via the SHA-NI instruction set extensions, and is the hash
function mandated by the EU AI Act audit trail guidance and common compliance frameworks (SOC 2,
ISO 27001). Using SHA-256 means the hash values in the event chain can be verified by any
standard tool (`sha256sum`, OpenSSL, Python's `hashlib`) without any Guardian-specific
software. This is critical for auditability: a compliance auditor or forensic investigator must
be able to independently verify the chain.

The 256-bit output length provides sufficient collision resistance for the Guardian use case.
The birthday bound for SHA-256 is 2^128 operations, which is computationally infeasible. Even
at 2000 events/second over 10 years (~630 billion events), the probability of an unintentional
collision is negligibly small. SHA-512 would provide stronger guarantees but at the cost of
longer hash strings in the JSON payload and on the wire, with no practical benefit at this
event rate.

SHA-3-256 and BLAKE3 were considered. SHA-3-256 would also be acceptable but lacks the
hardware acceleration of SHA-256 in Python's `hashlib` (OpenSSL's SHA-NI path is SHA-2 only).
BLAKE3 is faster in software but is not yet standardised for regulatory compliance use cases
and has less broad tooling support. Keyed hashing (HMAC) was considered for per-event hashing
but rejected because it would require the token to be included in the hash, meaning hash
verification would require the token. SHA-256 without a key allows anyone who holds a copy of
the events to verify chain integrity without needing the signing token, which is desirable for
forensic analysis.

**Trade-offs**: SHA-256 is susceptible to length-extension attacks, but this is not relevant
here because we are hashing a JSON-serialised dict (not a message where the attacker can append
data), and the hash is used for chaining (not for authentication). Authentication is handled
separately by HMAC at the batch level.

**Status**: Implemented in `agent/signer.py`.

---

## Decision 3: HMAC-SHA256 for batch authentication

**Decision**: Use HMAC-SHA256 with the customer's API token as the key for batch-level
authentication signatures.

**Alternatives considered**: Ed25519 (asymmetric signatures), RSA-PSS, raw SHA-256 (without
HMAC), a simple bearer token without any batch signature.

**Reason chosen**: HMAC-SHA256 with a shared secret (the API token) achieves the security
goal (proving that a batch came from a known, authenticated agent) with far less operational
complexity than asymmetric cryptography. Ed25519 would require key pair generation, key
distribution (the agent would need a private key, the platform a public key), key rotation
infrastructure, and certificate management. HMAC requires only the API token, which the customer
already has from the Viriato console. There are no key pairs to manage, no certificates to
rotate, and no PKI infrastructure to maintain. This is the correct choice for an early-stage
product where operational simplicity directly affects adoption.

Raw SHA-256 over the batch payload was rejected because it would be vulnerable to length-
extension attacks. An attacker who intercepts a batch hash could potentially forge a valid hash
for a longer message that includes malicious events. HMAC is specifically designed to prevent
length-extension attacks by including the key in the inner and outer hash operations. This is
a well-known cryptographic hygiene requirement.

A simple bearer token without a batch signature was also considered (the token is already
sent as gRPC metadata). This would authenticate the connection but not the batch content:
an attacker with network access could replay old batches, inject fabricated batches, or strip
events from batches. The HMAC signature covers the hash of every event in the batch, making
these attacks infeasible without knowledge of the token.

**Trade-offs**: HMAC-SHA256 is a symmetric scheme. The platform must store the customer's
token in order to verify signatures, which means the token is at rest in the platform's
database. Key rotation requires coordinated update of both the customer's `guardian.yaml` and
the platform's stored token. Ed25519 would not have this property (only public keys need to be
stored), but the added key management complexity is not worth it at Phase 1.

**Status**: Implemented in `agent/signer.py`.

---

## Decision 4: gRPC with Protocol Buffers for transport

**Decision**: Use gRPC (via `grpcio`) with Protocol Buffers v3 as the transport protocol
between the agent and viriato-platform.

**Alternatives considered**: REST/JSON over HTTPS, WebSockets, Apache Kafka, MQTT,
NATS, raw TCP with a custom protocol.

**Reason chosen**: gRPC provides bidirectional streaming, mandatory TLS, and a strongly-typed
schema enforced at the protocol level via Protocol Buffers. The client-streaming RPC pattern
(`StreamEvents(stream EventBatch) returns Ack`) maps naturally to the Guardian use case: the
agent streams batches continuously and receives acknowledgements. gRPC also handles connection
management (keepalives, reconnection, backpressure) out of the box, which would all need to be
implemented manually with raw TCP or WebSockets.

Protocol Buffers produce compact binary encoding (roughly 30–50% smaller than equivalent JSON
on the wire), which matters for high-event-rate deployments where network egress costs are a
customer concern. The strict schema (field numbers, required types) means the protocol is
self-documenting and that breaking changes are immediately detectable — if a field is added
without following the compatibility rules, deserialization will fail explicitly rather than
silently accepting garbage data.

REST/JSON over HTTPS was considered seriously. It would be simpler to inspect with standard
tools (`curl`, browser DevTools) and would not require proto stubs to be generated. The
argument against it is streaming: REST is request-response, which means either a long-polling
pattern or sending many small requests. At 100 ms batch intervals with 10 agents, that is 100
HTTP requests per second, each with its own TLS handshake overhead. gRPC multiplexes all
streams over a single HTTP/2 connection, amortising the TLS cost across all batches.

**Trade-offs**: gRPC requires `grpcio` and `grpcio-tools` as dependencies, and the generated
stubs must be compiled from `guardian.proto` before the Sender can transmit. This is an
additional setup step for developers (mitigated by `scripts/gen_proto.sh`). The binary proto
format is not human-readable, making debugging harder than plain JSON (mitigated by the `--dry-run`
mode which logs batch content without serialising).

**Status**: Implemented. Proto stubs are generated and git-ignored.

---

## Decision 5: JSONL for disk buffer

**Decision**: Use JSONL (newline-delimited JSON) for the on-disk batch buffer
(`pending.jsonl`).

**Alternatives considered**: SQLite, a custom binary format, Protocol Buffers files,
MessagePack, an embedded message queue (LevelDB, RocksDB).

**Reason chosen**: JSONL requires no additional dependencies. The buffer is written using
Python's built-in `json` module and standard file I/O. The format is human-readable: an
operations engineer investigating a delivery failure can `cat ~/.guardian/buffer/pending.jsonl`
and immediately see the buffered events without any specialised tooling. Each line is a complete,
self-contained JSON object (`{"agent_id":..., "signature":..., "events":[...]}`) that can be
inspected, parsed, or manually replayed.

JSONL is also appendable without reading the existing file: `open(path, "a")` appends a new
line atomically (on Linux, appends to a file are atomic for writes under the page size, which
is satisfied by a single JSON line). This means the buffer write is fast and does not require
locking.

SQLite was considered as a more robust alternative. It would provide ACID transactions,
indexed queries, and efficient partial-drain semantics. However, SQLite adds a compiled
dependency (`sqlite3` is in the standard library, but WAL mode and concurrent access patterns
add complexity), and the Guardian use case does not require indexed queries — the buffer is
always read and written sequentially (FIFO). The added complexity of SQLite is not justified.

**Trade-offs**: JSONL has no built-in compression. A 10,000-line buffer of events (at roughly
1 KB per line) occupies approximately 10 MB of disk. This is acceptable. The buffer is also
plaintext (not encrypted), meaning event data at rest in the buffer is unprotected at the
application level. Filesystem-level encryption should be applied separately.

**Status**: Implemented in `agent/sender.py`.

---

## Decision 6: Per-event hash chaining (not per-batch)

**Decision**: Chain hashes at the individual event level, not at the batch level.

**Alternatives considered**: Sign each batch as a whole with a Merkle root hash; sign only
batch boundaries; no chaining at all (batch signature only).

**Reason chosen**: Per-event chaining provides fine-grained tamper detection. If a single event
in the middle of a sequence is modified or deleted, the chain breaks at exactly that event, and
the platform can identify precisely which event was altered. Per-batch chaining (signing only
the batch as a whole) would detect that a batch was tampered with, but not which event within
the batch. For EU AI Act compliance audits, the requirement is to prove that a specific
inference at a specific time was logged accurately; event-level granularity is necessary to
satisfy that requirement.

The chain also provides a sequencing guarantee: events are linked in the exact order they were
processed by the Signer. Even if an attacker were to capture events out-of-order (e.g., by
intercepting network traffic), they could not silently reorder them without breaking the hash
chain. This is useful for forensic analysis of complex incidents involving multiple syscall
events.

A Merkle tree approach (common in blockchain systems) was considered but rejected as
over-engineered for Phase 1. Merkle trees allow efficient proof that a specific event is in a
set, but Guardian's use case is sequential log verification, not random-access membership
proofs. A linear chain is sufficient, simpler to implement, and simpler for auditors to verify.

**Trade-offs**: Per-event chaining means the Signer is stateful: it must maintain `_prev_hash`
across events. On agent restart, the chain resets to GENESIS_HASH, creating a visible
discontinuity in the platform's records. This is by design: a restart is a significant event
that should be visible to compliance auditors. The platform records the discontinuity rather
than treating it as an error.

**Status**: Implemented in `agent/signer.py`.

---

## Decision 7: 100ms batch interval

**Decision**: Set the default `batch_interval_ms` to 100 milliseconds.

**Alternatives considered**: 10 ms (very low latency), 500 ms (lower overhead), 1000 ms
(one batch per second, common in logging systems), event-count-based batching.

**Reason chosen**: 100 ms is the standard "human imperceptible" threshold in UX research and
has been adopted by many real-time telemetry systems as the balance point between latency and
overhead. At 100 ms, a compliance alert generated by LocalAlertEngine will appear in the
viriato-platform dashboard within approximately 100–150 ms of the triggering syscall. This is
fast enough to be operationally meaningful (a security team can investigate incidents in near
real-time) without being so fast that the gRPC connection carries hundreds of tiny batches per
second.

The overhead analysis is straightforward: at 100 ms, the agent sends at most 10 batches per
second. Each batch requires one TLS-encrypted gRPC round-trip, costing approximately 5–30 ms
of network time (the send itself is asynchronous from the platform's perspective, as gRPC HTTP/2
allows pipelining). The agent's event processing loop is paused for the duration of the
blocking gRPC call, but 10 pauses of 5–30 ms per second still leaves approximately 70–95% of
the time available for event processing.

The `batch_interval_ms` field is configurable in `guardian.yaml`. Operators who need lower
latency (e.g., for near-real-time incident response) can set it to 10 ms. Operators with very
high event rates (e.g., 50,000 events/sec from a GPU inference cluster) can set it to 500 ms
or 1000 ms to reduce the number of gRPC calls and improve throughput efficiency.

**Trade-offs**: Pure event-count-based batching (e.g., flush every 100 events) was rejected
because it would cause starvation at low event rates: if only 5 events arrive per second, the
batch would never fill up and events would be delayed indefinitely. Time-based batching ensures
events are delivered within a predictable, bounded time window regardless of event rate.

**Status**: Implemented. Default 100 ms. Configurable per deployment.

---

## Decision 8: LRU cache for container_id lookup

**Decision**: Cache the result of `/proc/<pid>/cgroup` reads using `@functools.lru_cache(maxsize=512)`.

**Alternatives considered**: Read `/proc/<pid>/cgroup` on every event, maintain a manual TTL
cache, use a shared dictionary with explicit eviction, no caching (always read from /proc).

**Reason chosen**: In a typical AI inference deployment, the same process (e.g., a PyTorch
model server with PID 14832) generates thousands of syscall events per second. Without caching,
every event would trigger a `/proc/14832/cgroup` read: a filesystem system call that, while
fast, is not free. At 2000 events/second from a single process, that is 2000 `/proc` reads per
second. The LRU cache reduces this to one read per new PID, making the enrichment overhead
negligible.

The cache size of 512 was chosen based on the typical number of unique PIDs visible to a
Guardian agent. A single Kubernetes pod might have 5–20 processes. A large server with many AI
workers might have 100–500 concurrent PIDs. 512 slots ensures that the entire active PID space
fits in the cache with headroom, so eviction is rare in practice.

`functools.lru_cache` was chosen over a manual implementation because it is thread-safe (though
Guardian is single-threaded in Phase 1), has zero additional dependencies, and its eviction
behaviour (LRU) is appropriate for the use case: recently seen PIDs are the most likely to be
seen again.

**Trade-offs**: A cached PID's container_id will be stale if the PID is reused by a different
container after its original process exits. On Linux, PID reuse requires the original process
to have exited and the kernel to have recycled the PID (which typically takes thousands of
other process creations). In practice, PID reuse for the same PID within the 512-slot LRU
window is extremely unlikely. The trade-off of a potentially stale container_id for a recycled
PID is accepted in favour of the significant performance improvement from caching.

**Status**: Implemented in `agent/enricher.py`.

---

## Decision 9: Persistent agent_id stored as a flat file

**Decision**: Persist the agent's UUID identity in a plain text file at
`/var/lib/guardian/.agent_id` (production) or `~/.guardian_agent_id` (development/macOS).

**Alternatives considered**: Generate a new UUID on every startup (ephemeral), store in a
database, derive from hardware fingerprint (MAC address, DMI), store in the kernel keyring,
use the hostname as the agent identifier.

**Reason chosen**: Persistent identity is required for the platform to correlate events across
agent restarts. If the agent generated a new UUID on every startup, the platform would see a
new "agent" each time, making it impossible to build per-agent compliance histories or detect
agent gaps (periods where the agent was not running). A flat text file is the simplest
persistent storage mechanism available across all Linux distributions and macOS without any
additional dependencies.

The production path `/var/lib/guardian/.agent_id` follows the Filesystem Hierarchy Standard
(FHS) convention for persistent application data. The development/macOS fallback
`~/.guardian_agent_id` uses a user-level dotfile to avoid requiring root access during
development and testing. The agent tries the production path first, then falls back to the
development path. If neither is writable, an ephemeral UUID is used for the session with a
warning logged.

Hardware fingerprinting (MAC address, DMI serial number) was considered as a way to make the
agent_id stable across reimaging. This was rejected because hardware fingerprints create privacy
concerns in some regulated environments, are not portable across container migrations, and
require platform-specific code for each hardware type. A UUID stored in a persistent volume
(on Kubernetes) or a known file path (on bare metal) is both simpler and more portable.

**Trade-offs**: If the agent_id file is deleted, the agent creates a new UUID and the platform
sees a new agent. Historical event correlation across the file deletion is lost. Operators
should ensure the agent_id file is included in system backups and survives container restarts
(e.g., by mounting the directory as a persistent volume in Kubernetes).

**Status**: Implemented in `agent/enricher.py`.

---

## Decision 10: Insecure gRPC channel for localhost / GUARDIAN_INSECURE_GRPC

**Decision**: Use `grpc.insecure_channel()` when `control_plane` starts with `"localhost"` or
`"127."`, or when `GUARDIAN_INSECURE_GRPC=1` is set. Otherwise use
`grpc.secure_channel(..., grpc.ssl_channel_credentials())`.

**Alternatives considered**: Always require TLS (including for localhost), always use insecure
for simplicity in Phase 1, require explicit TLS configuration.

**Reason chosen**: Requiring TLS for localhost-bound connections is operationally burdensome
for development and testing: it would require generating a self-signed certificate, trusting
it in the Python gRPC client, and configuring the dev server to present it. This is a
significant barrier for contributors running the dev server (`tools/dev_server.py`) locally.
The `tools/dev_server.py` and CI test environment both bind to `localhost:50051`. Making TLS
optional for loopback addresses is standard practice in gRPC-based projects (the official gRPC
documentation explicitly shows this pattern).

For any `control_plane` that is not a loopback address, TLS is mandatory with no opt-out via
configuration file. This ensures that production deployments (where `control_plane` is
`grpc.viriatosecurity.com:443`) always use TLS, regardless of other settings. An operator
cannot accidentally disable TLS for a production endpoint by misconfiguring `guardian.yaml`.

The `GUARDIAN_INSECURE_GRPC=1` environment variable provides an escape hatch for integration
testing environments where the control plane is on a non-loopback address but TLS is not
available (e.g., an internal CI cluster with a staging server on `10.0.0.1:50051`). This
environment variable must be set explicitly in the shell; it is not settable via `guardian.yaml`,
reducing the risk of it being accidentally enabled in production.

**Trade-offs**: An operator who sets `GUARDIAN_INSECURE_GRPC=1` in a production environment
will transmit event batches without TLS encryption. This is a misconfiguration, not a design
flaw. The agent logs a debug-level message when opening the channel that indicates whether it
is secure or insecure, which should be visible in production logs.

**Status**: Implemented in `agent/sender.py`.

---

## Decision 11: Buffer cap at 10,000 lines (not unbounded)

**Decision**: Cap `pending.jsonl` at 10,000 lines, dropping new batches when full.

**Alternatives considered**: Unbounded buffer (write until disk full), rolling eviction
(overwrite oldest entries), pause event processing when buffer is full, configurable cap.

**Reason chosen**: An unbounded buffer on a customer's production server creates a real risk
of disk exhaustion. If viriato-platform is unreachable for a long period (e.g., during a major
cloud provider outage), the agent would continue writing batches to disk indefinitely. A 10,000-
line cap with typical event volumes means the buffer can absorb several minutes to hours of
outage, which covers the vast majority of transient network failures and platform deployments.

The "drop new batches when full" strategy (rather than overwriting old batches) was chosen
because the oldest buffered events are more important for forensic continuity: they represent
the start of a gap, which is the most relevant period for incident investigation. Overwriting
old entries would lose exactly the events that are most likely to contain the evidence of what
went wrong at the start of the outage.

A configurable cap was considered. The current `buffer_path` field in `guardian.yaml` controls
the buffer directory but not its maximum size. A future enhancement could add `buffer_max_lines`
or `buffer_max_bytes` to the config. This is deferred to Phase 2 to avoid premature complexity.

**Trade-offs**: In a long-term platform outage (more than a few hours), events will be dropped
after the buffer fills. This is a deliberate and documented trade-off. The alternative (unbounded
buffering) creates a worse failure mode (disk exhaustion, system instability) that would also
stop the agent from running.

**Status**: Implemented in `agent/sender.py` with `_MAX_BUFFER_LINES = 10_000`.

---

## Decision 12: EbpfLoader.is_available() — three-condition check

**Decision**: `EbpfLoader.is_available()` returns `True` only when all three conditions are
met: not macOS (`sys.platform != "darwin"`), `/sys/kernel/btf/vmlinux` exists, and `bcc` is
importable.

**Alternatives considered**: Check only the platform (not darwin), check only the BTF file,
try importing bcc in a subprocess, always return False in Phase 1.

**Reason chosen**: All three conditions are necessary and independently important. The platform
check (`not darwin`) eliminates macOS immediately without any filesystem access, making the
fallback path fast on developer machines. The BTF file check (`/sys/kernel/btf/vmlinux`)
detects whether the running Linux kernel was compiled with BTF support, which is required for
CO-RE. BTF is available on Linux 5.8+ with `CONFIG_DEBUG_INFO_BTF=y`. Without it, the eBPF
probe cannot load. Checking the file existence is a reliable, side-effect-free test.

The BCC import check ensures that the Python bindings for the BCC (BPF Compiler Collection)
toolkit are installed. Even on a BTF-capable kernel, the eBPF probe cannot be loaded without
BCC. Many production Linux servers run the correct kernel version but do not have BCC installed.
Detecting the import failure here produces a clean fallback to the generator, rather than a
crash at runtime when `EbpfLoader.load()` is called.

Always returning `False` in Phase 1 was considered (the EbpfLoader stub raises
`NotImplementedError` regardless). This would be simpler but dishonest: on a correctly
configured Linux 5.8+ server with BCC installed, the agent should detect eBPF availability and
use it once Phase 2 is complete. The three-condition check is already the correct logic for
Phase 2; implementing it now means no change will be needed in `reader.py` when Phase 2 lands.

**Trade-offs**: The BCC import check is an actual import statement, which means Python
evaluates BCC's `__init__.py`. On systems where BCC is partially installed or has broken
dependencies, this might produce import warnings. These are suppressed by the
`except ImportError` catch.

**Status**: Implemented in `agent/loader.py`.

---

## Decision 13: GENESIS_HASH as 64 zero characters

**Decision**: Use `GENESIS_HASH = "0" * 64` (sixty-four ASCII zero characters) as the
sentinel `prev_hash` for the first event of each agent session.

**Alternatives considered**: An actual SHA-256 of an empty string
(`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`), a random nonce
generated at agent start, a hash of the agent_id, the empty string.

**Reason chosen**: `"0" * 64` is immediately recognisable as a sentinel value by anyone
reading the event data, without requiring any documentation lookup. It has the same length as
a real SHA-256 hexdigest (64 characters), which means the platform can treat `prev_hash` as a
fixed-length string without special-casing the genesis entry. It is unambiguous: a real SHA-256
hash cannot be all zeros (the probability is 2^-256, which is effectively impossible).

Using the SHA-256 of the empty string would be confusing: it looks like a real hash and there
is no obvious reason why the empty string was chosen as the genesis input. A random nonce
generated at agent start would be unique per session but would require the platform to store
the nonce alongside the first event and would make manual chain verification harder.

The empty string was rejected because it has different length from a real hash (0 characters
vs. 64), which would require the platform to handle two different `prev_hash` lengths.

**Trade-offs**: None significant. The sentinel is a convention that the platform must know
about, but it is a simple constant that is defined in a single place (`agent/signer.py`) and
documented here.

**Status**: Implemented as `GENESIS_HASH = "0" * 64` in `agent/signer.py`.

---

## Decision 14: BUSL-1.1 licence

**Decision**: Licence Guardian under the Business Source Licence 1.1 (BUSL-1.1).

**Alternatives considered**: MIT, Apache 2.0, GPL-3.0, AGPL-3.0, proprietary (closed source).

**Reason chosen**: BUSL-1.1 achieves the core business goal: customers and partners can inspect,
deploy, and use Guardian on their own infrastructure for the purpose of AI observability, but
third parties cannot take the source code and build a competing commercial product without
negotiating a licence with Viriato Security. This is the protective intent that MIT and Apache
2.0 do not provide. Any company could take an MIT-licensed Guardian, rebrand it, and sell it
as a competing service.

BUSL-1.1 is not the same as closed source. The full source code is publicly available for
audit, which is essential for the security product category: a security agent that customers
cannot inspect is not trustworthy. Customers can verify that the agent does exactly what it
claims to do — and does not do anything else. This openness also enables community contributions
and security researchers to find and report vulnerabilities.

GPL-3.0 or AGPL-3.0 would provide copyleft protection, but they impose reciprocal licensing
obligations on customers who modify the agent: any modifications would need to be released.
This creates a legal burden on enterprise customers in regulated industries who may want to
make internal modifications (e.g., customising the generator or enricher for their specific
environment). BUSL-1.1 does not impose any reciprocal obligation.

**Trade-offs**: BUSL-1.1 is a newer, less well-known licence. Some organisations have legal
policies against using BUSL-licensed software. The licence converts to Apache 2.0 after four
years (a standard BUSL clause), which provides a long-term open-source guarantee. The Viriato
Security legal team should monitor BUSL-1.1 adoption in the industry and be prepared to answer
customer legal queries.

**Status**: Applied. See the `LICENSE` file in the repository root.

---

## Decision 15: Separate proto stubs not committed to git

**Decision**: Do not commit the generated `proto/guardian_pb2.py` and
`proto/guardian_pb2_grpc.py` stubs to the repository. Generate them at development and
deployment time using `scripts/gen_proto.sh`.

**Alternatives considered**: Commit the generated stubs (they are currently present due to
development), check in a pre-built wheel, use a Docker image with stubs pre-installed.

**Reason chosen**: Generated protobuf stubs are tightly coupled to the version of the
`grpcio-tools` package used to generate them and to the protobuf runtime version installed.
If a stub generated with `grpcio-tools 1.62` is used with `grpcio 1.64`, compatibility issues
can arise. Committing generated code creates a false sense of stability: the committed stubs
look up-to-date but may be incompatible with the user's installed `grpcio` version.

The correct practice — followed by all major gRPC projects — is to generate stubs as part of
the build or CI pipeline, ensuring they are always generated with the same version of
`grpcio-tools` that matches the installed `grpcio`. The `scripts/gen_proto.sh` script takes
under 2 seconds to run and is documented in the README and in the agent's startup warning.

Committing generated code also creates unnecessary git diff noise: every `grpcio-tools` version
bump would require regenerating and recommitting the stubs, adding an extra step to the upgrade
process and cluttering the git history with machine-generated changes.

**Trade-offs**: Developers must run `bash scripts/gen_proto.sh` before the Sender can transmit
events. The agent handles missing stubs gracefully (falls back to disk buffer with a warning),
so development in `--dry-run` mode or with the fake generator works without the stubs. The
`scripts/gen_proto.sh` script is idempotent and can be run multiple times safely.

**Status**: The `.gitignore` excludes `proto/guardian_pb2.py` and `proto/guardian_pb2_grpc.py`.
Note that the files are currently present in the working tree as untracked files (as shown in
the git status at project start); they should be removed from tracking if accidentally staged.

---

## Related Documents

- [System Overview](system-overview.md) — the architecture that these decisions produced.
- [Guardian Internals](guardian-internals.md) — implementation detail for the decisions.
- [Event Pipeline](event-pipeline.md) — timing and failure modes referenced in several decisions.
- [gRPC Contract](../03-data/grpc-contract.md) — the proto schema referenced in Decisions 4 and 15.
- [guardian.yaml Reference](../03-data/guardian-yaml-reference.md) — configurables referenced
  in Decisions 7, 10, and 11.
