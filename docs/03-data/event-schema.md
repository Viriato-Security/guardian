# Event Schema

This document fully documents every field of the `RawEvent` dataclass defined in
`agent/generator.py`. `RawEvent` is the central data type of the Guardian pipeline: every
stage from the EventReader through to the gRPC Sender operates on instances of this class.

---

## Overview Table

| # | Field | Type | Default | Source stage | Proto field # |
|---|---|---|---|---|---|
| 1 | timestamp | str | `""` | kernel / generator | 1 |
| 2 | pid | int | `0` | kernel / generator | 2 |
| 3 | process | str | `""` | kernel / generator | 3 |
| 4 | syscall | str | `""` | kernel / generator | 4 |
| 5 | fd_path | str | `""` | kernel / generator | 5 |
| 6 | bytes | int | `0` | kernel / generator | 6 |
| 7 | network_addr | str | `""` | kernel / generator | 16 |
| 8 | return_val | str | `"0"` | kernel / generator | 7 |
| 9 | uid | int | `0` | kernel / generator | 8 |
| 10 | agent_id | str | `""` | enricher | 11 |
| 11 | model_name | str | `""` | enricher | 12 |
| 12 | container_id | str | `""` | enricher | 13 |
| 13 | pod_name | str | `""` | enricher | 14 |
| 14 | namespace | str | `""` | enricher | 15 |
| 15 | prev_hash | str | `""` | signer | 9 |
| 16 | this_hash | str | `""` | signer | 10 |

Fields 1–9 are populated by the kernel eBPF probe (Phase 2) or the `FakeEventGenerator`
(Phase 1). Fields 10–14 are populated by the `Enricher`. Fields 15–16 are populated by the
`Signer`. The event is fully populated by the time it reaches the Sender.

---

## Field Details

### Field 1: timestamp

| Property | Value |
|---|---|
| Python type | `str` |
| Format | ISO 8601, nanosecond precision, UTC, Z suffix |
| Example | `"2026-04-10T14:22:01.123456000Z"` |
| Constraints | Must be a valid ISO 8601 datetime string ending in Z. Nanoseconds: digits 20–28 of the string are the fractional seconds (9 digits). |
| Source | Phase 2: `bpf_ktime_get_boot_ns()` in kernel, converted to wall-clock UTC by EbpfLoader. Phase 1: `datetime.now(timezone.utc)` with microseconds zero-padded to nanoseconds. |
| If empty | The event is still valid but cannot be accurately placed in a time-series. The platform will log a warning. |
| Proto field | 1 (string) |

The timestamp format deliberately uses nanosecond precision even though Python's `datetime`
only provides microsecond resolution in Phase 1. The generator pads the microsecond field with
three trailing zeros (`f"{us:06d}000"`) to produce a 9-digit fractional seconds value. This
ensures schema consistency with Phase 2, where the kernel ring buffer provides genuine
nanosecond timestamps.

The timestamp is set at the moment the syscall enters the kernel (Phase 2) or at the moment
the generator produces the event (Phase 1). It is never modified by the Enricher or Signer.
Because it is included in the `this_hash` computation (as part of the full event dict), any
alteration to the timestamp after signing will invalidate the hash.

**EU AI Act relevance**: Article 12 (Record-keeping) requires that high-risk AI systems
maintain logs of activity with sufficient temporal precision to reconstruct the sequence of
events. The nanosecond-precision UTC timestamp directly satisfies this requirement.

---

### Field 2: pid

| Property | Value |
|---|---|
| Python type | `int` |
| Format | Unsigned 32-bit integer (Linux PID range: 1 to 4,194,304) |
| Example | `14832` |
| Constraints | Non-negative. 0 is the kernel idle process; Guardian events from userspace processes will have PID ≥ 1. |
| Source | Phase 2: `bpf_get_current_pid_tgid() >> 32`. Phase 1: `random.randint(1000, 65535)`. |
| If empty / zero | The event cannot be correlated to a specific process. The Enricher will attempt `/proc/0/cgroup`, which will fail silently and set `container_id = ""`. |
| Proto field | 2 (int32) |

PID is used by the Enricher to look up the container_id via `/proc/<pid>/cgroup`. It is also
available to the platform for incident correlation: if an alert fires for process PID 14832, a
security analyst can correlate it with other events from the same PID in the same time window.

**EU AI Act relevance**: Article 13 (Transparency) requires that high-risk AI systems be
designed to allow users to interpret their outputs and identify the responsible AI system.
The PID, combined with `process` and `model_name`, allows viriato-platform to attribute a
syscall to a specific AI model deployment.

---

### Field 3: process

| Property | Value |
|---|---|
| Python type | `str` |
| Format | Process executable name, up to 15 characters (Linux `comm` limit) in Phase 2 |
| Example | `"python"`, `"torchserve"` |
| Constraints | Non-empty for valid events. Phase 2 truncated to 15 chars by `bpf_get_current_comm()`. |
| Source | Phase 2: `bpf_get_current_comm()`. Phase 1: from the `watch` list in config, or `"python"` as default. |
| If empty | `model_name_for_process("")` returns `"unknown"`. The event is still valid. |
| Proto field | 3 (string) |

The `process` field is the primary key for the Enricher's `watch` list lookup. The Enricher
calls `config.model_name_for_process(event.process)` and stores the result in `model_name`.
Because Linux `bpf_get_current_comm()` returns the first 15 characters of the task's `comm`
field, process names longer than 15 characters will be truncated. Guardian's generator uses
full names (`"python"`, `"torchserve"`) that are within this limit.

**EU AI Act relevance**: Article 9 (Risk management) requires that high-risk AI systems
identify the components responsible for risk. The `process` field identifies which executable
is generating syscalls, enabling the platform to attribute risk events to specific AI components.

---

### Field 4: syscall

| Property | Value |
|---|---|
| Python type | `str` |
| Format | Lowercase syscall name |
| Example | `"read"`, `"write"`, `"openat"`, `"sendto"`, `"recvfrom"`, `"connect"`, `"socket"`, `"clone"`, `"execve"` |
| Constraints | Must be one of the syscalls in the `syscalls` list in `guardian.yaml`. Phase 1 also injects `"execve"` periodically regardless of config. |
| Source | Phase 2: set per-tracepoint in the BPF handler. Phase 1: randomly sampled from weighted pool. |
| If empty | The event cannot trigger any local alert rules (both rules check `syscall` first). The platform may raise an anomaly. |
| Proto field | 4 (string) |

The syscall name is the primary discriminator for local alert rules. The `sandbox_escape` rule
triggers only on `"execve"`. The `unexpected_network` rule triggers on `"connect"` and
`"sendto"`. The syscall also drives the selection of additional fields in the generator: events
with `"read"`, `"write"`, or `"openat"` syscalls will have `fd_path` and `bytes` populated;
events with `"sendto"`, `"recvfrom"`, or `"connect"` will have `network_addr` populated.

**EU AI Act relevance**: Articles 9 and 72 (Cybersecurity). The syscall name identifies the
type of system interaction, which is the foundational data for detecting adversarial
manipulation and unauthorized access to AI system resources.

---

### Field 5: fd_path

| Property | Value |
|---|---|
| Python type | `str` |
| Format | Absolute filesystem path or empty string |
| Example | `"/var/lib/models/patient-diagnosis-v2/model.pt"`, `"/proc/self/status"`, `"/dev/urandom"` |
| Constraints | May be empty for syscalls that do not involve file descriptors (e.g., `socket`, `clone`). |
| Source | Phase 2: `bpf_probe_read_user_str()` from the `filename` argument of the syscall. Phase 1: selected from a realistic pool of model and system paths. |
| If empty | Normal for network-only syscalls. The `sandbox_escape` rule checks `fd_path` against a set of shell binaries; an empty `fd_path` will never match. |
| Proto field | 5 (string) |

For `execve` syscalls, `fd_path` is the path of the binary being executed. This is the value
checked by the `sandbox_escape` rule against `{"/bin/bash", "/bin/sh", "/usr/bin/bash",
"/usr/bin/sh"}`. If an AI model process calls `execve("/bin/bash", ...)`, the local alert
engine fires immediately.

For `read`, `write`, and `openat` syscalls, `fd_path` identifies which file the process is
reading from or writing to. This is valuable for detecting model exfiltration (reads from model
weight files) and model poisoning (writes to model directories).

**EU AI Act relevance**: Article 15 (Accuracy and robustness). File access patterns for model
weight files, configuration files, and system files provide evidence for assessing whether the
AI system's operational environment is intact and unmodified.

---

### Field 6: bytes

| Property | Value |
|---|---|
| Python type | `int` |
| Format | Non-negative integer, bytes transferred |
| Example | `32768`, `4096`, `0` |
| Constraints | 0 for syscalls that do not transfer data (socket, clone, execve). Non-negative. |
| Source | Phase 2: `count` argument to read/write; `len` argument to sendto/recvfrom. Phase 1: `random.randint(512, 65536)` for file syscalls; `random.randint(64, 4096)` for network syscalls. |
| If empty / zero | Normal for non-data-transfer syscalls. |
| Proto field | 6 (int64) |

The `bytes` field enables the platform to detect data volume anomalies. A model server that
normally reads 32 KB of model weights per inference request and suddenly reads 1 GB is an
anomaly that could indicate model exfiltration or a data pipeline bug. The Anomaly Detection
module in viriato-platform builds per-model baselines for typical bytes-per-syscall distributions.

**EU AI Act relevance**: Article 17 (Quality management). Data volume anomalies can indicate
quality issues in the AI system's data handling, which must be monitored under a quality
management system.

---

### Field 7: network_addr

| Property | Value |
|---|---|
| Python type | `str` |
| Format | `"ip:port"` string, IPv4 or IPv6, or empty string |
| Example | `"10.0.0.1:8080"`, `"203.0.113.42:443"`, `""` |
| Constraints | Empty for non-network syscalls. IPv6 addresses should use the `[::1]:port` bracket notation in Phase 2. |
| Source | Phase 2: parsed from the `sockaddr` structure in `connect`/`sendto`/`recvfrom` arguments. Phase 1: selected from internal and external address pools. |
| If empty | Normal for file-only syscalls. The `unexpected_network` rule will not fire (it checks `syscall` first, before `network_addr`). |
| Proto field | 16 (string) — note: field number 16 is the last in the proto, matching the order in which it was added to the generator |

The `network_addr` field is the primary data for the `unexpected_network` alert rule. When the
`network_allowlist` in `guardian.yaml` is non-empty, any `connect` or `sendto` syscall to an
address not in the allowlist fires an alert immediately, before the event is even signed.

For forensic analysis of data exfiltration incidents, the combination of `network_addr` and
`bytes` tells the story: which external address the model connected to and how much data was
sent.

**EU AI Act relevance**: Article 72 (Cybersecurity). Unauthorized outbound network connections
from AI systems are a key attack vector for model exfiltration and must be detected and logged.

---

### Field 8: return_val

| Property | Value |
|---|---|
| Python type | `str` |
| Format | Decimal integer as a string, typically `"0"` on success or a negative errno value on failure |
| Example | `"0"`, `"-1"`, `"-13"` (EACCES), `"-22"` (EINVAL) |
| Constraints | The default is `"0"`. String type (not int) to accommodate large return values and errno codes. |
| Source | Phase 2: set in the `sys_exit` tracepoint handler. Phase 1: `"0"` normally; negative errno with 3% probability. |
| If empty | Treated as success (`"0"`) by the platform. |
| Proto field | 7 (string) |

`return_val` is stored as a string rather than an integer because the Linux `long` return value
can be outside the range of a 32-bit signed integer, and storing it as a string avoids type
coercion issues. The platform parses it as an integer for analysis purposes.

Negative return values indicate syscall failures. A model server that experiences repeated
`EACCES (-13)` errors on `openat` calls to its model weight file may have a permissions problem
or may be under attack (a malicious process modifying file permissions). The platform can
aggregate error rates per syscall and model to detect these patterns.

**EU AI Act relevance**: Article 9. Syscall failure patterns are part of the risk management
evidence base for high-risk AI systems.

---

### Field 9: uid

| Property | Value |
|---|---|
| Python type | `int` |
| Format | Unsigned 32-bit integer, Linux UID |
| Example | `1001`, `0` (root) |
| Constraints | 0 = root. Non-negative. |
| Source | Phase 2: `bpf_get_current_uid_gid() & 0xFFFFFFFF`. Phase 1: `random.randint(0, 1000)`. |
| If empty / zero | UID 0 is root. Events from root processes should be treated with elevated scrutiny by the compliance engine. |
| Proto field | 8 (int32) |

The UID identifies the operating system user under which the AI process is running. A
production AI inference server should never run as root. If `uid == 0` appears in events
from an AI process, this is a privilege anomaly that warrants an alert. The platform's
Anomaly Detection module flags root-owned AI process events as high-severity.

**EU AI Act relevance**: Article 9. Running AI systems with excessive privileges is a risk
management failure that must be detected and documented.

---

### Field 10: agent_id

| Property | Value |
|---|---|
| Python type | `str` |
| Format | UUID version 4, canonical lowercase with hyphens |
| Example | `"f47ac10b-58cc-4372-a567-0e02b2c3d479"` |
| Constraints | Must be a valid UUID4. Validated by `uuid.UUID(agent_id)` on load. |
| Source | Enricher: loaded from `/var/lib/guardian/.agent_id` or `~/.guardian_agent_id`. Created on first run. |
| If empty | Events without an agent_id cannot be attributed to a specific Guardian installation. The platform will reject them. |
| Proto field | 11 (string) |

`agent_id` is the stable identity of the Guardian installation. It is also sent as a top-level
field in the `EventBatch` proto message (field 1), allowing the platform to identify which
agent is sending without inspecting every event. Within the event itself, `agent_id` is hashed
into `this_hash`, ensuring the identity is cryptographically committed.

**EU AI Act relevance**: Article 12. The audit log must identify the specific AI system
deployment. `agent_id` provides this identity for each Guardian installation.

---

### Field 11: model_name

| Property | Value |
|---|---|
| Python type | `str` |
| Format | Free-form string; typically a semantic version identifier |
| Example | `"patient-diagnosis-v2"`, `"fraud-detection-v1"`, `"unknown"` |
| Constraints | `"unknown"` if the process is not in the `watch` list. Never empty after enrichment (returns `"unknown"` on miss). |
| Source | Enricher: `config.model_name_for_process(event.process)`. |
| If empty | After enrichment it will be `"unknown"`, not empty. An empty value in stored data indicates the enricher was bypassed. |
| Proto field | 12 (string) |

`model_name` allows the platform to aggregate events by AI model, not just by process name.
The same `python` process might host different models at different times; the `watch` list in
`guardian.yaml` maps process names to their current model. This field is the primary grouping
key for compliance dashboards, which show EU AI Act coverage per model.

**EU AI Act relevance**: Article 13. Model identity must be recorded in the audit log so that
compliance obligations can be attributed to specific AI systems.

---

### Field 12: container_id

| Property | Value |
|---|---|
| Python type | `str` |
| Format | 12-character Docker short container ID (hex) or empty string |
| Example | `"a3b4c5d6e7f8"`, `""` (not in a container) |
| Constraints | Exactly 12 characters if populated; empty string if not in a container or if `/proc/<pid>/cgroup` cannot be parsed. |
| Source | Enricher: parsed from `/proc/<pid>/cgroup` using regex `r"/docker/([a-f0-9]{12,64})"`. LRU-cached (512 slots). |
| If empty | The workload is running on bare metal or in a non-Docker container (e.g., containerd CRI without a Docker-format cgroup path). |
| Proto field | 13 (string) |

The 12-character short container ID matches the format used by `docker ps` output, making it
easy for operators to correlate Guardian events with container lifecycle events from Docker
logs. The platform uses container_id as part of the deployment context for compliance mapping.

**EU AI Act relevance**: Article 17. Container identity is part of the deployment audit trail
required for quality management systems governing high-risk AI.

---

### Field 13: pod_name

| Property | Value |
|---|---|
| Python type | `str` |
| Format | Kubernetes pod name (DNS subdomain, lowercase) or empty string |
| Example | `"diagnosis-inference-7d9f8c-xkbvp"`, `""` (not in Kubernetes) |
| Constraints | Set from `KUBERNETES_POD_NAME` environment variable. Empty if the variable is not set. |
| Source | Enricher: `os.environ.get("KUBERNETES_POD_NAME", "")` at Enricher init. |
| If empty | The workload is not running in Kubernetes or the Downward API is not configured. |
| Proto field | 14 (string) |

In Kubernetes deployments, the Downward API injects `KUBERNETES_POD_NAME` as an environment
variable into the pod. The Enricher reads this once at startup. The pod name provides the
Kubernetes-layer identity for the event, complementing the `container_id` (Docker layer) and
`namespace` (Kubernetes namespace layer).

**EU AI Act relevance**: Article 12. Kubernetes pod identity is part of the infrastructure
audit trail for cloud-native AI deployments.

---

### Field 14: namespace

| Property | Value |
|---|---|
| Python type | `str` |
| Format | Kubernetes namespace name (DNS label, lowercase) or empty string |
| Example | `"production"`, `"ai-inference"`, `""` |
| Constraints | Set from `KUBERNETES_NAMESPACE` environment variable. Empty if not in Kubernetes. |
| Source | Enricher: `os.environ.get("KUBERNETES_NAMESPACE", "")` at Enricher init. |
| If empty | Not running in Kubernetes or the Downward API is not configured. |
| Proto field | 15 (string) |

The Kubernetes namespace provides the multi-tenant context. In a cluster where multiple teams
deploy AI models (e.g., `"team-a"` and `"team-b"` namespaces), the platform can segregate
compliance views by namespace, ensuring each team's compliance officer sees only their own
events.

**EU AI Act relevance**: Article 13. Multi-tenant isolation is a transparency requirement for
shared AI infrastructure.

---

### Field 15: prev_hash

| Property | Value |
|---|---|
| Python type | `str` |
| Format | 64-character lowercase SHA-256 hexdigest or `GENESIS_HASH = "0" * 64` |
| Example | `"0000000000000000000000000000000000000000000000000000000000000000"` (genesis), `"a3f1b2...d9"` |
| Constraints | Exactly 64 hex characters. `"0" * 64` for the first event of each agent session. |
| Source | Signer: `event.prev_hash = self._prev_hash` (the `this_hash` of the previous event). |
| If empty | Invalid state — indicates the Signer was bypassed. The platform will reject the event or flag the chain as broken. |
| Proto field | 9 (string) |

`prev_hash` links this event to the previous event in the chain. Together with `this_hash`,
it forms the tamper-evident linked list. Any modification to any event in the chain (including
its `prev_hash`) will cause all subsequent `prev_hash` values to become inconsistent, making
tampering immediately detectable.

**EU AI Act relevance**: Article 12. Tamper-evident logging is a core record-keeping
requirement. The hash chain provides cryptographic proof that the log has not been modified
after capture.

---

### Field 16: this_hash

| Property | Value |
|---|---|
| Python type | `str` |
| Format | 64-character lowercase SHA-256 hexdigest |
| Example | `"7b2c4f8a1e9d3..."` (a real SHA-256 hex string) |
| Constraints | Exactly 64 hex characters. Computed as `SHA-256(json.dumps(asdict(event) without this_hash, sort_keys=True, separators=(',',':')))`. |
| Source | Signer: `event.this_hash = Signer._hash_event(event)`. |
| If empty | Invalid state — indicates the Signer was bypassed. The platform will reject the event. |
| Proto field | 10 (string) |

`this_hash` is the cryptographic commitment to this event's content. It covers all 15 other
fields (including `prev_hash`, which itself links to the previous event). The hash is computed
with `sort_keys=True` to ensure deterministic serialisation regardless of Python dict insertion
order, and `separators=(',',':')` to produce compact JSON with no superfluous whitespace.

The `this_hash` field itself is explicitly excluded from the hash input (`d.pop("this_hash", None)`)
to avoid the circularity of hashing a field whose value depends on the hash.

**EU AI Act relevance**: Articles 12, 72. `this_hash` provides the per-event integrity
guarantee. The Compliance Engine at viriato-platform can present `this_hash` values as
cryptographic evidence of log integrity to regulators.

---

## EU AI Act Article Summary

| Article | Title | Fields that serve it |
|---|---|---|
| 9 | Risk management | syscall, uid, return_val, process |
| 12 | Record-keeping | timestamp, pid, agent_id, prev_hash, this_hash |
| 13 | Transparency | process, model_name, namespace, container_id |
| 15 | Accuracy and robustness | fd_path, bytes, syscall |
| 17 | Quality management | bytes, return_val, container_id |
| 72 | Cybersecurity | network_addr, syscall, this_hash, prev_hash |

---

## Related Documents

- [Event Pipeline](../02-architecture/event-pipeline.md) — when each field is populated.
- [gRPC Contract](grpc-contract.md) — how these fields map to proto field numbers.
- [Data Flow](data-flow.md) — which fields are hashed, signed, and transmitted.
- [guardian.yaml Reference](guardian-yaml-reference.md) — how `watch`, `syscalls`, and
  `network_allowlist` influence which events are generated and how fields are populated.
