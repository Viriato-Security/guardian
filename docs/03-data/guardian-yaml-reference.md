# guardian.yaml Reference

This document is the complete reference for every field in `guardian.yaml`, Guardian's
configuration file. It covers the three search paths, every field with its type, default,
constraints, and behaviour, and the two environment variables that override configuration-file
settings.

---

## Configuration File Search

When `load_config(path=None)` is called (i.e., the `--config` flag was not given), the loader
searches the following paths in order, stopping at the first file that exists:

| Priority | Path | Typical use case |
|---|---|---|
| 1 | `./guardian.yaml` | Running from the repo root during development |
| 2 | `/etc/guardian/guardian.yaml` | System-wide installation (Linux, production) |
| 3 | `~/.guardian/guardian.yaml` | Per-user installation (macOS, development) |

If the `--config FILE` flag is provided on the command line, the search is bypassed and the
specified file is used directly. If the specified file does not exist, the agent raises
`FileNotFoundError` immediately without falling back to the search paths.

If no configuration file is found in any of the three search paths (and `--config` was not
given), the agent raises `FileNotFoundError` with a message listing all tried paths and a
hint to copy `guardian.yaml.example`.

---

## Top-Level Structure

A complete `guardian.yaml` looks like this:

```yaml
agent:
  token: "YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE"
  control_plane: "grpc.viriatosecurity.com:443"
  batch_interval_ms: 100
  buffer_path: "~/.guardian/buffer"

watch:
  - process: "python"
    model_name: "patient-diagnosis-v2"
  - process: "torchserve"
    model_name: "fraud-detection-v1"

syscalls:
  - read
  - write
  - openat
  - sendto
  - recvfrom
  - connect
  - execve
  - clone
  - socket

local_alerts:
  - type: sandbox_escape
    condition: "execve matches /bin/bash or /bin/sh"
    action: log_and_alert
  - type: unexpected_network
    condition: "connect to addr not in allowlist"
    action: log_and_alert

network_allowlist: []

compliance:
  organization: "Acme Healthcare AI"
  data_categories:
    - medical_records
    - PII
  articles: [12, 13, 15, 17, 72]
```

---

## Section: agent

The `agent` section controls low-level agent behaviour. All fields are nested under the `agent:`
key.

### agent.token

| Property | Value |
|---|---|
| Type | string |
| Required | Yes (effectively) |
| Default | None — must be provided |
| Example | `"vsk_prod_f47ac10b58cc4372a5670e02b2c3d479"` |

The customer API token obtained from the Viriato Security console. This token is used for two
purposes: as the HMAC-SHA256 key for batch signing (in the Signer), and as the
`Authorization: Bearer <token>` gRPC metadata header (in the Sender).

The token must not be empty and must not be the placeholder value
`"YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE"`. If either condition is true, the agent logs a warning
at startup:
```
Guardian token is not set or is still the placeholder. Events will be buffered locally
but NOT sent to viriato-platform. Obtain a real token at https://viriatosecurity.com
```
The agent continues to run with a placeholder token — signing, chaining, and buffering events
locally — but will not transmit events until a valid token is set.

**Security**: treat this value as a secret. Do not commit `guardian.yaml` with a real token
to version control. Set file permissions to `0600` (owner read/write only). In Kubernetes,
inject via a Secret volume mount rather than embedding in the ConfigMap.

**Invalid values**: any non-empty string is accepted by the loader. The platform will reject
batches signed with an incorrect token with a gRPC `PERMISSION_DENIED` error. Batches rejected
by the platform are buffered locally and retried automatically once the correct token is
configured.

---

### agent.control_plane

| Property | Value |
|---|---|
| Type | string |
| Required | No |
| Default | `"grpc.viriatosecurity.com:443"` |
| Example | `"grpc.viriatosecurity.com:443"`, `"localhost:50051"` |

The `host:port` address of the viriato-platform gRPC endpoint. The agent opens a persistent
gRPC channel to this address at startup.

**TLS behaviour**: if the value starts with `"localhost"` or `"127."`, or if the environment
variable `GUARDIAN_INSECURE_GRPC=1` is set, the agent uses `grpc.insecure_channel()`.
Otherwise `grpc.secure_channel(..., grpc.ssl_channel_credentials())` is used. The production
endpoint `grpc.viriatosecurity.com:443` always uses TLS.

**Invalid values**: if the address is malformed (e.g., missing the port), the gRPC channel
creation may succeed but the first `StreamEvents` call will fail with a `UNAVAILABLE` error.
Events will be buffered locally.

---

### agent.batch_interval_ms

| Property | Value |
|---|---|
| Type | integer |
| Required | No |
| Default | `100` |
| Unit | milliseconds |
| Valid range | 1 to 60000 (1 ms to 60 s) |
| Example | `100`, `500`, `1000` |

The time interval between batch flushes. After `batch_interval_ms` milliseconds have elapsed
since the last flush, all accumulated events are signed as a batch, serialised to proto, and
sent (or buffered) via the Sender.

Setting this lower (e.g., `10`) increases the frequency of gRPC calls and reduces latency
between an event occurring and it appearing in the viriato-platform dashboard. Setting it
higher (e.g., `1000`) reduces gRPC overhead at the cost of higher latency.

The default of `100` ms was chosen as the balance point between near-real-time visibility and
reasonable network overhead. See [Design Decisions](../02-architecture/design-decisions.md),
Decision 7.

**Invalid values**: the loader casts this to `int` using `int(agent_raw.get("batch_interval_ms", 100))`.
A non-integer value in the YAML will raise a `ValueError` during config loading. A value of 0
will cause the batch to flush on every event (maximum overhead). Negative values are not
validated and will cause the batch to never flush on the time condition (only on shutdown);
this is effectively a bug and should be avoided.

---

### agent.buffer_path

| Property | Value |
|---|---|
| Type | string (filesystem path) |
| Required | No |
| Default | `"/var/lib/guardian/buffer"` |
| Example | `"~/.guardian/buffer"` (development), `"/var/lib/guardian/buffer"` (production) |

The directory where `pending.jsonl` is written when gRPC delivery fails. The path is
expanded with `Path(buffer_path).expanduser()`, so `~` is resolved to the home directory.

The directory is created automatically if it does not exist (`mkdir -p` semantics). If the
configured path cannot be created due to a `PermissionError`, the Sender falls back to
`~/.guardian/buffer`. If neither path is writable, batches that fail to send are dropped with
an error log.

The buffer file itself is `<buffer_path>/pending.jsonl`. It is capped at 10,000 lines.

**Production recommendation**: on Linux systems with systemd, use the default
`/var/lib/guardian/buffer` (owned by the `guardian` service account). On macOS or for
development, the example file uses `~/.guardian/buffer`.

---

## Section: watch

The `watch` section defines which processes Guardian monitors and which AI model they are
running. It is a YAML list of entries, each with two fields.

```yaml
watch:
  - process: "python"
    model_name: "patient-diagnosis-v2"
  - process: "torchserve"
    model_name: "fraud-detection-v1"
```

### watch[].process

| Property | Value |
|---|---|
| Type | string |
| Required | Yes (within a watch entry) |
| Example | `"python"`, `"torchserve"`, `"gunicorn"` |

The executable name of the AI process to watch. This must match the `comm` value visible in
`/proc/<pid>/comm` — i.e., the base filename of the executable, truncated to 15 characters
on Linux. It is compared directly against `RawEvent.process` in the Enricher.

In Phase 2, the eBPF probe uses this list to populate the `watched_pids` BPF hash map.
In Phase 1 with the fake generator, `process` values are drawn from this list.

**Invalid values**: any non-empty string is accepted. If no events match a given `process`
value (e.g., the process is not running), the entry has no effect.

### watch[].model_name

| Property | Value |
|---|---|
| Type | string |
| Required | Yes (within a watch entry) |
| Example | `"patient-diagnosis-v2"`, `"fraud-detection-v1"` |

The AI model identifier to associate with events from this process. This value is written to
`RawEvent.model_name` by the Enricher. It is used as the primary grouping key in compliance
dashboards. It should be a stable, versioned identifier (not a hostname or PID).

**Invalid values**: any non-empty string. If the `model_name` field is missing from a `watch`
entry, the loader will raise a `KeyError` when constructing the `WatchEntry` dataclass.

---

## Section: syscalls

The `syscalls` section is a YAML list of syscall names that Guardian should monitor.

```yaml
syscalls:
  - read
  - write
  - openat
  - sendto
  - recvfrom
  - connect
  - execve
  - clone
  - socket
```

| Property | Value |
|---|---|
| Type | list of strings |
| Required | No |
| Default | Empty list — the fake generator uses its built-in weighted pool |
| Valid values | Any valid Linux syscall name supported by the eBPF probe |

In Phase 2, this list determines which tracepoints the eBPF probe attaches to. In Phase 1
with the fake generator, this list is used as the sampling pool for the weighted syscall
distribution. If the list is empty, the generator falls back to the built-in pool
(`read`, `write`, `openat`, `sendto`, `recvfrom`, `connect`, `socket`, `clone`).

The `execve` syscall is always injected by the generator every 500–1000 events for alert
testing, regardless of whether it appears in this list.

**Recommended set** for AI inference workloads: `read`, `write`, `openat`, `sendto`,
`recvfrom`, `connect`, `execve`, `clone`, `socket`. This covers file access, network
communication, process spawning, and socket creation — the full set of syscall categories
relevant to EU AI Act observability.

**Invalid values**: unrecognised syscall names are ignored by the fake generator (they will
be included in the weighted pool but with a weight of 1, which may slightly skew the
distribution). In Phase 2, unrecognised names that do not have corresponding tracepoints will
cause the eBPF probe to log a warning and skip that entry.

---

## Section: local_alerts

The `local_alerts` section defines the on-premises alert rules evaluated by
`LocalAlertEngine` before any event is transmitted to the platform.

```yaml
local_alerts:
  - type: sandbox_escape
    condition: "execve matches /bin/bash or /bin/sh"
    action: log_and_alert
  - type: unexpected_network
    condition: "connect to addr not in allowlist"
    action: log_and_alert
```

### local_alerts[].type

| Property | Value |
|---|---|
| Type | string |
| Required | Yes |
| Valid values | `"sandbox_escape"`, `"unexpected_network"` |

The rule type. Only these two values are supported in Phase 1.

- `"sandbox_escape"`: enables the rule that fires when an AI process calls `execve` with a
  shell binary path (`/bin/bash`, `/bin/sh`, `/usr/bin/bash`, `/usr/bin/sh`).
- `"unexpected_network"`: enables the rule that fires when an AI process calls `connect` or
  `sendto` to an address not in `network_allowlist`. This rule is a no-op when
  `network_allowlist` is empty.

Whether an alert type is enabled is determined by searching `config.local_alerts` for entries
with that `type`:
```python
sandbox_enabled = any(a.type == "sandbox_escape" for a in self._config.local_alerts)
```
So removing an entry from this list disables the corresponding rule.

### local_alerts[].condition

| Property | Value |
|---|---|
| Type | string |
| Required | Yes |
| Example | `"execve matches /bin/bash or /bin/sh"` |

A human-readable description of the rule condition. This field is stored in the config
dataclass but is not evaluated programmatically in Phase 1 — the actual condition logic is
hard-coded in `LocalAlertEngine`. The field serves as documentation for the operator and will
be used for rule customisation in Phase 2.

### local_alerts[].action

| Property | Value |
|---|---|
| Type | string |
| Required | No |
| Default | `"log_and_alert"` |
| Valid values | `"log_and_alert"` (Phase 1) |

The action to take when the rule fires. In Phase 1, only `"log_and_alert"` is supported:
the alert is logged at `ERROR` level and printed as JSON to stderr. Future actions (e.g.,
`"kill_process"`, `"block_syscall"`) are planned for Phase 2.

---

## Section: network_allowlist

```yaml
network_allowlist:
  - "10.0.0.1:8080"
  - "10.0.1.45:5000"
  - "172.16.0.5:6379"
```

| Property | Value |
|---|---|
| Type | list of strings |
| Required | No |
| Default | Empty list (no restriction) |
| Format | `"ip:port"` strings matching the format of `RawEvent.network_addr` |

The list of network addresses that AI processes are permitted to connect to. When this list is
non-empty and the `unexpected_network` local alert is enabled, any `connect` or `sendto`
syscall to an address not in this list fires an alert.

**When empty**: the `unexpected_network` rule is a no-op. All outbound connections are allowed
without triggering an alert. This is the safe default for new deployments where the allowlist
has not been defined.

**Format**: each entry must be a string in `"ip:port"` format, exactly matching the format of
`RawEvent.network_addr`. IPv4 examples: `"10.0.0.1:8080"`. IPv6 format (Phase 2): `"[::1]:6379"`.

**Invalid values**: entries that do not match the format of `network_addr` will simply never
match and the rule will fire for all network connections.

---

## Section: compliance

The `compliance` section provides metadata used by the viriato-platform Compliance Engine to
map events to EU AI Act obligations. It does not affect agent behaviour directly.

```yaml
compliance:
  organization: "Acme Healthcare AI"
  data_categories:
    - medical_records
    - PII
  articles: [12, 13, 15, 17, 72]
```

### compliance.organization

| Property | Value |
|---|---|
| Type | string |
| Required | No |
| Default | `""` |
| Example | `"Acme Healthcare AI"`, `"FintechCorp Ltd"` |

The name of the organisation deploying the AI system. This value is included in compliance
reports and audit exports generated by viriato-web. It identifies the responsible organisation
for EU AI Act purposes.

### compliance.data_categories

| Property | Value |
|---|---|
| Type | list of strings |
| Required | No |
| Default | Empty list |
| Example | `["medical_records", "PII", "financial_data"]` |

The categories of personal or sensitive data processed by the AI system. These are used by the
Compliance Engine to determine which EU AI Act articles and GDPR provisions apply. The values
are free-form strings; the platform maps them to regulatory frameworks using its own taxonomy.

### compliance.articles

| Property | Value |
|---|---|
| Type | list of integers |
| Required | No |
| Default | Empty list |
| Example | `[12, 13, 15, 17, 72]` |

The EU AI Act article numbers that this deployment is required to comply with. The Compliance
Engine uses this list to generate targeted compliance evidence reports. The recommended set for
high-risk AI systems under the EU AI Act is `[12, 13, 15, 17, 72]`.

---

## Environment Variables

Two environment variables can override or supplement `guardian.yaml` settings.

### GUARDIAN_FAKE_EVENTS

| Property | Value |
|---|---|
| Type | String (`"1"` to enable) |
| Default | `"0"` (not set) |
| Equivalent to | `--fake` CLI flag |

Setting `GUARDIAN_FAKE_EVENTS=1` forces the EventReader to use the `FakeEventGenerator`
regardless of platform capabilities. This is useful in CI environments, Docker containers on
macOS, and any context where eBPF is not available and you do not want to pass `--fake` on
the command line.

Example:
```bash
export GUARDIAN_FAKE_EVENTS=1
python -m agent.main
```

This environment variable takes precedence over the eBPF availability check: even on a Linux
5.8+ machine with BCC installed, setting `GUARDIAN_FAKE_EVENTS=1` will use the generator.

### GUARDIAN_INSECURE_GRPC

| Property | Value |
|---|---|
| Type | String (`"1"` to enable) |
| Default | `"0"` (not set) |

When set to `"1"`, forces the Sender to use `grpc.insecure_channel()` regardless of the
`control_plane` address. This bypasses TLS and should only be used in controlled test
environments (e.g., an internal staging server at a non-loopback address that has not been
set up with TLS).

Example:
```bash
export GUARDIAN_INSECURE_GRPC=1
python -m agent.main -c /etc/guardian/staging.yaml
```

**Security warning**: setting this in a production environment will transmit all event batches
in plaintext over the network. Event content (including model names, file paths, and network
addresses) will be visible to any network observer.

This variable is not settable in `guardian.yaml`. It must be explicitly set in the shell
environment to prevent it from being accidentally enabled in production by a configuration
file edit.

---

## Complete Field Reference Summary

| Field path | Type | Default | Required | Notes |
|---|---|---|---|---|
| `agent.token` | string | — | Effectively yes | HMAC key + gRPC auth header |
| `agent.control_plane` | string | `"grpc.viriatosecurity.com:443"` | No | `host:port` |
| `agent.batch_interval_ms` | integer | `100` | No | Milliseconds; 1–60000 |
| `agent.buffer_path` | string | `"/var/lib/guardian/buffer"` | No | ~ expanded |
| `watch[].process` | string | — | Yes (within entry) | Executable name |
| `watch[].model_name` | string | — | Yes (within entry) | AI model identifier |
| `syscalls[]` | list of string | `[]` | No | Syscall names |
| `local_alerts[].type` | string | — | Yes (within entry) | `sandbox_escape` or `unexpected_network` |
| `local_alerts[].condition` | string | — | Yes (within entry) | Human-readable, not evaluated in Phase 1 |
| `local_alerts[].action` | string | `"log_and_alert"` | No | Phase 1: only `log_and_alert` |
| `network_allowlist[]` | list of string | `[]` | No | `"ip:port"` strings |
| `compliance.organization` | string | `""` | No | Organisation name |
| `compliance.data_categories[]` | list of string | `[]` | No | Data category labels |
| `compliance.articles[]` | list of integer | `[]` | No | EU AI Act article numbers |

---

## Error Handling Summary

| Condition | Behaviour |
|---|---|
| No config file found in any search path | `FileNotFoundError` raised at startup |
| `--config FILE` given but FILE does not exist | `FileNotFoundError` raised at startup |
| `token` empty or placeholder | Warning logged; agent runs but cannot send events |
| Invalid `batch_interval_ms` (non-integer) | `ValueError` during config parsing |
| `watch` entry missing `process` or `model_name` | `KeyError` during config parsing |
| `local_alerts` entry with unknown `type` | Accepted; the rule is not activated (no match in `any(a.type == ...)`) |
| `network_allowlist` empty | `unexpected_network` rule is a no-op (no false positives) |

---

## Related Documents

- [Event Schema](event-schema.md) — how `watch`, `syscalls`, and `network_allowlist` influence
  the values of RawEvent fields.
- [Guardian Internals](../02-architecture/guardian-internals.md) — how each config field is
  consumed by the pipeline stages.
- [Design Decisions](../02-architecture/design-decisions.md) — Decision 7 (batch interval),
  Decision 10 (insecure gRPC), Decision 11 (buffer cap).
- [Event Pipeline](../02-architecture/event-pipeline.md) — how the batch flush interval
  affects timing.
