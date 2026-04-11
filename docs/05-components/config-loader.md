# Config Loader (`agent/config.py`)

## Overview

`agent/config.py` is the configuration subsystem for the Guardian agent. It defines all typed dataclasses that represent the structure of `guardian.yaml`, and exposes `load_config()` — the single entry point for loading and validating configuration at startup.

Every other agent module (enricher, signer, sender, generator, reader, local alerts) receives a `Config` object. No module reads environment variables or YAML directly except through this module.

---

## Dataclasses

### `AgentConfig`

Core runtime tunables for the agent process.

```python
@dataclass
class AgentConfig:
    token: str
    control_plane: str = "grpc.viriatosecurity.com:443"
    batch_interval_ms: int = 100
    buffer_path: str = "/var/lib/guardian/buffer"
```

| Field | Type | Default | Description |
|---|---|---|---|
| `token` | `str` | _(required)_ | Customer API token used for HMAC signing and gRPC authentication. No default; must be provided in `guardian.yaml`. |
| `control_plane` | `str` | `"grpc.viriatosecurity.com:443"` | `host:port` of the Viriato gRPC endpoint. Set to `"localhost:50051"` for local development. |
| `batch_interval_ms` | `int` | `100` | How many milliseconds of events to accumulate before signing and attempting to send a batch. Lower values reduce event latency; higher values improve throughput. |
| `buffer_path` | `str` | `"/var/lib/guardian/buffer"` | Directory for the on-disk event buffer (`pending.jsonl`). Must be writable by the Guardian process. Falls back to `~/.guardian/buffer` on `PermissionError`. |

---

### `WatchEntry`

Maps a monitored process name to the AI model it is running. Used by the Enricher to set the `model_name` field on events.

```python
@dataclass
class WatchEntry:
    process: str
    model_name: str
```

| Field | Type | Description |
|---|---|---|
| `process` | `str` | Exact process name to match (e.g. `"python"`, `"torchserve"`). Matched against `event.process` using exact string equality. |
| `model_name` | `str` | Human-readable model name written to the event (e.g. `"patient-diagnosis-v2"`). This is the value that appears in `AlertEvent.model_name` and in the control plane UI. |

**`guardian.yaml` example:**

```yaml
watch:
  - process: "python"
    model_name: "patient-diagnosis-v2"
  - process: "torchserve"
    model_name: "fraud-detection-v1"
```

---

### `LocalAlert`

A local alert rule declaration. These are evaluated by `LocalAlertEngine` in `agent/local_alerts.py`. The `guardian.yaml` declaration is informational metadata; the actual detection logic is hardcoded in the engine.

```python
@dataclass
class LocalAlert:
    type: str
    condition: str
    action: str
```

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | `str` | _(required)_ | Rule identifier. Currently supported: `"sandbox_escape"`, `"unexpected_network"`. |
| `condition` | `str` | _(required)_ | Human-readable description of the trigger condition. Not evaluated programmatically; for documentation purposes. |
| `action` | `str` | `"log_and_alert"` | What to do when the rule fires. Only `"log_and_alert"` is implemented in Phase 1. |

**`guardian.yaml` example:**

```yaml
local_alerts:
  - type: sandbox_escape
    condition: "execve matches /bin/bash or /bin/sh"
    action: log_and_alert
  - type: unexpected_network
    condition: "connect to addr not in allowlist"
    action: log_and_alert
```

---

### `ComplianceConfig`

EU AI Act compliance metadata. Used by the control plane to tag events with regulatory context for audit reporting.

```python
@dataclass
class ComplianceConfig:
    organization: str = ""
    data_categories: list[str] = field(default_factory=list)
    articles: list[int] = field(default_factory=list)
```

| Field | Type | Default | Description |
|---|---|---|---|
| `organization` | `str` | `""` | The name of the organisation operating the AI system (for audit reports). |
| `data_categories` | `list[str]` | `[]` | Data categories processed by the monitored AI models (e.g. `["medical_records", "PII"]`). |
| `articles` | `list[int]` | `[]` | EU AI Act article numbers applicable to this deployment (e.g. `[12, 13, 15, 17, 72]`). |

**`guardian.yaml` example:**

```yaml
compliance:
  organization: "Acme Healthcare AI"
  data_categories:
    - medical_records
    - PII
  articles: [12, 13, 15, 17, 72]
```

---

### `Config`

The top-level configuration object. Holds all sub-configurations and exposes convenience helpers.

```python
@dataclass
class Config:
    agent: AgentConfig
    watch: list[WatchEntry] = field(default_factory=list)
    syscalls: list[str] = field(default_factory=list)
    local_alerts: list[LocalAlert] = field(default_factory=list)
    network_allowlist: list[str] = field(default_factory=list)
    compliance: ComplianceConfig = field(default_factory=ComplianceConfig)
```

| Field | Type | Default | Description |
|---|---|---|---|
| `agent` | `AgentConfig` | _(required)_ | Core agent tunables. |
| `watch` | `list[WatchEntry]` | `[]` | Process-to-model mappings for enrichment. |
| `syscalls` | `list[str]` | `[]` | Syscalls to capture. If empty, `FakeEventGenerator` uses its built-in defaults. In Phase 2 this drives the eBPF filter. |
| `local_alerts` | `list[LocalAlert]` | `[]` | Local alert rule declarations. |
| `network_allowlist` | `list[str]` | `[]` | Allowed network addresses for `unexpected_network` rule. Empty means no restriction. |
| `compliance` | `ComplianceConfig` | _(defaults)_ | EU AI Act metadata. |

---

## Convenience Helpers on `Config`

### `model_name_for_process(process: str) -> str`

Returns the `model_name` configured for the given process name, or `"unknown"` if the process is not in the `watch` list.

```python
config.model_name_for_process("python")
# Returns "patient-diagnosis-v2" (if configured)

config.model_name_for_process("curl")
# Returns "unknown" (not in watch list)
```

Matching is exact string equality. There is no glob or regex matching in Phase 1.

### `batch_interval_seconds` property

```python
@property
def batch_interval_seconds(self) -> float:
    return self.agent.batch_interval_ms / 1000.0
```

Converts `batch_interval_ms` to seconds for use with `time.sleep()` in the main pipeline loop.

```python
config.batch_interval_seconds  # 0.1 (for default 100 ms)
```

---

## `load_config()` Function

```python
def load_config(path: Optional[str] = None) -> Config:
```

The single public entry point for loading configuration.

### Search Path Logic

The function searches for `guardian.yaml` in the following order (first match wins):

| Priority | Path | Notes |
|---|---|---|
| 1 | `path` argument | Only used if `path` is not `None` |
| 2 | `./guardian.yaml` | Current working directory |
| 3 | `/etc/guardian/guardian.yaml` | System-wide installation |
| 4 | `~/.guardian/guardian.yaml` | User home directory |

If `path` is provided explicitly and the file does not exist at that path, `FileNotFoundError` is raised **immediately** without falling back to the auto-discovery paths. This is intentional: if you explicitly specify a path, an absence is an error, not a prompt to search elsewhere.

If no file is found after searching all four locations, `FileNotFoundError` is raised with a message listing all paths that were tried.

```python
# Explicit path (no fallback):
config = load_config("/opt/guardian/guardian.yaml")

# Auto-discovery:
config = load_config()
```

### Token Validation

After loading, if `agent.token` is empty or equals the placeholder string `"YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE"`, a `logger.warning` is emitted:

```
WARNING:agent.config:Guardian token is not set or is still the placeholder.
Events will be buffered locally but NOT sent to viriato-platform.
Obtain a real token at https://viriatosecurity.com
```

This is a **warning, not an error**. The agent starts and continues running. Events are buffered locally but not forwarded to the platform. This allows developers to run Guardian without a token for local testing.

---

## Full `guardian.yaml` Example

```yaml
agent:
  token: "sk-viriato-prod-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  control_plane: "grpc.viriatosecurity.com:443"
  batch_interval_ms: 100
  buffer_path: "/var/lib/guardian/buffer"

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

network_allowlist:
  - "10.0.0.1:8080"
  - "172.16.0.5:6379"

compliance:
  organization: "Acme Healthcare AI"
  data_categories:
    - medical_records
    - PII
  articles: [12, 13, 15, 17, 72]
```

---

## Common Mistakes and Errors

### `FileNotFoundError` on startup

```
FileNotFoundError: guardian.yaml not found. Tried: [None, './guardian.yaml', '/etc/guardian/guardian.yaml', '~/.guardian/guardian.yaml'].
Copy guardian.yaml.example to guardian.yaml and fill in your token.
```

**Fix:** Copy `guardian.yaml.example` to `guardian.yaml` in the working directory and fill in your token.

---

### Token warning on every startup

```
WARNING:agent.config:Guardian token is not set or is still the placeholder.
```

**Fix:** Replace `YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE` in `guardian.yaml` with a real token from the Viriato console.

---

### `model_name` always `"unknown"` in events

**Cause:** The `watch` list is empty, or the process names in `watch` do not match the actual process names producing events.

**Fix:** Confirm the exact process name (e.g. `ps aux | grep python`) and add a matching `WatchEntry`. Process name matching is case-sensitive exact-string.

---

### `unexpected_network` alerts never fire

**Cause:** `network_allowlist` is empty (the default). An empty allowlist deactivates the rule entirely.

**Fix:** Add at least one address to `network_allowlist`. All connections to addresses not in the list will then trigger `unexpected_network` alerts.

---

### `batch_interval_ms: 0` causes tight loop

**Cause:** Setting `batch_interval_ms` to `0` means `batch_interval_seconds` returns `0.0`, and the main loop calls `time.sleep(0)` between batches — valid Python but will spin at near-100% CPU.

**Fix:** Use a minimum of `10` (10 ms) in production. The default `100` (100 ms) is appropriate for most deployments.

---

## Related Documents

- `docs/05-components/enricher.md` — uses `model_name_for_process()` and `watch` list
- `docs/05-components/local-alerts-engine.md` — uses `local_alerts` and `network_allowlist`
- `docs/05-components/sender.md` — uses `agent.control_plane`, `agent.token`, `agent.buffer_path`
- `docs/05-components/signer.md` — uses `agent.token`
- `docs/05-components/event-generator.md` — uses `syscalls` and `watch`
