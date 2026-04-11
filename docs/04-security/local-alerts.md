# Local Alert Engine

## Overview

The local alert engine evaluates security rules against each syscall event synchronously, without any network call. Alerts fire in-process the moment a matching event is observed. This design means Guardian can detect and surface critical threats even when the Viriato control plane is unreachable — during network partitions, agent startup before the first successful gRPC connection, or in air-gapped deployments.

The engine lives in `agent/local_alerts.py` and is a peer component in the pipeline, evaluated after enrichment but before (or alongside) the signing step in `agent/main.py`.

---

## Why Local Alerts Exist

The control plane performs sophisticated ML-based behavioural analysis on event streams over time. However, some threats are so clearly defined and so time-sensitive that waiting for a round-trip to the control plane would cause unacceptable delay. A process spawning `/bin/bash` from inside an AI model container is suspicious enough to warrant an immediate local alert regardless of what the remote analysis might conclude.

Local alerts provide:
- **Zero-latency detection:** evaluated on the hot path, before any I/O.
- **Offline detection:** no dependency on network connectivity.
- **Simple deterministic rules:** easy to audit, test, and reason about.
- **Operator control:** rules are declared in `guardian.yaml`; operators can enable, disable, or add alert types.

---

## Alert Types

### `sandbox_escape`

**Trigger condition:** `event.syscall == "execve"` AND `event.fd_path` is one of:

```python
{"/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"}
```

**Rationale:** AI model inference processes have no legitimate reason to spawn an interactive shell. An `execve` syscall targeting one of these four shell paths almost certainly indicates:
- A prompt injection attack causing the model to run shell commands.
- A compromised dependency executing a reverse shell.
- A container escape attempt that has already reached code execution.

The rule fires on the `execve` syscall specifically because this is the syscall that replaces the current process image with the shell binary. Earlier syscalls (`open`, `read` of the shell binary) are not sufficient indicators on their own.

**Implementation:**

```python
_SHELL_BINARIES = frozenset(
    ["/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"]
)

def _check_sandbox_escape(self, event: RawEvent) -> Optional[AlertEvent]:
    if event.syscall != "execve":
        return None
    if event.fd_path not in _SHELL_BINARIES:
        return None
    return AlertEvent(
        alert_type="sandbox_escape",
        pid=event.pid,
        process=event.process,
        syscall=event.syscall,
        detail=f"execve to {event.fd_path}",
        timestamp=event.timestamp,
        agent_id=event.agent_id,
        model_name=event.model_name,
    )
```

**`guardian.yaml` declaration:**

```yaml
local_alerts:
  - type: sandbox_escape
    condition: "execve matches /bin/bash or /bin/sh"
    action: log_and_alert
```

---

### `unexpected_network`

**Trigger condition:** `event.syscall` is `"connect"` or `"sendto"` AND `event.network_addr` is **not** in the configured `network_allowlist` AND the allowlist is **non-empty**.

**Critical semantic:** An **empty** `network_allowlist` means **no restriction**. The rule is entirely inactive when the allowlist is empty. This is intentional: operators who have not configured a network policy should not receive alerts for every outbound connection. The rule is opt-in at the policy level.

**Rationale:** AI model processes that exfiltrate training data or model weights do so via network connections. By declaring an explicit allowlist of expected endpoints (e.g. the internal Redis cache, the internal metrics endpoint), any unexpected outbound connection becomes immediately alertable — a strong signal of data exfiltration or command-and-control activity.

**Implementation:**

```python
_NETWORK_INITIATION_SYSCALLS = frozenset(["connect", "sendto"])

def _check_unexpected_network(self, event: RawEvent) -> Optional[AlertEvent]:
    if event.syscall not in _NETWORK_INITIATION_SYSCALLS:
        return None
    # Empty allowlist → no restriction (rule inactive)
    if not self._network_allowlist:
        return None
    if event.network_addr in self._network_allowlist:
        return None
    return AlertEvent(
        alert_type="unexpected_network",
        pid=event.pid,
        process=event.process,
        syscall=event.syscall,
        detail=f"connection to {event.network_addr} not in allowlist",
        timestamp=event.timestamp,
        agent_id=event.agent_id,
        model_name=event.model_name,
    )
```

**`guardian.yaml` declaration with an active allowlist:**

```yaml
network_allowlist:
  - "10.0.0.1:8080"
  - "10.0.1.45:5000"
  - "172.16.0.5:6379"

local_alerts:
  - type: unexpected_network
    condition: "connect to addr not in allowlist"
    action: log_and_alert
```

---

## Alert Action: `log_and_alert`

The only supported alert action in Phase 1 is `log_and_alert`. When an alert fires, the engine:

1. Increments `self._alert_count`.
2. If a custom handler is registered (`set_custom_handler()`), calls it with the `AlertEvent` and returns.
3. Otherwise, emits two outputs:
   - `logger.error("ALERT %s: %s", alert.alert_type, alert.detail)` — goes to the standard Python logging system (visible in systemd journal, Kubernetes pod logs, etc.).
   - `print(json.dumps(payload), file=sys.stderr)` — writes a machine-readable JSON object to stderr for log aggregators and SIEM tools that consume process stderr.

---

## Dual Output Mechanism

The default output (when no custom handler is set) writes to two destinations:

**Python logger (structured):**
```
ERROR:agent.local_alerts:ALERT sandbox_escape: execve to /bin/bash
```

This goes to whatever logging handler the application has configured (file handler, JSON formatter for log aggregators, etc.). It respects the operator's logging configuration.

**JSON to stderr (machine-readable):**
```json
{
  "alert_type": "sandbox_escape",
  "pid": 12345,
  "process": "python",
  "syscall": "execve",
  "detail": "execve to /bin/bash",
  "timestamp": "2026-04-10T12:00:00.000000000Z",
  "agent_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "model_name": "patient-diagnosis-v2"
}
```

The stderr JSON output allows tools like Fluentd, Fluent Bit, or Datadog Agent to collect alerts by tailing process stderr, without requiring any Guardian-specific log format configuration. SIEM integrations can consume this stream directly.

---

## `set_custom_handler()` Pattern

```python
def set_custom_handler(self, fn: Callable[[AlertEvent], None]) -> None:
```

Registering a custom handler **suppresses** both the `logger.error` call and the `print(json.dumps(payload), stderr)` output. Only `fn` is called.

Primary use cases:

**Testing:** Capture alerts in a list for assertion without polluting test output.

```python
captured = []
engine = LocalAlertEngine(sandbox_escape_enabled=True)
engine.set_custom_handler(captured.append)

event = RawEvent(syscall="execve", fd_path="/bin/bash", ...)
engine.evaluate(event)
assert len(captured) == 1
assert captured[0].alert_type == "sandbox_escape"
```

**Custom routing:** Send alerts to a Slack webhook, PagerDuty, or an internal incident management system without waiting for the control plane.

```python
def send_to_pagerduty(alert: AlertEvent) -> None:
    requests.post(PAGERDUTY_URL, json={
        "routing_key": PD_KEY,
        "event_action": "trigger",
        "payload": {
            "summary": f"Guardian: {alert.alert_type} on {alert.process}",
            "severity": "critical",
            "custom_details": {
                "detail": alert.detail,
                "agent_id": alert.agent_id,
                "model_name": alert.model_name,
            }
        }
    })

engine.set_custom_handler(send_to_pagerduty)
```

**Note:** `set_custom_handler()` replaces the entire default output path, including the logger. If you want both your custom handler and the default output, call them both explicitly inside `fn`.

---

## `AlertEvent` Dataclass

```python
@dataclass
class AlertEvent:
    alert_type: str    # "sandbox_escape" or "unexpected_network"
    pid: int           # PID of the process that triggered the alert
    process: str       # Process name (e.g. "python", "torchserve")
    syscall: str       # Syscall that matched ("execve", "connect", "sendto")
    detail: str        # Human-readable description of what was detected
    timestamp: str     # ISO 8601 nanosecond UTC timestamp from the event
    agent_id: str      # UUID of this Guardian installation
    model_name: str    # Model name from watch config, or "unknown"
```

`AlertEvent` is intentionally a subset of `RawEvent` fields, containing only the fields relevant to a human operator investigating the alert. Fields like `bytes`, `return_val`, `fd_path` (for network alerts), and hash fields are not included.

---

## What Local Alerts Cannot Detect

Local alerts evaluate each event in isolation. They cannot detect:

- **Gradual data exfiltration:** Small amounts of data sent to an allowed address over many events. This requires temporal analysis at the control plane.
- **Lateral movement via allowed paths:** A process that copies data to a shared volume rather than a network socket. There is no `unexpected_write` rule.
- **Sophisticated evasion:** A process that spawns a non-shell interpreter (e.g. `/usr/bin/python3`, `/usr/bin/node`) to execute arbitrary code. Only the four shell paths are in `_SHELL_BINARIES`.
- **Model weight exfiltration over allowed channels:** If the model is allowed to connect to `10.0.0.1:8080` (its inference API), sending model weights to that address will not trigger `unexpected_network`.
- **Timing-based or side-channel attacks:** No syscall timing information is available in the local alert engine.

These detection gaps are intentional — local alerts are a first line of defence, not a complete detection system. The Viriato control plane provides deeper ML-based analysis.

---

## How to Add a New Alert Type

To add a new alert type (e.g. `unexpected_file_access` that fires when an AI model reads outside its model directory):

**Step 1:** Add an `_enabled` flag and the rule list to `LocalAlertEngine.__init__()`:

```python
def __init__(self, ..., unexpected_file_access_enabled: bool = False,
             allowed_paths: Optional[list[str]] = None) -> None:
    ...
    self._unexpected_file_access_enabled = unexpected_file_access_enabled
    self._allowed_paths: list[str] = allowed_paths or []
```

**Step 2:** Write the rule method following the existing pattern:

```python
def _check_unexpected_file_access(self, event: RawEvent) -> Optional[AlertEvent]:
    if event.syscall not in ("read", "openat"):
        return None
    if not self._allowed_paths:
        return None
    if any(event.fd_path.startswith(p) for p in self._allowed_paths):
        return None
    return AlertEvent(
        alert_type="unexpected_file_access",
        pid=event.pid,
        process=event.process,
        syscall=event.syscall,
        detail=f"access to {event.fd_path} not in allowed paths",
        timestamp=event.timestamp,
        agent_id=event.agent_id,
        model_name=event.model_name,
    )
```

**Step 3:** Call the new rule in `evaluate()`:

```python
def evaluate(self, event: RawEvent) -> list[AlertEvent]:
    ...
    if self._unexpected_file_access_enabled:
        alert = self._check_unexpected_file_access(event)
        if alert is not None:
            alerts.append(alert)
    ...
```

**Step 4:** Add a `guardian.yaml` declaration and wire the new type in `main.py` where `LocalAlertEngine` is instantiated.

**Step 5:** Write tests covering: rule inactive when disabled, rule inactive when no config, rule fires on trigger, rule does not fire on non-trigger syscall.

---

## Related Documents

- `docs/04-security/threat-model.md` — threat actors that local alerts detect (T-6, T-9)
- `docs/05-components/local-alerts-engine.md` — `LocalAlertEngine` and `AlertEvent` full API reference
- `docs/05-components/config-loader.md` — `LocalAlert` and `network_allowlist` config fields
- `docs/05-components/enricher.md` — `agent_id` and `model_name` fields on `AlertEvent` come from enrichment
