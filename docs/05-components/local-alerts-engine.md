# Local Alert Engine (`agent/local_alerts.py`)

## Overview

`agent/local_alerts.py` implements the real-time, in-process security detection layer. It evaluates rules against each `RawEvent` synchronously without any network call. When a rule matches, it produces an `AlertEvent` and fires it via either the default output mechanism (logger + stderr JSON) or a registered custom handler.

The engine is intentionally simple: two hardcoded rules, deterministic logic, no ML, no state beyond counters. Complexity and temporal analysis belong to the Viriato control plane.

---

## `AlertEvent` Dataclass

```python
@dataclass
class AlertEvent:
    alert_type: str
    pid: int
    process: str
    syscall: str
    detail: str
    timestamp: str
    agent_id: str
    model_name: str
```

### Field Reference

| Field | Type | Description |
|---|---|---|
| `alert_type` | `str` | Rule identifier: `"sandbox_escape"` or `"unexpected_network"`. |
| `pid` | `int` | PID of the process that triggered the alert. Copied from `RawEvent.pid`. |
| `process` | `str` | Name of the triggering process (e.g. `"python"`, `"torchserve"`). Copied from `RawEvent.process`. |
| `syscall` | `str` | The syscall that matched the rule (e.g. `"execve"`, `"connect"`, `"sendto"`). Copied from `RawEvent.syscall`. |
| `detail` | `str` | Human-readable description of the specific match (e.g. `"execve to /bin/bash"`, `"connection to 203.0.113.42:443 not in allowlist"`). |
| `timestamp` | `str` | ISO 8601 UTC nanosecond timestamp from the triggering event. Copied from `RawEvent.timestamp`. |
| `agent_id` | `str` | UUID of this Guardian installation. Copied from `RawEvent.agent_id` (set by Enricher). |
| `model_name` | `str` | AI model name associated with the triggering process. Copied from `RawEvent.model_name` (set by Enricher). |

`AlertEvent` does not include `fd_path` (for network alerts), `bytes`, `return_val`, `uid`, hash fields, or container/Kubernetes context. The `detail` field encodes the relevant specifics as a human-readable string.

---

## `LocalAlertEngine` Class

```python
class LocalAlertEngine:
    def __init__(
        self,
        sandbox_escape_enabled: bool = True,
        unexpected_network_enabled: bool = True,
        network_allowlist: Optional[list[str]] = None,
    ) -> None:
```

### Constructor Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `sandbox_escape_enabled` | `bool` | `True` | Enable the `sandbox_escape` rule. |
| `unexpected_network_enabled` | `bool` | `True` | Enable the `unexpected_network` rule. |
| `network_allowlist` | `Optional[list[str]]` | `None` | Allowed network addresses for `unexpected_network`. `None` or `[]` = no restriction (rule inactive). |

The constructor stores these as instance attributes:

```python
self._sandbox_escape_enabled = sandbox_escape_enabled
self._unexpected_network_enabled = unexpected_network_enabled
self._network_allowlist: list[str] = network_allowlist or []
self._alert_count: int = 0
self._custom_handler: Optional[Callable[[AlertEvent], None]] = None
```

---

## `evaluate(event: RawEvent) -> list[AlertEvent]`

The primary public method. Called on every event in the pipeline.

```python
def evaluate(self, event: RawEvent) -> list[AlertEvent]:
    alerts: list[AlertEvent] = []

    if self._sandbox_escape_enabled:
        alert = self._check_sandbox_escape(event)
        if alert is not None:
            alerts.append(alert)

    if self._unexpected_network_enabled:
        alert = self._check_unexpected_network(event)
        if alert is not None:
            alerts.append(alert)

    for alert in alerts:
        self._fire(alert)

    return alerts
```

**Returns:** A list of `AlertEvent` objects for all rules that matched. Empty list for most events.

In theory, both rules could fire on the same event (e.g. a future rule combination), so `evaluate()` returns a list rather than a single `Optional[AlertEvent]`.

The `_fire()` call happens inside `evaluate()`, so side effects (logging, custom handler) occur synchronously before `evaluate()` returns.

---

## Rule Implementations

### `_check_sandbox_escape(event: RawEvent) -> Optional[AlertEvent]`

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

**Trigger conditions (ALL must be true):**
1. `event.syscall == "execve"`
2. `event.fd_path` is one of `{"/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"}`

The `_SHELL_BINARIES` set uses `frozenset` for O(1) membership testing. Order of checks: syscall first (fast string equality), then path set membership. The majority of events (reads, writes, network calls) are filtered at the syscall check.

The `detail` field is `f"execve to {event.fd_path}"`, producing strings like:
- `"execve to /bin/bash"`
- `"execve to /usr/bin/sh"`

---

### `_check_unexpected_network(event: RawEvent) -> Optional[AlertEvent]`

```python
_NETWORK_INITIATION_SYSCALLS = frozenset(["connect", "sendto"])

def _check_unexpected_network(self, event: RawEvent) -> Optional[AlertEvent]:
    if event.syscall not in _NETWORK_INITIATION_SYSCALLS:
        return None
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

**Trigger conditions (ALL must be true):**
1. `event.syscall` is `"connect"` or `"sendto"`
2. `self._network_allowlist` is non-empty (if empty, rule is inactive)
3. `event.network_addr` is NOT in `self._network_allowlist`

The `recvfrom` syscall is not in `_NETWORK_INITIATION_SYSCALLS` — it is a receive-side operation. The rule focuses on outbound connection initiation.

The `detail` field is `f"connection to {event.network_addr} not in allowlist"`, producing strings like:
- `"connection to 203.0.113.42:443 not in allowlist"`

---

## `_fire(alert: AlertEvent) -> None`

```python
def _fire(self, alert: AlertEvent) -> None:
    self._alert_count += 1

    if self._custom_handler is not None:
        self._custom_handler(alert)
        return

    payload = {
        "alert_type": alert.alert_type,
        "pid": alert.pid,
        "process": alert.process,
        "syscall": alert.syscall,
        "detail": alert.detail,
        "timestamp": alert.timestamp,
        "agent_id": alert.agent_id,
        "model_name": alert.model_name,
    }
    logger.error("ALERT %s: %s", alert.alert_type, alert.detail)
    print(json.dumps(payload), file=sys.stderr)
```

`_fire()` is called for every alert produced by `evaluate()`. It:

1. **Always** increments `self._alert_count`.
2. **If a custom handler is set:** calls `self._custom_handler(alert)` and returns. The default output (logger + stderr) is **suppressed**.
3. **Otherwise (default):** emits two outputs:
   - `logger.error("ALERT sandbox_escape: execve to /bin/bash")` — to the Python logging system.
   - `print(json.dumps(payload), file=sys.stderr)` — compact JSON on stderr for log aggregators.

The `payload` dict in the default output mirrors the `AlertEvent` fields exactly, making it straightforward to deserialise from a log stream.

---

## `set_custom_handler(fn: Callable[[AlertEvent], None]) -> None`

```python
def set_custom_handler(self, fn: Callable[[AlertEvent], None]) -> None:
```

Registers a callback that replaces the default logger + stderr output entirely.

**Suppression:** When a custom handler is set, neither `logger.error()` nor `print(..., file=sys.stderr)` is called. Only `fn(alert)` is called. The `alert_count` is still incremented regardless.

**Use cases:**
- Testing: collect alerts in a list without noise in test output.
- Production: route alerts to a SIEM, PagerDuty, Slack, or internal incident management system.
- Custom formatting: produce a different JSON schema for a specific log aggregator.

**Example (testing):**

```python
captured: list[AlertEvent] = []
engine = LocalAlertEngine(
    sandbox_escape_enabled=True,
    unexpected_network_enabled=True,
    network_allowlist=["10.0.0.1:8080"],
)
engine.set_custom_handler(captured.append)

event = RawEvent(
    syscall="execve",
    fd_path="/bin/sh",
    pid=1234,
    process="python",
    timestamp="2026-04-10T12:00:00.000000000Z",
    agent_id="f47ac10b-...",
    model_name="patient-diagnosis-v2",
)
engine.evaluate(event)

assert len(captured) == 1
assert captured[0].alert_type == "sandbox_escape"
assert captured[0].detail == "execve to /bin/sh"
```

---

## `alert_count` Property

```python
@property
def alert_count(self) -> int:
    return self._alert_count
```

Returns the total number of alerts fired since the engine was constructed. Incremented in `_fire()` before the custom handler or default output is invoked.

This counter is useful for:
- Metrics export (Prometheus, Datadog): track alert rate over time.
- Integration tests: assert a specific number of alerts fired during a test sequence.
- Health checks: alert if `alert_count` is unexpectedly zero (engine might be broken).

---

## How to Add a New Alert Type

Adding a new alert type requires changes to `local_alerts.py`, `main.py`, and the test suite. Follow this pattern:

**Step 1 — Add an enable flag and config to `__init__()`:**

```python
def __init__(
    self,
    ...,
    unusual_uid_enabled: bool = False,
    root_uid_threshold: int = 0,
) -> None:
    ...
    self._unusual_uid_enabled = unusual_uid_enabled
    self._root_uid_threshold = root_uid_threshold
```

**Step 2 — Write the rule method:**

```python
def _check_unusual_uid(self, event: RawEvent) -> Optional[AlertEvent]:
    if not self._unusual_uid_enabled:
        return None
    if event.uid > self._root_uid_threshold:
        return None
    # uid == 0 means root
    return AlertEvent(
        alert_type="unusual_uid",
        pid=event.pid,
        process=event.process,
        syscall=event.syscall,
        detail=f"syscall {event.syscall} by uid={event.uid}",
        timestamp=event.timestamp,
        agent_id=event.agent_id,
        model_name=event.model_name,
    )
```

**Step 3 — Call the rule in `evaluate()`:**

```python
if self._unusual_uid_enabled:
    alert = self._check_unusual_uid(event)
    if alert is not None:
        alerts.append(alert)
```

**Step 4 — Add to `guardian.yaml`:**

```yaml
local_alerts:
  - type: unusual_uid
    condition: "any syscall by uid=0"
    action: log_and_alert
```

**Step 5 — Wire in `agent/main.py`** where `LocalAlertEngine` is instantiated, passing the new config values.

**Step 6 — Write tests** for: rule fires on match, rule does not fire on non-match, rule inactive when disabled, custom handler receives correct `AlertEvent`.

---

## Constants

```python
_SHELL_BINARIES = frozenset(
    ["/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"]
)
_NETWORK_INITIATION_SYSCALLS = frozenset(["connect", "sendto"])
```

Both are module-level `frozenset` constants — immutable, hashable, and O(1) for membership tests. They are not configurable at runtime; any modification requires a code change and redeployment.

---

## Related Documents

- `docs/04-security/local-alerts.md` — design rationale, trigger conditions, what local alerts cannot detect
- `docs/05-components/enricher.md` — sets `agent_id` and `model_name` on `RawEvent` before alert evaluation
- `docs/05-components/config-loader.md` — `LocalAlert` dataclass, `network_allowlist` field
- `docs/04-security/threat-model.md` — threats that local alerts address (T-1, T-9)
