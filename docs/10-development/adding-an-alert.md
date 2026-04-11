# Adding a New Alert Type

This guide walks through every change needed to add a new local alert rule to
`LocalAlertEngine`. The example alert is **`large_data_exfiltration`** — fires when
a `sendto` syscall transfers more than 10 MB in a single call, which is anomalous
for AI inference workloads and may indicate data exfiltration.

---

## Overview of Changes

| Step | File | What changes |
|------|------|-------------|
| 1 | Design | Define the rule condition, action, and detail string |
| 2 | `agent/local_alerts.py` | Add `_check_large_data_exfiltration()` method |
| 3 | `agent/local_alerts.py` | Register the check in `evaluate()` |
| 4 | `guardian.yaml.example` | Add the alert definition |
| 5 | `tests/test_local_alerts.py` | Add tests (fires, doesn't fire, custom handler) |

---

## Step 1 — Design the Rule

Before writing any code, define the rule precisely:

| Property | Value |
|----------|-------|
| **alert_type** | `large_data_exfiltration` |
| **Trigger syscall** | `sendto` |
| **Trigger condition** | `bytes > 10 * 1024 * 1024` (10 485 760 bytes = 10 MiB) |
| **Action** | `log_and_alert` |
| **detail string** | `f"sendto {bytes} bytes to {network_addr}"` |
| **Config flag** | `large_data_exfiltration_enabled` constructor argument |

The threshold of 10 MiB per `sendto` call is well above any normal API response
body but well below a model weight file (which would typically be `mmap`d, not
sent via `sendto`).

---

## Step 2 — Add _check_large_data_exfiltration() to LocalAlertEngine

Open `agent/local_alerts.py`.

First, add a module-level constant for the threshold (keeps the magic number out of
the method body and makes it easy to test):

```python
_LARGE_DATA_THRESHOLD_BYTES: int = 10 * 1024 * 1024  # 10 MiB
```

Then add the private check method to `LocalAlertEngine`, alongside the existing
`_check_sandbox_escape()` and `_check_unexpected_network()` methods:

```python
def _check_large_data_exfiltration(self, event: RawEvent) -> Optional[AlertEvent]:
    """Fire when a single sendto transfers more than 10 MiB.

    Only inspects ``sendto`` events. ``recvfrom`` (inbound) is not flagged
    because receiving large responses is expected for model inference.
    """
    if event.syscall != "sendto":
        return None
    if event.bytes <= _LARGE_DATA_THRESHOLD_BYTES:
        return None
    return AlertEvent(
        alert_type="large_data_exfiltration",
        pid=event.pid,
        process=event.process,
        syscall=event.syscall,
        detail=f"sendto {event.bytes} bytes to {event.network_addr}",
        timestamp=event.timestamp,
        agent_id=event.agent_id,
        model_name=event.model_name,
    )
```

Also add the constructor argument so the alert can be enabled/disabled from config:

```python
class LocalAlertEngine:
    def __init__(
        self,
        sandbox_escape_enabled: bool = True,
        unexpected_network_enabled: bool = True,
        large_data_exfiltration_enabled: bool = True,   # <-- add this
        network_allowlist: Optional[list[str]] = None,
    ) -> None:
        self._sandbox_escape_enabled = sandbox_escape_enabled
        self._unexpected_network_enabled = unexpected_network_enabled
        self._large_data_exfiltration_enabled = large_data_exfiltration_enabled  # <-- add this
        self._network_allowlist: list[str] = network_allowlist or []
        self._alert_count: int = 0
        self._custom_handler: Optional[Callable[[AlertEvent], None]] = None
```

---

## Step 3 — Register the Check in evaluate()

Open `agent/local_alerts.py` and find the `evaluate()` method.
Add the new check alongside the existing ones:

```python
def evaluate(self, event: RawEvent) -> list[AlertEvent]:
    """Evaluate all active rules against *event*."""
    alerts: list[AlertEvent] = []

    if self._sandbox_escape_enabled:
        alert = self._check_sandbox_escape(event)
        if alert is not None:
            alerts.append(alert)

    if self._unexpected_network_enabled:
        alert = self._check_unexpected_network(event)
        if alert is not None:
            alerts.append(alert)

    if self._large_data_exfiltration_enabled:          # <-- add this block
        alert = self._check_large_data_exfiltration(event)
        if alert is not None:
            alerts.append(alert)

    for alert in alerts:
        self._fire(alert)

    return alerts
```

The pattern is always the same: check the `_enabled` flag, call the private method,
append if not `None`.

---

## Step 4 — Add to guardian.yaml.example

Open `guardian.yaml.example` and add the new alert type under `local_alerts`:

```yaml
local_alerts:
  - type: sandbox_escape
    condition: "execve matches /bin/bash or /bin/sh"
    action: log_and_alert
  - type: unexpected_network
    condition: "connect to addr not in allowlist"
    action: log_and_alert
  - type: large_data_exfiltration
    condition: "sendto bytes > 10485760"
    action: log_and_alert
```

The `condition` field is a human-readable description used for documentation and
future rule-engine parsing. It does not change runtime behaviour in Phase 1 —
`LocalAlertEngine` reads the `type` field to decide which checks to enable.

Update `agent/main.py` in `_setup_components()` to read the new type:

```python
large_data_enabled = any(
    a.type == "large_data_exfiltration" for a in self._config.local_alerts
)
self._alert_engine = LocalAlertEngine(
    sandbox_escape_enabled=sandbox_enabled,
    unexpected_network_enabled=network_enabled,
    large_data_exfiltration_enabled=large_data_enabled,
    network_allowlist=list(self._config.network_allowlist),
)
```

---

## Step 5 — Add Tests in test_local_alerts.py

Add the following tests to `tests/test_local_alerts.py`.

### Helper RawEvent factory

```python
def _sendto(
    network_addr: str = "203.0.113.42:443",
    bytes_count: int = 1024,
    process: str = "python",
    pid: int = 1234,
) -> RawEvent:
    return RawEvent(
        timestamp="2026-04-09T12:00:00.000000000Z",
        pid=pid,
        process=process,
        syscall="sendto",
        network_addr=network_addr,
        bytes=bytes_count,
    )
```

### Test: alert fires above threshold

```python
def test_large_data_exfiltration_fires_above_threshold() -> None:
    """Alert must fire when sendto bytes > 10 MiB."""
    engine = LocalAlertEngine(
        large_data_exfiltration_enabled=True,
    )
    received: list[AlertEvent] = []
    engine.set_custom_handler(received.append)  # suppress stderr noise

    alerts = engine.evaluate(_sendto(bytes_count=10 * 1024 * 1024 + 1))

    assert any(a.alert_type == "large_data_exfiltration" for a in alerts), (
        "Expected large_data_exfiltration alert for sendto > 10 MiB"
    )
    assert received[0].detail == f"sendto {10 * 1024 * 1024 + 1} bytes to 203.0.113.42:443"
```

### Test: alert does not fire at or below threshold

```python
def test_large_data_exfiltration_no_fire_at_threshold() -> None:
    """Alert must NOT fire when sendto bytes == 10 MiB (boundary: strictly greater than)."""
    engine = LocalAlertEngine(large_data_exfiltration_enabled=True)
    engine.set_custom_handler(lambda _: None)

    alerts = engine.evaluate(_sendto(bytes_count=10 * 1024 * 1024))

    assert not any(a.alert_type == "large_data_exfiltration" for a in alerts)


def test_large_data_exfiltration_no_fire_for_small_sendto() -> None:
    """Normal sendto (e.g. 4 KB) must not fire the alert."""
    engine = LocalAlertEngine(large_data_exfiltration_enabled=True)
    engine.set_custom_handler(lambda _: None)

    alerts = engine.evaluate(_sendto(bytes_count=4096))

    assert not any(a.alert_type == "large_data_exfiltration" for a in alerts)
```

### Test: alert does not fire for recvfrom

```python
def test_large_data_exfiltration_no_fire_for_recvfrom() -> None:
    """recvfrom is not flagged — only outbound sendto is checked."""
    engine = LocalAlertEngine(large_data_exfiltration_enabled=True)
    engine.set_custom_handler(lambda _: None)

    event = RawEvent(
        timestamp="2026-04-09T12:00:00.000000000Z",
        pid=1234,
        process="python",
        syscall="recvfrom",
        network_addr="203.0.113.42:443",
        bytes=50 * 1024 * 1024,  # 50 MiB inbound — expected for large model responses
    )
    alerts = engine.evaluate(event)

    assert not any(a.alert_type == "large_data_exfiltration" for a in alerts)
```

### Test: custom handler pattern for testing without stderr noise

The `set_custom_handler()` method replaces the default `logger.error` + `print`
output. Always use it in tests to avoid polluting the test output:

```python
def test_custom_handler_receives_large_data_alert() -> None:
    """set_custom_handler must be called with the AlertEvent on a match."""
    received: list[AlertEvent] = []
    engine = LocalAlertEngine(large_data_exfiltration_enabled=True)
    engine.set_custom_handler(received.append)

    engine.evaluate(_sendto(bytes_count=20 * 1024 * 1024))

    assert len(received) == 1
    assert received[0].alert_type == "large_data_exfiltration"
    assert received[0].pid == 1234
    assert received[0].process == "python"
```

Run the new tests:

```bash
python -m pytest tests/test_local_alerts.py -v -k large_data
```

All five tests must pass.

---

## Pattern Summary

Every alert follows the same three-part pattern:

1. **Constant** — threshold or set at module level.
2. **Method** — `_check_<name>(self, event: RawEvent) -> Optional[AlertEvent]`.
   Returns `None` if no match, an `AlertEvent` if triggered.
3. **Registration** — `_<name>_enabled` constructor flag, checked in `evaluate()`.

Following this pattern keeps `evaluate()` a simple linear scan and makes each rule
independently testable.

---

## Related Documents

- [adding-a-syscall.md](adding-a-syscall.md)
- [local-setup.md](local-setup.md)
- [contributing.md](contributing.md)
- [../../docs/04-security/local-alerts.md](../04-security/)
