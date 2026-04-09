"""Tests for agent/local_alerts.py — local alert engine."""

from __future__ import annotations

from typing import Any

import pytest

from agent.config import AgentConfig, Config, LocalAlert
from agent.generator import RawEvent
from agent.local_alerts import AlertEvent, LocalAlertEngine

# Sentinel to distinguish "no custom handler set" from an empty list of alerts
_SENTINEL = object()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    alerts: Any = _SENTINEL,
    allowlist: list[str] | None = None,
) -> Config:
    """Build a Config with optional alert rules and allowlist."""
    if alerts is _SENTINEL:
        default_alerts: list[LocalAlert] = [
            LocalAlert(type="sandbox_escape", condition="execve matches shell", action="log_and_alert"),
            LocalAlert(type="unexpected_network", condition="connect not in allowlist", action="log_and_alert"),
        ]
        local_alerts = default_alerts
    else:
        local_alerts = list(alerts)

    return Config(
        agent=AgentConfig(token="test-token"),
        local_alerts=local_alerts,
        network_allowlist=allowlist or [],
    )


def _make_engine(
    alerts: Any = _SENTINEL,
    allowlist: list[str] | None = None,
) -> LocalAlertEngine:
    """Create an engine, injecting a custom handler to suppress output."""
    cfg = _make_config(alerts=alerts, allowlist=allowlist)
    sandbox = any(a.type == "sandbox_escape" for a in cfg.local_alerts)
    network = any(a.type == "unexpected_network" for a in cfg.local_alerts)
    engine = LocalAlertEngine(
        sandbox_escape_enabled=sandbox,
        unexpected_network_enabled=network,
        network_allowlist=list(cfg.network_allowlist),
    )
    # Suppress output in tests
    engine.set_custom_handler(lambda alert: None)
    return engine


def _execve(fd_path: str = "/bin/bash", process: str = "python", pid: int = 1234) -> RawEvent:
    return RawEvent(
        timestamp="2026-04-09T12:00:00.000000000Z",
        pid=pid,
        process=process,
        syscall="execve",
        fd_path=fd_path,
    )


def _connect(network_addr: str, process: str = "python", pid: int = 1234) -> RawEvent:
    return RawEvent(
        timestamp="2026-04-09T12:00:00.000000000Z",
        pid=pid,
        process=process,
        syscall="connect",
        network_addr=network_addr,
    )


def _read(fd_path: str = "/tmp/model.pt") -> RawEvent:
    return RawEvent(
        timestamp="2026-04-09T12:00:00.000000000Z",
        pid=1234,
        process="python",
        syscall="read",
        fd_path=fd_path,
        bytes=4096,
    )


def _recvfrom(network_addr: str = "1.2.3.4:443") -> RawEvent:
    return RawEvent(
        timestamp="2026-04-09T12:00:00.000000000Z",
        pid=1234,
        process="python",
        syscall="recvfrom",
        network_addr=network_addr,
    )


# ---------------------------------------------------------------------------
# sandbox_escape tests
# ---------------------------------------------------------------------------


def test_sandbox_escape_fires_on_bin_bash() -> None:
    engine = _make_engine()
    alerts = engine.evaluate(_execve("/bin/bash"))
    assert any(a.alert_type == "sandbox_escape" for a in alerts)


def test_sandbox_escape_fires_on_bin_sh() -> None:
    engine = _make_engine()
    alerts = engine.evaluate(_execve("/bin/sh"))
    assert any(a.alert_type == "sandbox_escape" for a in alerts)


def test_sandbox_escape_fires_on_usr_bin_sh() -> None:
    engine = _make_engine()
    alerts = engine.evaluate(_execve("/usr/bin/sh"))
    assert any(a.alert_type == "sandbox_escape" for a in alerts)


def test_sandbox_escape_no_fire_on_python() -> None:
    engine = _make_engine()
    alerts = engine.evaluate(_execve("/usr/bin/python3"))
    assert not any(a.alert_type == "sandbox_escape" for a in alerts)


def test_sandbox_escape_no_fire_on_read_with_bash_path() -> None:
    engine = _make_engine()
    alerts = engine.evaluate(_read("/bin/bash"))
    assert not any(a.alert_type == "sandbox_escape" for a in alerts)


def test_sandbox_escape_alert_contains_correct_pid_and_process() -> None:
    engine = _make_engine()
    alerts = engine.evaluate(_execve("/bin/bash", process="torchserve", pid=5555))
    se = [a for a in alerts if a.alert_type == "sandbox_escape"]
    assert len(se) == 1
    assert se[0].pid == 5555
    assert se[0].process == "torchserve"


# ---------------------------------------------------------------------------
# unexpected_network tests
# ---------------------------------------------------------------------------


def test_unexpected_network_fires_on_unlisted_connect() -> None:
    engine = _make_engine(allowlist=["10.0.0.1:8080"])
    alerts = engine.evaluate(_connect("99.99.99.99:443"))
    assert any(a.alert_type == "unexpected_network" for a in alerts)


def test_no_fire_on_connect_to_allowed_addr() -> None:
    engine = _make_engine(allowlist=["10.0.0.1:8080"])
    alerts = engine.evaluate(_connect("10.0.0.1:8080"))
    assert not any(a.alert_type == "unexpected_network" for a in alerts)


def test_no_fire_when_allowlist_is_empty() -> None:
    """Empty allowlist means no restriction — all addresses allowed."""
    engine = _make_engine(allowlist=[])
    alerts = engine.evaluate(_connect("99.99.99.99:443"))
    assert not any(a.alert_type == "unexpected_network" for a in alerts)


def test_no_fire_on_recvfrom() -> None:
    """recvfrom is not a connection initiation — should not fire unexpected_network."""
    engine = _make_engine(allowlist=["10.0.0.1:8080"])
    alerts = engine.evaluate(_recvfrom("99.99.99.99:443"))
    assert not any(a.alert_type == "unexpected_network" for a in alerts)


# ---------------------------------------------------------------------------
# General tests
# ---------------------------------------------------------------------------


def test_empty_alert_list_no_alerts() -> None:
    """Engine with zero rules must produce zero alerts."""
    engine = _make_engine(alerts=[])
    alerts = engine.evaluate(_execve("/bin/bash"))
    assert alerts == []


def test_alert_count_increments() -> None:
    engine = _make_engine()
    engine.evaluate(_execve("/bin/bash"))
    engine.evaluate(_execve("/bin/sh"))
    assert engine.alert_count == 2


def test_custom_handler_receives_alert_event() -> None:
    received: list[AlertEvent] = []
    engine = _make_engine()
    engine.set_custom_handler(received.append)
    engine.evaluate(_execve("/bin/bash"))
    assert len(received) == 1
    assert isinstance(received[0], AlertEvent)


def test_normal_read_fires_no_alerts() -> None:
    engine = _make_engine()
    alerts = engine.evaluate(_read())
    assert alerts == []
