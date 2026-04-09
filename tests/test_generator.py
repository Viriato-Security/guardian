"""Tests for agent/generator.py — fake event generation."""

from __future__ import annotations

import re
import warnings
from dataclasses import fields

import pytest

from agent.config import AgentConfig, Config, WatchEntry
from agent.generator import FakeEventGenerator, RawEvent, _now_iso_ns

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$")

_DEFAULT_SYSCALLS = [
    "read", "write", "openat", "sendto", "recvfrom", "connect", "execve", "clone", "socket"
]


def _make_config(
    syscalls: list[str] | None = None,
    watch: list[WatchEntry] | None = None,
) -> Config:
    return Config(
        agent=AgentConfig(token="test-token"),
        syscalls=syscalls or _DEFAULT_SYSCALLS,
        watch=watch
        or [
            WatchEntry(process="python", model_name="patient-diagnosis-v2"),
            WatchEntry(process="torchserve", model_name="fraud-detection-v1"),
        ],
    )


def _collect(n: int = 10, config: Config | None = None) -> list[RawEvent]:
    """Collect *n* events quickly (no sleeping)."""
    cfg = config or _make_config()
    gen = FakeEventGenerator(cfg)
    # Monkey-patch the stream to not sleep
    import time as _time

    events: list[RawEvent] = []
    # Directly call _make_event to avoid sleeping
    for _ in range(n):
        events.append(gen._make_event())
        gen._events_generated += 1
    return events


# ---------------------------------------------------------------------------
# Basic generation tests
# ---------------------------------------------------------------------------


def test_generates_events() -> None:
    events = _collect(5)
    assert len(events) == 5


def test_all_events_are_rawevent_instances() -> None:
    events = _collect(20)
    for e in events:
        assert isinstance(e, RawEvent)


def test_timestamp_format() -> None:
    events = _collect(20)
    for e in events:
        assert _TS_RE.match(e.timestamp), f"Bad timestamp: {e.timestamp!r}"


def test_pid_positive() -> None:
    events = _collect(20)
    for e in events:
        assert e.pid > 0


def test_uid_non_negative() -> None:
    events = _collect(20)
    for e in events:
        assert e.uid >= 0


def test_syscall_from_configured_list() -> None:
    syscalls = ["read", "write", "openat"]
    cfg = _make_config(syscalls=syscalls)
    gen = FakeEventGenerator(cfg)
    # Generate non-execve events (reset next_execve far in future)
    gen._next_execve_in = 10_000
    gen._events_generated = 0
    for _ in range(50):
        e = gen._make_event()
        gen._events_generated += 1
        if e.syscall != "execve":
            assert e.syscall in syscalls, f"Unexpected syscall: {e.syscall}"


def test_process_from_watch_list() -> None:
    watch = [
        WatchEntry(process="python", model_name="m1"),
        WatchEntry(process="torchserve", model_name="m2"),
    ]
    cfg = _make_config(watch=watch)
    events = _collect(30, config=cfg)
    allowed = {"python", "torchserve"}
    for e in events:
        assert e.process in allowed, f"Unexpected process: {e.process}"


def test_read_write_events_have_bytes_gt_zero() -> None:
    cfg = _make_config(syscalls=["read", "write"])
    gen = FakeEventGenerator(cfg)
    gen._next_execve_in = 10_000
    gen._events_generated = 0
    for _ in range(30):
        e = gen._make_event()
        gen._events_generated += 1
        if e.syscall in ("read", "write"):
            assert e.bytes > 0, f"Expected bytes > 0 for {e.syscall}"


def test_network_events_have_non_empty_network_addr() -> None:
    cfg = _make_config(syscalls=["sendto", "recvfrom", "connect"])
    gen = FakeEventGenerator(cfg)
    gen._next_execve_in = 10_000
    gen._events_generated = 0
    for _ in range(30):
        e = gen._make_event()
        gen._events_generated += 1
        if e.syscall in ("sendto", "recvfrom", "connect"):
            assert e.network_addr, f"Expected non-empty network_addr for {e.syscall}"


def test_execve_events_have_fd_path_starting_with_slash() -> None:
    cfg = _make_config()
    gen = FakeEventGenerator(cfg)
    # Force an execve by making next_execve_in = 0
    gen._next_execve_in = 0
    gen._events_generated = 0
    e = gen._make_event()
    assert e.syscall == "execve"
    assert e.fd_path.startswith("/")


def test_no_none_fields() -> None:
    events = _collect(30)
    field_names = [f.name for f in fields(RawEvent)]
    for e in events:
        for fname in field_names:
            val = getattr(e, fname)
            assert val is not None, f"Field {fname!r} is None"


def test_return_val_is_str() -> None:
    events = _collect(30)
    for e in events:
        assert isinstance(e.return_val, str)


def test_distinct_syscall_types_in_200_events() -> None:
    events = _collect(200)
    syscalls = {e.syscall for e in events}
    assert len(syscalls) >= 4, f"Too few syscall types: {syscalls}"


# ---------------------------------------------------------------------------
# _now_iso_ns tests
# ---------------------------------------------------------------------------


def test_now_iso_ns_correct_format() -> None:
    ts = _now_iso_ns()
    assert _TS_RE.match(ts), f"Bad format: {ts!r}"


def test_now_iso_ns_ends_in_z() -> None:
    ts = _now_iso_ns()
    assert ts.endswith("Z")


def test_now_iso_ns_no_deprecation_warnings() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        _now_iso_ns()  # must not raise
