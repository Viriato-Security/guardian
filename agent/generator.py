"""
Phase 1 fake event generator.

Produces RawEvent instances whose schema is identical to what the Phase 2
eBPF loader will emit.  Used on macOS and in CI where kernel code cannot run.
"""

from __future__ import annotations

import random
import time
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterator

from agent.config import Config


@dataclass
class RawEvent:
    """Kernel event as captured (or synthesised) before enrichment/signing."""

    timestamp: str = ""
    pid: int = 0
    process: str = ""
    syscall: str = ""
    fd_path: str = ""
    bytes: int = 0
    network_addr: str = ""
    return_val: str = "0"
    uid: int = 0
    # Filled by enricher.py
    agent_id: str = ""
    model_name: str = ""
    container_id: str = ""
    pod_name: str = ""
    namespace: str = ""
    # Filled by signer.py
    prev_hash: str = ""
    this_hash: str = ""


def _now_iso_ns() -> str:
    """Return the current UTC time as ISO 8601 with exactly 9 nanosecond digits.

    Uses ``datetime.now(timezone.utc)`` — no deprecated ``utcfromtimestamp``.
    Ends in ``Z``.
    """
    now = datetime.now(timezone.utc)
    # datetime only gives microseconds; pad to nanoseconds with zeros.
    us = now.microsecond
    ns_str = f"{us:06d}000"  # 6 µs digits + 3 trailing zeros → 9 digits
    return now.strftime("%Y-%m-%dT%H:%M:%S") + f".{ns_str}Z"


# ---------------------------------------------------------------------------
# Realistic data pools
# ---------------------------------------------------------------------------

_FILE_PATHS = [
    "/var/lib/models/patient-diagnosis-v2/model.pt",
    "/var/lib/models/fraud-detection-v1/config.json",
    "/tmp/torch_cache/hub/checkpoints/model.bin",
    "/tmp/torch_cache/hub/checkpoints/tokenizer.json",
    "/proc/self/status",
    "/proc/self/maps",
    "/dev/urandom",
    "/etc/ld.so.cache",
    "/usr/lib/libpython3.12.so",
]

_INTERNAL_ADDRS = [
    "10.0.0.1:8080",
    "10.0.1.45:5000",
    "10.1.2.3:9090",
    "172.16.0.5:6379",
]

_EXTERNAL_ADDRS = [
    "203.0.113.42:443",
    "198.51.100.7:80",
    "93.184.216.34:443",
]

_ALL_NETWORK_ADDRS = _INTERNAL_ADDRS + _EXTERNAL_ADDRS

_SHELL_PATHS = ["/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"]

# Syscall distribution mimicking PyTorch inference workload
_SYSCALL_WEIGHTS = {
    "read": 35,
    "write": 25,
    "openat": 15,
    "sendto": 7,
    "recvfrom": 6,
    "connect": 5,
    "socket": 4,
    "clone": 3,
}


class FakeEventGenerator:
    """Generates a stream of realistic fake syscall events.

    The stream mimics a PyTorch-based AI inference workload.  Every 80–150
    events an ``execve`` is injected (regardless of the configured syscall
    list) so that local alert rules can be tested end-to-end.

    Args:
        config: Loaded guardian configuration.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._syscall_pool = list(config.syscalls) if config.syscalls else list(_SYSCALL_WEIGHTS)
        self._watch_entries = config.watch
        self._events_generated: int = 0
        self._next_execve_in: int = random.randint(500, 1000)

        # Build weighted syscall list for realistic distribution
        self._weighted_syscalls: list[str] = []
        for sc in self._syscall_pool:
            weight = _SYSCALL_WEIGHTS.get(sc, 1)
            self._weighted_syscalls.extend([sc] * weight)

    @property
    def events_generated(self) -> int:
        """Total events emitted so far."""
        return self._events_generated

    def stream(self) -> Iterator[RawEvent]:
        """Yield RawEvent instances indefinitely, sleeping between each.

        Sleep interval: ``random.uniform(0.0005, 0.002)`` (500–2000 µs),
        simulating 500–2000 syscalls/sec.
        """
        while True:
            event = self._make_event()
            self._events_generated += 1
            yield event
            time.sleep(random.uniform(0.0005, 0.002))

    def _make_event(self) -> RawEvent:
        """Produce a single synthetic RawEvent."""
        # Inject execve periodically for alert testing
        if self._events_generated >= self._next_execve_in:
            self._next_execve_in = self._events_generated + random.randint(500, 1000)
            return self._make_execve_event()

        syscall = random.choice(self._weighted_syscalls) if self._weighted_syscalls else "read"
        return self._make_syscall_event(syscall)

    def _make_syscall_event(self, syscall: str) -> RawEvent:
        process, pid, uid = self._random_process()
        ev = RawEvent(
            timestamp=_now_iso_ns(),
            pid=pid,
            process=process,
            syscall=syscall,
            return_val="0",
            uid=uid,
        )

        if syscall in ("read", "write", "openat"):
            ev.fd_path = random.choice(_FILE_PATHS)
            ev.bytes = random.randint(512, 65536)

        elif syscall in ("sendto", "recvfrom", "connect"):
            ev.network_addr = random.choice(_ALL_NETWORK_ADDRS)
            if syscall in ("sendto", "recvfrom"):
                ev.bytes = random.randint(64, 4096)

        elif syscall == "socket":
            pass  # no additional fields

        elif syscall == "clone":
            pass  # no additional fields

        # Occasionally inject an errno
        if random.random() < 0.03:
            ev.return_val = random.choice(["-1", "-2", "-13", "-22"])

        return ev

    def _make_execve_event(self) -> RawEvent:
        process, pid, uid = self._random_process()
        return RawEvent(
            timestamp=_now_iso_ns(),
            pid=pid,
            process=process,
            syscall="execve",
            fd_path=random.choice(_SHELL_PATHS),
            bytes=0,
            network_addr="",
            return_val="0",
            uid=uid,
        )

    def _random_process(self) -> tuple[str, int, int]:
        if self._watch_entries:
            entry = random.choice(self._watch_entries)
            process = entry.process
        else:
            process = "python"
        pid = random.randint(1000, 65535)
        uid = random.randint(0, 1000)
        return process, pid, uid
