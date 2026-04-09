"""
Local alert engine — fires rules synchronously without any network call.

Rules:
  sandbox_escape    execve to a shell binary (/bin/bash, /bin/sh, …)
  unexpected_network  connect/sendto to an address not in the allowlist
                      (only active when allowlist is non-empty)
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from typing import Callable, Optional

from agent.generator import RawEvent

logger = logging.getLogger(__name__)

_SHELL_BINARIES = frozenset(
    ["/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"]
)
_NETWORK_INITIATION_SYSCALLS = frozenset(["connect", "sendto"])

# Sentinel to distinguish "no handler configured" from "empty list of alerts"
_SENTINEL = object()


@dataclass
class AlertEvent:
    """Fired when a local alert rule matches."""

    alert_type: str
    pid: int
    process: str
    syscall: str
    detail: str
    timestamp: str
    agent_id: str
    model_name: str


class LocalAlertEngine:
    """Evaluates local alert rules against each RawEvent.

    Args:
        sandbox_escape_enabled: Whether to fire sandbox_escape alerts.
        unexpected_network_enabled: Whether to fire unexpected_network alerts.
        network_allowlist: Allowed network addresses.  An *empty* list means
            no restriction (all addresses allowed).  Pass a non-empty list to
            restrict.
    """

    def __init__(
        self,
        sandbox_escape_enabled: bool = True,
        unexpected_network_enabled: bool = True,
        network_allowlist: Optional[list[str]] = None,
    ) -> None:
        self._sandbox_escape_enabled = sandbox_escape_enabled
        self._unexpected_network_enabled = unexpected_network_enabled
        self._network_allowlist: list[str] = network_allowlist or []
        self._alert_count: int = 0
        self._custom_handler: Optional[Callable[[AlertEvent], None]] = None

    @property
    def alert_count(self) -> int:
        """Total alerts fired since this engine was created."""
        return self._alert_count

    def set_custom_handler(self, fn: Callable[[AlertEvent], None]) -> None:
        """Override the default stderr output with a custom callback.

        When set, the default ``logger.error`` / ``print`` calls are
        suppressed — only *fn* is called.  Useful for testing.
        """
        self._custom_handler = fn

    def evaluate(self, event: RawEvent) -> list[AlertEvent]:
        """Evaluate all active rules against *event*.

        Returns a (possibly empty) list of AlertEvent objects.
        """
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

    # ------------------------------------------------------------------
    # Rule implementations
    # ------------------------------------------------------------------

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

    def _check_unexpected_network(self, event: RawEvent) -> Optional[AlertEvent]:
        if event.syscall not in _NETWORK_INITIATION_SYSCALLS:
            return None
        # Empty allowlist → no restriction
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

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

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
