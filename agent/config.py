"""
Guardian configuration loader.

Reads guardian.yaml from standard search paths, validates it, and exposes
typed dataclasses consumed by every other agent module.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

_PLACEHOLDER_TOKEN = "YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE"
_SEARCH_PATHS = [
    "./guardian.yaml",
    "/etc/guardian/guardian.yaml",
    os.path.expanduser("~/.guardian/guardian.yaml"),
]


@dataclass
class AgentConfig:
    """Low-level agent tunables."""

    token: str
    control_plane: str = "grpc.viriatosecurity.com:443"
    batch_interval_ms: int = 100
    buffer_path: str = "/var/lib/guardian/buffer"


@dataclass
class WatchEntry:
    """Maps a process name to a model name for enrichment."""

    process: str
    model_name: str


@dataclass
class LocalAlert:
    """A local alert rule definition (evaluated by LocalAlertEngine)."""

    type: str
    condition: str
    action: str


@dataclass
class ComplianceConfig:
    """EU AI Act compliance metadata."""

    organization: str = ""
    data_categories: list[str] = field(default_factory=list)
    articles: list[int] = field(default_factory=list)


@dataclass
class Config:
    """Top-level guardian configuration."""

    agent: AgentConfig
    watch: list[WatchEntry] = field(default_factory=list)
    syscalls: list[str] = field(default_factory=list)
    local_alerts: list[LocalAlert] = field(default_factory=list)
    network_allowlist: list[str] = field(default_factory=list)
    compliance: ComplianceConfig = field(default_factory=ComplianceConfig)

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def model_name_for_process(self, process: str) -> str:
        """Return the model name configured for *process*, or ``'unknown'``."""
        for entry in self.watch:
            if entry.process == process:
                return entry.model_name
        return "unknown"

    @property
    def batch_interval_seconds(self) -> float:
        """batch_interval_ms converted to seconds."""
        return self.agent.batch_interval_ms / 1000.0


# ------------------------------------------------------------------
# Public loader
# ------------------------------------------------------------------


def load_config(path: Optional[str] = None) -> Config:
    """Load and validate *guardian.yaml*.

    Search order (first found wins):
      1. *path* argument (if provided)
      2. ``./guardian.yaml``
      3. ``/etc/guardian/guardian.yaml``
      4. ``~/.guardian/guardian.yaml``

    Raises ``FileNotFoundError`` if no config file is found.
    When *path* is provided explicitly and does not exist, raises immediately
    without falling back to auto-discovery.
    Logs a warning (does **not** raise) if the token is still the placeholder.
    """
    if path is not None and not os.path.isfile(path):
        raise FileNotFoundError(f"Config file not found: {path}")

    candidates = [path] if path else []
    candidates.extend(_SEARCH_PATHS)

    raw: dict  # type: ignore[type-arg]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            with open(candidate) as fh:
                raw = yaml.safe_load(fh) or {}
            logger.debug("Loaded config from %s", candidate)
            break
    else:
        raise FileNotFoundError(
            f"guardian.yaml not found. Tried: {candidates}. "
            "Copy guardian.yaml.example to guardian.yaml and fill in your token."
        )

    return _parse(raw)


def _parse(raw: dict) -> Config:  # type: ignore[type-arg]
    agent_raw = raw.get("agent", {})
    agent = AgentConfig(
        token=str(agent_raw.get("token", "")),
        control_plane=str(agent_raw.get("control_plane", "grpc.viriatosecurity.com:443")),
        batch_interval_ms=int(agent_raw.get("batch_interval_ms", 100)),
        buffer_path=str(agent_raw.get("buffer_path", "/var/lib/guardian/buffer")),
    )

    if not agent.token or agent.token == _PLACEHOLDER_TOKEN:
        logger.warning(
            "Guardian token is not set or is still the placeholder. "
            "Events will be buffered locally but NOT sent to viriato-platform. "
            "Obtain a real token at https://viriatosecurity.com"
        )

    watch = [
        WatchEntry(process=str(e["process"]), model_name=str(e["model_name"]))
        for e in raw.get("watch", [])
    ]

    syscalls: list[str] = [str(s) for s in raw.get("syscalls", [])]

    local_alerts = [
        LocalAlert(
            type=str(a["type"]),
            condition=str(a["condition"]),
            action=str(a.get("action", "log_and_alert")),
        )
        for a in raw.get("local_alerts", [])
    ]

    network_allowlist: list[str] = [str(a) for a in raw.get("network_allowlist", [])]

    compliance_raw = raw.get("compliance", {})
    compliance = ComplianceConfig(
        organization=str(compliance_raw.get("organization", "")),
        data_categories=[str(c) for c in compliance_raw.get("data_categories", [])],
        articles=[int(a) for a in compliance_raw.get("articles", [])],
    )

    return Config(
        agent=agent,
        watch=watch,
        syscalls=syscalls,
        local_alerts=local_alerts,
        network_allowlist=network_allowlist,
        compliance=compliance,
    )
