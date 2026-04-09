"""
Context enricher — fills in agent_id, model_name, container_id, pod_name,
and namespace on each RawEvent before it reaches the signer.
"""

from __future__ import annotations

import functools
import logging
import os
import re
import uuid

from agent.config import Config
from agent.generator import RawEvent

logger = logging.getLogger(__name__)

_DOCKER_CGROUP_RE = re.compile(r"/docker/([a-f0-9]{12,64})")
_AGENT_ID_PROD = "/var/lib/guardian/.agent_id"
_AGENT_ID_DEV = os.path.expanduser("~/.guardian_agent_id")


def _load_or_create_agent_id() -> str:
    """Return the persistent agent UUID, creating it on first run."""
    for path in (_AGENT_ID_PROD, _AGENT_ID_DEV):
        if os.path.isfile(path):
            try:
                agent_id = open(path).read().strip()
                uuid.UUID(agent_id)  # validate format
                return agent_id
            except (OSError, ValueError):
                pass

    # Create a new UUID and persist it
    new_id = str(uuid.uuid4())
    for path in (_AGENT_ID_PROD, _AGENT_ID_DEV):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(new_id)
            logger.info("Created agent_id %s at %s", new_id, path)
            return new_id
        except OSError:
            continue

    # Last resort: in-memory only (not persisted)
    logger.warning("Could not persist agent_id — using ephemeral UUID")
    return new_id


class Enricher:
    """Mutates RawEvent in-place with environment context.

    Args:
        config: Loaded guardian configuration.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._agent_id: str = _load_or_create_agent_id()
        self._pod_name: str = os.environ.get("KUBERNETES_POD_NAME", "")
        self._namespace: str = os.environ.get("KUBERNETES_NAMESPACE", "")

    @property
    def agent_id(self) -> str:
        """The UUID identifying this Guardian installation."""
        return self._agent_id

    def enrich(self, event: RawEvent) -> RawEvent:
        """Fill agent_id, model_name, container_id, pod_name, namespace.

        Mutates *event* in-place and returns the same object.
        """
        event.agent_id = self._agent_id
        event.model_name = self._config.model_name_for_process(event.process)
        event.container_id = self._container_id(event.pid)
        event.pod_name = self._pod_name
        event.namespace = self._namespace
        return event

    @functools.lru_cache(maxsize=512)
    def _container_id(self, pid: int) -> str:
        """Parse /proc/<pid>/cgroup to extract a Docker short container ID.

        Returns a 12-character short ID, or ``''`` if not in a container or
        the file does not exist.

        LRU-cached per PID (512 slots) to avoid /proc reads on every event.
        """
        cgroup_path = f"/proc/{pid}/cgroup"
        try:
            with open(cgroup_path) as fh:
                content = fh.read()
        except OSError:
            return ""

        match = _DOCKER_CGROUP_RE.search(content)
        if match:
            return match.group(1)[:12]
        return ""
