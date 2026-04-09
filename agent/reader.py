"""
Event reader — abstracts over the fake generator and the Phase 2 eBPF loader.

Source selection rules (first match wins):
1. ``--fake`` CLI flag OR ``GUARDIAN_FAKE_EVENTS=1`` env var → generator
2. ``EbpfLoader.is_available()`` → eBPF loader
3. Otherwise → generator with a warning logged
"""

from __future__ import annotations

import logging
import os
from typing import Iterator

from agent.config import Config
from agent.generator import FakeEventGenerator, RawEvent
from agent.loader import EbpfLoader

logger = logging.getLogger(__name__)


class EventReader:
    """Unified event source for the Guardian agent pipeline.

    Args:
        config: Loaded guardian configuration.
        force_fake: If True, always use the fake generator (mirrors ``--fake``).
    """

    def __init__(self, config: Config, force_fake: bool = False) -> None:
        self._config = config
        self._force_fake = force_fake
        self._source: str = ""

    @property
    def source(self) -> str:
        """``'generator'`` or ``'ebpf'`` — set after ``stream()`` is called."""
        return self._source

    def stream(self) -> Iterator[RawEvent]:
        """Yield RawEvent instances from the selected source.

        Selects the source exactly once, then streams indefinitely.
        """
        use_fake = self._force_fake or os.environ.get("GUARDIAN_FAKE_EVENTS", "0") == "1"

        if use_fake:
            self._source = "generator"
            logger.info("Event source: fake generator (forced)")
            yield from FakeEventGenerator(self._config).stream()
            return

        if EbpfLoader.is_available():
            self._source = "ebpf"
            logger.info("Event source: eBPF probe")
            loader = EbpfLoader()
            loader.load()
            yield from loader.stream()
            return

        # Fallback to generator with a warning
        self._source = "generator"
        logger.warning(
            "eBPF not available on this platform (Phase 2 requires Linux 5.8+ with BTF). "
            "Falling back to fake event generator. "
            "Pass --fake to suppress this warning."
        )
        yield from FakeEventGenerator(self._config).stream()
