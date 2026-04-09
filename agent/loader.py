"""
Phase 2 eBPF loader stub.

On Linux 5.8+ with BTF and the ``bcc`` package installed this class will load
``probe/guardian.bpf.c`` and attach it to the kernel tracepoints.

Phase 1 note: this class always raises ``NotImplementedError``.  The agent
falls back to ``FakeEventGenerator`` automatically.
"""

from __future__ import annotations

import os
import sys


class EbpfLoader:
    """Loads and manages the guardian eBPF probe.

    .. note::
        Phase 2 stub — raises ``NotImplementedError`` on all platforms.
    """

    @staticmethod
    def is_available() -> bool:
        """Return True only if the eBPF runtime requirements are met.

        Requirements:
        - Linux (not macOS / Windows)
        - ``/sys/kernel/btf/vmlinux`` exists (BTF support, Linux 5.8+)
        - ``bcc`` Python bindings importable
        """
        if sys.platform == "darwin":
            return False
        if not os.path.exists("/sys/kernel/btf/vmlinux"):
            return False
        try:
            import bcc  # type: ignore[import]  # noqa: F401
        except ImportError:
            return False
        return True

    def load(self) -> None:
        """Attach the eBPF probe to kernel tracepoints.

        Raises:
            NotImplementedError: Always — Phase 2 not yet implemented.
        """
        raise NotImplementedError(
            "eBPF loader not yet implemented (Phase 2). "
            "Use --fake or set GUARDIAN_FAKE_EVENTS=1 to run with the fake generator."
        )

    def stream(self):  # type: ignore[return]
        """Yield RawEvent instances from the kernel ring buffer.

        Raises:
            NotImplementedError: Always — Phase 2 not yet implemented.
        """
        raise NotImplementedError("eBPF stream not yet implemented (Phase 2).")
