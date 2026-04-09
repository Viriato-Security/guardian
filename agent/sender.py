"""
gRPC sender with disk-buffer fallback.

Streams signed EventBatch messages to viriato-platform.  On any gRPC error
the batch is serialised to ``buffer_path/pending.jsonl`` (max 10 000 lines).
A successful send drains the buffer first (oldest-first replay).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

from agent.generator import RawEvent

logger = logging.getLogger(__name__)

_MAX_BUFFER_LINES = 10_000


class Sender:
    """Sends signed event batches to viriato-platform via gRPC.

    Args:
        agent_id: UUID of this Guardian installation.
        control_plane: ``host:port`` of the gRPC endpoint.
        token: Customer API token (sent as gRPC metadata).
        buffer_path: Directory for the disk buffer fallback.
    """

    def __init__(
        self,
        agent_id: str,
        control_plane: str,
        token: str,
        buffer_path: str = "~/.guardian/buffer",
    ) -> None:
        self._agent_id = agent_id
        self._control_plane = control_plane
        self._token = token
        self._buffer_path = Path(buffer_path).expanduser()
        self._buffer_file = self._buffer_path / "pending.jsonl"
        self._channel: Any = None
        self._stub: Any = None
        self._total_sent: int = 0
        self._total_buffered: int = 0
        self._grpc_available: bool = False
        self._init_grpc()

    @property
    def total_sent(self) -> int:
        """Total events successfully sent to viriato-platform."""
        return self._total_sent

    @property
    def total_buffered(self) -> int:
        """Total events written to the disk buffer."""
        return self._total_buffered

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_batch(self, events: list[RawEvent], signature: str) -> bool:
        """Send a signed batch to viriato-platform.

        On success:
        - Drains the disk buffer (replays older batches first).
        - Increments ``total_sent``.
        - Returns ``True``.

        On failure (RpcError or proto stubs missing):
        - Buffers the batch to disk.
        - Increments ``total_buffered``.
        - Returns ``False``.
        """
        if not self._grpc_available:
            logger.warning(
                "gRPC stubs not generated. Buffer to disk. "
                "Run:  bash scripts/gen_proto.sh"
            )
            self._buffer_batch(events, signature)
            return False

        try:
            import grpc  # type: ignore[import]

            batch_proto = self._build_batch_proto(events, signature)
            self._stub.StreamEvents(iter([batch_proto]))  # type: ignore[union-attr]
            self._total_sent += len(events)
            self._drain_buffer()
            return True

        except Exception as exc:  # grpc.RpcError and others
            logger.error("gRPC send failed (%s): buffering %d events", exc, len(events))
            self._buffer_batch(events, signature)
            return False

    def close(self) -> None:
        """Close the gRPC channel."""
        if self._channel is not None:
            try:
                self._channel.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_grpc(self) -> None:
        """Attempt to import generated proto stubs and open the channel."""
        try:
            import grpc  # type: ignore[import]
            from proto import guardian_pb2_grpc  # type: ignore[import]

            insecure = (
                self._control_plane.startswith("localhost")
                or self._control_plane.startswith("127.")
                or os.environ.get("GUARDIAN_INSECURE_GRPC", "0") == "1"
            )
            if insecure:
                self._channel = grpc.insecure_channel(self._control_plane)
            else:
                self._channel = grpc.secure_channel(
                    self._control_plane, grpc.ssl_channel_credentials()
                )
            self._stub = guardian_pb2_grpc.GuardianIngestStub(self._channel)
            self._grpc_available = True
            logger.debug("gRPC channel opened to %s", self._control_plane)
        except (ImportError, Exception) as exc:
            logger.warning("gRPC not available (%s) — disk buffer only", exc)
            self._grpc_available = False

    def _build_batch_proto(self, events: list[RawEvent], signature: str) -> Any:
        from proto import guardian_pb2  # type: ignore[import]

        proto_events = [
            guardian_pb2.Event(
                timestamp=e.timestamp,
                pid=e.pid,
                process=e.process,
                syscall=e.syscall,
                fd_path=e.fd_path,
                bytes=e.bytes,
                return_val=e.return_val,
                uid=e.uid,
                prev_hash=e.prev_hash,
                this_hash=e.this_hash,
                agent_id=e.agent_id,
                model_name=e.model_name,
                container_id=e.container_id,
                pod_name=e.pod_name,
                namespace=e.namespace,
                network_addr=e.network_addr,
            )
            for e in events
        ]
        return guardian_pb2.EventBatch(
            agent_id=self._agent_id,
            signature=signature,
            events=proto_events,
        )

    def _resolve_buffer_dir(self) -> bool:
        """Ensure ``self._buffer_path`` is a writable directory.

        Tries the configured path first; on ``PermissionError`` falls back to
        ``~/.guardian/buffer``.  Updates ``self._buffer_path`` and
        ``self._buffer_file`` in-place so subsequent batches skip the retry.

        Returns:
            ``True`` if a writable directory was found, ``False`` if both paths
            fail (caller should drop the batch).
        """
        fallback = Path.home() / ".guardian" / "buffer"
        for candidate in (self._buffer_path, fallback):
            try:
                candidate.mkdir(parents=True, exist_ok=True)
                if candidate != self._buffer_path:
                    logger.warning(
                        "Cannot write to %s (PermissionError) — using %s instead",
                        self._buffer_path,
                        candidate,
                    )
                    self._buffer_path = candidate
                    self._buffer_file = candidate / "pending.jsonl"
                return True
            except PermissionError:
                continue
        logger.error(
            "Cannot create buffer directory at %s or %s — dropping batch",
            self._buffer_path,
            fallback,
        )
        return False

    def _buffer_batch(self, events: list[RawEvent], signature: str) -> None:
        """Append batch to pending.jsonl, respecting the 10 000 line cap."""
        if not self._resolve_buffer_dir():
            return

        # Check current line count
        current_lines = 0
        if self._buffer_file.exists():
            with open(self._buffer_file) as fh:
                current_lines = sum(1 for _ in fh)

        if current_lines >= _MAX_BUFFER_LINES:
            logger.warning("Disk buffer full (%d lines) — dropping batch", _MAX_BUFFER_LINES)
            return

        from dataclasses import asdict

        line = json.dumps(
            {
                "agent_id": self._agent_id,
                "signature": signature,
                "events": [asdict(e) for e in events],
            }
        )
        with open(self._buffer_file, "a") as fh:
            fh.write(line + "\n")

        self._total_buffered += len(events)
        logger.info("Buffered %d events to %s", len(events), self._buffer_file)

    def _drain_buffer(self) -> None:
        """Replay buffered batches in order; stop on first failure."""
        if not self._buffer_file.exists():
            return

        with open(self._buffer_file) as fh:
            lines = fh.readlines()

        if not lines:
            return

        remaining: list[str] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                # Lightweight re-send: just log success, don't deserialise fully
                import grpc  # type: ignore[import]
                from proto import guardian_pb2, guardian_pb2_grpc  # type: ignore[import]

                events_data = data.get("events", [])
                from agent.generator import RawEvent
                from dataclasses import fields

                field_names = {f.name for f in fields(RawEvent)}
                events = [
                    RawEvent(**{k: v for k, v in e.items() if k in field_names})
                    for e in events_data
                ]
                batch_proto = self._build_batch_proto(events, data.get("signature", ""))
                self._stub.StreamEvents(iter([batch_proto]))  # type: ignore[union-attr]
                self._total_sent += len(events)
                logger.debug("Drained buffered batch (%d events)", len(events))
            except Exception as exc:
                logger.warning("Drain failed (%s) — stopping", exc)
                remaining.append(line)
                break

        # Rewrite buffer with only the un-drained lines
        with open(self._buffer_file, "w") as fh:
            for line in remaining:
                fh.write(line + "\n")
