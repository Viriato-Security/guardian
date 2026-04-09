"""
Guardian agent entry point.

Pipeline:  reader → enricher → alert_engine → signer → batch → sender

Usage:
    python -m agent.main [--config guardian.yaml] [--fake] [--dry-run] [--log-level DEBUG]
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from typing import Optional

logger = logging.getLogger(__name__)


def setup_logging(level: str = "INFO") -> None:
    """Configure stdout logging; suppress noisy gRPC internals."""
    logging.basicConfig(
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)-20s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    # gRPC emits a lot of DEBUG noise; cap at WARNING
    logging.getLogger("grpc").setLevel(logging.WARNING)
    logging.getLogger("grpc._channel").setLevel(logging.WARNING)


class GuardianAgent:
    """Orchestrates the full Guardian event pipeline.

    Args:
        args: Parsed argparse namespace from :func:`_build_parser`.
    """

    def __init__(self, args: argparse.Namespace) -> None:
        self._args = args
        self._running = False
        self._batch: list = []
        self._stats: dict[str, int] = {
            "events": 0,
            "batches": 0,
            "alerts": 0,
            "grpc_sent": 0,
            "buffered": 0,
        }

        from agent.config import load_config

        self._config = load_config(args.config)
        self._setup_components()

    def _setup_components(self) -> None:
        from agent.enricher import Enricher
        from agent.local_alerts import LocalAlertEngine
        from agent.reader import EventReader
        from agent.signer import Signer

        self._reader = EventReader(self._config, force_fake=self._args.fake)
        self._enricher = Enricher(self._config)
        self._signer = Signer(self._config.agent.token)

        # Build alert engine from config
        sandbox_enabled = any(a.type == "sandbox_escape" for a in self._config.local_alerts)
        network_enabled = any(a.type == "unexpected_network" for a in self._config.local_alerts)
        self._alert_engine = LocalAlertEngine(
            sandbox_escape_enabled=sandbox_enabled,
            unexpected_network_enabled=network_enabled,
            network_allowlist=list(self._config.network_allowlist),
        )

        if not self._args.dry_run:
            from agent.sender import Sender

            self._sender: Optional[object] = Sender(
                agent_id=self._enricher.agent_id,
                control_plane=self._config.agent.control_plane,
                token=self._config.agent.token,
                buffer_path=self._config.agent.buffer_path,
            )
        else:
            self._sender = None

    def run(self) -> None:
        """Block until SIGTERM or SIGINT, then flush and exit."""
        self._running = True
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)

        logger.info(
            "Guardian agent starting. source=%s dry_run=%s",
            self._reader.source if hasattr(self._reader, '_source') else "?",
            self._args.dry_run,
        )

        interval = self._config.batch_interval_seconds
        last_flush = time.monotonic()

        try:
            for event in self._reader.stream():
                if not self._running:
                    break

                # Pipeline
                self._enricher.enrich(event)
                alerts = self._alert_engine.evaluate(event)
                self._stats["alerts"] += len(alerts)
                self._signer.sign_event(event)
                self._batch.append(event)
                self._stats["events"] += 1

                # Flush on interval
                if time.monotonic() - last_flush >= interval:
                    self._flush()
                    last_flush = time.monotonic()

        except Exception as exc:
            if self._running:
                logger.error("Pipeline error: %s", exc, exc_info=True)
        finally:
            self._flush()
            self._shutdown()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _flush(self) -> None:
        if not self._batch:
            return

        events = list(self._batch)
        self._batch.clear()

        try:
            signature = self._signer.sign_batch(events)
        except ValueError as exc:
            logger.error("sign_batch failed: %s", exc)
            return

        self._stats["batches"] += 1

        if self._args.dry_run:
            logger.info(
                "DRY RUN: batch ready — %d events, sig=%s…",
                len(events),
                signature[:16],
            )
            return

        from agent.sender import Sender

        assert isinstance(self._sender, Sender)
        ok = self._sender.send_batch(events, signature)
        if ok:
            self._stats["grpc_sent"] += len(events)
        else:
            self._stats["buffered"] += len(events)

    def _handle_shutdown(self, signum: int, frame: object) -> None:
        logger.info("Received signal %d — shutting down gracefully…", signum)
        self._running = False

    def _shutdown(self) -> None:
        if self._sender is not None:
            from agent.sender import Sender

            assert isinstance(self._sender, Sender)
            self._sender.close()

        logger.info(
            "Guardian stopped. events=%d batches=%d alerts=%d grpc_sent=%d buffered=%d",
            self._stats["events"],
            self._stats["batches"],
            self._stats["alerts"],
            self._stats["grpc_sent"],
            self._stats["buffered"],
        )


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="guardian",
        description="Guardian eBPF AI observability agent — Viriato Security",
    )
    p.add_argument("-c", "--config", metavar="FILE", help="Path to guardian.yaml")
    p.add_argument(
        "--fake",
        action="store_true",
        default=False,
        help="Use fake event generator (Phase 1 / macOS / CI)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Run full pipeline but skip gRPC send",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log verbosity (default: INFO)",
    )
    return p


def cli_main() -> None:
    """Entry point for the ``guardian`` console script."""
    parser = _build_parser()
    args = parser.parse_args()
    setup_logging(args.log_level)
    GuardianAgent(args).run()


if __name__ == "__main__":
    cli_main()
