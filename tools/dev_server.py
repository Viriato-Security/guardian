"""
Guardian developer tools server.

Serves dev_ui.html and exposes REST + SSE endpoints for manual pipeline testing.
No extra dependencies beyond requirements.txt.

Usage:
    python tools/dev_server.py
    # Opens at http://localhost:8765
"""

from __future__ import annotations

import json
import os
import queue
import re
import signal
import socketserver
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional

# Project root → guardian modules importable
sys.path.insert(0, str(Path(__file__).parent.parent))

PORT = 8765
TOOLS_DIR = Path(__file__).parent
UI_FILE = TOOLS_DIR / "dev_ui.html"

# ---------------------------------------------------------------------------
# Global agent state (thread-safe via _lock)
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_agent_proc: Optional[subprocess.Popen] = None  # type: ignore[type-arg]
_log_queue: queue.Queue[Optional[str]] = queue.Queue(maxsize=20_000)
_stats: dict[str, object] = {
    "events": 0, "batches": 0, "alerts": 0,
    "grpc_sent": 0, "buffered": 0, "running": False,
}

_STATS_RE = re.compile(
    r"Guardian stopped.*events=(\d+).*batches=(\d+).*alerts=(\d+)"
    r".*grpc_sent=(\d+).*buffered=(\d+)"
)


def _parse_stat_line(line: str) -> None:
    m = _STATS_RE.search(line)
    if m:
        with _lock:
            _stats.update(
                events=int(m.group(1)),
                batches=int(m.group(2)),
                alerts=int(m.group(3)),
                grpc_sent=int(m.group(4)),
                buffered=int(m.group(5)),
            )


# ---------------------------------------------------------------------------
# Threading HTTP server
# ---------------------------------------------------------------------------

class _Server(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:  # type: ignore[override]
        pass  # suppress default per-request access log

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def do_OPTIONS(self) -> None:
        self._cors(200)

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self._serve_html()
        elif self.path == "/api/status":
            with _lock:
                self._json(dict(_stats))
        elif self.path == "/api/stream-agent":
            self._sse_stream()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body: dict = json.loads(raw)
        except json.JSONDecodeError:
            body = {}

        routes = {
            "/api/run-agent":    lambda: self._run_agent(body),
            "/api/stop-agent":   lambda: self._stop_agent(),
            "/api/send-batch":   lambda: self._send_batch(body),
            "/api/verify-chain": lambda: self._verify_chain(body),
        }
        handler = routes.get(self.path)
        if handler:
            handler()
        else:
            self.send_response(404)
            self.end_headers()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _cors(self, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _json(self, data: object, status: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _serve_html(self) -> None:
        if not UI_FILE.exists():
            self._json({"error": f"UI file not found: {UI_FILE}"}, 404)
            return
        content = UI_FILE.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    # ------------------------------------------------------------------
    # SSE stream — delivers agent log lines to the browser
    # ------------------------------------------------------------------

    def _sse_stream(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        try:
            while True:
                try:
                    line = _log_queue.get(timeout=0.5)
                    if line is None:  # sentinel: subprocess ended
                        self.wfile.write(b"event: done\ndata: {}\n\n")
                        self.wfile.flush()
                        break
                    payload = json.dumps({"line": line})
                    self.wfile.write(f"data: {payload}\n\n".encode())
                    self.wfile.flush()
                except queue.Empty:
                    # Heartbeat keeps the connection alive through proxies
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass  # client disconnected

    # ------------------------------------------------------------------
    # Agent lifecycle
    # ------------------------------------------------------------------

    def _run_agent(self, body: dict) -> None:
        global _agent_proc
        dry_run: bool = bool(body.get("dry_run", True))
        log_level: str = str(body.get("log_level", "DEBUG"))

        with _lock:
            if _agent_proc is not None and _agent_proc.poll() is None:
                self._json({"error": "Agent is already running — stop it first"}, 400)
                return

        # Drain stale log lines from a previous run
        while not _log_queue.empty():
            try:
                _log_queue.get_nowait()
            except queue.Empty:
                break

        cmd = [
            sys.executable, "-m", "agent.main",
            "--fake",
            "--config", "guardian.yaml",
            "--log-level", log_level,
        ]
        if dry_run:
            cmd.append("--dry-run")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(Path(__file__).parent.parent),
        )

        with _lock:
            _agent_proc = proc
            _stats["running"] = True
            for k in ("events", "batches", "alerts", "grpc_sent", "buffered"):
                _stats[k] = 0

        def _reader() -> None:
            assert proc.stdout is not None
            for raw_line in proc.stdout:
                line = raw_line.rstrip("\n")
                _parse_stat_line(line)
                try:
                    _log_queue.put(line, timeout=0.1)
                except queue.Full:
                    pass
            _log_queue.put(None)  # sentinel → tells SSE handler to close
            with _lock:
                _stats["running"] = False

        threading.Thread(target=_reader, daemon=True).start()
        self._json({"started": True, "dry_run": dry_run, "pid": proc.pid})

    def _stop_agent(self) -> None:
        with _lock:
            proc = _agent_proc
        if proc is None or proc.poll() is not None:
            self._json({"error": "No agent is currently running"}, 400)
            return
        proc.send_signal(signal.SIGTERM)
        self._json({"stopped": True})

    # ------------------------------------------------------------------
    # gRPC batch send
    # ------------------------------------------------------------------

    def _send_batch(self, body: dict) -> None:
        try:
            import traceback
            from dataclasses import asdict

            from agent.config import AgentConfig, Config, WatchEntry
            from agent.enricher import Enricher
            from agent.generator import FakeEventGenerator
            from agent.signer import Signer

            n_events  = max(1, min(100, int(body.get("n_events", 10))))
            syscall   = str(body.get("syscall", "read"))
            model     = str(body.get("model_name", "patient-diagnosis-v2"))
            endpoint  = str(body.get("endpoint", "localhost:50051"))
            agent_id  = str(body.get("agent_id", str(uuid.uuid4())))
            token     = "dev-test-token"

            cfg = Config(
                agent=AgentConfig(token=token, control_plane=endpoint),
                watch=[WatchEntry(process="python", model_name=model)],
                syscalls=[syscall],
            )

            # Generate events with the requested syscall, no execve injection
            gen = FakeEventGenerator(cfg)
            gen._next_execve_in = 10_000_000
            gen._events_generated = 0

            events = []
            for _ in range(n_events):
                if syscall == "execve":
                    e = gen._make_execve_event()
                else:
                    e = gen._make_syscall_event(syscall)
                gen._events_generated += 1
                events.append(e)

            # Enrich then sign
            enricher = Enricher(cfg)
            for e in events:
                enricher.enrich(e)

            signer = Signer(token)
            for e in events:
                signer.sign_event(e)
            signature = signer.sign_batch(events)

            # Attempt gRPC delivery
            grpc_info: dict = {"sent": False, "error": None, "ack": None}
            try:
                import grpc
                from proto import guardian_pb2, guardian_pb2_grpc  # type: ignore[import]

                insecure = endpoint.startswith(("localhost", "127."))
                if insecure:
                    channel = grpc.insecure_channel(endpoint)
                else:
                    channel = grpc.secure_channel(endpoint, grpc.ssl_channel_credentials())

                stub = guardian_pb2_grpc.GuardianIngestStub(channel)
                batch_proto = guardian_pb2.EventBatch(
                    agent_id=agent_id,
                    signature=signature,
                    events=[
                        guardian_pb2.Event(
                            timestamp=e.timestamp, pid=e.pid, process=e.process,
                            syscall=e.syscall, fd_path=e.fd_path, bytes=e.bytes,
                            return_val=e.return_val, uid=e.uid,
                            prev_hash=e.prev_hash, this_hash=e.this_hash,
                            agent_id=e.agent_id, model_name=e.model_name,
                            container_id=e.container_id, pod_name=e.pod_name,
                            namespace=e.namespace, network_addr=e.network_addr,
                        )
                        for e in events
                    ],
                )
                ack = stub.StreamEvents(iter([batch_proto]))
                grpc_info = {
                    "sent": True,
                    "ack": {"received": ack.received, "events_stored": ack.events_stored},
                }
                channel.close()
            except Exception as exc:
                grpc_info = {"sent": False, "error": str(exc), "ack": None}

            self._json({
                "agent_id":  agent_id,
                "signature": signature,
                "n_events":  len(events),
                "grpc":      grpc_info,
                "events":    [asdict(e) for e in events],
            })

        except Exception as exc:
            import traceback as tb
            self._json({"error": str(exc), "traceback": tb.format_exc()}, 500)

    # ------------------------------------------------------------------
    # Server-side chain verification (mirrors client-side JS for comparison)
    # ------------------------------------------------------------------

    def _verify_chain(self, body: dict) -> None:
        try:
            from dataclasses import fields

            from agent.generator import RawEvent
            from agent.signer import verify_chain

            events_data: list = body.get("events", [])
            field_names = {f.name for f in fields(RawEvent)}
            events = [
                RawEvent(**{k: v for k, v in e.items() if k in field_names})
                for e in events_data
            ]
            ok, reason = verify_chain(events)
            self._json({"valid": ok, "reason": reason, "count": len(events)})
        except Exception as exc:
            self._json({"error": str(exc)}, 500)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    os.chdir(Path(__file__).parent.parent)
    server = _Server(("localhost", PORT), _Handler)
    print(f"\n  Guardian Dev Server  →  http://localhost:{PORT}")
    print(f"  UI: {UI_FILE}")
    print("  Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dev server…")
        with _lock:
            if _agent_proc and _agent_proc.poll() is None:
                _agent_proc.send_signal(signal.SIGTERM)
                try:
                    _agent_proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    _agent_proc.kill()
        server.shutdown()


if __name__ == "__main__":
    main()
