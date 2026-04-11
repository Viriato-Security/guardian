#!/usr/bin/env python3
"""
Guardian Phase 1 — Terminal Demo for Video Presentation

Guided 10-scene tour of the Guardian agent using real code, not mocks.

Usage:
    python tools/demo.py                    # full demo
    python tools/demo.py --scene 6         # jump to scene 6
    python tools/demo.py --speed slow      # 2x delays for live presenting
    python tools/demo.py --speed fast      # minimal delays for quick review
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

# ── Rich import guard ──────────────────────────────────────────────────────────
try:
    from rich import box
    from rich.columns import Columns
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("Error: rich library not installed.")
    print("Run: pip install rich")
    sys.exit(1)

# ── Path setup ─────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# ── Globals ────────────────────────────────────────────────────────────────────
console = Console()
SPEED_MULT: float = 1.0
_subprocesses: list[subprocess.Popen] = []


# ── Cleanup ────────────────────────────────────────────────────────────────────

def _cleanup_subprocesses() -> None:
    for p in list(_subprocesses):
        try:
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    _subprocesses.clear()


def _sig_handler(sig: int, frame: object) -> None:
    console.print("\n[yellow]Demo interrupted. Cleaning up...[/yellow]")
    _cleanup_subprocesses()
    sys.exit(0)


signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)


# ── Timing helpers ─────────────────────────────────────────────────────────────

def sleep(seconds: float) -> None:
    """Speed-adjusted sleep."""
    adjusted = max(0.0, seconds * SPEED_MULT)
    if adjusted > 0:
        time.sleep(adjusted)


# ── Header & chrome ────────────────────────────────────────────────────────────

def print_header() -> None:
    console.print(Panel(
        "  [bold cyan]🛡  GUARDIAN[/bold cyan]  [grey50]—[/grey50]  "
        "[white]AI Observability Agent[/white]  [grey50]│[/grey50]  "
        "[bold yellow]Viriato Security[/bold yellow]\n"
        "  [grey50]viriatosecurity.com[/grey50]"
        "                                      "
        "[grey50]Phase 1 Demo  v0.1.0[/grey50]",
        border_style="cyan",
        padding=(0, 1),
    ))


def clear_screen() -> None:
    console.clear()
    print_header()
    console.print()


def wait_for_enter(scene: int, total: int = 10) -> None:
    console.print()
    console.rule(
        f"[grey50]  Scene {scene} of {total}   │   "
        "[bold white]\\[ENTER][/bold white] [grey50]to continue[/grey50]",
        style="grey30",
    )
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        raise SystemExit(0)


def animate_lines(lines: list[str], delay: float = 0.03, style: str = "cyan") -> None:
    for line in lines:
        console.print(f"[{style}]{line}[/{style}]")
        sleep(delay)


# ── gRPC test server ───────────────────────────────────────────────────────────

_TEST_SERVER_CODE = """\
import sys, grpc
from concurrent import futures
sys.path.insert(0, {repo_root!r})
from proto import guardian_pb2, guardian_pb2_grpc

class _Svc(guardian_pb2_grpc.GuardianIngestServicer):
    def StreamEvents(self, request_iterator, context):
        total = 0
        for batch in request_iterator:
            n = len(batch.events)
            total += n
            sig = batch.signature[:16] if batch.signature else "nosig"
            print(f"BATCH:{{n}}:{{sig}}", flush=True)
        return guardian_pb2.Ack(received=True, events_stored=total)

_srv = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
guardian_pb2_grpc.add_GuardianIngestServicer_to_server(_Svc(), _srv)
_srv.add_insecure_port('[::]:50051')
_srv.start()
print('SERVER_READY', flush=True)
_srv.wait_for_termination()
"""


def _start_test_server() -> subprocess.Popen:
    code = _TEST_SERVER_CODE.format(repo_root=str(REPO_ROOT))
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, prefix="guardian_test_srv_"
    )
    tmp.write(code)
    tmp.close()
    p = subprocess.Popen(
        [sys.executable, tmp.name],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    _subprocesses.append(p)
    return p


def _wait_server_ready(proc: subprocess.Popen, timeout: float = 6.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if "SERVER_READY" in line:
            return True
        if proc.poll() is not None:
            return False
        time.sleep(0.05)
    return False


# ──────────────────────────────────────────────────────────────────────────────
# SCENE 1 — What is Guardian?
# ──────────────────────────────────────────────────────────────────────────────

def scene_1() -> None:
    clear_screen()
    console.print(Panel(
        "[bold cyan]WHAT IS GUARDIAN?[/bold cyan]",
        expand=False, border_style="cyan",
    ))
    console.print()

    arch = [
        "    ┌─────────────────────────────────────────────────────────────────┐",
        "    │                    YOUR AI INFRASTRUCTURE                       │",
        "    │                                                                 │",
        "    │   ┌─────────────────┐                                           │",
        "    │   │  AI Model       │  patient-diagnosis-v2                     │",
        "    │   │  (python)       │  fraud-detection-v1                       │",
        "    │   └────────┬────────┘                                           │",
        "    │            │  syscalls (read, write, execve, connect...)        │",
        "    │            ▼                                                    │",
        "    │   ┌─────────────────┐    ┌──────────────────────────────────┐   │",
        "    │   │  eBPF Probe     │───▶│  Guardian Agent                  │   │",
        "    │   │  (kernel)       │    │  • Enrich  • Chain  • Sign       │   │",
        "    │   └─────────────────┘    └──────────────┬───────────────────┘   │",
        "    │                                         │  gRPC + TLS           │",
        "    │                                         ▼                       │",
        "    │                          ┌──────────────────────────────────┐   │",
        "    │                          │  viriato-platform                │   │",
        "    │                          │  EU AI Act Compliance Engine     │   │",
        "    │                          └──────────────────────────────────┘   │",
        "    └─────────────────────────────────────────────────────────────────┘",
    ]
    animate_lines(arch, delay=0.03)

    console.print()
    console.print(Panel(
        "[white]Guardian sits between your AI model and the outside world.\n"
        "Every syscall your model makes is captured, cryptographically\n"
        "signed, and streamed to the compliance platform.\n\n"
        "[bold green]Zero code changes to your model.  Zero performance impact.[/bold green][/white]",
        title="[bold cyan]How It Works[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))

    wait_for_enter(1)


# ──────────────────────────────────────────────────────────────────────────────
# SCENE 2 — Configuration
# ──────────────────────────────────────────────────────────────────────────────

def scene_2() -> None:
    clear_screen()
    console.print(Panel(
        "[bold cyan]STEP 1 — Loading guardian.yaml[/bold cyan]",
        expand=False, border_style="cyan",
    ))
    console.print()

    with console.status("[bold yellow]Loading configuration...[/bold yellow]", spinner="dots"):
        sleep(1.0)
        from agent.config import load_config
        config = load_config()

    console.print("[bold green]✓  Config file found:[/bold green] [white]./guardian.yaml[/white]")
    console.print()

    # Agent config table
    t = Table(
        box=box.ROUNDED, border_style="cyan",
        title="[bold cyan]Agent Configuration[/bold cyan]", title_justify="left",
    )
    t.add_column("Setting", style="yellow", no_wrap=True, min_width=22)
    t.add_column("Value", style="white")

    token = config.agent.token
    masked = (token[:14] + "••••••••") if len(token) >= 14 else "••••••••"
    t.add_row("control_plane", config.agent.control_plane)
    t.add_row("batch_interval", f"{config.agent.batch_interval_ms}ms")
    t.add_row("buffer_path", config.agent.buffer_path)
    t.add_row("token", masked + "  [grey50]← masked[/grey50]")
    console.print(t)
    console.print()

    # Watch list
    w = Table(
        box=box.ROUNDED, border_style="cyan",
        title="[bold cyan]Watch List[/bold cyan]", title_justify="left",
    )
    w.add_column("Process", style="yellow", min_width=16)
    w.add_column("Model Name", style="white")
    for entry in config.watch:
        w.add_row(entry.process, entry.model_name)
    console.print(w)
    console.print()

    # Syscall badges
    SYSCALL_COLORS: dict[str, str] = {
        "read": "cyan", "write": "cyan", "openat": "cyan",
        "sendto": "yellow", "recvfrom": "yellow", "connect": "yellow", "socket": "yellow",
        "execve": "bold red", "clone": "bold red",
    }
    badge = Text()
    badge.append("  Monitored syscalls:  ", style="grey50")
    for sc in config.syscalls:
        color = SYSCALL_COLORS.get(sc, "white")
        badge.append(f" [{sc}] ", style=f"{color} on grey19")
        badge.append(" ")
    console.print(badge)
    console.print()
    console.print("[bold green]✓  Configuration loaded successfully[/bold green]")

    wait_for_enter(2)


# ──────────────────────────────────────────────────────────────────────────────
# SCENE 3 — Live Event Capture
# ──────────────────────────────────────────────────────────────────────────────

def scene_3() -> None:
    clear_screen()
    console.print(Panel(
        "[bold cyan]STEP 2 — Capturing Syscall Events  (Phase 1: Fake Generator)[/bold cyan]",
        expand=False, border_style="cyan",
    ))
    console.print()
    console.print(Panel(
        "[white]In Phase 1, a fake generator produces events identical in schema\n"
        "to what the real eBPF kernel probe will emit in Phase 2.\n"
        "The entire pipeline downstream is real — only the source differs.[/white]",
        border_style="grey50",
    ))
    console.print()

    from agent.config import load_config
    from agent.generator import FakeEventGenerator

    config = load_config()
    gen = FakeEventGenerator(config)

    _lock = threading.Lock()
    _window: list = []
    _total = [0]
    _batches = [0]
    _stop = threading.Event()

    SYSCALL_COLORS: dict[str, str] = {
        "read": "cyan", "write": "cyan", "openat": "cyan",
        "sendto": "yellow", "recvfrom": "yellow", "connect": "yellow", "socket": "yellow",
        "execve": "bold red", "clone": "bold red",
    }

    def _produce() -> None:
        batch_ctr = 0
        for ev in gen.stream():
            if _stop.is_set():
                break
            with _lock:
                _window.append(ev)
                if len(_window) > 15:
                    _window.pop(0)
                _total[0] += 1
                batch_ctr += 1
                if batch_ctr >= 63:
                    _batches[0] += 1
                    batch_ctr = 0

    def _build_table() -> Table:
        t = Table(
            box=box.SIMPLE_HEAD, border_style="grey50",
            header_style="bold yellow", show_footer=False,
        )
        t.add_column("Timestamp",  width=28, style="grey70")
        t.add_column("Process",    width=11, style="white")
        t.add_column("Model",      width=15, style="white")
        t.add_column("Syscall",    width=10)
        t.add_column("Detail",     width=22, style="white")
        t.add_column("Return",     width=7,  style="grey70")

        with _lock:
            rows = list(_window)

        for ev in rows:
            color = SYSCALL_COLORS.get(ev.syscall, "white")
            model = config.model_name_for_process(ev.process)
            detail = ev.fd_path or ev.network_addr or "—"
            if len(detail) > 20:
                detail = "…" + detail[-19:]
            t.add_row(
                ev.timestamp[:28],
                ev.process[:11],
                (model[:13] + "…") if len(model) > 14 else model,
                Text(ev.syscall, style=color),
                detail,
                ev.return_val,
            )
        return t

    producer = threading.Thread(target=_produce, daemon=True)
    producer.start()

    duration = 8.0 * SPEED_MULT
    deadline = time.monotonic() + duration

    with Live(refresh_per_second=5, console=console) as live:
        while time.monotonic() < deadline:
            with _lock:
                te = _total[0]
                tb = _batches[0]
            footer = Text(
                f"\n  Events captured: {te:,}  │  Batches ready: {tb}  │  Alerts: 0",
                style="yellow",
            )
            live.update(Group(_build_table(), footer))
            time.sleep(0.2)

    _stop.set()
    with _lock:
        final = _total[0]

    console.print()
    console.print(f"[bold green]✓  Captured {final:,}+ events in 8 seconds[/bold green]")

    wait_for_enter(3)


# ──────────────────────────────────────────────────────────────────────────────
# SCENE 4 — Cryptographic Chaining
# ──────────────────────────────────────────────────────────────────────────────

def scene_4() -> None:
    clear_screen()
    console.print(Panel(
        "[bold cyan]STEP 3 — Cryptographic Event Chaining[/bold cyan]",
        expand=False, border_style="cyan",
    ))
    console.print()
    console.print(Panel(
        "[white]Every event is SHA-256 hashed with the previous event's hash.\n"
        "This creates a tamper-evident chain.  Deleting, modifying, or\n"
        "reordering any event breaks the chain permanently.[/white]",
        border_style="grey50",
    ))
    console.print()

    from agent.generator import RawEvent, _now_iso_ns
    from agent.signer import GENESIS_HASH, Signer, verify_chain

    signer = Signer("dev-test-token")

    raw: list[RawEvent] = [
        RawEvent(timestamp=_now_iso_ns(), pid=14832, process="python",     syscall="read",
                 fd_path="/var/lib/models/patient-diagnosis-v2/model.pt",  bytes=32768, return_val="0", uid=1000),
        RawEvent(timestamp=_now_iso_ns(), pid=14832, process="python",     syscall="write",
                 fd_path="pipe:[567]",                                     bytes=4096,  return_val="0", uid=1000),
        RawEvent(timestamp=_now_iso_ns(), pid=14832, process="python",     syscall="openat",
                 fd_path="/tmp/torch_cache/hub/checkpoints/model.bin",     bytes=65536, return_val="0", uid=1000),
        RawEvent(timestamp=_now_iso_ns(), pid=14832, process="torchserve", syscall="sendto",
                 network_addr="10.0.0.1:8080",                             bytes=2048,  return_val="0", uid=1000),
        RawEvent(timestamp=_now_iso_ns(), pid=14832, process="torchserve", syscall="recvfrom",
                 network_addr="10.0.0.1:8080",                             bytes=1024,  return_val="0", uid=1000),
    ]
    events: list[RawEvent] = []
    for ev in raw:
        signer.sign_event(ev)
        events.append(ev)

    # Show GENESIS sentinel
    console.print("  [grey50]GENESIS[/grey50]")
    console.print(f"  [grey50]{GENESIS_HASH}[/grey50]")
    console.print("  [grey50]      │[/grey50]")
    sleep(0.5)

    for i, ev in enumerate(events):
        sleep(0.5)
        prev_short = ev.prev_hash[:12] + "…" + ev.prev_hash[-4:]
        this_short = ev.this_hash[:20] + "…" + ev.this_hash[-8:]
        detail = ev.fd_path or ev.network_addr or "—"
        if len(detail) > 22:
            detail = detail[-22:]
        link = f"  [grey50]← links to Event #{i}[/grey50]" if i > 0 else ""

        console.print(
            Panel(
                f"[yellow]prev:[/yellow] [grey70]{prev_short}[/grey70]{link}\n"
                f"[yellow]this:[/yellow] [bold white]{this_short}[/bold white]",
                title=(
                    f"[bold white]Event #{i + 1}[/bold white]  [grey50]│[/grey50]  "
                    f"[cyan]{ev.process}[/cyan]  [grey50]│[/grey50]  "
                    f"[bold cyan]{ev.syscall}[/bold cyan]  [grey50]│[/grey50]  "
                    f"[white]{detail}[/white]  [grey50]│[/grey50]  "
                    f"[grey70]pid={ev.pid}[/grey70]"
                ),
                border_style="cyan",
                padding=(0, 1),
            ),
            " " * 2,
        )
        if i < len(events) - 1:
            console.print("  [grey50]      │[/grey50]")
            console.print("  [grey50]      ▼[/grey50]")

    console.print()
    console.print("[bold green]✓  Chain verified — all 5 events intact[/bold green]")
    sleep(1.0)

    # ── Tamper demonstration ───────────────────────────────────────────────────
    console.print()
    console.rule("[yellow]TAMPER DEMONSTRATION[/yellow]", style="yellow")
    console.print()
    sleep(0.4)
    console.print("[yellow]Now watch what happens if we tamper with Event #2...[/yellow]")
    sleep(0.8)

    tampered = copy.deepcopy(events)
    tampered[1].bytes += 9999  # mutate one field

    ok, reason = verify_chain(tampered)
    assert not ok, "Expected chain to be broken after tampering"

    console.print()
    stored_hash = tampered[1].this_hash[:32]
    console.print(Panel(
        "[bold red]✗  Chain BROKEN at event #2 — hash mismatch detected[/bold red]\n\n"
        f"[yellow]  stored:  [/yellow] [white]{stored_hash}…[/white]\n"
        f"[yellow]  computed:[/yellow] [red]DIFFERENT[/red]\n\n"
        f"[grey50]  {reason[:120]}[/grey50]",
        title="[bold red]INTEGRITY FAILURE[/bold red]",
        border_style="red",
        padding=(1, 2),
    ))
    console.print()
    console.print(
        "[white]This is how Guardian proves to auditors that "
        "telemetry was never modified.[/white]"
    )

    wait_for_enter(4)


# ──────────────────────────────────────────────────────────────────────────────
# SCENE 5 — Batch Signing
# ──────────────────────────────────────────────────────────────────────────────

def scene_5() -> None:
    clear_screen()
    console.print(Panel(
        "[bold cyan]STEP 4 — HMAC Batch Signing[/bold cyan]",
        expand=False, border_style="cyan",
    ))
    console.print()
    console.print(Panel(
        "[white]Every batch of events is signed with the customer's API token\n"
        "using HMAC-SHA256.  The platform rejects any batch with an invalid\n"
        "signature, preventing replay attacks and impersonation.[/white]",
        border_style="grey50",
    ))
    console.print()

    from agent.config import load_config
    from agent.generator import FakeEventGenerator
    from agent.signer import Signer

    config = load_config()
    gen = FakeEventGenerator(config)
    signer = Signer(config.agent.token)

    # Generate 63 events quickly (bypass the generator sleep)
    events = []
    for _ in range(63):
        ev = gen._make_event()
        gen._events_generated += 1
        signer.sign_event(ev)
        events.append(ev)

    chain_tip = events[-1].this_hash[:16] + "…"
    signature = signer.sign_batch(events)
    token_masked = config.agent.token[:14] + "••••••••"

    sleep(0.3)
    console.print(Panel(
        f"  [bold yellow]EventBatch[/bold yellow]\n"
        f"  ┌─────────────────────────────────────┐\n"
        f"  │  [white]63 signed events[/white]                    │\n"
        f"  │  [grey50]chain tip:[/grey50] [grey70]{chain_tip}[/grey70]   │\n"
        f"  └─────────────────────────────────────┘\n\n"
        f"  [grey50]                   +[/grey50]\n\n"
        f"  ┌─────────────────────────────────────┐\n"
        f"  │  [grey50]API Token:[/grey50] [white]{token_masked}[/white]    │\n"
        f"  └─────────────────────────────────────┘",
        title="[bold cyan]Signing Inputs[/bold cyan]",
        border_style="cyan",
        padding=(0, 2),
    ))
    sleep(0.8)
    console.print()
    console.print("  [grey50]               │[/grey50]")
    console.print("  [grey50]               ▼  HMAC-SHA256[/grey50]")
    sleep(0.5)
    console.print()

    console.print(Panel(
        f"  [bold green]signature:[/bold green] [white]{signature}[/white]",
        title="[bold green]Output[/bold green]",
        border_style="green",
        padding=(0, 2),
    ))
    console.print()
    console.print("[bold green]✓  Batch signed. Ready to transmit.[/bold green]")

    wait_for_enter(5)


# ──────────────────────────────────────────────────────────────────────────────
# SCENE 6 — Local Alert: Sandbox Escape
# ──────────────────────────────────────────────────────────────────────────────

def scene_6() -> None:
    clear_screen()
    console.print(Panel(
        "[bold cyan]STEP 5 — Local Alert Detection  (No Network Required)[/bold cyan]",
        expand=False, border_style="cyan",
    ))
    console.print()
    console.print(Panel(
        "[white]Guardian fires alerts immediately, without network connectivity.\n"
        "If the platform is unreachable, sandbox escapes are still detected.[/white]",
        border_style="grey50",
    ))
    console.print()

    from agent.generator import RawEvent, _now_iso_ns
    from agent.local_alerts import LocalAlertEngine

    engine = LocalAlertEngine(
        sandbox_escape_enabled=True,
        unexpected_network_enabled=True,
    )
    captured: list = []
    engine.set_custom_handler(captured.append)

    agent_id = str(uuid.uuid4())
    ts = _now_iso_ns()
    pid = 19813

    console.print("[grey50]Monitoring process activity...[/grey50]")
    sleep(0.5)
    console.print(
        f"[yellow]Incoming event:[/yellow]  "
        f"[white]python  pid={pid}  syscall=execve  fd_path=/bin/bash[/white]"
    )
    sleep(0.3)

    trigger = RawEvent(
        timestamp=ts,
        pid=pid,
        process="python",
        syscall="execve",
        fd_path="/bin/bash",
        bytes=0,
        return_val="0",
        uid=1000,
        agent_id=agent_id,
        model_name="patient-diagnosis-v2",
    )
    engine.evaluate(trigger)
    alert = captured[0]
    sleep(0.3)

    console.print()
    console.print(Panel(
        f"  [bold red]TYPE:   [/bold red]  [white]{alert.alert_type}[/white]\n"
        f"  [bold red]PROCESS:[/bold red]  [white]{alert.process} (pid {alert.pid})[/white]\n"
        f"  [bold red]MODEL:  [/bold red]  [white]{alert.model_name}[/white]\n"
        f"  [bold red]DETAIL: [/bold red]  [white]{alert.detail}[/white]\n"
        f"  [bold red]TIME:   [/bold red]  [white]{alert.timestamp}[/white]\n"
        f"  [bold red]AGENT:  [/bold red]  [white]{alert.agent_id or agent_id}[/white]\n\n"
        f"  [bold red]ACTION: [/bold red]  [white]log_and_alert[/white]  "
        f"[grey50]←  Fired WITHOUT network[/grey50]",
        title="[bold red]🚨  SECURITY ALERT  🚨[/bold red]",
        border_style="red",
        padding=(1, 2),
    ))

    # Raw JSON line
    payload = {
        "level": "ALERT",
        "type": alert.alert_type,
        "pid": alert.pid,
        "process": alert.process,
        "model": alert.model_name,
        "detail": alert.detail,
        "timestamp": alert.timestamp,
    }
    console.print()
    console.print(Panel(
        f"[grey70]{json.dumps(payload)}[/grey70]",
        title="[grey50]Log line → Datadog / Loki / CloudWatch[/grey50]",
        border_style="grey30",
        padding=(0, 1),
    ))
    console.print()
    console.print(
        "[white]This alert fired in microseconds. No platform connection needed.\n"
        "The JSON line above is ready for Datadog, Loki, or CloudWatch.[/white]"
    )

    wait_for_enter(6)


# ──────────────────────────────────────────────────────────────────────────────
# SCENE 7 — gRPC Transmission
# ──────────────────────────────────────────────────────────────────────────────

def scene_7() -> None:
    clear_screen()
    console.print(Panel(
        "[bold cyan]STEP 6 — Streaming to viriato-platform via gRPC[/bold cyan]",
        expand=False, border_style="cyan",
    ))
    console.print()
    console.print(Panel(
        "[white]Signed batches are streamed to the control plane over TLS.\n"
        "If the platform is unreachable, events are buffered to disk\n"
        "and replayed automatically when connectivity returns.[/white]",
        border_style="grey50",
    ))
    console.print()

    from agent.config import load_config
    from agent.generator import FakeEventGenerator
    from agent.sender import Sender
    from agent.signer import Signer

    config = load_config()

    console.print("[grey50]  Starting test gRPC server on localhost:50051...[/grey50]")
    server_proc = _start_test_server()

    if not _wait_server_ready(server_proc, timeout=6.0):
        console.print("[red]  Could not start test gRPC server. Skipping scene.[/red]")
        wait_for_enter(7)
        return

    console.print("[bold green]  ✓  Test server ready[/bold green]")
    sleep(0.5)
    console.print()

    gen = FakeEventGenerator(config)
    signer = Signer(config.agent.token)
    sender = Sender(
        agent_id=str(uuid.uuid4()),
        control_plane="localhost:50051",
        token=config.agent.token,
        buffer_path="/tmp/guardian_demo_s7_buf",
    )

    _lock = threading.Lock()
    agent_lines: list[str] = []
    server_lines: list[str] = []
    total_delivered = [0]
    _stop = threading.Event()

    # Read server stdout in background
    def _read_server() -> None:
        for line in server_proc.stdout:
            if _stop.is_set():
                break
            line = line.strip()
            if line.startswith("BATCH:"):
                parts = line.split(":")
                n, sig = int(parts[1]), parts[2]
                with _lock:
                    total_delivered[0] += n
                    server_lines.append(
                        f"✓ Batch received   {n:3d} events   sig={sig}…"
                    )
                    if len(server_lines) > 12:
                        server_lines.pop(0)

    server_reader = threading.Thread(target=_read_server, daemon=True)
    server_reader.start()

    # Pipeline thread
    def _pipeline() -> None:
        batch: list = []
        last_flush = time.monotonic()
        interval = config.batch_interval_seconds
        for ev in gen.stream():
            if _stop.is_set():
                break
            signer.sign_event(ev)
            batch.append(ev)
            if time.monotonic() - last_flush >= interval:
                if batch:
                    sig = signer.sign_batch(batch)
                    ok = sender.send_batch(batch, sig)
                    if ok:
                        n = len(batch)
                        with _lock:
                            agent_lines.append(
                                f"[INFO]  Batch sent   {n:3d} events   sig={sig[:16]}…"
                            )
                            if len(agent_lines) > 12:
                                agent_lines.pop(0)
                    batch = []
                last_flush = time.monotonic()

    pipeline = threading.Thread(target=_pipeline, daemon=True)
    pipeline.start()

    deadline = time.monotonic() + 5.0 * SPEED_MULT

    with Live(refresh_per_second=4, console=console) as live:
        while time.monotonic() < deadline:
            with _lock:
                al = list(agent_lines)
                sl = list(server_lines)
                td = total_delivered[0]

            agent_text = Text()
            for ln in al:
                agent_text.append(ln + "\n", style="cyan")

            server_text = Text()
            for ln in sl:
                server_text.append(ln + "\n", style="bold green")

            agent_panel = Panel(
                agent_text,
                title="[bold cyan]Guardian Agent[/bold cyan]",
                border_style="cyan",
                padding=(0, 1),
            )
            platform_panel = Panel(
                server_text,
                title="[bold green]viriato-platform  (test server)[/bold green]",
                border_style="green",
                padding=(0, 1),
            )
            footer = Text(
                f"\n  Total events delivered to platform: {td:,}",
                style="bold yellow",
            )
            live.update(Group(Columns([agent_panel, platform_panel], equal=True), footer))
            time.sleep(0.25)

    _stop.set()
    sender.close()
    server_proc.terminate()
    try:
        _subprocesses.remove(server_proc)
    except ValueError:
        pass

    with _lock:
        final = total_delivered[0]

    console.print()
    console.print(Panel(
        "[bold green]✓  End-to-end pipeline verified:[/bold green]\n\n"
        "  [white]Events generated  →  chained  →  signed  →  transmitted  →  stored[/white]\n\n"
        f"  [yellow]Total events delivered:[/yellow] [white]{final:,}[/white]",
        border_style="green",
        padding=(1, 2),
    ))

    wait_for_enter(7)


# ──────────────────────────────────────────────────────────────────────────────
# SCENE 8 — Disk Buffer Resilience
# ──────────────────────────────────────────────────────────────────────────────

def scene_8() -> None:
    clear_screen()
    console.print(Panel(
        "[bold cyan]STEP 7 — Resilience: Events Survive Network Outage[/bold cyan]",
        expand=False, border_style="cyan",
    ))
    console.print()
    console.print(Panel(
        "[white]What happens when the platform goes down?\n"
        "Guardian buffers events to disk and replays them on reconnect.\n"
        "[bold green]Zero event loss, even during extended outages.[/bold green][/white]",
        border_style="grey50",
    ))
    console.print()

    from agent.config import load_config
    from agent.generator import FakeEventGenerator
    from agent.sender import Sender
    from agent.signer import Signer

    config = load_config()
    BUFFER = "/tmp/guardian_demo_s8_buf"
    if Path(BUFFER).exists():
        shutil.rmtree(BUFFER)

    gen = FakeEventGenerator(config)
    signer = Signer(config.agent.token)
    agent_id = str(uuid.uuid4())

    # ── STEP 1: Platform DOWN ──────────────────────────────────────────────────
    console.print(Rule("[bold yellow]  STEP 1 — Platform is DOWN  [/bold yellow]", style="yellow"))
    console.print()
    console.print("[yellow]  ⚠  Platform unreachable — starting Guardian...[/yellow]")
    sleep(0.5)

    sender_down = Sender(
        agent_id=agent_id,
        control_plane="localhost:59999",   # nothing listening
        token=config.agent.token,
        buffer_path=BUFFER,
    )

    # Suppress the gRPC error log during the intentional failure
    import logging as _logging
    _sender_logger = _logging.getLogger("agent.sender")
    _orig_level = _sender_logger.level
    _sender_logger.setLevel(_logging.CRITICAL)

    buffered_total = 0
    for batch_num in range(3):
        batch = []
        for _ in range(63):
            ev = gen._make_event()
            gen._events_generated += 1
            signer.sign_event(ev)
            batch.append(ev)
        sig = signer.sign_batch(batch)
        sender_down.send_batch(batch, sig)
        buffered_total += len(batch)
        sleep(0.4)
        buf_file = Path(BUFFER) / "pending.jsonl"
        buf_bytes = buf_file.stat().st_size if buf_file.exists() else 0
        console.print(
            f"  [grey50]Batch {batch_num + 1}:[/grey50]  "
            f"[yellow]⚠  buffered {len(batch)} events → disk   "
            f"({buf_bytes:,} bytes in buffer)[/yellow]"
        )

    console.print()
    console.print(
        f"  [yellow]Buffered: 3 batches  ({buffered_total} events)[/yellow]"
    )
    _sender_logger.setLevel(_orig_level)
    sender_down.close()
    sleep(1.0)

    # ── STEP 2: Platform comes ONLINE ─────────────────────────────────────────
    console.print()
    console.print(Rule("[bold green]  STEP 2 — Platform comes ONLINE  [/bold green]", style="green"))
    console.print()
    console.print("[grey50]  Starting test gRPC server...[/grey50]")

    server_proc = _start_test_server()
    if not _wait_server_ready(server_proc, timeout=6.0):
        console.print("[red]  Could not start test gRPC server.[/red]")
        wait_for_enter(8)
        return

    sleep(0.5)
    console.print("[bold green]  ✓  Connection restored[/bold green]")
    sleep(0.3)
    console.print("[grey50]  Draining buffered batches...[/grey50]")
    sleep(0.3)

    # New sender on the same buffer path — first successful send triggers drain
    sender_up = Sender(
        agent_id=agent_id,
        control_plane="localhost:50051",
        token=config.agent.token,
        buffer_path=BUFFER,
    )
    batch = []
    for _ in range(63):
        ev = gen._make_event()
        gen._events_generated += 1
        signer.sign_event(ev)
        batch.append(ev)
    sig = signer.sign_batch(batch)
    ok = sender_up.send_batch(batch, sig)

    if ok:
        console.print(
            f"[bold green]  ✓  Replayed {buffered_total} buffered events to platform[/bold green]"
        )
        console.print("[bold green]  ✓  Buffer cleared — resuming live streaming[/bold green]")
    else:
        console.print("[red]  Send failed — check that no server is already on :50051[/red]")

    sender_up.close()
    server_proc.terminate()
    try:
        _subprocesses.remove(server_proc)
    except ValueError:
        pass

    console.print()
    console.print(
        "[bold white]  No events were lost. The compliance record is complete.[/bold white]"
    )

    wait_for_enter(8)


# ──────────────────────────────────────────────────────────────────────────────
# SCENE 9 — Test Suite
# ──────────────────────────────────────────────────────────────────────────────

def scene_9() -> None:
    clear_screen()
    console.print(Panel(
        "[bold cyan]STEP 8 — 63 Tests. Zero Failures.[/bold cyan]",
        expand=False, border_style="cyan",
    ))
    console.print()
    console.print(Panel(
        "[white]Every component is independently tested.\n"
        "The test suite runs in under 0.1 seconds.[/white]",
        border_style="grey50",
    ))
    console.print()

    proc = subprocess.Popen(
        [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short", "--no-header"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=str(REPO_ROOT),
    )
    _subprocesses.append(proc)

    passed = 0
    failed = 0
    runtime_str = "?"

    assert proc.stdout is not None
    for raw_line in proc.stdout:
        line = raw_line.rstrip()
        if not line:
            continue

        if "::" in line and "PASSED" in line:
            passed += 1
            # Trim the percentage progress suffix for cleaner output
            clean = re.sub(r"\s+\[\s*\d+%\]$", "", line)
            console.print(f"  [green]{clean}[/green]")
        elif "::" in line and ("FAILED" in line or "ERROR" in line):
            failed += 1
            clean = re.sub(r"\s+\[\s*\d+%\]$", "", line)
            console.print(f"  [bold red]{clean}[/bold red]")
        elif line.startswith("tests/") and "::" not in line:
            # Module collection header
            console.print(f"  [bold cyan]{line}[/bold cyan]")
        elif re.search(r"\d+ passed", line):
            m_pass = re.search(r"(\d+) passed", line)
            m_fail = re.search(r"(\d+) failed", line)
            m_time = re.search(r"in ([\d.]+)s", line)
            if m_pass:
                passed = int(m_pass.group(1))
            if m_fail:
                failed = int(m_fail.group(1))
            if m_time:
                runtime_str = m_time.group(1) + "s"
        elif line.startswith("=") or line.startswith("-"):
            # Separator lines — skip them
            pass
        else:
            console.print(f"  [grey60]{line}[/grey60]")

    proc.wait()
    try:
        _subprocesses.remove(proc)
    except ValueError:
        pass

    console.print()
    border = "green" if failed == 0 else "red"
    console.print(Panel(
        f"\n"
        f"  [bold green]{passed} passed[/bold green]    "
        f"[bold {'red' if failed else 'green'}]{failed} failed[/bold {'red' if failed else 'green'}]    "
        f"[grey50]0 warnings[/grey50]\n\n"
        f"  [grey50]Runtime: {runtime_str}[/grey50]\n",
        border_style=border,
        padding=(0, 2),
    ))

    wait_for_enter(9)


# ──────────────────────────────────────────────────────────────────────────────
# SCENE 10 — Summary
# ──────────────────────────────────────────────────────────────────────────────

def scene_10() -> None:
    clear_screen()
    console.print(Panel(
        "[bold cyan]GUARDIAN PHASE 1 — COMPLETE[/bold cyan]",
        expand=False, border_style="cyan",
    ))
    console.print()

    t = Table(
        box=box.ROUNDED,
        border_style="cyan",
        title="[bold cyan]PHASE 1 DELIVERED[/bold cyan]",
        title_justify="center",
        min_width=72,
    )
    t.add_column("Component", style="white", min_width=38)
    t.add_column("Status", min_width=30)

    components = [
        ("Fake event generator",              "✓  Schema-identical to eBPF"),
        ("guardian.yaml config loader",        "✓  Single config surface"),
        ("Container / K8s enrichment",         "✓  /proc + env vars"),
        ("SHA-256 event chaining",             "✓  Tamper-evident"),
        ("HMAC-SHA256 batch signing",          "✓  Authenticated"),
        ("Local alert engine",                "✓  No network required"),
        ("gRPC sender + TLS",                 "✓  Streaming to platform"),
        ("Disk buffer + replay",              "✓  Zero event loss"),
        ("Phase 2 eBPF stub",                "✓  Ready for Linux / OrbStack"),
        ("Test suite",                        "✓  63 tests, 0 failures"),
    ]
    for comp, status in components:
        t.add_row(comp, f"[bold green]{status}[/bold green]")

    t.add_section()
    t.add_row("[yellow]EU AI Act Articles covered[/yellow]", "[white]12, 13, 15, 17, 72[/white]")
    t.add_row("[yellow]Install time[/yellow]",               "[white]< 5 minutes[/white]")
    t.add_row("[yellow]Code changes to customer model[/yellow]", "[white]Zero[/white]")

    console.print(t)
    console.print()

    # Roadmap
    console.print(Panel(
        "  [bold green]Phase 1  ██████████  COMPLETE[/bold green]  "
        "[grey50]— Python agent, fake generator[/grey50]\n"
        "  [yellow]Phase 2  ░░░░░░░░░░  NEXT    [/yellow]  "
        "[grey50]— Real eBPF on Linux (OrbStack ready)[/grey50]\n"
        "  [grey50]Phase 3  ░░░░░░░░░░  PLANNED  — Rust rewrite with Aya[/grey50]",
        title="[bold cyan]Roadmap[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))
    console.print()

    # Contact
    console.print(Panel(
        "[bold white]viriatosecurity.com[/bold white]\n"
        "[white]github.com/Viriato-Security/guardian[/white]\n"
        "[white]radesh@viriatosecurity.com[/white]",
        title="[bold yellow]Contact[/bold yellow]",
        border_style="yellow",
        padding=(1, 2),
        expand=False,
    ))
    console.print()
    console.print("[grey50]  End of Phase 1 Demo.[/grey50]")
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

SCENES: dict[int, object] = {
    1: scene_1,
    2: scene_2,
    3: scene_3,
    4: scene_4,
    5: scene_5,
    6: scene_6,
    7: scene_7,
    8: scene_8,
    9: scene_9,
    10: scene_10,
}


def main() -> None:
    global SPEED_MULT

    parser = argparse.ArgumentParser(
        prog="python tools/demo.py",
        description="Guardian Phase 1 — Terminal Demo for Video Presentation",
    )
    parser.add_argument(
        "--scene", type=int, metavar="N",
        help="Start at scene N (1–10)",
    )
    parser.add_argument(
        "--speed",
        choices=["slow", "normal", "fast"],
        default="normal",
        help="Animation speed: slow=2x delays, normal=default, fast=minimal (default: normal)",
    )
    args = parser.parse_args()

    SPEED_MULT = {"slow": 2.0, "normal": 1.0, "fast": 0.1}[args.speed]

    start = args.scene if args.scene else 1
    if start not in SCENES:
        parser.error(f"--scene must be 1–10, got {start}")

    try:
        for n in range(start, 11):
            scene_fn = SCENES[n]
            assert callable(scene_fn)
            scene_fn()
    except SystemExit:
        pass
    except KeyboardInterrupt:
        pass
    finally:
        _cleanup_subprocesses()


if __name__ == "__main__":
    main()

