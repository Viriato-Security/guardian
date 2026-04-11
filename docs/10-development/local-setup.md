# Local Development Setup

This guide walks through every step needed to run Guardian locally for development —
from installing prerequisites to launching the agent in dry-run mode, running the test
suite, and using the interactive demo.

---

## Prerequisites

### macOS

1. **Python 3.12 or later**

   Install with Homebrew (recommended):

   ```bash
   brew install python@3.12
   ```

   Or download the installer from [python.org](https://www.python.org/downloads/).

   Verify:

   ```bash
   python3.12 --version
   # Python 3.12.x
   ```

2. **Git** — ships with Xcode Command Line Tools (`xcode-select --install`).

3. **grpcio-tools** — needed to generate proto stubs (installed via `requirements.txt`).

### Linux

Same as macOS except:

- Use your distro's package manager, e.g. `sudo apt install python3.12 python3.12-venv python3.12-dev`.
- The default `buffer_path` in production is `/var/lib/guardian/buffer` (requires write permission or `sudo`). For local development, the default `~/.guardian/buffer` is fine.
- Phase 2 eBPF probes require Linux kernel 5.8+ with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`). Phase 1 fake generator works everywhere.

---

## Clone and Install

```bash
# 1. Clone the repo
git clone https://github.com/Viriato-Security/guardian.git
cd guardian

# 2. Create a virtual environment
python3.12 -m venv .venv

# 3. Activate it
source .venv/bin/activate   # macOS / Linux

# 4. Install Python dependencies
pip install -r requirements.txt

# 5. Generate the proto stubs (required before first run)
bash scripts/gen_proto.sh

# 6. Copy the example config
cp guardian.yaml.example guardian.yaml
```

At this point you have a working dev environment. The generated stubs land in
`proto/guardian_pb2.py` and `proto/guardian_pb2_grpc.py` — both are `.gitignore`d
and must never be committed.

---

## Configure guardian.yaml

Open `guardian.yaml` and fill in at minimum:

```yaml
agent:
  token: "YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE"
  control_plane: "grpc.viriatosecurity.com:443"
  batch_interval_ms: 100
  buffer_path: "~/.guardian/buffer"   # Linux production: /var/lib/guardian/buffer
```

For local development without a real token, run with `--dry-run` (see below) —
Guardian will batch and sign events but skip the gRPC send. A warning is logged if
the token is still the placeholder value.

---

## Running the Agent

### Dry-run mode (recommended for local dev)

Runs the full pipeline — config load, event generation, enrichment, alert evaluation,
signing — but skips the gRPC send:

```bash
python -m agent.main --fake --dry-run --log-level DEBUG
```

Flags:

| Flag | Effect |
|------|--------|
| `--fake` | Forces the Phase 1 fake event generator (no eBPF required) |
| `--dry-run` | Skips gRPC send; logs batch summary instead |
| `--log-level DEBUG` | Shows per-event detail, hash chains, buffer activity |
| `-c FILE` | Load config from a specific path |

### With a real token (send to platform)

```bash
python -m agent.main --fake
```

Remove `--dry-run` to enable gRPC. Events are buffered to `~/.guardian/buffer/pending.jsonl`
when the platform is unreachable and replayed on the next successful connection.

### Watching real processes (Linux only)

Edit `guardian.yaml` to name the processes you want to monitor, then run without `--fake`:

```bash
python -m agent.main --log-level INFO
```

---

## Running the Test Suite

```bash
# All tests
python -m pytest tests/ -v

# Single file
python -m pytest tests/test_generator.py -v

# Single test
python -m pytest tests/test_local_alerts.py::test_sandbox_escape_fires_on_bin_bash -v

# With coverage (requires pytest-cov)
python -m pytest tests/ --cov=agent --cov-report=term-missing
```

The test suite has 63 tests across five modules and requires no network access or
root privileges. All tests pass on macOS and Linux.

---

## Running the Demo

The interactive terminal demo walks through all Guardian capabilities in 10 scenes
using real code, not mocks. It requires the `rich` library (`pip install rich`).

```bash
python tools/demo.py                  # full demo
python tools/demo.py --scene 6       # jump to a specific scene
python tools/demo.py --speed slow    # 2x delays for live presenting
python tools/demo.py --speed fast    # minimal delays for quick review
```

The demo starts a lightweight test gRPC server internally so scenes involving sends
work without a live platform connection.

---

## Running the Test gRPC Server

If you want a standalone local server that accepts EventBatch messages and prints
acknowledgements, you can run the bundled test server from `tools/demo.py`.
The server listens on `localhost:50051` by default and returns `Ack{received: true}`.

To use it, set `control_plane: "localhost:50051"` in `guardian.yaml` and the agent
will use an insecure channel automatically (`GUARDIAN_INSECURE_GRPC=1` also works).

---

## Editor Setup

### VSCode (recommended)

Install the following extensions:

| Extension | Purpose |
|-----------|---------|
| **Python** (Microsoft) | Language support, debugger |
| **Pylance** | Type-checking with pyright |
| **Ruff** | Fast linter and formatter |
| **vscode-proto3** | Syntax highlighting for `.proto` files |

Recommended `settings.json` additions:

```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python",
  "editor.formatOnSave": true,
  "[python]": {
    "editor.defaultFormatter": "charliermarsh.ruff"
  }
}
```

### mypy

Guardian uses strict mypy. Run:

```bash
python -m mypy agent/ --strict --python-version=3.12 --ignore-missing-imports
```

The `pyproject.toml` contains the mypy configuration so `python -m mypy agent/` is
sufficient once the project config is active.

---

## Common Development Workflows

### Regenerate proto stubs after editing guardian.proto

```bash
bash scripts/gen_proto.sh
```

The script compiles `proto/guardian.proto`, outputs the stubs to `proto/`, and
fixes the import in `guardian_pb2_grpc.py` so it reads
`from proto import guardian_pb2` rather than a bare `import guardian_pb2`.

### Add a new syscall to the fake generator

See [adding-a-syscall.md](adding-a-syscall.md) for the full step-by-step guide.

### Add a new alert rule

See [adding-an-alert.md](adding-an-alert.md) for the full step-by-step guide.

### Inspect the disk buffer

```bash
cat ~/.guardian/buffer/pending.jsonl | python -m json.tool | head -100
```

Each line is a JSON object with `agent_id`, `signature`, and `events` fields.

---

## Phase 2 (Linux eBPF)

Phase 2 requires Linux 5.8+ with BTF. For macOS development, install
[OrbStack](https://orbstack.dev/) — it provides a lightweight Linux VM with a
modern kernel and BTF support, and integrates with the macOS filesystem.

```bash
# Inside an OrbStack Linux VM
python -m agent.main --log-level DEBUG
# Automatically uses the eBPF loader if available; falls back to fake generator otherwise
```

---

## Related Documents

- [adding-a-syscall.md](adding-a-syscall.md)
- [adding-an-alert.md](adding-an-alert.md)
- [proto-changes.md](proto-changes.md)
- [contributing.md](contributing.md)
- [../../docs/02-architecture/](../02-architecture/)
