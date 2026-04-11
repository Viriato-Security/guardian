# Installation

This document covers installing Guardian from source on macOS and Linux. Phase 1 runs entirely in Python and requires no kernel modules or BPF toolchain. Phase 2 will require additional kernel dependencies documented separately.

---

## Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| Python | 3.12 | Required for `datetime.now(UTC)` and match-statement typing |
| git | Any recent | For cloning the repository |
| pip | Included with Python 3.12 | For installing dependencies |
| bash | Any | For running `install.sh` and `gen_proto.sh` |

### Verify Python Version

```bash
python3 --version
```

Must print `Python 3.12.x` or higher. If not:

**macOS**:
```bash
brew install python@3.12
# or
pyenv install 3.12.7 && pyenv global 3.12.7
```

**Ubuntu / Debian**:
```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install python3.12 python3.12-venv python3.12-pip
```

**From python.org**: Download the installer from [python.org/downloads](https://python.org/downloads).

---

## Step-by-Step Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/Viriato-Security/guardian.git
cd guardian
```

### Step 2: Create a Virtual Environment

A virtual environment isolates Guardian's dependencies from your system Python:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Verify the environment is active:

```bash
which python
# Should print: /path/to/guardian/.venv/bin/python
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

This installs all runtime and development dependencies. Key packages:

| Package | Version | Purpose |
|---------|---------|---------|
| `grpcio` | >=1.62.0 | gRPC transport to control plane |
| `grpcio-tools` | >=1.62.0 | proto stub generation |
| `pyyaml` | >=6.0.1 | YAML configuration parsing |
| `cryptography` | >=42.0.0 | HMAC-SHA256 batch signing |
| `rich` | >=13.0.0 | Terminal UI for demo and logging |
| `pytest` | >=8.0.0 | Test runner |
| `pytest-cov` | >=4.1.0 | Coverage measurement |
| `mypy` | >=1.8.0 | Static type checking |

### Step 4: Generate Proto Stubs

The gRPC protocol buffer stubs are generated from `proto/guardian.proto` and are not committed to the repository (they are `.gitignore`d):

```bash
bash scripts/gen_proto.sh
```

Expected output:

```
Compiling /path/to/guardian/proto/guardian.proto ...
Fixed import in /path/to/guardian/proto/guardian_pb2_grpc.py
Done. Generated:
  proto/guardian_pb2.py
  proto/guardian_pb2_grpc.py
```

What `gen_proto.sh` does internally:
1. Runs `python -m grpc_tools.protoc --proto_path=proto --python_out=proto --grpc_python_out=proto proto/guardian.proto`
2. Applies a `sed` fix to replace `import guardian_pb2` with `from proto import guardian_pb2` in the generated `guardian_pb2_grpc.py` (the protoc output assumes a different import path than what Guardian uses)

On macOS, the `sed -i ''` (BSD sed) syntax is used automatically. On Linux, `sed -i` (GNU sed) is used.

### Step 5: Copy Configuration

```bash
cp guardian.yaml.example guardian.yaml
```

### Step 6: Edit Configuration

Open `guardian.yaml` and set your API token:

```bash
nano guardian.yaml   # or vim, or any editor
```

Replace `YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE` with the token from [viriatosecurity.com](https://viriatosecurity.com). See [Configuration](configuration.md) for all options.

---

## Using install.sh (Automated)

The `install.sh` script automates steps 3–5:

```bash
bash install.sh
```

The script performs exactly these steps:

1. **Python version check**: Verifies `python3` is available and is 3.12+. Exits with an error message if not.

2. **Install dependencies**: Runs `python3 -m pip install --quiet -r requirements.txt`.

3. **Generate proto stubs**: Runs `bash scripts/gen_proto.sh`.

4. **Copy configuration**: Copies `guardian.yaml.example` to `guardian.yaml` if `guardian.yaml` does not already exist. If `guardian.yaml` already exists, it is left unchanged.

At completion, `install.sh` prints:

```
[guardian] Installation complete!

Next steps:
  1. Edit guardian.yaml and set your API token.
  2. Run the agent in dry-run mode to verify:
       python -m agent.main --fake --dry-run --log-level DEBUG
  3. Run in production mode (Linux with eBPF in Phase 2):
       python -m agent.main --config /etc/guardian/guardian.yaml
```

Note: `install.sh` does not create or activate a virtual environment. Create the `.venv` first (Step 2 above) and ensure it is active before running `install.sh`.

---

## Manual Installation (if install.sh Fails)

If `install.sh` fails on a non-standard system, perform each step manually:

```bash
# Check Python version manually
python3 -c "import sys; assert sys.version_info >= (3,12), 'Need Python 3.12+'"

# Install each dependency group individually if requirements.txt fails
pip install "grpcio>=1.62.0"
pip install "grpcio-tools>=1.62.0"
pip install "pyyaml>=6.0.1"
pip install "cryptography>=42.0.0"
pip install "rich>=13.0.0"
pip install "pytest>=8.0.0" "pytest-cov>=4.1.0" "mypy>=1.8.0"

# Generate proto stubs manually
python -m grpc_tools.protoc \
  --proto_path=proto \
  --python_out=proto \
  --grpc_python_out=proto \
  proto/guardian.proto

# Fix the import in the generated stub (macOS)
sed -i '' 's/^import guardian_pb2/from proto import guardian_pb2/' proto/guardian_pb2_grpc.py

# Fix the import in the generated stub (Linux)
sed -i 's/^import guardian_pb2/from proto import guardian_pb2/' proto/guardian_pb2_grpc.py

# Copy config
cp guardian.yaml.example guardian.yaml
```

---

## Installing as a Package (Console Script)

To install Guardian as an editable package with the `guardian` console script:

```bash
pip install -e .
```

After installation, the `guardian` command is available:

```bash
guardian --help
guardian --fake --dry-run --log-level DEBUG
```

The console script entry point is defined in `pyproject.toml`:

```toml
[project.scripts]
guardian = "agent.main:cli_main"
```

---

## Verifying the Installation

After completing all steps, verify the agent starts correctly:

```bash
python -m agent.main --fake --dry-run --log-level DEBUG
```

Expected output:

```
DEBUG    agent.config     Loaded config from ./guardian.yaml
DEBUG    agent.enricher   Agent ID: <uuid4>
DEBUG    agent.generator  FakeEventGenerator initialised with 9 syscalls, 2 watch entries
INFO     agent.main       Starting Guardian agent (fake events, dry-run mode)
DEBUG    agent.signer     Signed event 1
DEBUG    agent.signer     Signed event 2
...
INFO     agent.main       Batch 1: 10 events — dry-run (not sent)
```

If this output appears, the installation is complete. Stop with `Ctrl+C`.

Run the unit tests to verify the Python environment:

```bash
pytest tests/ -v
```

All 63 tests should pass in under 0.1 seconds.

---

## Common Errors

### "Python 3.12+ required (found 3.11.x)"

Upgrade Python. The `install.sh` error message includes the found version. Use `pyenv` or your system package manager to install 3.12.

### "ModuleNotFoundError: No module named 'grpc_tools'"

The virtual environment is not activated, or `pip install -r requirements.txt` was not run:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### "Proto stubs not found — running without gRPC"

The gRPC stubs were not generated. Run:

```bash
bash scripts/gen_proto.sh
```

This message appears as a WARNING in the agent log. The agent continues running but buffers all batches to disk instead of sending them.

### "FileNotFoundError: guardian.yaml not found"

Guardian searches for configuration in these locations in order:
1. `./guardian.yaml` (current directory)
2. `/etc/guardian/guardian.yaml` (system-wide)
3. `~/.guardian/guardian.yaml` (user home)

If none exist, a `FileNotFoundError` is raised. Copy the example file:

```bash
cp guardian.yaml.example guardian.yaml
```

Or specify an explicit path:

```bash
python -m agent.main --config /path/to/my/guardian.yaml
```

### "Guardian token is not set or is still the placeholder"

The token in `guardian.yaml` is still `YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE`. Edit the file and replace it with a real token from [viriatosecurity.com](https://viriatosecurity.com). The agent logs a WARNING but continues running.

### "BCC import error" or "EbpfLoader unavailable"

This is expected on macOS or any system without eBPF support. The agent automatically falls back to `FakeEventGenerator`. For production use, run on Linux. For development on macOS, always use `--fake`.

---

## Phase 2 Additional Requirements (Linux Only)

Phase 2 adds the eBPF probe. Additional installation steps will be required:

```bash
# Ubuntu 22.04
sudo apt-get install -y \
    linux-headers-$(uname -r) \
    clang-14 \
    python3-bcc

# Verify BPF is available
python3 -c "import bcc; print('BCC available')"
```

Phase 2 installation will be documented fully when that phase ships. For now, use `--fake` on macOS and any system without BPF support.

---

## Related Documents

- [Configuration](configuration.md)
- [Deployment](deployment.md)
- [Troubleshooting](troubleshooting.md)
- [Running Tests](../08-testing/running-tests.md)
