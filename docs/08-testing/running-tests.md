# Running Tests

This document covers every command needed to run Guardian's tests, from initial setup through coverage reports and individual test execution.

---

## Prerequisites

Before running any tests, ensure the following:

### 1. Python 3.12+

```bash
python3 --version
# Must print Python 3.12.x or higher
```

If Python 3.12 is not installed, download from [python.org](https://python.org) or use `pyenv`:

```bash
pyenv install 3.12.7
pyenv local 3.12.7
```

### 2. Create and Activate a Virtual Environment

```bash
cd /path/to/guardian
python3 -m venv .venv
source .venv/bin/activate
```

On Windows:

```cmd
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs all runtime and development dependencies including `pytest>=8.0.0` and `pytest-cov>=4.1.0`.

### 4. Generate Proto Stubs

```bash
bash scripts/gen_proto.sh
```

This compiles `proto/guardian.proto` into `proto/guardian_pb2.py` and `proto/guardian_pb2_grpc.py`. The gRPC stubs are required by the `Sender` module. Tests that do not directly use `Sender` will still pass without stubs, but generating them is required for full coverage.

Expected output:

```
Compiling /path/to/guardian/proto/guardian.proto ...
Fixed import in /path/to/guardian/proto/guardian_pb2_grpc.py
Done. Generated:
  proto/guardian_pb2.py
  proto/guardian_pb2_grpc.py
```

---

## Running Unit Tests

### Full Suite

```bash
python -m pytest tests/ -v
```

Expected output:

```
============================= test session starts ==============================
platform darwin -- Python 3.12.x, pytest-8.x.x, pluggy-1.x.x
collected 63 items

tests/test_config.py::test_load_config_parses_yaml PASSED                [  1%]
tests/test_config.py::test_placeholder_token_logs_warning PASSED         [  3%]
tests/test_config.py::test_model_name_for_process_resolves PASSED        [  4%]
tests/test_config.py::test_model_name_for_unknown_process PASSED         [  6%]
tests/test_config.py::test_batch_interval_seconds PASSED                 [  7%]
tests/test_config.py::test_file_not_found_raises PASSED                  [  9%]
tests/test_enricher.py::test_agent_id_is_valid_uuid PASSED               [ 11%]
...
tests/test_signer.py::test_sign_batch_empty_token_raises PASSED          [100%]

============================== 63 passed in 0.05s ==============================
```

### Short (No Verbose Flag)

```bash
python -m pytest tests/
```

Output is one dot per test. Failures show the short traceback configured in `pyproject.toml` (`addopts = "--tb=short"`).

### Stop on First Failure

```bash
python -m pytest tests/ -x
```

Useful during development to fix one failure at a time without scrolling through a full failure list.

### Show Local Variables in Failures

```bash
python -m pytest tests/ -v --tb=long -l
```

Prints local variable values in the stack trace. Helpful when a complex assertion fails and you need to see the actual values.

---

## Running a Single Test File

```bash
pytest tests/test_signer.py -v
```

Expected output:

```
============================= test session starts ==============================
collected 16 items

tests/test_signer.py::test_first_event_chains_from_genesis PASSED        [  6%]
tests/test_signer.py::test_second_event_chains_from_first PASSED         [ 12%]
tests/test_signer.py::test_chain_of_ten_passes_verify PASSED             [ 18%]
tests/test_signer.py::test_this_hash_is_deterministic PASSED             [ 25%]
tests/test_signer.py::test_hash_changes_when_field_mutated PASSED        [ 31%]
tests/test_signer.py::test_events_signed_counter_increments PASSED       [ 37%]
tests/test_signer.py::test_verify_chain_valid PASSED                     [ 43%]
tests/test_signer.py::test_verify_chain_empty PASSED                     [ 50%]
tests/test_signer.py::test_verify_chain_tampered_field PASSED            [ 56%]
tests/test_signer.py::test_verify_chain_swapped_order PASSED             [ 62%]
tests/test_signer.py::test_verify_chain_deleted_event PASSED             [ 68%]
tests/test_signer.py::test_sign_batch_returns_64_char_hex PASSED         [ 75%]
tests/test_signer.py::test_sign_batch_is_deterministic PASSED            [ 81%]
tests/test_signer.py::test_sign_batch_different_tokens_differ PASSED     [ 87%]
tests/test_signer.py::test_sign_batch_empty_raises PASSED                [ 93%]
tests/test_signer.py::test_sign_batch_empty_token_raises PASSED          [100%]

============================== 16 passed in 0.01s ==============================
```

Other test files:

```bash
pytest tests/test_config.py -v       # 6 tests
pytest tests/test_enricher.py -v     # 11 tests
pytest tests/test_generator.py -v    # 16 tests
pytest tests/test_local_alerts.py -v # 14 tests
```

---

## Running a Single Test by Name

```bash
pytest tests/test_signer.py::test_chain_of_ten_passes_verify -v
```

Expected output:

```
============================= test session starts ==============================
collected 1 item

tests/test_signer.py::test_chain_of_ten_passes_verify PASSED            [100%]

============================== 1 passed in 0.01s ==============================
```

Any test in the suite:

```bash
pytest tests/test_generator.py::test_now_iso_ns_no_deprecation_warnings -v
pytest tests/test_local_alerts.py::test_sandbox_escape_fires_on_usr_bin_sh -v
pytest tests/test_config.py::test_placeholder_token_logs_warning -v
pytest tests/test_enricher.py::test_container_id_empty_for_nonexistent_pid -v
```

---

## Running Tests by Keyword

Run all tests whose name contains a keyword:

```bash
pytest tests/ -k "signer" -v        # All signer tests
pytest tests/ -k "chain" -v          # All chain-related tests
pytest tests/ -k "sandbox" -v        # All sandbox_escape tests
pytest tests/ -k "config or enricher" -v  # Config and enricher tests
```

---

## Coverage Report

### Terminal Report with Missing Lines

```bash
python -m pytest tests/ --cov=agent --cov-report=term-missing
```

Expected output (abbreviated):

```
---------- coverage: platform darwin, python 3.12.x ----------
Name                      Stmts   Miss  Cover   Missing
---------------------------------------------------------
agent/__init__.py             0      0   100%
agent/config.py              68      2    97%   134-135
agent/enricher.py            54      4    93%   89, 102-103, 117
agent/generator.py           72      1    99%   201
agent/local_alerts.py        61      2    97%   78, 91
agent/loader.py              31     31     0%   (integration only)
agent/main.py                89     89     0%   (integration only)
agent/reader.py              24     24     0%   (integration only)
agent/sender.py              98     98     0%   (integration only)
agent/signer.py              53      0   100%
---------------------------------------------------------
TOTAL                       550    251    54%
```

The 0% rows for `main.py`, `reader.py`, and `sender.py` are correct. See [Test Strategy — Why 0% Unit Coverage is Correct](test-strategy.md#why-mainpy-readerpy-and-senderpy-have-0-unit-coverage).

### HTML Report

```bash
python -m pytest tests/ --cov=agent --cov-report=html
open htmlcov/index.html   # macOS
xdg-open htmlcov/index.html  # Linux
```

The HTML report shows annotated source with covered lines in green and uncovered lines in red.

### Coverage with Minimum Threshold

```bash
python -m pytest tests/ --cov=agent --cov-fail-under=50
```

Fails the test run if total coverage drops below 50%. Use in CI to prevent regressions.

---

## Dry-Run Agent (Manual Integration Verification)

This is not a pytest command but is the first step in manual integration testing. It runs the full pipeline without sending to the real control plane:

```bash
python -m agent.main --fake --dry-run --log-level DEBUG
```

Expected output (abbreviated):

```
DEBUG    agent.config     Loaded config from ./guardian.yaml
DEBUG    agent.enricher   Agent ID: 3f7c1b2a-...
DEBUG    agent.generator  FakeEventGenerator initialised with 9 syscalls, 2 watch entries
DEBUG    agent.signer     Signed event 1 (prev_hash: 0000000000000000...)
DEBUG    agent.signer     Signed event 2 (prev_hash: a3f7c9...)
...
INFO     agent.main       Batch 1: 10 events — dry-run (not sent)
```

Stop with `Ctrl+C`. If the output matches this pattern, the pipeline is wired correctly.

Flags:
- `--fake`: force `FakeEventGenerator` regardless of what is in `guardian.yaml`
- `--dry-run`: skip gRPC send, print batch summary only
- `--log-level DEBUG`: emit all DEBUG messages to stderr

---

## Demo Tool

The terminal demo exercises all pipeline stages interactively:

```bash
python tools/demo.py
```

Jump to a specific scene:

```bash
python tools/demo.py --scene 6    # gRPC send scene
python tools/demo.py --scene 7    # Disk buffer scene
python tools/demo.py --scene 4    # Chain verification scene
```

Run with minimal delays (fastest):

```bash
python tools/demo.py --speed fast
```

Run with maximum delays (for live presentations):

```bash
python tools/demo.py --speed slow
```

The demo requires the `rich` library:

```bash
pip install rich
```

Expected output for Scene 6 (gRPC send):

```
Scene 6: Live gRPC Send
Starting test gRPC server on localhost:50051...
SERVER_READY
Sending batch of 10 events...
BATCH:10:a3f7c9d1e2b4f8a0  ← server confirms receipt
Chain verification: PASS
```

---

## Checking pyproject.toml Configuration

The pytest configuration lives in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
addopts = "--tb=short"
```

`addopts = "--tb=short"` means failures always show a short traceback. Override with `--tb=long` or `--tb=no` on the command line.

---

## Troubleshooting Failed Runs

### "ModuleNotFoundError: No module named 'agent'"

You are running pytest from outside the repository root, or the virtual environment is not activated.

```bash
cd /path/to/guardian
source .venv/bin/activate
pytest tests/ -v
```

### "ModuleNotFoundError: No module named 'proto'"

Proto stubs are not generated. Run:

```bash
bash scripts/gen_proto.sh
```

### "ModuleNotFoundError: No module named 'pytest'"

The virtual environment is not activated or `pip install -r requirements.txt` was not run.

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### Tests Fail with "FileNotFoundError: guardian.yaml"

The integration dry-run requires a `guardian.yaml`. Unit tests do not — if unit tests are failing with this error, the test is incorrectly trying to load the live config. Check that the test uses `_write_yaml(tmp_path, ...)` rather than `load_config()` without a path.

---

## Related Documents

- [Test Strategy](test-strategy.md)
- [Unit Tests](unit-tests.md)
- [Integration Testing](integration-testing.md)
- [Installation](../09-operations/installation.md)
