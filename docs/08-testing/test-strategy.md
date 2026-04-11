# Test Strategy

## Philosophy: Tests as Specifications

Guardian's tests are not an afterthought. They are the specification for what each module must do. When Phase 2 or Phase 3 ships, every existing test must pass unchanged — not because the project is conservative, but because the tests encode contracts that the rest of the system depends on.

If a test needs to change because behaviour changed, that change requires explicit justification. Most changes to Guardian should not require any test changes — they should require new tests for new behaviour. A test that needs to be deleted or loosened is almost always a signal that a contract was broken, not that the test was wrong.

This philosophy has a practical consequence: tests are written before or alongside code, not after. The suite exists not to measure correctness after the fact but to define correctness upfront.

## The Contract Principle

The most important architectural insight in Guardian's test design: **the fake event generator must produce `RawEvent` instances that are structurally identical to what the eBPF loader will produce in Phase 2.**

This contract is enforced by tests in `test_generator.py`. Every field that `FakeEventGenerator` produces will be produced by `EbpfLoader`. The types must match. The semantics must match. The tests for the generator serve double duty: they test Phase 1 behaviour AND specify what Phase 2 must satisfy.

This means the 63 tests written in Phase 1 are directly applicable as acceptance criteria for Phase 2. When `EbpfLoader` ships, it must pass every test in `test_generator.py` without modification to those tests. The only change will be swapping `FakeEventGenerator` for `EbpfLoader` in the test helper function — and if any test fails at that point, the eBPF implementation is wrong.

Specific generator contracts enforced by tests:

- Timestamps are ISO 8601 with nanosecond precision and a trailing `Z` — format `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z`
- Every field on `RawEvent` is non-None
- `pid` is always positive; `uid` is always non-negative
- `read` and `write` syscalls always have `bytes > 0`
- Network syscalls (`sendto`, `recvfrom`, `connect`) always have a non-empty `network_addr`
- `execve` events always have an `fd_path` beginning with `/`
- `return_val` is always a string
- `process` is always from the configured watch list
- At least four distinct syscall types appear in 200 consecutive events

## Testing Pyramid

```
         /\
        /  \
       / E2E\      End-to-end: demo.py, GUARDIAN_FAKE_EVENTS=1 --dry-run
      /------\
     /        \
    / Integration\  gRPC test server, disk buffer drain, pipeline
   /------------\
  /              \
 /   Unit Tests   \  63 tests: config, enricher, generator,
/------------------\  local_alerts, signer
```

Each level has a distinct purpose, cost, and run frequency.

### Unit Tests — 63 Tests, Phase 1 Complete

Pure unit tests. No network. No filesystem (except temp paths via pytest's `tmp_path` fixture). No root. No BPF. Runs in 0.04–0.06 seconds.

Distribution across modules:

| File | Module | Tests |
|------|--------|-------|
| `test_config.py` | `agent/config.py` | 6 |
| `test_enricher.py` | `agent/enricher.py` | 11 |
| `test_generator.py` | `agent/generator.py` | 16 |
| `test_local_alerts.py` | `agent/local_alerts.py` | 14 |
| `test_signer.py` | `agent/signer.py` | 16 |
| **Total** | | **63** |

Unit tests run on every commit, every pull request, on every developer's machine without any special setup.

### Integration Tests — Phase 2

Integration tests verify the interaction between modules and with external systems:

- Pipeline integration: reader → enricher → signer → batch → sender
- gRPC send with a local test server (the `_TEST_SERVER_CODE` embedded in `tools/demo.py`)
- Disk buffer write and drain (simulate gRPC failure, verify buffer growth, restore connectivity, verify drain)
- Full pipeline with `GUARDIAN_FAKE_EVENTS=1` and `--dry-run`

Integration tests may require filesystem writes and spawning subprocesses but do not require root or BPF. They run on every CI merge to main.

### End-to-End and Demo

`tools/demo.py` and `tools/dev.sh` serve as manual end-to-end verification. They are not automated in CI but are run before every release. The demo exercises all 10 scenes of the pipeline with real code, real gRPC communication to a local test server, and real event generation.

Phase 2 adds automated end-to-end tests on Linux with root that verify real syscalls are captured by the eBPF probe and flow through the entire pipeline to the control plane.

## Why Tests Run Without Root or Network

Unit tests must run in CI without elevated privileges. This is non-negotiable for two reasons:

1. **CI environment**: GitHub Actions runners do not grant root. Tests that require root cannot run in the standard unit test job.
2. **Developer experience**: Any developer must be able to run `pytest tests/` from their laptop — macOS, Linux, or Windows — without any special setup beyond `pip install -r requirements.txt`.

This constraint actively shapes module design. Modules that interact with the environment are written to degrade gracefully rather than raise:

- `Enricher._container_id()` catches `OSError` (returns `""` if `/proc/<pid>/cgroup` is unavailable)
- `Sender._init_grpc()` catches `ImportError` and continues without gRPC, enabling disk-buffer-only operation
- `EbpfLoader.is_available()` returns `False` on macOS without raising any exception
- `LocalAlertEngine.set_custom_handler()` allows tests to suppress terminal output without patching `sys.stderr` or the logging system

These are not workarounds for testing — they are correct production behaviours. A Guardian instance should not crash because it is running on a system without BPF support; it should fall back to fake events. A Sender should not crash because the gRPC endpoint is unreachable; it should buffer to disk.

## Coverage Targets

| Module | Coverage Target | Rationale |
|--------|----------------|-----------|
| `agent/config.py` | >95% | Pure dataclass parsing logic, no I/O |
| `agent/enricher.py` | >90% | Some `/proc` paths only reachable on Linux with real PIDs |
| `agent/generator.py` | >95% | Pure logic, fully deterministic with mocked time |
| `agent/signer.py` | 100% | Cryptographic correctness is safety-critical |
| `agent/local_alerts.py` | >95% | Security rules must be exhaustively tested |
| `agent/main.py` | 0% unit | I/O coordinator — integration tested only |
| `agent/reader.py` | 0% unit | Thin source-selection abstraction — integration tested |
| `agent/sender.py` | 0% unit | gRPC and disk I/O — integration tested |

## Why main.py, reader.py, and sender.py Have 0% Unit Coverage

These modules are I/O coordinators. Their logic is thin; their dependencies are external: a gRPC channel, a ring buffer, a subprocess, a POSIX signal loop.

Unit testing them would require mocking so many dependencies that the tests end up testing the mocks, not the code. A unit test for `Sender.send_batch` that mocks `grpc.channel.unary_stream` tells you nothing about whether the batch actually arrives at the server. That question is only answered by running against a real gRPC server.

The correct placement in the pyramid:

- `main.py`: tested end-to-end by running `GUARDIAN_FAKE_EVENTS=1 python -m agent.main --dry-run --log-level DEBUG`
- `reader.py`: tested by integration tests that verify source selection (fake vs. eBPF) and event emission
- `sender.py`: tested by integration tests with a local gRPC test server (see `_TEST_SERVER_CODE` in `tools/demo.py`)

A coverage report showing 0% for these three files is not a failure. It is evidence that the test suite is correctly stratified.

## CI Strategy

### Current CI — Phase 1

The unit test suite requires only Python 3.12+, `pip install -r requirements.txt`, and the proto stubs. No Docker, no database, no network services.

Recommended GitHub Actions workflow:

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.12"]

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Generate proto stubs
        run: bash scripts/gen_proto.sh

      - name: Run unit tests with coverage
        run: |
          pytest tests/ \
            --cov=agent \
            --cov-report=term-missing \
            --cov-fail-under=80
```

Key properties:
- Runs on every push and pull request
- No extra services (no Docker, no gRPC server, no database)
- Target completion time: under 30 seconds for 63 tests
- Matrix over Python 3.12 (expand to 3.13 when stable)

### Phase 2 CI Addition

A separate job requiring a Linux runner with `CAP_BPF`:

```yaml
  ebpf-integration:
    runs-on: ubuntu-22.04
    needs: unit-tests
    if: github.ref == 'refs/heads/main'

    steps:
      - uses: actions/checkout@v4

      - name: Install BCC
        run: |
          sudo apt-get update
          sudo apt-get install -y clang-14 python3-bcc linux-headers-$(uname -r)

      - name: Run eBPF integration tests
        run: sudo pytest tests/integration/ --log-level=DEBUG -v
```

This job runs only on main branch merges. Pull requests from contributors can merge based on unit tests alone; the eBPF job is a gate for production.

## Test Isolation

Every test must be isolated. No test should depend on the execution order of other tests or leave state that affects subsequent tests.

Isolation rules:

- **No global state mutation**: tests that use `Signer` create fresh `Signer` instances; they do not patch the class or module globals
- **No shared mutable fixtures**: fixtures return new objects; they do not cache
- **Temp directories**: tests that write files use pytest's `tmp_path` fixture, which provides a directory unique per test and cleaned up after the session
- **Environment variables**: patched using `monkeypatch.setenv()` / `monkeypatch.delenv()`, which automatically restore the original values after the test
- **Custom alert handlers**: tests use `engine.set_custom_handler(lambda alert: None)` rather than patching `sys.stderr` or the logging system globally

These rules are enforced by code review. Any test that violates isolation will fail unpredictably when run in parallel (`pytest-xdist`) or in random order (`pytest-randomly`).

## Adding Tests

Every new function or code path added to a covered module requires at least:

1. One test for the happy path (correct input produces correct output)
2. One test for each distinct error case (invalid input, missing resource, boundary condition)

See [Unit Tests](unit-tests.md) for the file-by-file guide on how to add tests to each module, including the helper patterns used in each file.

---

## Related Documents

- [Unit Tests](unit-tests.md)
- [Integration Testing](integration-testing.md)
- [Running Tests](running-tests.md)
- [Phase 1: Python Agent](../07-phases/phase1-python-agent.md)
