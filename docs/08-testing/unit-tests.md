# Unit Tests

Guardian has 63 unit tests spread across five files, each targeting one module. Tests run in 0.04–0.06 seconds with no network, no root, and no real filesystem writes (except via pytest's `tmp_path` fixture).

Run the full suite:

```bash
pytest tests/ -v
```

Run with coverage:

```bash
pytest tests/ --cov=agent --cov-report=term-missing
```

---

## test_config.py — 6 tests

**Module under test**: `agent/config.py`

**What it covers**: YAML parsing, token validation, process-to-model-name resolution, the `batch_interval_seconds` derived property, and error handling for missing files.

### Test List

| Test | What it verifies |
|------|-----------------|
| `test_load_config_parses_yaml` | Full YAML round-trip: token, control_plane, batch_interval_ms, buffer_path, watch list, syscalls, local_alerts, network_allowlist, compliance fields |
| `test_placeholder_token_logs_warning` | Token value `"YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE"` emits a WARNING log but does not raise; the config object is still returned |
| `test_model_name_for_process_resolves` | `cfg.model_name_for_process("python")` returns `"patient-diagnosis-v2"`; `"torchserve"` returns `"fraud-detection-v1"` |
| `test_model_name_for_unknown_process` | `cfg.model_name_for_process("nginx")` returns `"unknown"` |
| `test_batch_interval_seconds` | `batch_interval_ms=200` yields `batch_interval_seconds == pytest.approx(0.2)` |
| `test_file_not_found_raises` | `load_config("/nonexistent/path.yaml")` raises `FileNotFoundError` |

### Key Pattern: `_write_yaml` with `tmp_path`

All tests that need a YAML file on disk use this helper:

```python
def _write_yaml(tmp_path, content: str) -> str:
    p = tmp_path / "guardian.yaml"
    p.write_text(textwrap.dedent(content))
    return str(p)
```

`tmp_path` is a pytest built-in fixture that provides a `pathlib.Path` pointing to a unique temporary directory. It is created fresh for each test and removed after the session. The helper writes the YAML text, dedents it (allowing indented heredoc-style strings in the test), and returns the path as a string for `load_config()`.

The `_FULL_YAML` constant contains a complete, valid configuration used by four of the six tests. Tests that need unusual configurations write their own YAML inline.

### Coverage Target

`>95%`. The only uncovered paths are internal error branches for malformed YAML that are difficult to trigger without pathological input.

---

## test_enricher.py — 11 tests

**Module under test**: `agent/enricher.py`

**What it covers**: Agent ID generation and persistence, per-event enrichment (agent_id, model_name, pod_name, namespace, container_id), Kubernetes environment variable injection, and graceful handling of missing `/proc` entries.

### Test List

| Test | What it verifies |
|------|-----------------|
| `test_agent_id_is_valid_uuid` | `Enricher.agent_id` is a valid UUID4 string (parsed by `uuid.UUID()` without raising) |
| `test_enrich_sets_agent_id` | After `enricher.enrich(event)`, `event.agent_id == enricher.agent_id` |
| `test_enrich_returns_same_object` | `enrich()` returns the same object (in-place mutation), not a copy |
| `test_enrich_sets_model_name_for_python` | Event with `process="python"` gets `model_name="patient-diagnosis-v2"` |
| `test_enrich_sets_model_name_for_torchserve` | Event with `process="torchserve"` gets `model_name="fraud-detection-v1"` |
| `test_enrich_returns_unknown_for_unrecognised_process` | Event with `process="nginx"` gets `model_name="unknown"` |
| `test_pod_name_from_env` | `KUBERNETES_POD_NAME=guardian-pod-xyz` → `event.pod_name="guardian-pod-xyz"` |
| `test_namespace_from_env` | `KUBERNETES_NAMESPACE=production` → `event.namespace="production"` |
| `test_empty_pod_name_when_not_in_k8s` | When `KUBERNETES_POD_NAME` is absent, `event.pod_name=""` |
| `test_empty_namespace_when_not_in_k8s` | When `KUBERNETES_NAMESPACE` is absent, `event.namespace=""` |
| `test_container_id_empty_for_nonexistent_pid` | `enricher._container_id(9999999)` returns `""` without raising (handles missing `/proc` entry) |

### Key Patterns

**`monkeypatch` for environment variables**: The Kubernetes tests use pytest's `monkeypatch` fixture to set and delete environment variables cleanly:

```python
def test_pod_name_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBERNETES_POD_NAME", "guardian-pod-xyz")
    enricher = Enricher(_make_config())
    event = _make_event()
    enricher.enrich(event)
    assert event.pod_name == "guardian-pod-xyz"
```

`monkeypatch.setenv` and `monkeypatch.delenv(raising=False)` automatically restore the original environment after the test, ensuring isolation.

**Testing graceful degradation**: `test_container_id_empty_for_nonexistent_pid` uses PID `9999999`, which almost certainly does not exist. This verifies that `_container_id()` catches `OSError` and returns `""` rather than propagating the exception — a contract required by the no-root, no-/proc testing environment.

### Coverage Target

`>90%`. The agent ID file persistence path (`/var/lib/guardian/.agent_id`) requires root and a real filesystem, so it is covered at the integration level.

---

## test_generator.py — 16 tests

**Module under test**: `agent/generator.py`

**What it covers**: The fake event generator's output correctness, timestamp formatting, field invariants, syscall and process selection, and the internal `_now_iso_ns()` function.

This is the most architecturally significant test file. Its tests define the contract that Phase 2's `EbpfLoader` must satisfy.

### Test List

| Test | What it verifies |
|------|-----------------|
| `test_generates_events` | Collecting 5 events returns exactly 5 items |
| `test_all_events_are_rawevent_instances` | Every item in 20 events is a `RawEvent` instance |
| `test_timestamp_format` | Every timestamp matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$` |
| `test_pid_positive` | Every event's `pid > 0` |
| `test_uid_non_negative` | Every event's `uid >= 0` |
| `test_syscall_from_configured_list` | With `syscalls=["read","write","openat"]`, non-execve events only use those syscalls |
| `test_process_from_watch_list` | Every event's `process` is from the configured watch list |
| `test_read_write_events_have_bytes_gt_zero` | `read` and `write` events always have `bytes > 0` |
| `test_network_events_have_non_empty_network_addr` | `sendto`, `recvfrom`, `connect` events always have non-empty `network_addr` |
| `test_execve_events_have_fd_path_starting_with_slash` | `execve` events always have `fd_path` starting with `/` |
| `test_no_none_fields` | No field on any of 30 events is `None` |
| `test_return_val_is_str` | `return_val` is always of type `str` |
| `test_distinct_syscall_types_in_200_events` | At least 4 distinct syscall types appear in 200 events |
| `test_now_iso_ns_correct_format` | `_now_iso_ns()` returns a string matching the ISO 8601 nanosecond regex |
| `test_now_iso_ns_ends_in_z` | `_now_iso_ns()` always ends with `"Z"` |
| `test_now_iso_ns_no_deprecation_warnings` | `_now_iso_ns()` emits no `DeprecationWarning` (guards against use of deprecated `datetime` APIs) |

### Key Patterns

**Timestamp regex**: The timestamp format is asserted with a compiled regex constant:

```python
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$")
```

Nine decimal digits after the period enforce nanosecond precision (not microsecond). The trailing `Z` enforces UTC. Both constraints must hold for Phase 2 eBPF events.

**`_collect` helper avoiding sleep**: The generator's `stream()` method sleeps between events for realistic simulation. Tests bypass this by calling `gen._make_event()` directly:

```python
def _collect(n: int = 10, config: Config | None = None) -> list[RawEvent]:
    cfg = config or _make_config()
    gen = FakeEventGenerator(cfg)
    events: list[RawEvent] = []
    for _ in range(n):
        events.append(gen._make_event())
        gen._events_generated += 1
    return events
```

Incrementing `gen._events_generated` after each call ensures internal state (like `_next_execve_in` countdown) progresses correctly.

**Controlling execve injection**: Several tests pin `gen._next_execve_in = 10_000` to prevent execve events from appearing in short samples, and `gen._next_execve_in = 0` to force an execve on the next call.

**DeprecationWarning guard**: `test_now_iso_ns_no_deprecation_warnings` wraps the call in `warnings.catch_warnings()` with `simplefilter("error", DeprecationWarning)`. Any deprecated `datetime` API call becomes a test failure.

### Coverage Target

`>95%`.

---

## test_local_alerts.py — 14 tests

**Module under test**: `agent/local_alerts.py`

**What it covers**: The sandbox escape detection rule, the unexpected network connection rule, alert count tracking, the custom handler interface, and edge cases (empty rule list, empty allowlist, non-connection syscalls).

### Test List

| Test | What it verifies |
|------|-----------------|
| `test_sandbox_escape_fires_on_bin_bash` | `execve("/bin/bash")` triggers a `sandbox_escape` alert |
| `test_sandbox_escape_fires_on_bin_sh` | `execve("/bin/sh")` triggers a `sandbox_escape` alert |
| `test_sandbox_escape_fires_on_usr_bin_sh` | `execve("/usr/bin/sh")` triggers a `sandbox_escape` alert |
| `test_sandbox_escape_no_fire_on_python` | `execve("/usr/bin/python3")` does not trigger `sandbox_escape` |
| `test_sandbox_escape_no_fire_on_read_with_bash_path` | A `read` syscall with `fd_path="/bin/bash"` does not trigger `sandbox_escape` — path alone is insufficient, syscall must be `execve` |
| `test_sandbox_escape_alert_contains_correct_pid_and_process` | The `AlertEvent` returned contains the correct `pid` and `process` from the triggering event |
| `test_unexpected_network_fires_on_unlisted_connect` | `connect("99.99.99.99:443")` fires when allowlist is `["10.0.0.1:8080"]` |
| `test_no_fire_on_connect_to_allowed_addr` | `connect("10.0.0.1:8080")` does not fire when that address is in the allowlist |
| `test_no_fire_when_allowlist_is_empty` | An empty allowlist means no restriction — all addresses are allowed |
| `test_no_fire_on_recvfrom` | `recvfrom` is not a connection initiation; it never triggers `unexpected_network` |
| `test_empty_alert_list_no_alerts` | An engine configured with zero rules produces zero alerts for any event |
| `test_alert_count_increments` | `engine.alert_count` increments by 1 for each alert fired |
| `test_custom_handler_receives_alert_event` | Handler registered via `set_custom_handler()` is called with an `AlertEvent` instance |
| `test_normal_read_fires_no_alerts` | A normal `read` syscall produces no alerts |

### Key Patterns

**`set_custom_handler` suppression**: Every test creates an engine with a no-op custom handler to suppress terminal output:

```python
engine.set_custom_handler(lambda alert: None)
```

This is preferable to patching `sys.stderr` or the `logging` module globally, because it tests the actual suppression interface that production code uses rather than mocking infrastructure.

**`test_custom_handler_receives_alert_event`** inverts this pattern to verify the interface works:

```python
def test_custom_handler_receives_alert_event() -> None:
    received: list[AlertEvent] = []
    engine = _make_engine()
    engine.set_custom_handler(received.append)
    engine.evaluate(_execve("/bin/bash"))
    assert len(received) == 1
    assert isinstance(received[0], AlertEvent)
```

**Event factory helpers**: Three factory functions build minimal `RawEvent` instances for specific syscalls:

- `_execve(fd_path, process, pid)` — builds an `execve` event
- `_connect(network_addr, process, pid)` — builds a `connect` event
- `_read(fd_path)` — builds a `read` event
- `_recvfrom(network_addr)` — builds a `recvfrom` event

These helpers use `RawEvent`'s default field values for fields not relevant to the test, keeping assertions focused.

**`_SENTINEL` pattern**: The `_make_config` helper uses a sentinel object to distinguish "use default alerts" from "use an empty list":

```python
_SENTINEL = object()

def _make_config(alerts: Any = _SENTINEL, ...) -> Config:
    if alerts is _SENTINEL:
        local_alerts = [...]  # defaults
    else:
        local_alerts = list(alerts)
```

This avoids the common Python bug of using `None` as a default for a mutable parameter.

### Coverage Target

`>95%`. Every rule and edge case in the engine is explicitly tested.

---

## test_signer.py — 16 tests

**Module under test**: `agent/signer.py`

**What it covers**: The cryptographic hash chain (linking events to a genesis hash and to each other), the `verify_chain` function (valid chain, empty chain, tampered field, swapped order, deleted event), and the HMAC-SHA256 batch signature.

### Test List

**Chain tests** (6):

| Test | What it verifies |
|------|-----------------|
| `test_first_event_chains_from_genesis` | First signed event has `prev_hash == GENESIS_HASH` and a 64-character `this_hash` |
| `test_second_event_chains_from_first` | Second event's `prev_hash` equals first event's `this_hash` |
| `test_chain_of_ten_passes_verify` | Ten chained events pass `verify_chain()` |
| `test_this_hash_is_deterministic` | Two signers given identical events produce identical `this_hash` values |
| `test_hash_changes_when_field_mutated` | Mutating `pid` after signing changes `Signer._hash_event()` output |
| `test_events_signed_counter_increments` | `signer.events_signed` starts at 0 and increments by 1 per event signed |

**`verify_chain` tests** (5):

| Test | What it verifies |
|------|-----------------|
| `test_verify_chain_valid` | A correctly signed chain returns `(True, ...)` |
| `test_verify_chain_empty` | An empty list returns `(True, ...)` |
| `test_verify_chain_tampered_field` | Mutating `events[2].pid` without rehashing returns `(False, ...)` |
| `test_verify_chain_swapped_order` | Swapping two events in the list returns `(False, ...)` |
| `test_verify_chain_deleted_event` | Removing the middle event from a chain returns `(False, ...)` |

**`sign_batch` tests** (5):

| Test | What it verifies |
|------|-----------------|
| `test_sign_batch_returns_64_char_hex` | `sign_batch()` returns a 64-character string of valid hex digits |
| `test_sign_batch_is_deterministic` | Two calls with the same events and token return the same signature |
| `test_sign_batch_different_tokens_differ` | Different tokens produce different batch signatures for the same events |
| `test_sign_batch_empty_raises` | `sign_batch([])` raises `ValueError` |
| `test_sign_batch_empty_token_raises` | `Signer("")` raises `ValueError` at construction |

### Key Patterns

**`_fresh_signer` helper**: Every test that needs a `Signer` calls `_fresh_signer()`:

```python
def _fresh_signer() -> Signer:
    return Signer("test-token-secret")
```

This ensures no state bleeds between tests. `Signer` accumulates `_prev_hash` state across calls; sharing an instance between tests would make test order matter.

**`_make_event(**kwargs)` with defaults**: The event factory defines all required fields as defaults and allows per-test overrides:

```python
def _make_event(**kwargs) -> RawEvent:
    defaults = dict(
        timestamp="2026-04-09T12:00:00.000000000Z",
        pid=1234,
        process="python",
        ...
    )
    defaults.update(kwargs)
    return RawEvent(**defaults)
```

Tests that need distinct events pass `pid=i` to make each event unique. Tests that need to verify field sensitivity mutate after signing.

**Determinism tests**: `test_this_hash_is_deterministic` creates two independent signers and signs events with identical field values, then asserts identical hashes. This catches any source of non-determinism (timestamps, UUIDs, random seeds) in the hash function.

**Tamper detection tests**: `test_verify_chain_tampered_field`, `test_verify_chain_swapped_order`, and `test_verify_chain_deleted_event` each represent a distinct attack or corruption scenario that `verify_chain` must detect. All three must return `(False, ...)`.

### Coverage Target

`100%`. Cryptographic code has no acceptable uncovered paths.

---

## How to Run Tests

### Full suite, verbose

```bash
pytest tests/ -v
```

Expected output: 63 passed in ~0.05 seconds.

### Single file

```bash
pytest tests/test_signer.py -v
```

### Single test by name

```bash
pytest tests/test_signer.py::test_chain_of_ten_passes_verify -v
```

### With coverage report

```bash
pytest tests/ --cov=agent --cov-report=term-missing
```

The `--cov-report=term-missing` flag shows which specific lines in each module are not covered.

### Stopping on first failure

```bash
pytest tests/ -x
```

### Running only tests matching a keyword

```bash
pytest tests/ -k "signer or config"
```

---

## How to Add a New Test

### Choose the right file

Add tests to the file that tests the module being changed. One file per module.

### Use the existing helper pattern

Every test file has a `_make_config()` or `_make_event()` helper. Use it. Do not construct `Config` or `RawEvent` objects inline in tests — the helpers encapsulate required fields and default values.

### Follow the naming convention

Test names follow the pattern `test_<what>_<condition>_<expected>`. Examples:

- `test_sandbox_escape_fires_on_bin_bash`
- `test_verify_chain_tampered_field`
- `test_enrich_returns_unknown_for_unrecognised_process`

### Ensure isolation

- Create fresh objects in each test; do not share state across tests
- Use `tmp_path` for any file writes
- Use `monkeypatch` for environment variables
- Use `set_custom_handler(lambda alert: None)` to suppress output in alert tests

### Example: adding a test to test_config.py

```python
def test_compliance_articles_include_gdpr_17(tmp_path) -> None:
    path = _write_yaml(tmp_path, _FULL_YAML)
    cfg = load_config(path)
    # _FULL_YAML has articles: [12, 13]
    # Verify the parser preserves the list as integers
    assert isinstance(cfg.compliance.articles, list)
    assert all(isinstance(a, int) for a in cfg.compliance.articles)
```

---

## Related Documents

- [Test Strategy](test-strategy.md)
- [Integration Testing](integration-testing.md)
- [Running Tests](running-tests.md)
- [agent/signer.py](../../agent/signer.py)
- [agent/local_alerts.py](../../agent/local_alerts.py)
- [agent/generator.py](../../agent/generator.py)
