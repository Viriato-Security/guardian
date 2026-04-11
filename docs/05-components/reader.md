# Event Reader (`agent/reader.py`)

## Overview

`agent/reader.py` provides a unified interface for the event source layer. It abstracts over two implementations:

1. **`FakeEventGenerator`** — the Phase 1 synthetic event stream (always available).
2. **`EbpfLoader`** — the Phase 2 kernel eBPF probe (Linux 5.8+, requires BCC and BTF).

The rest of the pipeline (`Enricher`, `Signer`, `LocalAlertEngine`, `Sender`) consumes `RawEvent` objects from `EventReader.stream()` without knowing or caring which source produced them. This is the abstraction boundary that makes Phase 2 eBPF integration a drop-in replacement rather than a pipeline rewrite.

---

## `EventReader` Class

```python
class EventReader:
    def __init__(self, config: Config, force_fake: bool = False) -> None:
        self._config = config
        self._force_fake = force_fake
        self._source: str = ""
```

### Constructor Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `config` | `Config` | _(required)_ | Loaded guardian configuration. Passed through to `FakeEventGenerator` or `EbpfLoader`. |
| `force_fake` | `bool` | `False` | If `True`, always use the fake generator. Mirrors the `--fake` CLI flag. |

### `source` Property

```python
@property
def source(self) -> str:
    return self._source
```

Returns `"generator"` or `"ebpf"`. This property is set when `stream()` is called and source selection occurs. It is an empty string `""` before `stream()` is called.

Use `source` to log or display which event source the agent is using at startup:

```python
reader = EventReader(config, force_fake=args.fake)
# source is "" here

for event in reader.stream():
    if reader.source:  # set after first yield
        logger.info("Event source: %s", reader.source)
        break
```

---

## Source Selection Algorithm

`stream()` selects the event source exactly once, at the time it is called. The decision tree is:

```
Is force_fake == True?
    OR is GUARDIAN_FAKE_EVENTS env var == "1"?
         │
         YES → source = "generator"
               log.info("Event source: fake generator (forced)")
               yield from FakeEventGenerator(config).stream()
               return
         │
         NO
         │
         └─ Is EbpfLoader.is_available() == True?
                 │
                 YES → source = "ebpf"
                       log.info("Event source: eBPF probe")
                       loader = EbpfLoader()
                       loader.load()
                       yield from loader.stream()
                       return
                 │
                 NO
                 │
                 └─ (fallback)
                    source = "generator"
                    log.warning("eBPF not available on this platform...")
                    yield from FakeEventGenerator(config).stream()
```

**Priority 1 — Explicit fake flag.** If `force_fake=True` or `GUARDIAN_FAKE_EVENTS=1`, the generator is always used. No eBPF availability check is performed. This path logs at `INFO` level.

**Priority 2 — eBPF available.** If eBPF requirements are met (see `EbpfLoader.is_available()` below), the eBPF loader is used. Note: in Phase 1 the loader raises `NotImplementedError` even if `is_available()` returns `True`. This path logs at `INFO` level.

**Priority 3 — Fallback generator.** If neither of the above is true, the fake generator is used with a `WARNING` log. The warning explains that Phase 2 requires Linux 5.8+ with BTF and instructs the operator to pass `--fake` to suppress it.

---

## `stream()` Method

```python
def stream(self) -> Iterator[RawEvent]:
```

Yields `RawEvent` instances indefinitely from the selected source. The selection is made once at the top of `stream()` before the first yield.

**Usage:**

```python
reader = EventReader(config, force_fake=True)
for event in reader.stream():
    enricher.enrich(event)
    signer.sign_event(event)
    batch.append(event)
    ...
```

The generator never returns (it is an infinite iterator). The calling code is responsible for breaking the loop (e.g. on `KeyboardInterrupt` or `SIGTERM`).

---

## `--fake` Flag and `GUARDIAN_FAKE_EVENTS` Env Var

Two mechanisms trigger the fake generator explicitly:

### `--fake` CLI Flag

Processed in `agent/main.py`. When present:

```python
args = parser.parse_args()
reader = EventReader(config, force_fake=args.fake)
```

The `force_fake=True` argument is passed to `EventReader`.

### `GUARDIAN_FAKE_EVENTS=1` Environment Variable

Checked inside `stream()`:

```python
use_fake = self._force_fake or os.environ.get("GUARDIAN_FAKE_EVENTS", "0") == "1"
```

This allows fake mode to be activated in Docker Compose or Kubernetes environments without modifying the command line:

```yaml
env:
  - name: GUARDIAN_FAKE_EVENTS
    value: "1"
```

Any value other than exactly `"1"` is treated as `False`. Both mechanisms are checked with `OR`, so either is sufficient.

---

## Why This Abstraction Exists

Without `EventReader`, `agent/main.py` would contain explicit `if` logic to choose between the generator and the loader:

```python
# Bad pattern — don't do this:
if args.fake or not EbpfLoader.is_available():
    source = FakeEventGenerator(config)
else:
    source = EbpfLoader()
    source.load()
```

This has several problems:
- The source-selection logic would be duplicated in tests and potentially in any future CLI commands.
- Adding a third source (e.g. a mock source for integration testing, or a file replay source) would require editing `main.py`.
- The `source` name would not be captured in a standard way for metrics and logging.

`EventReader` centralises the decision, makes it testable in isolation, and gives other modules a stable interface: `reader.stream()` always returns `Iterator[RawEvent]` regardless of what is behind it.

---

## Source Selection in the Context of Availability Testing

`EbpfLoader.is_available()` performs three checks (see `docs/05-components/loader.md`):

| Check | Fails on |
|---|---|
| `sys.platform != "darwin"` | macOS always routes to generator |
| `/sys/kernel/btf/vmlinux` exists | Old kernels, non-BTF Linux |
| `import bcc` succeeds | Systems without BCC Python bindings |

In a typical Phase 1 deployment environment:

| Environment | `is_available()` result | `source` |
|---|---|---|
| macOS (development) | `False` | `"generator"` |
| Ubuntu 22.04 without BCC | `False` | `"generator"` |
| CI (GitHub Actions, Linux) | `False` (no BTF/BCC) | `"generator"` |
| Linux 5.8+, BCC installed | `True` | `"ebpf"` (Phase 2) |

---

## Integration with the Pipeline

In `agent/main.py`, `EventReader` is the first component in the pipeline:

```python
reader = EventReader(config, force_fake=args.fake)
enricher = Enricher(config)
signer = Signer(config.agent.token)
alert_engine = LocalAlertEngine(...)
sender = Sender(...)

batch: list[RawEvent] = []

for event in reader.stream():
    enricher.enrich(event)
    signer.sign_event(event)
    alerts = alert_engine.evaluate(event)
    batch.append(event)

    if len(batch) >= BATCH_SIZE or time_to_flush:
        sig = signer.sign_batch(batch)
        sender.send_batch(batch, sig)
        batch = []
```

---

## Related Documents

- `docs/05-components/event-generator.md` — `FakeEventGenerator` details, `RawEvent` schema
- `docs/05-components/loader.md` — `EbpfLoader.is_available()` logic and Phase 2 plan
- `docs/05-components/enricher.md` — consumes events from `EventReader.stream()`
- `docs/02-architecture/` — overall pipeline data flow
