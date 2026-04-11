# Error Codes and Log Messages

This document lists every error, warning, and notable log message that Guardian
produces, with its exact text, what it means, the likely cause, and how to fix it.

---

## Python Exceptions

These exceptions are raised (not logged) and will propagate unless caught by the
calling code.

---

### FileNotFoundError — load_config

**Raised by**: `agent/config.py:load_config()`

**Exact message**:

```
guardian.yaml not found. Tried: [<path_list>].
Copy guardian.yaml.example to guardian.yaml and fill in your token.
```

Or, when a specific path is given and does not exist:

```
Config file not found: <path>
```

**What it means**: `load_config()` searched all standard locations for `guardian.yaml`
and found none. Standard search order:
1. The explicit `path` argument (if provided)
2. `./guardian.yaml`
3. `/etc/guardian/guardian.yaml`
4. `~/.guardian/guardian.yaml`

**Likely cause**:
- Running the agent in a directory without a `guardian.yaml`.
- Forgot to run `cp guardian.yaml.example guardian.yaml`.
- Specified `--config /wrong/path.yaml` and the file does not exist at that path.

**How to fix**:

```bash
cp guardian.yaml.example guardian.yaml
# Edit guardian.yaml and fill in your token
```

---

### ValueError — Signer.__init__ empty token

**Raised by**: `agent/signer.py:Signer.__init__()`

**Exact message**:

```
Signer token must not be empty.
```

**What it means**: `Signer` was instantiated with an empty string as the token.

**Likely cause**:
- `agent.token` in `guardian.yaml` is an empty string (`token: ""`).
- `guardian.yaml` was loaded but the `agent` section or `token` key is missing.

**How to fix**:

Set a non-empty token in `guardian.yaml`:

```yaml
agent:
  token: "YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE"
```

For local development without a real token, use `--dry-run`. The Signer still
requires a non-empty token even in dry-run mode (use any non-empty placeholder string).

---

### ValueError — sign_batch empty batch

**Raised by**: `agent/signer.py:Signer.sign_batch()`

**Exact message**:

```
sign_batch requires at least one event.
```

**What it means**: `sign_batch()` was called with an empty list of events.

**Likely cause**: This should not occur in normal operation because `_flush()` in
`main.py` checks `if not self._batch: return` before calling `sign_batch()`. If
this exception appears, it indicates a logic error in a custom caller.

**How to fix**: Ensure `sign_batch()` is only called with a non-empty list. If you
are writing a custom sender or test, guard the call:

```python
if events:
    signature = signer.sign_batch(events)
```

---

### NotImplementedError — EbpfLoader Phase 2

**Raised by**: `agent/loader.py:EbpfLoader.load()` or `EbpfLoader.stream()`

**Exact message**:

```
EbpfLoader is not implemented in Phase 1. Use FakeEventGenerator.
```

(Exact text may vary — see `agent/loader.py` for the current message.)

**What it means**: The eBPF loader is a Phase 2 feature. In Phase 1, calling
`EbpfLoader.load()` or `EbpfLoader.stream()` raises `NotImplementedError`.

**Likely cause**: Running on Linux without the `--fake` flag and without eBPF
support (e.g. kernel < 5.8, no BTF). The `EventReader` should fall back to the
fake generator automatically and log a warning instead of letting this propagate.

**How to fix**: Add `--fake` to force the fake generator:

```bash
python -m agent.main --fake --dry-run
```

Or set the environment variable:

```bash
GUARDIAN_FAKE_EVENTS=1 python -m agent.main
```

---

## Log WARNING Messages

Log warnings indicate a degraded or unexpected state that does not stop the agent
but may require operator attention.

---

### Guardian token is not set or is still the placeholder

**Logger**: `agent.config`

**Exact message**:

```
Guardian token is not set or is still the placeholder.
Events will be buffered locally but NOT sent to viriato-platform.
Obtain a real token at https://viriatosecurity.com
```

**What it means**: The token in `guardian.yaml` is empty or equals the literal
string `YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE`.

**Likely cause**: Fresh install; `guardian.yaml` was copied from the example but not
edited; running in a CI environment where the token is not configured.

**How to fix**: Replace the placeholder in `guardian.yaml` with a real token from
the Viriato Security console. For local development without sending to the platform,
use `--dry-run` (the warning still appears but events are not buffered to disk).

---

### eBPF not available on this platform

**Logger**: `agent.reader`

**Exact message**:

```
eBPF not available on this platform (Phase 2 requires Linux 5.8+ with BTF).
Falling back to fake event generator.
Pass --fake to suppress this warning.
```

**What it means**: `EbpfLoader.is_available()` returned `False`, so the agent
automatically fell back to the fake event generator.

**Likely cause**:
- Running on macOS (eBPF is Linux-only).
- Running in CI (no kernel access).
- Running on Linux kernel < 5.8 or without BTF (`CONFIG_DEBUG_INFO_BTF=y`).

**How to fix**: For development on macOS or CI, add `--fake` to suppress the warning:

```bash
python -m agent.main --fake --dry-run
```

For production Linux, ensure the kernel is 5.8+ with BTF. For macOS development with
real eBPF, use an OrbStack Linux VM.

---

### Could not persist agent_id — using ephemeral UUID

**Logger**: `agent.enricher`

**Exact message**:

```
Could not persist agent_id — using ephemeral UUID
```

**What it means**: The `Enricher` could not write the generated `agent_id` to either
`/var/lib/guardian/.agent_id` (production path) or `~/.guardian_agent_id`
(development path). An in-memory UUID is used for this session only.

**Likely cause**:
- Running with insufficient permissions to write to `/var/lib/guardian/` and the
  home directory is also not writable (e.g. restricted container environment).
- `/var/lib/guardian/` does not exist and cannot be created.

**Consequence**: Each restart will produce a new `agent_id`. The platform will see
this as a new installation on every restart. Events from different sessions cannot
be correlated by `agent_id`.

**How to fix**: Ensure the agent can write to at least one of:
- `/var/lib/guardian/` (create with `sudo mkdir -p /var/lib/guardian && sudo chown $(whoami) /var/lib/guardian`)
- `~/.guardian_agent_id` (ensure home directory is writable)

---

## Log ERROR Messages

Log errors indicate a significant failure that may cause event loss or service disruption.

---

### gRPC send failed — buffering N events

**Logger**: `agent.sender`

**Exact message**:

```
gRPC send failed (<exception>): buffering <N> events
```

Example:

```
gRPC send failed (StatusCode.UNAVAILABLE: Connection refused): buffering 47 events
```

**What it means**: The gRPC call to `viriato-platform` raised an exception. The
batch was written to the disk buffer (`pending.jsonl`) instead. The `<N>` events are
not lost — they will be replayed on the next successful connection.

**Likely cause**:
- viriato-platform is unreachable (network issue, platform maintenance).
- TLS certificate error.
- `control_plane` in `guardian.yaml` is wrong (typo in hostname or port).
- The gRPC channel timed out.

**How to fix**:
1. Check network connectivity to `grpc.viriatosecurity.com:443`.
2. Verify the `control_plane` setting in `guardian.yaml`.
3. Check for platform status at the Viriato Security status page.
4. Inspect the disk buffer to confirm events are being saved:
   ```bash
   wc -l ~/.guardian/buffer/pending.jsonl
   ```

---

### Disk buffer full (N lines) — dropping batch

**Logger**: `agent.sender`

**Exact message**:

```
Disk buffer full (10000 lines) — dropping batch
```

**What it means**: The `pending.jsonl` buffer has reached 10,000 lines (the maximum
cap). The current batch is being dropped — events in this batch are permanently lost.

**Likely cause**:
- The platform has been unreachable for an extended period (hours or more).
- The `buffer_path` is on a filesystem with insufficient disk space.
- The agent is generating events faster than it can replay them on reconnect.

**How to fix**:
1. Restore connectivity to the platform. Once connected, Guardian replays buffered
   batches and frees buffer space.
2. If the platform will be unreachable for a long time, manually archive and clear
   the buffer:
   ```bash
   cp ~/.guardian/buffer/pending.jsonl /tmp/pending_backup.jsonl
   truncate -s 0 ~/.guardian/buffer/pending.jsonl
   ```
3. Monitor disk buffer size and alert when it approaches 10,000 lines.

---

### ALERT sandbox_escape

**Logger**: `agent.local_alerts`

**Exact message**:

```
ALERT sandbox_escape: execve to /bin/bash
```

(The path varies: `/bin/sh`, `/usr/bin/bash`, `/usr/bin/sh`.)

**What it means**: A monitored process called `execve` with a shell binary as the
target. This is the `sandbox_escape` alert from `LocalAlertEngine`. The full
`AlertEvent` JSON is printed to stderr.

**Likely cause (normal)**: The `FakeEventGenerator` injects `execve` events every
500–1000 events for testing purposes. In Phase 1, most `sandbox_escape` alerts
are from the fake generator.

**Likely cause (production)**: A real process spawned a shell. This may indicate:
- A security incident (container escape attempt, code injection).
- A legitimate maintenance script (should be excluded from monitoring via process list).

**How to respond**: Investigate the `pid`, `process`, and `timestamp` in the alert
JSON. Correlate with platform dashboards.

---

### ALERT unexpected_network

**Logger**: `agent.local_alerts`

**Exact message**:

```
ALERT unexpected_network: connection to 203.0.113.42:443 not in allowlist
```

**What it means**: A monitored process made a `connect` or `sendto` syscall to an
address not in `network_allowlist`. Only fires when `network_allowlist` is non-empty.

**Likely cause**:
- A legitimate new dependency (model registry, feature store endpoint) not yet added
  to the allowlist.
- Unexpected outbound connection from the model (possible data exfiltration).

**How to respond**: Identify the destination. If it is expected, add it to
`network_allowlist` in `guardian.yaml`. If unexpected, investigate.

---

### Pipeline error

**Logger**: `agent.main`

**Exact message**:

```
Pipeline error: <exception_message>
```

Example:

```
Pipeline error: [Errno 28] No space left on device
```

**What it means**: An unhandled exception escaped the main pipeline loop in
`GuardianAgent.run()`. The `exc_info=True` flag means the full traceback is also
logged at ERROR level. The agent will attempt to flush remaining events and shut down.

**Likely cause**:
- Disk full (buffer write failed with `ENOSPC`).
- Unexpected `RawEvent` field type causing a serialisation error.
- An unhandled edge case in the enricher, signer, or sender.

**How to fix**: Check the full traceback in the logs. Common fixes:
- Disk full: clear space or move `buffer_path` to a larger volume.
- Serialisation error: check for unexpected `None` values in `RawEvent` fields.
- Open a GitHub issue with the full traceback if the root cause is unclear.

---

## Log INFO Messages

These messages appear at the default log level and indicate normal operation.

| Message | When | Meaning |
|---------|------|---------|
| `Guardian agent starting. source=<source> dry_run=<bool>` | Startup | Agent has initialised and is beginning the event loop |
| `Event source: fake generator (forced)` | Startup with `--fake` | Using the Phase 1 fake generator |
| `Event source: eBPF probe` | Startup on Linux with eBPF | Using the Phase 2 eBPF loader |
| `Created agent_id <uuid> at <path>` | First run | New agent_id generated and persisted |
| `DRY RUN: batch ready — <N> events, sig=<prefix>…` | `--dry-run` mode | Batch signed but not sent |
| `Buffered <N> events to <path>` | Platform unreachable | Events written to disk buffer |
| `Drained buffered batch (<N> events)` | Reconnect | Buffered events replayed successfully |
| `Guardian stopped. events=<N> batches=<N> alerts=<N> grpc_sent=<N> buffered=<N>` | Shutdown | Final statistics summary |
| `Received signal <N> — shutting down gracefully…` | SIGTERM / SIGINT | Graceful shutdown initiated |

---

## Related Documents

- [glossary.md](glossary.md)
- [faq.md](faq.md)
- [api-reference.md](api-reference.md)
- [../10-development/local-setup.md](../10-development/local-setup.md)
