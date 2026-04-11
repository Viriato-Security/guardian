# Disk Buffer

Guardian includes a persistent disk buffer that stores event batches when the gRPC connection to the control plane is unavailable. When connectivity is restored, the buffer drains automatically in FIFO order before sending new batches.

The disk buffer is implemented in `agent/sender.py` in the `Sender` class.

---

## Buffer Location

The buffer directory is configured in `guardian.yaml`:

```yaml
agent:
  buffer_path: "~/.guardian/buffer"         # macOS / development
  # buffer_path: "/var/lib/guardian/buffer"  # Linux production
```

The buffer file is always:

```
<buffer_path>/pending.jsonl
```

### Default Locations

| Environment | Default Path |
|-------------|-------------|
| macOS / development | `~/.guardian/buffer/pending.jsonl` |
| Linux (configured) | `/var/lib/guardian/buffer/pending.jsonl` |
| Linux (fallback) | `~/.guardian/buffer/pending.jsonl` |

The `~` is expanded at runtime using `Path(buffer_path).expanduser()`.

### Fallback Path

If Guardian cannot create or write to the configured `buffer_path` due to a `PermissionError` (for example, `/var/lib/guardian/buffer` was not created with the correct permissions), it automatically falls back to `~/.guardian/buffer`:

```
WARNING  agent.sender  Cannot write to /var/lib/guardian (PermissionError) — using /home/user/.guardian/buffer instead
```

Once the fallback is used, `Sender._buffer_path` and `Sender._buffer_file` are updated in-place, so all subsequent batches go to the fallback directory without retrying the original path. This avoids logging the same warning on every batch interval.

If both the configured path and the fallback fail (e.g., the home directory is also unwritable), Guardian logs an ERROR and drops the batch:

```
ERROR    agent.sender  Cannot create buffer directory at /var/lib/guardian or /home/user/.guardian/buffer — dropping batch
```

---

## File Format

`pending.jsonl` is a newline-delimited JSON file. Each line is one complete batch:

```json
{"agent_id":"3f7c1b2a-4d5e-6f7a-8b9c-0d1e2f3a4b5c","signature":"a3f7c9d1e2b4f8a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3","events":[{"timestamp":"2026-04-10T12:00:00.000000000Z","pid":1234,"process":"python","syscall":"read","fd_path":"/tmp/model.pt","bytes":4096,"network_addr":"","return_val":"0","uid":1000,"agent_id":"3f7c1b2a-...","model_name":"patient-diagnosis-v2","container_id":"","pod_name":"","namespace":"","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","this_hash":"a3f7c9d1..."}]}
```

Formatted for readability:

```json
{
  "agent_id": "3f7c1b2a-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "signature": "a3f7c9d1e2b4f8a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3",
  "events": [
    {
      "timestamp": "2026-04-10T12:00:00.000000000Z",
      "pid": 1234,
      "process": "python",
      "syscall": "read",
      "fd_path": "/tmp/model.pt",
      "bytes": 4096,
      "network_addr": "",
      "return_val": "0",
      "uid": 1000,
      "agent_id": "3f7c1b2a-...",
      "model_name": "patient-diagnosis-v2",
      "container_id": "",
      "pod_name": "",
      "namespace": "",
      "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "this_hash": "a3f7c9d1..."
    }
  ]
}
```

### Field Descriptions

| Field | Description |
|-------|-------------|
| `agent_id` | UUID of the Guardian agent that generated this batch |
| `signature` | 64-character hex HMAC-SHA256 of the batch contents using the API token |
| `events` | Array of serialised `RawEvent` dataclass instances |

Each `RawEvent` in `events` contains all fields including `prev_hash` and `this_hash` (the cryptographic chain links were set at signing time before buffering).

---

## What Triggers Buffering

A batch is written to `pending.jsonl` when any of the following occur:

### 1. gRPC RpcError

Any `grpc.RpcError` raised by `stub.StreamEvents()` causes the batch to be buffered:

```python
except Exception as exc:  # grpc.RpcError and others
    logger.error("gRPC send failed (%s): buffering %d events", exc, len(events))
    self._buffer_batch(events, signature)
```

Common causes: connection refused, TLS handshake failure, deadline exceeded, server unavailable.

### 2. Proto Stubs Not Generated

If `grpcio` or the generated proto stubs (`proto/guardian_pb2.py`) are not importable, `Sender._grpc_available` is set to `False` at construction time:

```python
WARNING  agent.sender  gRPC stubs not generated. Buffer to disk. Run: bash scripts/gen_proto.sh
```

All batches are buffered until the agent is restarted with working stubs.

### 3. Any Unexpected Exception

The `except Exception` clause in `send_batch()` catches all unexpected errors (not just `RpcError`) and buffers the batch. This ensures that unexpected failures during serialisation or channel state do not cause event loss.

---

## 10,000 Line Cap

The buffer is capped at 10,000 lines (10,000 batches). When the cap is reached, new batches are dropped with a WARNING:

```
WARNING  agent.sender  Disk buffer full (10000 lines) — dropping batch
```

The cap is defined in `agent/sender.py`:

```python
_MAX_BUFFER_LINES = 10_000
```

### Why 10,000?

At the default batch size and interval (10 events / 100ms), the buffer holds approximately:

- 10,000 batches × 10 events = 100,000 events
- At 10 batches/second, that is 1,000 seconds (about 17 minutes) of events

For typical deployments, a 17-minute outage is enough to buffer through transient connectivity issues, cloud provider blips, and planned maintenance windows. A longer outage should trigger an alert (see [Deployment — Health Monitoring](deployment.md#health-monitoring)).

### Behaviour When Cap is Reached

1. A WARNING is logged for every dropped batch
2. The `pending.jsonl` file is not modified (it stays at 10,000 lines)
3. `Sender.total_buffered` continues incrementing (tracks events that should have been buffered, not just those that were)
4. New events are lost until the buffer drains

---

## FIFO Drain on Successful Send

When a gRPC send succeeds, `Sender._drain_buffer()` is called immediately. It:

1. Reads all lines from `pending.jsonl`
2. Replays them in order (oldest first — true FIFO)
3. Stops replaying at the first failure (preserves ordering guarantee)
4. Rewrites `pending.jsonl` with only the lines that could not be sent

```python
def _drain_buffer(self) -> None:
    ...
    for line in lines:
        try:
            # deserialise and resend
            self._stub.StreamEvents(iter([batch_proto]))
            self._total_sent += len(events)
        except Exception as exc:
            logger.warning("Drain failed (%s) — stopping", exc)
            remaining.append(line)
            break

    # Rewrite buffer with only the un-drained lines
    with open(self._buffer_file, "w") as fh:
        for line in remaining:
            fh.write(line + "\n")
```

This means:
- If draining fails mid-way, the successfully drained lines are removed and the rest are preserved
- The drain stops at the first failure (does not skip failed batches and continue, which would violate ordering)
- The new live batch is only sent after the drain attempt, ensuring the platform receives events in chronological order

---

## Inspecting the Buffer Manually

```bash
# Count buffered batches
wc -l ~/.guardian/buffer/pending.jsonl

# View first batch (pretty-printed)
head -1 ~/.guardian/buffer/pending.jsonl | python3 -m json.tool

# Count total buffered events
python3 -c "
import json
total = 0
with open('${HOME}/.guardian/buffer/pending.jsonl') as f:
    for line in f:
        total += len(json.loads(line)['events'])
print(f'{total} buffered events in {total // 10} estimated batches')
"

# View all signatures (for verification)
python3 -c "
import json
with open('${HOME}/.guardian/buffer/pending.jsonl') as f:
    for i, line in enumerate(f):
        batch = json.loads(line)
        print(f'Batch {i}: {len(batch[\"events\"])} events, sig={batch[\"signature\"][:16]}...')
"
```

For the production path:

```bash
sudo cat /var/lib/guardian/buffer/pending.jsonl | head -1 | python3 -m json.tool
```

---

## Safely Clearing the Buffer

Do not clear the buffer unless you have confirmed that the Viriato Security platform has received and acknowledged the events, or you are intentionally discarding the buffered data.

### Confirm Platform Receipt

Log into the Viriato Security console and verify:
1. The event count for your agent matches your expectation
2. The timestamp of the last received event is after the start of the outage that caused buffering

### Clear the Buffer

```bash
# Development / macOS
> ~/.guardian/buffer/pending.jsonl
# or completely remove:
rm ~/.guardian/buffer/pending.jsonl

# Linux production
sudo sh -c '> /var/lib/guardian/buffer/pending.jsonl'
```

Truncating the file (using `>`) rather than removing it is preferred. The `Sender` detects an empty file and skips the drain, which is more efficient than recreating the file.

---

## Disk Full Behaviour

If the disk is full when Guardian tries to append to `pending.jsonl`, the `open()` or `write()` call raises an `OSError` with `errno.ENOSPC`. This propagates through `_buffer_batch()` and is caught by the outer exception handler in `send_batch()`.

The batch is dropped with an ERROR log:

```
ERROR    agent.sender  gRPC send failed (gRPC error): buffering N events
ERROR    agent.sender  Cannot create buffer directory or write batch — dropping
```

Guardian does not retry. The batch is lost. Monitor disk usage on the buffer path and alert before it fills completely.

---

## Recovery Scenarios

### Scenario 1: Brief Outage (< 17 minutes)

**What happened:** Control plane unreachable for 10 minutes.

**What Guardian did:** Buffered all batches to `pending.jsonl`.

**Recovery:** When connectivity restored, first successful `send_batch()` triggered `_drain_buffer()`, which replayed all 10 minutes of batches in order. The buffer file is now empty. No manual action required.

**Signal:** Watch `total_buffered` decrease back to 0 in the logs.

### Scenario 2: Extended Outage (> 17 minutes)

**What happened:** Control plane unreachable for 30 minutes.

**What Guardian did:** Buffered 10,000 batches (approximately 17 minutes of events), then dropped all subsequent batches with WARNING messages.

**Recovery:**
1. Connectivity is restored
2. Guardian drains the 10,000 buffered batches
3. Events from the gap after the buffer was full are not recoverable

**Signal:** Multiple `Disk buffer full (10000 lines) — dropping batch` WARNING log lines.

**Mitigation:** Increase `buffer_path` disk allocation, or reduce `batch_interval_ms` to send smaller, more frequent batches that take longer to fill the cap.

### Scenario 3: Agent Restart During Buffering

**What happened:** Agent restarted (crash, update, systemd restart) while buffer contained un-drained batches.

**What Guardian does on restart:**
1. Reads the new config
2. Opens the same `pending.jsonl` file (the buffer persists across restarts)
3. On the first successful send, drains the buffer in FIFO order

The `prev_hash` / `this_hash` chain will break at the restart boundary (the new agent starts from `GENESIS_HASH`). The platform records this as an expected agent restart event.

### Scenario 4: Platform Restart

**What happened:** The Viriato Security control plane restarted and is now at a different chain state.

**What Guardian does:** Continues sending batches. The platform handles chain reconciliation on its end. The agent does not need to be restarted.

### Scenario 5: Buffer File Corruption

**Symptom:**

```
WARNING  agent.sender  Drain failed (json.JSONDecodeError: Expecting value: line 1...) — stopping
```

**Cause:** A line in `pending.jsonl` is malformed (e.g., partial write due to a crash mid-write).

**Recovery:**

Manually inspect and repair the file:

```bash
# Find the malformed line
python3 -c "
import json
with open('~/.guardian/buffer/pending.jsonl') as f:
    for i, line in enumerate(f, 1):
        try:
            json.loads(line)
        except json.JSONDecodeError as e:
            print(f'Line {i}: {e}')
"

# Remove the malformed line (example: line 5)
sed -i '5d' ~/.guardian/buffer/pending.jsonl

# Or clear everything and start fresh
> ~/.guardian/buffer/pending.jsonl
```

---

## Related Documents

- [Configuration — buffer_path](configuration.md#agent-section)
- [Troubleshooting — Reading the Buffer](troubleshooting.md#reading-the-disk-buffer)
- [Troubleshooting — Permission Denied](troubleshooting.md#permission-denied-varlibguardian)
- [Deployment — Health Monitoring](deployment.md#health-monitoring)
- [agent/sender.py](../../agent/sender.py)
