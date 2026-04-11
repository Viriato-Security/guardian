# Sender (`agent/sender.py`)

## Overview

`agent/sender.py` is responsible for transmitting signed event batches to the Viriato Security control plane. It implements a two-tier delivery strategy:

1. **Primary: gRPC streaming** to `grpc.viriatosecurity.com:443` (or any configured `control_plane` address) over TLS.
2. **Fallback: disk buffer** — on any gRPC failure, the batch is written to `pending.jsonl` in the configured buffer directory.

On a successful gRPC send, the Sender drains any previously buffered batches in FIFO order before returning. This ensures that the control plane always receives events in the correct chronological order even after network outages.

---

## `Sender` Class

```python
class Sender:
    def __init__(
        self,
        agent_id: str,
        control_plane: str,
        token: str,
        buffer_path: str = "~/.guardian/buffer",
    ) -> None:
```

### Constructor Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `agent_id` | `str` | _(required)_ | UUID of this Guardian installation (from `Enricher.agent_id`). Included in every `EventBatch` proto. |
| `control_plane` | `str` | _(required)_ | `host:port` of the gRPC endpoint (e.g. `"grpc.viriatosecurity.com:443"` or `"localhost:50051"`). |
| `token` | `str` | _(required)_ | Customer API token, sent as gRPC metadata and used to authenticate the connection. |
| `buffer_path` | `str` | `"~/.guardian/buffer"` | Directory path for the disk buffer fallback. Tilde-expanded on construction. The buffer file is `{buffer_path}/pending.jsonl`. |

### Internal State After Construction

| Attribute | Type | Description |
|---|---|---|
| `_channel` | gRPC channel or `None` | The open gRPC channel (TLS or insecure). `None` if gRPC is unavailable. |
| `_stub` | `GuardianIngestStub` or `None` | The gRPC stub for the `GuardianIngest` service. |
| `_grpc_available` | `bool` | `True` if gRPC stubs were imported and the channel opened successfully. |
| `_total_sent` | `int` | Running count of events successfully sent to the control plane. |
| `_total_buffered` | `int` | Running count of events written to the disk buffer. |

---

## gRPC Channel Initialisation: `_init_grpc()`

Called automatically in `__init__()`. Attempts to import the generated proto stubs and open the gRPC channel.

```python
def _init_grpc(self) -> None:
    try:
        import grpc
        from proto import guardian_pb2_grpc

        insecure = (
            self._control_plane.startswith("localhost")
            or self._control_plane.startswith("127.")
            or os.environ.get("GUARDIAN_INSECURE_GRPC", "0") == "1"
        )
        if insecure:
            self._channel = grpc.insecure_channel(self._control_plane)
        else:
            self._channel = grpc.secure_channel(
                self._control_plane, grpc.ssl_channel_credentials()
            )
        self._stub = guardian_pb2_grpc.GuardianIngestStub(self._channel)
        self._grpc_available = True
    except (ImportError, Exception) as exc:
        logger.warning("gRPC not available (%s) — disk buffer only", exc)
        self._grpc_available = False
```

### TLS vs Insecure Channel Selection

A channel is opened **without TLS** (insecure) when any of these conditions are true:

| Condition | Example |
|---|---|
| `control_plane` starts with `"localhost"` | `"localhost:50051"` |
| `control_plane` starts with `"127."` | `"127.0.0.1:50051"` |
| `GUARDIAN_INSECURE_GRPC=1` environment variable | Used in Docker Compose test environments |

Otherwise, TLS is used with `grpc.ssl_channel_credentials()` (system CA trust store). The production address `grpc.viriatosecurity.com:443` always uses TLS.

If `grpc` or the generated proto stubs (`proto/guardian_pb2_grpc.py`) cannot be imported, `_grpc_available` is set to `False` and the Sender operates in buffer-only mode. Run `bash scripts/gen_proto.sh` to generate the stubs.

---

## `send_batch(events, signature) -> bool`

```python
def send_batch(self, events: list[RawEvent], signature: str) -> bool:
```

The primary public method. Attempts to send a signed batch to the control plane.

**On success:**
1. Calls `self._stub.StreamEvents(iter([batch_proto]))`.
2. Increments `self._total_sent` by `len(events)`.
3. Calls `self._drain_buffer()` to replay any previously buffered batches.
4. Returns `True`.

**On failure (gRPC `RpcError` or any exception):**
1. Logs the error.
2. Calls `self._buffer_batch(events, signature)` to persist the batch to disk.
3. Increments `self._total_buffered` by `len(events)`.
4. Returns `False`.

**If gRPC is unavailable (`_grpc_available == False`):**
- Logs a warning recommending `bash scripts/gen_proto.sh`.
- Calls `self._buffer_batch()` directly.
- Returns `False`.

---

## `_buffer_batch()`: Disk Buffer with 10,000 Line Cap

```python
def _buffer_batch(self, events: list[RawEvent], signature: str) -> None:
```

Appends a batch to `pending.jsonl` as a single JSON line.

### Buffer Format

Each line in `pending.jsonl` is a JSON object:

```json
{
  "agent_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "signature": "3d5e2a1f9c8b7a6e...",
  "events": [
    {"timestamp": "...", "pid": 1234, "process": "python", ...},
    ...
  ]
}
```

This is a JSONL (JSON Lines) file — one complete JSON object per line, newline-separated.

### 10,000 Line Cap

Before appending, the function counts the existing lines in `pending.jsonl`. If the count is already at or above `10000`, the batch is **dropped** (not written) and a warning is logged:

```
WARNING:agent.sender:Disk buffer full (10000 lines) — dropping batch
```

This prevents unbounded disk growth during extended network outages. The 10,000 line limit is enforced per-file (not per-event), so the actual number of events buffered depends on batch sizes.

### Fallback Path on `PermissionError`

The Sender tries to write to the configured `buffer_path` first. If that directory cannot be created (typically because the configured path is `/var/lib/guardian/buffer` and the agent is running as an unprivileged user), it falls back to `~/.guardian/buffer`:

```python
fallback = Path.home() / ".guardian" / "buffer"
for candidate in (self._buffer_path, fallback):
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        ...
        return True
    except PermissionError:
        continue
```

After falling back, `self._buffer_path` and `self._buffer_file` are updated in-place so that all subsequent batches go directly to the fallback path without retrying the original.

---

## `_drain_buffer()`: FIFO Replay

```python
def _drain_buffer(self) -> None:
```

Called automatically after every successful `send_batch()`. Reads all lines from `pending.jsonl` and replays them to the control plane in order (oldest first = FIFO).

**Algorithm:**

1. Read all lines from `pending.jsonl` into memory.
2. For each line:
   - Parse the JSON.
   - Reconstruct `RawEvent` objects from the `"events"` list.
   - Build the `EventBatch` proto.
   - Call `self._stub.StreamEvents()`.
   - On success: increment `total_sent`, continue to next line.
   - On failure: append the line to `remaining`, **stop** (do not attempt further lines).
3. Rewrite `pending.jsonl` with only the `remaining` lines (those that were not successfully drained).

**Stop on first failure:** This preserves ordering. If a drain fails at batch _k_, batches _k+1, k+2, ..._ are kept in the buffer in their original order. The next successful `send_batch()` will retry from batch _k_.

**FIFO semantics:** Because `_drain_buffer()` reads lines in file order and stops on failure, the control plane always receives events in the order they were generated. Partial drain does not reorder events.

---

## `close()`

```python
def close(self) -> None:
```

Closes the gRPC channel. Should be called when the agent is shutting down cleanly (e.g. on `SIGTERM`). Swallows any exception from `channel.close()` to avoid masking shutdown errors.

---

## Properties

### `total_sent`

```python
@property
def total_sent(self) -> int:
    return self._total_sent
```

Total number of events successfully sent to the control plane since this `Sender` was constructed. Includes events re-sent via `_drain_buffer()`.

### `total_buffered`

```python
@property
def total_buffered(self) -> int:
    return self._total_buffered
```

Total number of events written to the disk buffer since construction. Events that were later successfully drained are included in this count; they are not subtracted when drained.

---

## `GUARDIAN_INSECURE_GRPC` Environment Variable

Setting `GUARDIAN_INSECURE_GRPC=1` forces an insecure gRPC channel regardless of the `control_plane` address. This is intended for:
- Docker Compose test environments where the mock control plane runs without TLS.
- CI pipelines where certificate management is impractical.

**Never set this in production.** Insecure channels transmit event payloads (including process names, file paths, network addresses) in plaintext.

---

## Operational Notes

### Checking Buffer Health

```bash
wc -l ~/.guardian/buffer/pending.jsonl
```

If this count is near 10,000, the agent has been unable to reach the control plane for an extended period. Investigate network connectivity and token validity.

### Clearing the Buffer

```bash
rm ~/.guardian/buffer/pending.jsonl
```

This permanently discards all buffered events. Only do this if the events are known to be unrecoverable (e.g. the agent has been offline for so long that the events are no longer useful for compliance).

### Buffer Location in Production

In production Kubernetes deployments, `buffer_path` should point to a PersistentVolumeClaim directory:

```yaml
agent:
  buffer_path: "/var/lib/guardian/buffer"
```

With a corresponding `volumeMount` in the pod spec. Without a persistent volume, a pod restart will lose all buffered events.

---

## Related Documents

- `docs/04-security/batch-signing.md` — what `signature` contains and how the control plane verifies it
- `docs/05-components/signer.md` — produces the `signature` passed to `send_batch()`
- `docs/05-components/enricher.md` — provides `agent_id` for the `EventBatch` proto
- `docs/05-components/config-loader.md` — `agent.control_plane`, `agent.token`, `agent.buffer_path`
