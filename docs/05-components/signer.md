# Signer (`agent/signer.py`)

## Overview

`agent/signer.py` provides two cryptographic operations:

1. **`Signer.sign_event()`** — sets `prev_hash` and `this_hash` on each event, building the tamper-evident chain.
2. **`Signer.sign_batch()`** — computes an HMAC-SHA256 signature over the ordered list of event hashes, providing batch-level authenticity.

Additionally, the module-level function `verify_chain()` allows any party with the event data to independently verify chain integrity without any secret key.

For algorithm rationale and security properties, see `docs/04-security/cryptographic-design.md` and `docs/04-security/event-chaining.md`.

---

## Constants

```python
GENESIS_HASH = "0" * 64
# "0000000000000000000000000000000000000000000000000000000000000000"
```

A 64-character string of ASCII zeros. Used as `prev_hash` for the first event in every chain. It is a sentinel value (not the hash of anything) that signals the start of a chain.

The constant is public and can be imported directly:

```python
from agent.signer import GENESIS_HASH
```

---

## `Signer` Class

```python
class Signer:
    def __init__(self, token: str) -> None:
```

### Constructor

| Parameter | Type | Description |
|---|---|---|
| `token` | `str` | Customer API token used as the HMAC-SHA256 key. Must not be empty. |

**Raises:** `ValueError("Signer token must not be empty.")` if `token` is an empty string.

At construction, the internal state is:
- `self._token = token` — the HMAC key, stored as a string (encoded to bytes at signing time).
- `self._prev_hash = GENESIS_HASH` — the chain starts at the genesis sentinel.
- `self._events_signed = 0` — counter of events signed in this session.

---

### `sign_event(event: RawEvent) -> RawEvent`

```python
def sign_event(self, event: RawEvent) -> RawEvent:
    event.prev_hash = self._prev_hash
    event.this_hash = self._hash_event(event)
    self._prev_hash = event.this_hash
    self._events_signed += 1
    return event
```

**Effect:** Mutates `event` in-place by setting `prev_hash` and `this_hash`. Returns the same object for pipeline chaining.

**Chain advance:** After setting `event.this_hash`, the Signer updates its internal `_prev_hash` to `event.this_hash`. The next call to `sign_event()` will use this new value as the next event's `prev_hash`.

**Order requirement:** Events must be passed to `sign_event()` in the exact order they should appear in the chain. Passing events out of order produces a structurally valid but logically incorrect chain that may not match the platform's expected continuity.

**Pre-condition:** The event should have been enriched (all context fields set) before calling `sign_event()`, so that the enriched fields are included in the hash. See `docs/05-components/enricher.md`.

**Example:**

```python
signer = Signer(token="my-api-token")

event_0 = RawEvent(timestamp="2026-04-10T12:00:00.000000000Z", ...)
signer.sign_event(event_0)
# event_0.prev_hash == "0" * 64  (GENESIS_HASH)
# event_0.this_hash == "a3f9c1b2..."

event_1 = RawEvent(timestamp="2026-04-10T12:00:00.001000000Z", ...)
signer.sign_event(event_1)
# event_1.prev_hash == "a3f9c1b2..."  (event_0.this_hash)
# event_1.this_hash == "7d2ef083..."
```

---

### `sign_batch(events: list[RawEvent]) -> str`

```python
def sign_batch(self, events: list[RawEvent]) -> str:
    if not events:
        raise ValueError("sign_batch requires at least one event.")
    payload = json.dumps(
        [{"prev": e.prev_hash, "this": e.this_hash} for e in events],
        separators=(",", ":"),
    )
    return hmac.new(
        self._token.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()
```

**Input:** A non-empty list of `RawEvent` objects that have already been processed by `sign_event()` (i.e. both `prev_hash` and `this_hash` are set).

**Output:** A 64-character lowercase hexadecimal HMAC-SHA256 digest.

**Raises:** `ValueError("sign_batch requires at least one event.")` if `events` is empty.

The payload is the compact JSON serialisation of `[{"prev": ..., "this": ...}]`. The same payload construction must be used by the control plane for verification. See `docs/04-security/batch-signing.md` for the full construction.

**Example:**

```python
events = [event_0, event_1, event_2]
# All events already signed via sign_event()

signature = signer.sign_batch(events)
# Returns "3d5e2a1f9c8b7a6e4f3d2c1b0a9e8f7d..."
```

---

### `_hash_event(event: RawEvent) -> str` (static method)

```python
@staticmethod
def _hash_event(event: RawEvent) -> str:
    d: dict = asdict(event)
    d.pop("this_hash", None)
    serialised = json.dumps(d, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialised.encode()).hexdigest()
```

This is the canonical hash function for a single event. It is a `@staticmethod` because it does not depend on the Signer's internal state and is also called by `verify_chain()` (which has no Signer instance).

**Steps:**
1. Convert the event dataclass to a plain dict via `dataclasses.asdict()`.
2. Remove the `"this_hash"` key (the event cannot be part of its own hash input).
3. Serialise to compact JSON with sorted keys for determinism.
4. Return the lowercase hex SHA-256 digest of the UTF-8 encoded JSON.

The `default=str` argument ensures that any non-JSON-serialisable field value (e.g. a future `datetime` object) is converted to its string representation rather than raising `TypeError`.

---

### `events_signed` Property

```python
@property
def events_signed(self) -> int:
    return self._events_signed
```

Returns the total number of events signed by this `Signer` instance since construction. Useful for metrics and pipeline monitoring.

---

## `verify_chain()` Function

```python
def verify_chain(events: list[RawEvent]) -> tuple[bool, str]:
```

A module-level function (not a method) that verifies the integrity of a list of events. Does not require a `Signer` instance or any secret key.

**Returns:**
- `(True, "ok")` — the chain is valid.
- `(False, reason_string)` — the chain is invalid; `reason_string` explains the first failure found.

**Algorithm:**

| Step | Check | Failure message |
|---|---|---|
| 0 | If `events` is empty, return `(True, "ok")`. | — |
| 1 | `events[0].prev_hash == GENESIS_HASH` | `"Event 0 prev_hash is not GENESIS_HASH (got '...')"` |
| 2 (each event) | `event.this_hash == Signer._hash_event(event)` | `"Event i this_hash mismatch: expected ..., got ..."` |
| 3 (each event after first) | `event.prev_hash == events[i-1].this_hash` | `"Event i prev_hash mismatch: expected ..., got ..."` |

Steps 2 and 3 are performed in a single loop pass (O(n) time). The function returns on the first failure encountered.

**Usage example (audit script):**

```python
from agent.signer import verify_chain
from agent.generator import RawEvent
from dataclasses import fields
import json

with open("exported_events.json") as f:
    data = json.load(f)

field_names = {fld.name for fld in fields(RawEvent)}
events = [
    RawEvent(**{k: v for k, v in e.items() if k in field_names})
    for e in data["events"]
]

valid, reason = verify_chain(events)
print("VALID" if valid else f"INVALID: {reason}")
```

---

## Thread Safety

**The `Signer` class is NOT thread-safe.**

The `_prev_hash` and `_events_signed` attributes are mutated on every call to `sign_event()`. If two threads call `sign_event()` concurrently, the chain state will be corrupted — the same `prev_hash` might be assigned to two events, or the counter might be incremented incorrectly.

The design invariant is: **one `Signer` instance per pipeline**. The pipeline in `agent/main.py` is single-threaded. If a multi-threaded or async architecture is introduced in a future phase, each pipeline worker must have its own `Signer` instance, or an external lock must serialize access.

---

## Chain Restart on Agent Restart

Every time the Guardian agent process starts, it creates a new `Signer` instance, which sets `self._prev_hash = GENESIS_HASH`. This starts a new chain.

**Consequence:** The chain between the last run and the current run is not linked. The first event of the new run has `prev_hash = GENESIS_HASH`, regardless of what the last event of the previous run looked like.

The control plane detects this by observing a new `GENESIS_HASH` `prev_hash` for a known `agent_id`. This is treated as a "chain restart" event in the audit log. Auditors must account for chain restarts when verifying a complete audit history across multiple runs.

Chain restarts are also observable via process supervision logs (systemd journal, Kubernetes events), which record agent start/stop times that correlate with the restart events in the chain log.

---

## Chain State Is Not Persisted

The `_prev_hash` state is held entirely in memory. If the agent is killed (SIGKILL) or crashes, the in-memory state is lost. Events in the batch that was being processed at kill time are not signed and not sent.

This is an intentional trade-off:
- Persisting `_prev_hash` to disk on every event would require a durable atomic write (fsync), which adds significant I/O overhead on the hot path.
- The chain restart at restart time is observable and recorded, so the gap is detectable.

---

## Related Documents

- `docs/04-security/event-chaining.md` — detailed explanation of the hash chain and `verify_chain()` steps
- `docs/04-security/batch-signing.md` — `sign_batch()` HMAC construction and control plane verification
- `docs/04-security/cryptographic-design.md` — algorithm choices, GENESIS_HASH semantics, known limitations
- `docs/05-components/enricher.md` — must run before `sign_event()` so context fields are in the hash
