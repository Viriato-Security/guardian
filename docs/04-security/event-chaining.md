# Event Chaining

## Purpose

Guardian records syscall events as a tamper-evident linked list. Each event cryptographically commits to every event that preceded it. This makes it impossible to silently delete, insert, mutate, or reorder events without producing a detectable inconsistency — as long as the verifier recomputes the hashes from the raw event data.

This document explains exactly how the chain is constructed, provides a step-by-step visual walkthrough, describes what breaks and what does not break the chain, and documents the `verify_chain()` algorithm used by auditors.

---

## The Hash Function

Every `RawEvent` has two hash fields set by `agent/signer.py`:

| Field | Set by | Description |
|---|---|---|
| `prev_hash` | `Signer.sign_event()` | The `this_hash` of the immediately preceding event (or `GENESIS_HASH` for event 0) |
| `this_hash` | `Signer.sign_event()` | SHA-256 of this event's canonical serialisation |

The canonical serialisation used to compute `this_hash` is:

```python
import hashlib
import json
from dataclasses import asdict

def _hash_event(event: RawEvent) -> str:
    d = asdict(event)
    d.pop("this_hash", None)           # exclude this_hash from its own input
    serialised = json.dumps(
        d,
        sort_keys=True,                # deterministic field ordering
        separators=(',', ':'),         # no spaces — compact canonical form
        default=str,                   # coerce any non-serialisable types
    )
    return hashlib.sha256(serialised.encode()).hexdigest()
```

The output is a 64-character lowercase hexadecimal string representing 256 bits.

---

## Why `this_hash` Is Excluded from Its Own Input

`this_hash` is defined as the hash of the event. If `this_hash` were included in the fields hashed to produce itself, the definition would be circular and impossible to compute. The field must be absent (or set to an empty string) at hash-computation time, then written back to the event after the hash is computed.

This is the standard self-referential field exclusion pattern seen in Git commits (the commit hash is the hash of the commit object, which does not include the hash itself) and in blockchain blocks.

---

## Why `sort_keys=True`

Python dictionaries (and by extension `dataclasses.asdict()`) preserve insertion order as of Python 3.7, but the canonical serialisation must be deterministic regardless of how the dataclass was constructed or in what order fields happen to appear in memory. `sort_keys=True` ensures that the JSON representation always uses alphabetical field order, producing the same byte sequence on any Python version and on any platform.

If `sort_keys=True` were omitted, two events with identical field values but different field insertion orders would produce different hashes, breaking `verify_chain()` on a different machine or after an upgrade that changes the dataclass field order.

---

## Why `separators=(',', ':')`

The default `json.dumps()` output includes a space after `:` (e.g. `{"a": 1}`). The compact separator `(',', ':')` removes this whitespace, producing `{"a":1}`. This is purely for determinism: any verifier using the same compact form will produce the same bytes. The space difference would produce a different SHA-256 hash.

---

## The Chain as a Linked List

```
GENESIS_HASH ("0" * 64)
      │
      ▼ prev_hash
┌─────────────────────────────────────────────────────────────────┐
│  Event 0                                                        │
│  prev_hash  = "0000...0000" (GENESIS_HASH)                      │
│  timestamp  = "2026-04-10T12:00:00.000000000Z"                  │
│  pid        = 12345                                             │
│  syscall    = "read"                                            │
│  ...                                                            │
│  this_hash  = SHA-256(all fields above except this_hash)        │
│             = "a3f9...c1b2"                                     │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼ prev_hash = event 0's this_hash
┌─────────────────────────────────────────────────────────────────┐
│  Event 1                                                        │
│  prev_hash  = "a3f9...c1b2"                                     │
│  timestamp  = "2026-04-10T12:00:00.001234000Z"                  │
│  pid        = 12345                                             │
│  syscall    = "openat"                                          │
│  ...                                                            │
│  this_hash  = SHA-256(all fields above except this_hash)        │
│             = "7d2e...f083"                                     │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼ prev_hash = event 1's this_hash
┌─────────────────────────────────────────────────────────────────┐
│  Event 2                                                        │
│  prev_hash  = "7d2e...f083"                                     │
│  ...                                                            │
│  this_hash  = "c8a1...9e54"                                     │
└─────────────────────────────────────────────────────────────────┘
```

Each event's `prev_hash` is the hash of the previous event's full content. Therefore, changing any field of event _i_ changes event _i_'s `this_hash`, which means event _i+1_'s `prev_hash` no longer matches, breaking the chain from position _i+1_ onward.

---

## Visual Walkthrough with Example Hashes

Below is a concrete minimal example showing three events with abbreviated hashes (8 hex chars shown; real hashes are 64 chars).

**Event 0 (first event):**

```python
event_0 = RawEvent(
    timestamp="2026-04-10T12:00:00.000000000Z",
    pid=1234,
    process="python",
    syscall="read",
    fd_path="/var/lib/models/patient-diagnosis-v2/model.pt",
    bytes=4096,
    network_addr="",
    return_val="0",
    uid=1000,
    agent_id="f47ac10b-58cc-4372-a567-0e02b2c3d479",
    model_name="patient-diagnosis-v2",
    container_id="a1b2c3d4e5f6",
    pod_name="inference-pod-0",
    namespace="production",
    prev_hash="0000000000000000000000000000000000000000000000000000000000000000",
    this_hash="",  # not yet set
)
# After sign_event():
# this_hash = SHA-256(json with this_hash excluded) = "a3f9c1b2..."
event_0.prev_hash = "0" * 64   # GENESIS_HASH
event_0.this_hash = "a3f9c1b2e4d7f890..."
```

**Event 1 (second event):**

```python
event_1 = RawEvent(
    timestamp="2026-04-10T12:00:00.001234000Z",
    pid=1234,
    process="python",
    syscall="openat",
    fd_path="/var/lib/models/patient-diagnosis-v2/config.json",
    bytes=512,
    network_addr="",
    return_val="0",
    uid=1000,
    agent_id="f47ac10b-58cc-4372-a567-0e02b2c3d479",
    model_name="patient-diagnosis-v2",
    container_id="a1b2c3d4e5f6",
    pod_name="inference-pod-0",
    namespace="production",
    prev_hash="a3f9c1b2e4d7f890...",  # = event_0.this_hash
    this_hash="7d2ef0836c...",
)
```

**Event 2 (third event, sandbox escape):**

```python
event_2 = RawEvent(
    timestamp="2026-04-10T12:00:00.002500000Z",
    pid=1234,
    process="python",
    syscall="execve",
    fd_path="/bin/bash",
    bytes=0,
    network_addr="",
    return_val="0",
    uid=1000,
    agent_id="f47ac10b-58cc-4372-a567-0e02b2c3d479",
    model_name="patient-diagnosis-v2",
    container_id="a1b2c3d4e5f6",
    pod_name="inference-pod-0",
    namespace="production",
    prev_hash="7d2ef0836c...",  # = event_1.this_hash
    this_hash="c8a19e547b...",
)
```

The chain is: `GENESIS_HASH → event_0 → event_1 → event_2`.

---

## What Breaks the Chain

The following operations produce a detectable chain break:

### Deletion of an Interior Event

If event 1 is removed from the sequence `[event_0, event_1, event_2]`, the verifier sees `[event_0, event_2]`. The check `event_2.prev_hash == event_0.this_hash` fails because `event_2.prev_hash` is `event_1.this_hash`, not `event_0.this_hash`.

### Insertion of a Fabricated Event

If a fabricated event is inserted between event_1 and event_2, the fabricated event's `prev_hash` must equal `event_1.this_hash` (correct) but its `this_hash` must become the new `event_2.prev_hash`. Since `event_2.prev_hash` was originally set to `event_1.this_hash`, the fabricated event's `this_hash` would need to equal `event_1.this_hash` — which would require a SHA-256 second-preimage collision. Without this, `event_2.prev_hash` no longer matches the fabricated event's `this_hash`, breaking the chain.

Alternatively, all subsequent events (event_2 onward) would need to be rehashed with updated `prev_hash` values, which also requires computing valid `this_hash` values — feasible computationally but detectable via the batch signature if the attacker does not have the token.

### Field Mutation

Changing `event_1.syscall` from `"openat"` to `"read"` changes the JSON input to `_hash_event()`. The recomputed hash differs from `event_1.this_hash`. `verify_chain()` detects the mismatch at position 1.

### Reordering

Swapping event_1 and event_2 means event_2 (now at position 1) has `prev_hash = event_1.this_hash`, but the verifier expects position 1's `prev_hash` to equal `event_0.this_hash`. The check `events[1].prev_hash == events[0].this_hash` fails.

---

## What Does NOT Break the Chain

### Appending New Events

Appending a genuine new event at the end of the chain does not break existing events. The new event's `prev_hash` equals the last existing event's `this_hash`, and `verify_chain()` traverses forward from index 0, so existing chain links are unaffected.

### Chain Truncation (Tail Deletion)

Deleting the last _k_ events from the tail of the chain does not break the remaining chain. The remaining events still form a valid chain terminating at the new last event. Tail deletion is undetectable from the chain structure alone; it requires the control plane to track sequence continuity (expected next `prev_hash` for each `agent_id`).

---

## `verify_chain()` Step by Step

```python
def verify_chain(events: list[RawEvent]) -> tuple[bool, str]:
```

The function returns `(True, "ok")` on a valid chain and `(False, reason)` on any failure.

**Step 1: Empty list is trivially valid.**

```python
if not events:
    return True, "ok"
```

An empty event list has no chain links to verify. This handles the case where a batch interval produces no events.

**Step 2: Check the first event's `prev_hash` is GENESIS_HASH.**

```python
if events[0].prev_hash != GENESIS_HASH:
    return False, f"Event 0 prev_hash is not GENESIS_HASH (got {events[0].prev_hash!r})"
```

A valid chain always starts with the sentinel. If the first event has any other `prev_hash`, either the chain was spliced mid-sequence (the first event of the sequence is not the first event of the run) or it has been tampered with.

**Step 3: For each event, verify `this_hash` matches recomputed hash.**

```python
for i, event in enumerate(events):
    expected_hash = Signer._hash_event(event)
    if event.this_hash != expected_hash:
        return False, f"Event {i} this_hash mismatch: expected {expected_hash}, got {event.this_hash}"
```

`_hash_event()` recomputes the hash from the event's current field values. If any field has been modified since signing, this check will fail at that event index.

**Step 4: For each event after the first, verify `prev_hash` links to the preceding event.**

```python
    if i > 0 and event.prev_hash != events[i - 1].this_hash:
        return False, (
            f"Event {i} prev_hash mismatch: "
            f"expected {events[i - 1].this_hash}, got {event.prev_hash}"
        )
```

This confirms the linked-list structure. Steps 3 and 4 together mean that both the content of each event and the chain linkage are verified in a single O(n) pass.

**Step 5: Return success.**

```python
return True, "ok"
```

---

## How Auditors Use Chain Verification

An auditor who receives a set of events from the Viriato control plane (e.g. as a JSON export) can independently verify the chain without any Guardian-specific tooling:

```python
from agent.signer import verify_chain
from agent.generator import RawEvent
from dataclasses import fields
import json

# Load exported events (e.g. from control plane API)
with open("exported_events.json") as f:
    raw = json.load(f)

field_names = {fld.name for fld in fields(RawEvent)}
events = [
    RawEvent(**{k: v for k, v in e.items() if k in field_names})
    for e in raw["events"]
]

valid, reason = verify_chain(events)
if valid:
    print("Chain is intact.")
else:
    print(f"Chain BROKEN: {reason}")
```

The verification requires only the event data itself — no API token, no secret. The token is only needed to verify the batch signature (authenticity), which is a separate check.

For a full audit:
1. Run `verify_chain()` to confirm structural integrity (no tampering).
2. Recompute the batch HMAC with the known token to confirm authenticity (genuine origin).
3. Check chain continuity across batches: `batch[k+1].events[0].prev_hash == batch[k].events[-1].this_hash`.

---

## Related Documents

- `docs/04-security/cryptographic-design.md` — algorithm selection, GENESIS_HASH, key management
- `docs/04-security/batch-signing.md` — HMAC signing and payload construction
- `docs/05-components/signer.md` — `Signer` class reference and thread safety
- `docs/04-security/threat-model.md` — what breaks/does not break the chain from an attacker's perspective
