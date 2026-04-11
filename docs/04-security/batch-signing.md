# Batch Signing

## Overview

After a set of events has been hash-chained, Guardian computes an HMAC-SHA256 signature over a compact payload derived from the chain. This signature is transmitted alongside the events to the Viriato control plane, which verifies it to confirm that the batch originated from a legitimate Guardian agent holding the customer's API token.

Batch signing provides **authenticity**: proof of origin. The hash chain (see `docs/04-security/event-chaining.md`) provides **integrity**: proof of non-tampering. Both properties are required for a complete tamper-evident audit log.

---

## Signing Payload Construction

The signing payload is constructed in `Signer.sign_batch()`:

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

**Step 1:** Build a list of `{"prev": ..., "this": ...}` dictionaries, one per event, in chain order.

```python
[
    {"prev": "0000...0000", "this": "a3f9c1b2..."},
    {"prev": "a3f9c1b2...", "this": "7d2ef083..."},
    {"prev": "7d2ef083...", "this": "c8a19e54..."},
]
```

**Step 2:** Serialise with compact separators `(',', ':')` — no spaces — to produce a deterministic byte string. Field order within each object is deterministic because the dict literal always has `"prev"` before `"this"`.

**Step 3:** Compute `HMAC-SHA256(token_bytes, payload_bytes)` and return the 64-character hex digest.

---

## Why Only Hashes Are Signed, Not Full Events

The payload contains only `prev_hash` and `this_hash` for each event, not the full event field values. There are three reasons for this design:

**1. The hashes already commit to the full event content.**
`this_hash = SHA-256(all event fields except this_hash)`. Any change to any event field changes `this_hash`. Signing the hashes is therefore equivalent to signing the event content — any modification of event data produces a different hash, which produces a different HMAC.

**2. Payload size.**
A batch of 100 events with full field values (process names, file paths, network addresses, timestamps) could easily be 50–100 KB. The hash-only payload is exactly `100 * ({"prev":"[64]","this":"[64]"})` ≈ 14 KB before JSON overhead. This matters for HMAC computation speed in high-throughput deployments.

**3. Separation of concerns.**
The control plane's signature verification step does not need to re-parse the full event structure. It only needs the ordered list of hash pairs, which it can verify against the full events independently in a second pass.

---

## HMAC Construction Line by Line

```python
import hashlib
import hmac

# token: str — customer API token from guardian.yaml
# payload: str — compact JSON of hash pairs (see above)

mac = hmac.new(
    token.encode(),       # key: UTF-8 bytes of the API token
    payload.encode(),     # message: UTF-8 bytes of the JSON payload
    hashlib.sha256,       # digest: SHA-256
)
signature = mac.hexdigest()
# signature is a 64-character lowercase hex string
# e.g. "3d5e2a1f9c8b7a6e4f3d2c1b0a9e8f7d..."
```

The resulting signature is a 256-bit value represented as 64 lowercase hexadecimal characters.

---

## Why HMAC, Not Raw SHA-256

A naive alternative would be `SHA-256(token + payload)` (concatenation). This is vulnerable to the **length-extension attack**:

Given `H = SHA-256(secret || message)`, an attacker who knows `H` and `len(secret)` can compute `SHA-256(secret || message || padding || extension)` for any `extension`, without knowing `secret`. For a Merkle-Damgard hash like SHA-256, this is a structural property of the algorithm.

HMAC(SHA-256) is defined as:

```
HMAC(K, m) = SHA-256( (K XOR opad) || SHA-256( (K XOR ipad) || m ) )
```

The double-hash construction ensures that knowing the output `HMAC(K, m)` gives no leverage for computing `HMAC(K, m')` for a different message `m'` without knowing `K`. Length-extension attacks do not apply.

In Guardian's case, the attack would allow an adversary to extend the signed hash list with additional fabricated entries (appending fabricated events to the signed batch). HMAC prevents this.

---

## How the Platform Verifies

The control plane receives an `EventBatch` proto containing:

```protobuf
message EventBatch {
    string agent_id  = 1;
    string signature = 2;  // 64-char HMAC-SHA256 hex
    repeated Event events = 3;
}
```

Verification steps at the control plane:

1. Retrieve the customer's API token associated with `agent_id`.
2. Reconstruct the payload: `json.dumps([{"prev": e.prev_hash, "this": e.this_hash} for e in events], separators=(',',':'))`.
3. Compute `HMAC-SHA256(token, payload).hexdigest()`.
4. Compare (in constant time, i.e. `hmac.compare_digest`) against the received `signature`.
5. If they match: the batch is authentic. Proceed to chain integrity verification.
6. If they differ: reject the batch with `UNAUTHENTICATED`.

**Constant-time comparison** (`hmac.compare_digest` or equivalent) is essential to prevent timing side-channel attacks that would allow an adversary to enumerate valid signature prefixes byte by byte.

---

## Replay Attack Resistance

A **replay attack** is when an adversary captures a valid, signed batch and retransmits it to the control plane at a later time (or repeatedly) to confuse the audit timeline or trigger duplicate alerts.

The current batch signing construction does **not** include a nonce or wall-clock timestamp in the HMAC payload. This means the same batch would produce the same signature if retransmitted. Replay prevention is therefore a **control plane responsibility**, not a Guardian agent responsibility.

The control plane can detect replays by:

1. **Hash chain continuity.** Each batch's first event has a `prev_hash` that equals the last event of the previous batch for the same `agent_id`. If a replayed batch's first `prev_hash` does not match the current expected value, it is rejected as a duplicate or out-of-order delivery.
2. **Timestamp range checks.** Events carry `timestamp` fields with nanosecond UTC timestamps. A replayed batch's timestamps will fall outside the expected current window.
3. **Deduplication by `(agent_id, this_hash of last event)`.** The last event's `this_hash` uniquely identifies the batch; a duplicate submission with the same final hash can be rejected.

---

## Token Rotation Semantics

When the API token is rotated, all subsequent batches are signed with the new token. Historical batches remain verifiable using the old token for the duration of the control plane's key retention period.

Guardian's Signer stores the token in memory at construction time (`self._token`). Rotation requires:

1. Update `guardian.yaml` with the new token.
2. Restart the Guardian agent process.
3. The Signer is re-instantiated with the new token and `prev_hash = GENESIS_HASH`.

**Consequence:** Token rotation starts a new chain. The chain continuity between the last batch under the old token and the first batch under the new token is broken (the new first event has `prev_hash = GENESIS_HASH`). The control plane records the rotation event to explain the chain restart in audit logs.

If an attacker compromises the old token after rotation, they can forge signatures on historical events (since the old token is known). They cannot forge signatures on new events without the new token. This is why forensic analysis of historical events must be performed before the old token is retired.

---

## Signature Output Guarantee

`sign_batch()` always returns a 64-character lowercase hexadecimal string. This is guaranteed by `hashlib.sha256` producing a 32-byte (256-bit) digest, which `hexdigest()` encodes as 64 lowercase hex characters.

Example:

```
"3d5e2a1f9c8b7a6e4f3d2c1b0a9e8f7d6c5b4a392817060504030201f0e0d0c"
```

The control plane should reject any `signature` field that is not exactly 64 characters of lowercase hexadecimal as malformed.

---

## Error Conditions

| Condition | Behaviour |
|---|---|
| `events` is empty | `ValueError("sign_batch requires at least one event.")` |
| `token` is empty string | `ValueError("Signer token must not be empty.")` raised at `Signer.__init__()` |
| Event `prev_hash` or `this_hash` is empty string | HMAC is computed over the payload including empty strings; no error raised, but the resulting signature covers unsigned events and will fail chain verification |

Events should always be signed (via `sign_event()`) before being passed to `sign_batch()`.

---

## Related Documents

- `docs/04-security/event-chaining.md` — hash chain construction and `verify_chain()`
- `docs/04-security/cryptographic-design.md` — algorithm rationale, HMAC vs SHA-256, key management
- `docs/04-security/threat-model.md` — replay attack threat (T-4), token compromise (T-5)
- `docs/05-components/signer.md` — `Signer` class API reference
