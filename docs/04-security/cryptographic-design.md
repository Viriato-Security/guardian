# Guardian Cryptographic Design

## Overview

Guardian provides two independent cryptographic properties for its event stream:

1. **Integrity** — the hash chain guarantees that the ordered sequence of events has not been tampered with after signing. Any deletion, insertion, mutation, or reordering of events is detectable.
2. **Authenticity** — the HMAC-SHA256 batch signature proves that a given batch was produced by a Guardian agent holding the customer's API token. An attacker without the token cannot forge a valid signature.

These properties are complementary. Integrity alone (hash chain without a signature) allows anyone who sees the events to verify consistency, but does not prove origin. Authenticity alone (signature without chaining) proves who sent a batch but does not detect in-batch tampering between signature computation and platform ingestion. Together they provide a tamper-evident, origin-authenticated audit log.

---

## Why Both Properties Are Needed

Consider the following attack scenarios:

**Without the hash chain (signature only):** An attacker who intercepts a batch in transit can delete individual events, reorder them, or replace them with fabricated ones, then re-sign the modified batch using the same token. The control plane would accept the forged batch as authentic.

**Without the batch signature (hash chain only):** An attacker who obtains the hash chain can compute valid hashes for a fabricated chain starting from GENESIS_HASH (since SHA-256 is a public function). The control plane would see a structurally valid chain but with no proof of origin.

The combination forces an attacker to possess the API token (secret) _and_ to compute valid SHA-256 hashes for any modification — which is feasible but detectable via key rotation and chain continuity checks at the platform.

---

## Cryptographic Algorithms

### Event Hashing: SHA-256

Each event's `this_hash` is computed as:

```
this_hash = SHA-256(
    json.dumps(
        asdict(event) with 'this_hash' key removed,
        sort_keys=True,
        separators=(',', ':')
    ).encode('utf-8')
)
```

Algorithm: **SHA-256** (FIPS 180-4).
Output: 64-character lowercase hexadecimal string (256 bits).
Implementation: `hashlib.sha256` from the Python standard library.

SHA-256 is used here rather than SHA-3 or BLAKE2 for two reasons: ubiquity (every audit toolchain supports it) and the absence of length-extension vulnerability in the chaining construction (the chain is a hash-of-fields, not a Merkle-Damgard extension of a previous hash).

### Batch Signing: HMAC-SHA256

Each batch of events is signed as:

```
payload   = json.dumps(
    [{"prev": e.prev_hash, "this": e.this_hash} for e in events],
    separators=(',', ':')
)
signature = hmac.new(
    token.encode('utf-8'),
    payload.encode('utf-8'),
    hashlib.sha256
).hexdigest()
```

Algorithm: **HMAC-SHA256** (RFC 2104).
Output: 64-character lowercase hexadecimal string (256 bits).
Implementation: `hmac.new` from the Python standard library.

HMAC is used rather than a raw SHA-256(token || payload) construction because raw concatenation is vulnerable to length-extension attacks (SHA-256 without HMAC allows an attacker who knows `SHA-256(secret || message)` to compute `SHA-256(secret || message || padding || extension)` without knowing the secret). HMAC's inner/outer hash construction prevents this.

---

## GENESIS_HASH

```python
GENESIS_HASH = "0" * 64
# "0000000000000000000000000000000000000000000000000000000000000000"
```

The first event in any Guardian chain sets `prev_hash = GENESIS_HASH`. This is a sentinel value — not a hash of anything — that signals "this is the start of a chain." Its role is purely structural: `verify_chain()` checks that `events[0].prev_hash == GENESIS_HASH` as its first assertion.

GENESIS_HASH is a public constant. Using a fixed known value rather than a random nonce means that chain verification does not require any shared secret: any party with the events can verify the chain structure independently. The signing key (API token) is only needed to verify the batch signature, which requires possession of the token.

---

## Key Management

### API Token as Signing Key

Guardian uses the customer API token directly as the HMAC key. The token is:

- Obtained from the Viriato Security console.
- Stored in `guardian.yaml` under `agent.token`.
- Read at startup by `load_config()`.
- Passed to `Signer(token)` and `Sender(token=token)`.
- Never logged, never transmitted in cleartext (it appears only in the HMAC key position, never in a batch payload).

The token is a shared symmetric key: both the Guardian agent and the Viriato control plane hold it. The control plane uses it to verify the HMAC signature on each received batch.

### Token Rotation

When a token is rotated:

1. A new token is issued by the Viriato console.
2. `guardian.yaml` is updated with the new token.
3. The Guardian agent is restarted (or sent SIGHUP if live reload is implemented).
4. The Signer reinitialises with `prev_hash = GENESIS_HASH`, starting a new chain.
5. The old token remains valid on the control plane for a rotation grace period to allow drain of any buffered events signed with the old key.

Batches signed with the old token before rotation remain verifiable for as long as the old token is retained. Auditors must know which token was active during which time window to verify historical batches.

### Token Security Requirements

| Property | Requirement |
|---|---|
| Minimum length | 32 bytes (256 bits) of entropy recommended |
| Storage | `chmod 600 guardian.yaml`, owned by Guardian service account |
| Transmission | HMAC key only; never in plaintext HTTP or gRPC metadata in cleartext |
| Rotation frequency | At minimum on suspected compromise; recommended annually |
| Placeholder detection | Guardian logs a warning if token equals `YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE` |

---

## Chain Restart Semantics

The Guardian Signer is **not thread-safe** and must not be shared across goroutines or threads. One Signer instance per pipeline run is the design invariant.

On every agent restart (process restart, not just configuration reload), the Signer starts a new chain from GENESIS_HASH. This means:

- The last event of the previous run and the first event of the new run are **not** linked in the chain.
- The control plane detects a new chain start by observing `prev_hash == GENESIS_HASH` for an `agent_id` whose chain was already in progress.
- A restart gap in the audit log is observable but not attributable to tampering without additional corroboration (e.g. process supervision logs showing the restart event).

This is an intentional trade-off: persisting chain state across restarts would require atomic writes to disk on every event (expensive), and the restart gap is already visible via the `agent_id` continuity mechanism.

---

## Transport Security

Events are transmitted to `grpc.viriatosecurity.com:443` over TLS using gRPC. The channel is created with `grpc.ssl_channel_credentials()` (system trust store), providing:

- **Confidentiality:** event payloads are encrypted in transit.
- **Server authentication:** the server's TLS certificate is validated against the system CA bundle.
- **Integrity:** TLS record MAC prevents undetected in-transit modification.

An insecure channel (no TLS) is used only when:
- `control_plane` starts with `"localhost"` or `"127."`, or
- the environment variable `GUARDIAN_INSECURE_GRPC=1` is set.

This allows local development and testing without certificates while defaulting to TLS in production.

---

## Security Assumptions

The cryptographic design is secure under these assumptions:

1. **SHA-256 collision resistance holds.** Preimage and second-preimage resistance are assumed. If SHA-256 is broken, hash chain integrity is compromised.
2. **HMAC-SHA256 pseudorandomness holds.** The HMAC construction is computationally indistinguishable from a random function to adversaries who do not know the key.
3. **The API token is confidential.** An attacker who obtains the token can forge valid signatures. Token confidentiality is an operational responsibility.
4. **The host kernel is not compromised.** eBPF event sources are trusted as accurate representations of kernel activity.
5. **The Python standard library `hmac` and `hashlib` implementations are correct.** No side-channel or implementation attacks against these modules are in scope.

---

## Known Limitations

| Limitation | Impact | Planned Mitigation |
|---|---|---|
| Root host compromise bypasses everything | Complete audit trail forgery | Hardware attestation (future phase) |
| Static long-lived token; no forward secrecy | Retroactive forgery if token leaked | Ed25519 per-event signing (Phase 3) |
| No nonce in batch payload | Replay attack possible (control plane must detect) | Sequence number or timestamp range in batch (Phase 2) |
| SHA-256 hash chain (no Merkle tree) | O(n) verification time | Acceptable for current event volumes |
| HMAC key = API token (authentication token overloaded as signing key) | Token rotation invalidates old signatures | Separate signing key (Phase 3) |

---

## Phase 3: Ed25519 Per-Event Signing

Phase 3 will replace the current HMAC batch signature with Ed25519 asymmetric signatures applied per-event. This provides:

- **Non-repudiation:** the customer's private key signs each event; the public key is registered with the control plane.
- **Forward secrecy:** with ephemeral key derivation (e.g. X3DH), compromise of the long-term key does not expose past events.
- **Offline verification:** any party with the public key can verify event authenticity without contacting Viriato.

The hash chain integrity mechanism (SHA-256) will be retained in Phase 3.

---

## Related Documents

- `docs/04-security/event-chaining.md` — exact `_hash_event()` construction and `verify_chain()` algorithm
- `docs/04-security/batch-signing.md` — HMAC payload construction line by line
- `docs/04-security/threat-model.md` — threat actors and residual risks
- `docs/05-components/signer.md` — `Signer` class reference
