"""
Cryptographic event chaining and batch signing.

Event chaining (tamper-evident log):
  event.prev_hash = previous event's this_hash  (GENESIS_HASH for first)
  event.this_hash = SHA-256( json.dumps(all fields except this_hash) )

Batch signing (HMAC-SHA256):
  payload   = json.dumps([{"prev": e.prev_hash, "this": e.this_hash} for e in events])
  signature = hmac(token, payload, sha256).hexdigest()
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import asdict
from typing import Any

from agent.generator import RawEvent

logger = logging.getLogger(__name__)

# Sentinel: the first event's prev_hash is 64 zeros.
GENESIS_HASH = "0" * 64


class Signer:
    """Signs and chains RawEvent objects.

    Args:
        token: Customer API token used for HMAC signing.

    Raises:
        ValueError: If *token* is empty.
    """

    def __init__(self, token: str) -> None:
        if not token:
            raise ValueError("Signer token must not be empty.")
        self._token = token
        self._prev_hash: str = GENESIS_HASH
        self._events_signed: int = 0

    @property
    def events_signed(self) -> int:
        """Number of events signed so far."""
        return self._events_signed

    def sign_event(self, event: RawEvent) -> RawEvent:
        """Set prev_hash and this_hash on *event*, mutating it in-place.

        Returns the same object for chaining convenience.
        """
        event.prev_hash = self._prev_hash
        event.this_hash = self._hash_event(event)
        self._prev_hash = event.this_hash
        self._events_signed += 1
        return event

    def sign_batch(self, events: list[RawEvent]) -> str:
        """Return an HMAC-SHA256 hex signature over the hashes of *events*.

        Args:
            events: Non-empty list of already-chained events.

        Returns:
            64-character lowercase hex string.

        Raises:
            ValueError: If *events* is empty.
        """
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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_event(event: RawEvent) -> str:
        """SHA-256 of the event dict (excluding the this_hash field itself)."""
        d: dict[str, Any] = asdict(event)
        d.pop("this_hash", None)
        serialised = json.dumps(d, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(serialised.encode()).hexdigest()


# ------------------------------------------------------------------
# Verification
# ------------------------------------------------------------------


def verify_chain(events: list[RawEvent]) -> tuple[bool, str]:
    """Verify the hash chain of *events*.

    Checks:
    - ``events[0].prev_hash == GENESIS_HASH``
    - Each event's this_hash matches a fresh recomputation
    - Each event's prev_hash matches the previous event's this_hash

    Returns:
        ``(True, "ok")`` if the chain is valid (including for empty list).
        ``(False, reason)`` on any failure.
    """
    if not events:
        return True, "ok"

    if events[0].prev_hash != GENESIS_HASH:
        return False, f"Event 0 prev_hash is not GENESIS_HASH (got {events[0].prev_hash!r})"

    for i, event in enumerate(events):
        expected_hash = Signer._hash_event(event)
        if event.this_hash != expected_hash:
            return False, f"Event {i} this_hash mismatch: expected {expected_hash}, got {event.this_hash}"
        if i > 0 and event.prev_hash != events[i - 1].this_hash:
            return False, (
                f"Event {i} prev_hash mismatch: "
                f"expected {events[i - 1].this_hash}, got {event.prev_hash}"
            )

    return True, "ok"
