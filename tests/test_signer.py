"""Tests for agent/signer.py — event chaining and batch signing."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json

import pytest

from agent.generator import RawEvent
from agent.signer import GENESIS_HASH, Signer, verify_chain


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(**kwargs) -> RawEvent:  # type: ignore[no-untyped-def]
    defaults = dict(
        timestamp="2026-04-09T12:00:00.000000000Z",
        pid=1234,
        process="python",
        syscall="read",
        fd_path="/tmp/model.pt",
        bytes=4096,
        network_addr="",
        return_val="0",
        uid=1000,
        agent_id="test-agent",
        model_name="test-model",
        container_id="",
        pod_name="",
        namespace="",
    )
    defaults.update(kwargs)
    return RawEvent(**defaults)


def _fresh_signer() -> Signer:
    return Signer("test-token-secret")


# ---------------------------------------------------------------------------
# Chain tests
# ---------------------------------------------------------------------------


def test_first_event_chains_from_genesis() -> None:
    s = _fresh_signer()
    e = _make_event()
    s.sign_event(e)
    assert e.prev_hash == GENESIS_HASH
    assert len(e.this_hash) == 64


def test_second_event_chains_from_first() -> None:
    s = _fresh_signer()
    e1 = _make_event(pid=1)
    e2 = _make_event(pid=2)
    s.sign_event(e1)
    s.sign_event(e2)
    assert e2.prev_hash == e1.this_hash


def test_chain_of_ten_passes_verify() -> None:
    s = _fresh_signer()
    events = [_make_event(pid=i) for i in range(10)]
    for e in events:
        s.sign_event(e)
    ok, reason = verify_chain(events)
    assert ok, reason


def test_this_hash_is_deterministic() -> None:
    s1 = _fresh_signer()
    s2 = _fresh_signer()
    e1 = _make_event(pid=42)
    e2 = _make_event(pid=42)
    s1.sign_event(e1)
    s2.sign_event(e2)
    assert e1.this_hash == e2.this_hash


def test_hash_changes_when_field_mutated() -> None:
    s = _fresh_signer()
    e = _make_event()
    s.sign_event(e)
    original_hash = e.this_hash
    e2 = copy.deepcopy(e)
    e2.pid = 9999
    new_hash = Signer._hash_event(e2)
    assert original_hash != new_hash


def test_events_signed_counter_increments() -> None:
    s = _fresh_signer()
    assert s.events_signed == 0
    for i in range(5):
        s.sign_event(_make_event(pid=i))
    assert s.events_signed == 5


# ---------------------------------------------------------------------------
# verify_chain tests
# ---------------------------------------------------------------------------


def test_verify_chain_valid() -> None:
    s = _fresh_signer()
    events = [_make_event(pid=i) for i in range(5)]
    for e in events:
        s.sign_event(e)
    ok, reason = verify_chain(events)
    assert ok, reason


def test_verify_chain_empty() -> None:
    ok, reason = verify_chain([])
    assert ok, reason


def test_verify_chain_tampered_field() -> None:
    s = _fresh_signer()
    events = [_make_event(pid=i) for i in range(5)]
    for e in events:
        s.sign_event(e)
    events[2].pid = 99999  # mutate without rehashing
    ok, _ = verify_chain(events)
    assert not ok


def test_verify_chain_swapped_order() -> None:
    s = _fresh_signer()
    events = [_make_event(pid=i) for i in range(5)]
    for e in events:
        s.sign_event(e)
    # Swap events[1] and events[2]
    events[1], events[2] = events[2], events[1]
    ok, _ = verify_chain(events)
    assert not ok


def test_verify_chain_deleted_event() -> None:
    s = _fresh_signer()
    events = [_make_event(pid=i) for i in range(5)]
    for e in events:
        s.sign_event(e)
    del events[2]  # remove middle event
    ok, _ = verify_chain(events)
    assert not ok


# ---------------------------------------------------------------------------
# sign_batch tests
# ---------------------------------------------------------------------------


def _signed_batch(n: int = 3, token: str = "test-token") -> tuple[list[RawEvent], str]:
    s = Signer(token)
    events = [_make_event(pid=i) for i in range(n)]
    for e in events:
        s.sign_event(e)
    return events, s.sign_batch(events)


def test_sign_batch_returns_64_char_hex() -> None:
    _, sig = _signed_batch()
    assert len(sig) == 64
    int(sig, 16)  # must be valid hex


def test_sign_batch_is_deterministic() -> None:
    events, sig1 = _signed_batch()
    # Rebuild signer to same state
    s2 = Signer("test-token")
    for e in events:
        pass  # hashes are already set
    sig2 = s2.sign_batch(events)
    assert sig1 == sig2


def test_sign_batch_different_tokens_differ() -> None:
    events, _ = _signed_batch(token="token-A")
    sA = Signer("token-A")
    sB = Signer("token-B")
    sig_a = sA.sign_batch(events)
    sig_b = sB.sign_batch(events)
    assert sig_a != sig_b


def test_sign_batch_empty_raises() -> None:
    s = _fresh_signer()
    with pytest.raises(ValueError):
        s.sign_batch([])


def test_sign_batch_empty_token_raises() -> None:
    with pytest.raises(ValueError):
        Signer("")
