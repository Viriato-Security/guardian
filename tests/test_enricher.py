"""Tests for agent/enricher.py — context enrichment."""

from __future__ import annotations

import os
import uuid

import pytest

from agent.config import AgentConfig, Config, WatchEntry
from agent.enricher import Enricher
from agent.generator import RawEvent


def _make_config(
    watch: list[WatchEntry] | None = None,
) -> Config:
    return Config(
        agent=AgentConfig(token="test-token"),
        watch=watch
        or [
            WatchEntry(process="python", model_name="patient-diagnosis-v2"),
            WatchEntry(process="torchserve", model_name="fraud-detection-v1"),
        ],
    )


def _make_event(process: str = "python") -> RawEvent:
    return RawEvent(
        timestamp="2026-04-09T12:00:00.000000000Z",
        pid=1234,
        process=process,
        syscall="read",
    )


# ---------------------------------------------------------------------------
# agent_id tests
# ---------------------------------------------------------------------------


def test_agent_id_is_valid_uuid() -> None:
    e = Enricher(_make_config())
    uuid.UUID(e.agent_id)  # raises if invalid


def test_enrich_sets_agent_id() -> None:
    enricher = Enricher(_make_config())
    event = _make_event()
    enricher.enrich(event)
    assert event.agent_id == enricher.agent_id


def test_enrich_returns_same_object() -> None:
    enricher = Enricher(_make_config())
    event = _make_event()
    result = enricher.enrich(event)
    assert result is event


# ---------------------------------------------------------------------------
# model_name tests
# ---------------------------------------------------------------------------


def test_enrich_sets_model_name_for_python() -> None:
    enricher = Enricher(_make_config())
    event = _make_event(process="python")
    enricher.enrich(event)
    assert event.model_name == "patient-diagnosis-v2"


def test_enrich_sets_model_name_for_torchserve() -> None:
    enricher = Enricher(_make_config())
    event = _make_event(process="torchserve")
    enricher.enrich(event)
    assert event.model_name == "fraud-detection-v1"


def test_enrich_returns_unknown_for_unrecognised_process() -> None:
    enricher = Enricher(_make_config())
    event = _make_event(process="nginx")
    enricher.enrich(event)
    assert event.model_name == "unknown"


# ---------------------------------------------------------------------------
# Kubernetes context tests
# ---------------------------------------------------------------------------


def test_pod_name_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBERNETES_POD_NAME", "guardian-pod-xyz")
    enricher = Enricher(_make_config())
    event = _make_event()
    enricher.enrich(event)
    assert event.pod_name == "guardian-pod-xyz"


def test_namespace_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBERNETES_NAMESPACE", "production")
    enricher = Enricher(_make_config())
    event = _make_event()
    enricher.enrich(event)
    assert event.namespace == "production"


def test_empty_pod_name_when_not_in_k8s(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KUBERNETES_POD_NAME", raising=False)
    enricher = Enricher(_make_config())
    event = _make_event()
    enricher.enrich(event)
    assert event.pod_name == ""


def test_empty_namespace_when_not_in_k8s(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KUBERNETES_NAMESPACE", raising=False)
    enricher = Enricher(_make_config())
    event = _make_event()
    enricher.enrich(event)
    assert event.namespace == ""


# ---------------------------------------------------------------------------
# container_id tests
# ---------------------------------------------------------------------------


def test_container_id_empty_for_nonexistent_pid() -> None:
    enricher = Enricher(_make_config())
    # PID 9999999 almost certainly does not exist
    result = enricher._container_id(9999999)
    assert result == ""
