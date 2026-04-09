"""Tests for agent/config.py — guardian.yaml loader."""

from __future__ import annotations

import logging
import os
import textwrap

import pytest
import yaml

from agent.config import Config, load_config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_yaml(tmp_path, content: str) -> str:
    p = tmp_path / "guardian.yaml"
    p.write_text(textwrap.dedent(content))
    return str(p)


_FULL_YAML = """\
    agent:
      token: "real-token-abc123"
      control_plane: "grpc.viriatosecurity.com:443"
      batch_interval_ms: 200
      buffer_path: "/tmp/guardian/buffer"

    watch:
      - process: "python"
        model_name: "patient-diagnosis-v2"
      - process: "torchserve"
        model_name: "fraud-detection-v1"

    syscalls:
      - read
      - write
      - openat

    local_alerts:
      - type: sandbox_escape
        condition: "execve matches shell"
        action: log_and_alert

    network_allowlist:
      - "10.0.0.1:8080"

    compliance:
      organization: "Acme Health"
      data_categories:
        - medical_records
      articles: [12, 13]
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_load_config_parses_yaml(tmp_path: pytest.TempPathFactory) -> None:
    path = _write_yaml(tmp_path, _FULL_YAML)
    cfg = load_config(path)
    assert isinstance(cfg, Config)
    assert cfg.agent.token == "real-token-abc123"
    assert cfg.agent.control_plane == "grpc.viriatosecurity.com:443"
    assert cfg.agent.batch_interval_ms == 200
    assert cfg.agent.buffer_path == "/tmp/guardian/buffer"
    assert len(cfg.watch) == 2
    assert cfg.watch[0].process == "python"
    assert cfg.watch[1].model_name == "fraud-detection-v1"
    assert "read" in cfg.syscalls
    assert len(cfg.local_alerts) == 1
    assert cfg.local_alerts[0].type == "sandbox_escape"
    assert cfg.network_allowlist == ["10.0.0.1:8080"]
    assert cfg.compliance.organization == "Acme Health"
    assert 12 in cfg.compliance.articles


def test_placeholder_token_logs_warning(
    tmp_path: pytest.TempPathFactory, caplog: pytest.LogCaptureFixture
) -> None:
    yaml_text = """\
        agent:
          token: "YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE"
          control_plane: "grpc.viriatosecurity.com:443"
          batch_interval_ms: 100
          buffer_path: "/tmp/buf"
        watch: []
        syscalls: []
    """
    path = _write_yaml(tmp_path, yaml_text)
    with caplog.at_level(logging.WARNING, logger="agent.config"):
        cfg = load_config(path)
    assert any("token" in msg.lower() or "placeholder" in msg.lower() for msg in caplog.messages)
    # Must NOT raise
    assert cfg.agent.token == "YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE"


def test_model_name_for_process_resolves(tmp_path: pytest.TempPathFactory) -> None:
    path = _write_yaml(tmp_path, _FULL_YAML)
    cfg = load_config(path)
    assert cfg.model_name_for_process("python") == "patient-diagnosis-v2"
    assert cfg.model_name_for_process("torchserve") == "fraud-detection-v1"


def test_model_name_for_unknown_process(tmp_path: pytest.TempPathFactory) -> None:
    path = _write_yaml(tmp_path, _FULL_YAML)
    cfg = load_config(path)
    assert cfg.model_name_for_process("nginx") == "unknown"


def test_batch_interval_seconds(tmp_path: pytest.TempPathFactory) -> None:
    path = _write_yaml(tmp_path, _FULL_YAML)
    cfg = load_config(path)
    assert cfg.batch_interval_seconds == pytest.approx(0.2)  # 200 ms


def test_file_not_found_raises(tmp_path: pytest.TempPathFactory) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(str(tmp_path / "nonexistent.yaml"))
