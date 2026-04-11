# Configuration

Guardian is configured via a YAML file. The agent searches for this file in the following locations, in order:

1. `./guardian.yaml` — current working directory
2. `/etc/guardian/guardian.yaml` — system-wide (Linux production)
3. `~/.guardian/guardian.yaml` — user home directory

To specify an explicit path:

```bash
python -m agent.main --config /path/to/guardian.yaml
```

The example configuration is at `guardian.yaml.example` in the repository root.

---

## Getting an API Token

1. Create an account at [viriatosecurity.com](https://viriatosecurity.com)
2. Navigate to the API Tokens section in the console
3. Generate a new token for your deployment
4. Copy the token value

The token authenticates your Guardian agent to the Viriato Security control plane. Each deployment (host, container, or Kubernetes node) should use its own token if you want per-deployment attribution in the console.

If the token is missing or is still the placeholder value `YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE`, Guardian logs a WARNING on startup but continues running. Batches will be signed with the placeholder token and rejected by the control plane.

---

## Complete Configuration Reference

```yaml
agent:
  token: "YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE"
  control_plane: "grpc.viriatosecurity.com:443"
  batch_interval_ms: 100
  buffer_path: "~/.guardian/buffer"

watch:
  - process: "python"
    model_name: "patient-diagnosis-v2"
  - process: "torchserve"
    model_name: "fraud-detection-v1"

syscalls:
  - read
  - write
  - openat
  - sendto
  - recvfrom
  - connect
  - execve
  - clone
  - socket

local_alerts:
  - type: sandbox_escape
    condition: "execve matches /bin/bash or /bin/sh"
    action: log_and_alert
  - type: unexpected_network
    condition: "connect to addr not in allowlist"
    action: log_and_alert

network_allowlist: []

compliance:
  organization: "Acme Healthcare AI"
  data_categories:
    - medical_records
    - PII
  articles: [12, 13, 15, 17, 72]
```

---

## agent Section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `token` | string | (required) | API token from viriatosecurity.com |
| `control_plane` | string | `grpc.viriatosecurity.com:443` | gRPC endpoint for the Viriato platform |
| `batch_interval_ms` | integer | `100` | How often to send a batch (milliseconds) |
| `buffer_path` | string | `~/.guardian/buffer` | Directory for disk buffer fallback |

### token

```yaml
agent:
  token: "grd_live_abc123xyz789..."
```

The token is sent as gRPC metadata with each batch. It is used by the platform to authenticate the agent and associate events with your account.

### control_plane

```yaml
agent:
  control_plane: "grpc.viriatosecurity.com:443"
```

The host and port of the Viriato Security gRPC endpoint. Uses TLS by default. To disable TLS for local development, set `GUARDIAN_INSECURE_GRPC=1`.

For local testing with `tools/demo.py`, the test server runs on `localhost:50051`.

### batch_interval_ms

```yaml
agent:
  batch_interval_ms: 100    # 100ms = 10 batches/second
```

Controls how frequently events are grouped into a batch and sent. Lower values reduce latency but increase gRPC overhead. The default of 100ms (10 batches per second) is appropriate for most deployments.

`batch_interval_seconds` is a derived property: `batch_interval_ms / 1000.0`.

### buffer_path

```yaml
agent:
  buffer_path: "/var/lib/guardian/buffer"    # Linux production
  # buffer_path: "~/.guardian/buffer"        # macOS / dev
```

Directory where `pending.jsonl` is written when gRPC delivery fails. On PermissionError (e.g., `/var/lib/guardian/buffer` is not writable), Guardian automatically falls back to `~/.guardian/buffer`.

See [Disk Buffer](disk-buffer.md) for complete documentation.

---

## watch Section

The `watch` list defines which processes Guardian monitors and what model name to attach to their events.

```yaml
watch:
  - process: "python"
    model_name: "patient-diagnosis-v2"
  - process: "torchserve"
    model_name: "fraud-detection-v1"
  - process: "vllm"
    model_name: "llm-production-v3"
```

| Field | Description |
|-------|-------------|
| `process` | Exact process name as it appears in `/proc/<pid>/comm` (Linux) |
| `model_name` | Human-readable model identifier sent with every event from this process |

Events from processes not in the watch list are still captured but receive `model_name: "unknown"`.

In Phase 1 with `FakeEventGenerator`, events are generated with `process` values randomly selected from this watch list.

In Phase 2 with the eBPF probe, the probe filters kernel ring buffer events to include only PIDs whose process name matches a `watch` entry.

---

## syscalls Section

```yaml
syscalls:
  - read
  - write
  - openat
  - sendto
  - recvfrom
  - connect
  - execve
  - clone
  - socket
```

The list of syscall names to trace. In Phase 2, the eBPF probe attaches kprobes only for syscalls in this list. Removing a syscall reduces overhead but also reduces visibility.

Recommended syscalls for AI workload monitoring:

| Syscall | Why it matters |
|---------|---------------|
| `read` | Model weight file reads, dataset reads |
| `write` | Log writes, output writes |
| `openat` | File open operations (model loading) |
| `sendto` | Network sends (inference results, telemetry) |
| `recvfrom` | Network receives (incoming requests) |
| `connect` | Outbound connection initiations |
| `execve` | Process execution (sandbox escape detection) |
| `clone` | Process/thread creation |
| `socket` | Socket creation |

---

## local_alerts Section

Local alerts fire immediately on the host without waiting for a round-trip to the control plane. They use the `LocalAlertEngine` in `agent/local_alerts.py`.

```yaml
local_alerts:
  - type: sandbox_escape
    condition: "execve matches /bin/bash or /bin/sh"
    action: log_and_alert
  - type: unexpected_network
    condition: "connect to addr not in allowlist"
    action: log_and_alert
```

### sandbox_escape

Fires when a watched process executes a shell binary. Specifically, when:
- `syscall == "execve"`
- `fd_path` is one of: `/bin/bash`, `/bin/sh`, `/usr/bin/sh`, `/usr/bin/bash`, or any path ending in `sh` or `bash`

A Python process executing `/bin/bash` is a strong signal of a prompt injection attack or container escape attempt.

### unexpected_network

Fires when a watched process initiates a network connection to an address not in `network_allowlist`. Specifically, when:
- `syscall == "connect"`
- `network_addr` is not in the allowlist

Does not fire for `recvfrom` (inbound), only `connect` (outbound initiation).

If `network_allowlist` is empty, this rule is disabled (all connections are allowed). Populate the allowlist with your known-good endpoints to enable this rule.

### action

Currently, `log_and_alert` is the only supported action. It logs a WARNING to stderr and calls the registered alert handler. Future actions will include `block` (kill the process) and `quarantine`.

---

## network_allowlist Section

```yaml
network_allowlist:
  - "10.0.0.1:8080"
  - "172.16.0.0/16:443"
  - "internal-db.prod:5432"
```

List of allowed `host:port` addresses for outbound `connect` syscalls. If a `connect` event's `network_addr` is not in this list, the `unexpected_network` alert fires (if that rule is enabled).

An empty `network_allowlist` disables the unexpected network rule entirely. This is the safe default: if you have not populated the allowlist, the rule will not fire false positives.

---

## compliance Section

```yaml
compliance:
  organization: "Acme Healthcare AI"
  data_categories:
    - medical_records
    - PII
  articles: [12, 13, 15, 17, 72]
```

Compliance metadata is attached to batches sent to the control plane. It is used for compliance reporting dashboards and audit exports.

| Field | Description |
|-------|-------------|
| `organization` | Human-readable organization name |
| `data_categories` | Types of data processed by monitored AI systems |
| `articles` | Regulatory article numbers (e.g., GDPR Article 13, EU AI Act Article 12) |

---

## Environment Variables

These variables override `guardian.yaml` behaviour at runtime without modifying the file:

| Variable | Value | Effect |
|----------|-------|--------|
| `GUARDIAN_INSECURE_GRPC` | `1` | Use insecure (no-TLS) gRPC channel. Required for local test server. |
| `GUARDIAN_FAKE_EVENTS` | `1` | Force `FakeEventGenerator` even if eBPF is available. |

### GUARDIAN_INSECURE_GRPC

```bash
GUARDIAN_INSECURE_GRPC=1 python -m agent.main
```

Use when `control_plane` is `localhost:50051` or another local address without TLS. Guardian also auto-detects `localhost` and `127.x.x.x` addresses and uses insecure gRPC for those automatically.

### GUARDIAN_FAKE_EVENTS

```bash
GUARDIAN_FAKE_EVENTS=1 python -m agent.main
```

Forces the fake event generator regardless of whether the eBPF probe is available. Use for development on macOS, CI, and dry-run testing.

---

## Kubernetes Configuration

In a Kubernetes DaemonSet, use the Downward API to inject `pod_name` and `namespace` as environment variables so Guardian can attach them to every event:

```yaml
# In your DaemonSet pod spec:
env:
  - name: KUBERNETES_POD_NAME
    valueFrom:
      fieldRef:
        fieldPath: metadata.name
  - name: KUBERNETES_NAMESPACE
    valueFrom:
      fieldRef:
        fieldPath: metadata.namespace
```

Guardian reads these variables in `agent/enricher.py` and sets `event.pod_name` and `event.namespace` on every enriched event.

The `guardian.yaml` for Kubernetes typically uses `/var/lib/guardian/buffer` for the buffer path:

```yaml
agent:
  token: "grd_live_..."
  control_plane: "grpc.viriatosecurity.com:443"
  batch_interval_ms: 100
  buffer_path: "/var/lib/guardian/buffer"
```

This path should be backed by a `hostPath` volume so it persists across pod restarts. See [Deployment — Kubernetes DaemonSet](deployment.md#kubernetes-daemonset) for the complete DaemonSet YAML.

---

## Example: systemd Service Configuration

For a systemd-managed Linux service, store the configuration at `/etc/guardian/guardian.yaml`:

```bash
sudo mkdir -p /etc/guardian
sudo cp guardian.yaml /etc/guardian/guardian.yaml
sudo chmod 640 /etc/guardian/guardian.yaml
sudo chown root:guardian /etc/guardian/guardian.yaml
```

The systemd unit file specifies the config path via an environment file or directly. See [Deployment — Systemd](deployment.md#linux-systemd-service) for the complete unit file.

---

## Related Documents

- [Installation](installation.md)
- [Deployment](deployment.md)
- [Disk Buffer](disk-buffer.md)
- [Troubleshooting](troubleshooting.md)
