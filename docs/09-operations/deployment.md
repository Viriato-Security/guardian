# Deployment

This document covers production deployment of Guardian on Linux as a systemd service, as a Docker sidecar container, and as a Kubernetes DaemonSet. Phase 1 covers the Python agent only. Phase 2 eBPF requirements (kernel capabilities) are noted where they differ.

---

## Network Requirements

Guardian requires one outbound connection:

| Destination | Protocol | Port | Purpose |
|-------------|---------|------|---------|
| `grpc.viriatosecurity.com` | gRPC / HTTP2 over TLS | 443 | Event delivery to control plane |

No inbound ports are required. Guardian does not run a server process.

If port 443 is blocked, contact [hello@viriatosecurity.com](mailto:hello@viriatosecurity.com) for an alternative endpoint.

---

## Linux Systemd Service

### Prerequisites

- Ubuntu 20.04+ or any systemd-based Linux distribution
- Python 3.12+ installed system-wide
- A system user `guardian` created for the service

### Setup

**1. Create the guardian system user:**

```bash
sudo useradd --system --shell /usr/sbin/nologin --home /var/lib/guardian guardian
sudo mkdir -p /var/lib/guardian/buffer
sudo chown -R guardian:guardian /var/lib/guardian
```

**2. Install Guardian:**

```bash
sudo git clone https://github.com/Viriato-Security/guardian.git /opt/guardian
cd /opt/guardian
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt
sudo bash scripts/gen_proto.sh
```

**3. Configure:**

```bash
sudo mkdir -p /etc/guardian
sudo cp /opt/guardian/guardian.yaml.example /etc/guardian/guardian.yaml
sudo nano /etc/guardian/guardian.yaml
# Set your API token and watch list
sudo chmod 640 /etc/guardian/guardian.yaml
sudo chown root:guardian /etc/guardian/guardian.yaml
```

**4. Create the systemd unit file:**

```ini
# /etc/systemd/system/guardian.service
[Unit]
Description=Guardian AI Observability Agent
Documentation=https://github.com/Viriato-Security/guardian
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=guardian
Group=guardian
WorkingDirectory=/opt/guardian

# Phase 1: Python agent with fake events or Phase 2: real eBPF
# For Phase 1 testing:
#   ExecStart=/opt/guardian/.venv/bin/python -m agent.main --fake
# For Phase 2 production (requires CAP_BPF):
ExecStart=/opt/guardian/.venv/bin/python -m agent.main \
    --config /etc/guardian/guardian.yaml

# Phase 2 only: uncomment to grant BPF capability without full root
# AmbientCapabilities=CAP_BPF CAP_SYS_PTRACE
# CapabilityBoundingSet=CAP_BPF CAP_SYS_PTRACE

Environment="PYTHONUNBUFFERED=1"
EnvironmentFile=-/etc/guardian/guardian.env

# Restart policy
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=3

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=guardian

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/guardian /tmp

[Install]
WantedBy=multi-user.target
```

**5. Enable and start the service:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable guardian
sudo systemctl start guardian
sudo systemctl status guardian
```

**6. Verify it is running:**

```bash
journalctl -u guardian -f
```

Expected log output:

```
guardian[1234]: INFO     agent.config     Loaded config from /etc/guardian/guardian.yaml
guardian[1234]: INFO     agent.enricher   Agent ID: <uuid>
guardian[1234]: INFO     agent.main       Guardian agent started
```

### Optional Environment File

Sensitive values can be placed in `/etc/guardian/guardian.env` (referenced by `EnvironmentFile=-/etc/guardian/guardian.env`):

```bash
# /etc/guardian/guardian.env
GUARDIAN_TOKEN=grd_live_abc123xyz789
```

And in `guardian.yaml`, reference the environment variable:
```yaml
agent:
  token: "${GUARDIAN_TOKEN}"
```

---

## Docker Sidecar Container

Run Guardian as a sidecar alongside your AI workload container.

### Dockerfile

```dockerfile
FROM python:3.12-slim

WORKDIR /opt/guardian

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN bash scripts/gen_proto.sh

# Default config path (override with --config)
COPY guardian.yaml.example /etc/guardian/guardian.yaml

RUN useradd --system --shell /usr/sbin/nologin guardian \
    && mkdir -p /var/lib/guardian/buffer \
    && chown -R guardian:guardian /var/lib/guardian

USER guardian

ENTRYPOINT ["python", "-m", "agent.main"]
CMD ["--config", "/etc/guardian/guardian.yaml"]
```

### docker-compose.yml

```yaml
version: "3.9"

services:
  # Your AI workload
  torchserve:
    image: pytorch/torchserve:latest
    volumes:
      - model-store:/home/model-server/model-store
    networks:
      - ai-net

  # Guardian sidecar
  guardian:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      - GUARDIAN_TOKEN=grd_live_abc123xyz789
      - KUBERNETES_POD_NAME=local-dev
      - KUBERNETES_NAMESPACE=default
    volumes:
      - ./guardian.yaml:/etc/guardian/guardian.yaml:ro
      - guardian-buffer:/var/lib/guardian/buffer
    networks:
      - ai-net
    # Phase 2 only: share process namespace for /proc access
    # pid: service:torchserve
    restart: unless-stopped
    depends_on:
      - torchserve

volumes:
  model-store:
  guardian-buffer:

networks:
  ai-net:
```

Build and run:

```bash
docker-compose up -d guardian
docker-compose logs -f guardian
```

---

## Kubernetes DaemonSet

Deploy Guardian as a DaemonSet so one instance runs on every node that hosts AI workloads.

### Complete DaemonSet YAML

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: guardian-system

---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: guardian
  namespace: guardian-system

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: guardian-config
  namespace: guardian-system
data:
  guardian.yaml: |
    agent:
      token: "REPLACED_BY_SECRET"
      control_plane: "grpc.viriatosecurity.com:443"
      batch_interval_ms: 100
      buffer_path: "/var/lib/guardian/buffer"

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
        condition: "execve matches shell"
        action: log_and_alert
      - type: unexpected_network
        condition: "connect not in allowlist"
        action: log_and_alert

    network_allowlist: []

    compliance:
      organization: "Acme Healthcare AI"
      data_categories:
        - medical_records
      articles: [12, 13, 15, 17]

---
apiVersion: v1
kind: Secret
metadata:
  name: guardian-token
  namespace: guardian-system
type: Opaque
stringData:
  token: "grd_live_YOUR_TOKEN_HERE"

---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: guardian
  namespace: guardian-system
  labels:
    app: guardian
    version: "0.1.0"
spec:
  selector:
    matchLabels:
      app: guardian
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  template:
    metadata:
      labels:
        app: guardian
        version: "0.1.0"
    spec:
      serviceAccountName: guardian
      tolerations:
        # Allow scheduling on all nodes including control plane
        - operator: Exists
          effect: NoSchedule

      containers:
        - name: guardian
          image: ghcr.io/viriato-security/guardian:0.1.0
          imagePullPolicy: Always

          args:
            - "--config"
            - "/etc/guardian/guardian.yaml"

          env:
            # Inject pod identity via Downward API
            - name: KUBERNETES_POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: KUBERNETES_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            # Inject token from secret
            - name: GUARDIAN_TOKEN
              valueFrom:
                secretKeyRef:
                  name: guardian-token
                  key: token
            - name: PYTHONUNBUFFERED
              value: "1"

          volumeMounts:
            - name: config
              mountPath: /etc/guardian
              readOnly: true
            - name: buffer
              mountPath: /var/lib/guardian/buffer
            # Phase 2 only: mount /proc and /sys for eBPF
            # - name: proc
            #   mountPath: /host/proc
            #   readOnly: true
            # - name: sys
            #   mountPath: /host/sys
            #   readOnly: true

          resources:
            requests:
              cpu: "50m"
              memory: "64Mi"
            limits:
              cpu: "200m"
              memory: "256Mi"

          # Phase 2 only: BPF capability
          # securityContext:
          #   capabilities:
          #     add:
          #       - BPF
          #       - SYS_PTRACE
          #   readOnlyRootFilesystem: true

          livenessProbe:
            exec:
              command:
                - python
                - -c
                - "import os; os.kill(1, 0)"
            initialDelaySeconds: 10
            periodSeconds: 30

      volumes:
        - name: config
          configMap:
            name: guardian-config
        - name: buffer
          hostPath:
            path: /var/lib/guardian/buffer
            type: DirectoryOrCreate
        # Phase 2 only:
        # - name: proc
        #   hostPath:
        #     path: /proc
        # - name: sys
        #   hostPath:
        #     path: /sys
```

Deploy:

```bash
kubectl apply -f guardian-daemonset.yaml
kubectl -n guardian-system get pods
kubectl -n guardian-system logs -l app=guardian -f
```

### Downward API for Pod Identity

The DaemonSet injects `KUBERNETES_POD_NAME` and `KUBERNETES_NAMESPACE` via the Kubernetes Downward API. Guardian's `Enricher` reads these environment variables and attaches them to every event, enabling filtering by pod and namespace in the Viriato Security console.

---

## Security: Minimum Privileges

### Phase 1 (Python Agent Only)

Phase 1 requires no special privileges. The `guardian` system user needs:
- Read access to `guardian.yaml`
- Write access to `buffer_path` (e.g., `/var/lib/guardian/buffer`)
- Outbound TCP to `grpc.viriatosecurity.com:443`

### Phase 2 (eBPF Probe)

Phase 2 requires additional Linux capabilities for the eBPF probe. The goal is to grant the minimum required capabilities rather than running as root:

| Capability | Why needed |
|-----------|-----------|
| `CAP_BPF` | Load and attach eBPF programs |
| `CAP_SYS_PTRACE` | Read `/proc/<pid>/mem` for context enrichment |
| `CAP_PERFMON` | Access perf event ring buffers |

These capabilities are set via `AmbientCapabilities` in the systemd unit or `securityContext.capabilities.add` in Kubernetes. Full root is not required in Phase 2.

---

## Health Monitoring

Monitor the Guardian agent with these signals:

### Disk Buffer Size

If `total_buffered > 0` and growing, events are not reaching the control plane. Check network connectivity and the gRPC endpoint.

```bash
wc -l ~/.guardian/buffer/pending.jsonl
# or for system install:
wc -l /var/lib/guardian/buffer/pending.jsonl
```

Alert if this exceeds 100 lines for more than 5 minutes.

### Agent Process

Monitor that the Guardian process is running:

```bash
# systemd
systemctl is-active guardian

# Kubernetes
kubectl -n guardian-system get pods -l app=guardian
```

Alert if the process is not running.

### Log Errors

Watch for these log patterns:

| Pattern | Meaning |
|---------|---------|
| `gRPC send failed` | Connectivity issue; buffering |
| `Disk buffer full (10000 lines)` | Extended outage; events being dropped |
| `Chain verification failed` | Agent restarted (expected on restart); investigate if repeated without restart |
| `Guardian token is not set` | Configuration error; events not accepted by platform |

---

## Related Documents

- [Installation](installation.md)
- [Configuration](configuration.md)
- [Disk Buffer](disk-buffer.md)
- [Troubleshooting](troubleshooting.md)
