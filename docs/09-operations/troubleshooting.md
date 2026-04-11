# Troubleshooting

This document covers the most common problems encountered when installing, configuring, and running Guardian, with diagnosis steps and solutions for each.

---

## Permission Denied: /var/lib/guardian

**Symptom:**

```
PermissionError: [Errno 13] Permission denied: '/var/lib/guardian/buffer'
```

or in the agent log:

```
WARNING  agent.sender  Cannot write to /var/lib/guardian (PermissionError) — using /home/user/.guardian/buffer instead
```

**Cause:** The `guardian` user or the current user does not have write access to `/var/lib/guardian/buffer`.

**Solutions:**

Option 1 — Create the directory with correct ownership:

```bash
sudo mkdir -p /var/lib/guardian/buffer
sudo chown -R guardian:guardian /var/lib/guardian
sudo chmod 750 /var/lib/guardian
```

Option 2 — Use the home directory buffer path instead (edit `guardian.yaml`):

```yaml
agent:
  buffer_path: "~/.guardian/buffer"
```

Guardian will create this directory automatically if it does not exist. No sudo required.

Option 3 — The agent handles this automatically. When it cannot write to `buffer_path`, it falls back to `~/.guardian/buffer` and logs the above WARNING. If the fallback also fails, it logs an ERROR and drops the batch. See [Disk Buffer — Fallback Path](disk-buffer.md#fallback-path).

---

## Proto Stubs Not Found

**Symptom:**

```
WARNING  agent.sender  gRPC not available (No module named 'proto.guardian_pb2') — disk buffer only
```

or when running tests:

```
ModuleNotFoundError: No module named 'proto.guardian_pb2'
```

**Cause:** The gRPC protocol buffer stubs were not generated. These files are not committed to the repository and must be compiled from `proto/guardian.proto`.

**Solution:**

```bash
bash scripts/gen_proto.sh
```

Expected output:

```
Compiling .../proto/guardian.proto ...
Fixed import in .../proto/guardian_pb2_grpc.py
Done. Generated:
  proto/guardian_pb2.py
  proto/guardian_pb2_grpc.py
```

Verify the files exist:

```bash
ls proto/
# Should include: guardian_pb2.py  guardian_pb2_grpc.py
```

If `grpcio-tools` is not installed:

```bash
pip install grpcio-tools>=1.62.0
bash scripts/gen_proto.sh
```

---

## No guardian.yaml Found

**Symptom:**

```
FileNotFoundError: guardian.yaml not found in ./guardian.yaml, /etc/guardian/guardian.yaml, or ~/.guardian/guardian.yaml
```

**Cause:** Guardian searches three locations and found no configuration file.

**Solution:**

Copy the example file to the current directory:

```bash
cp guardian.yaml.example guardian.yaml
```

Or copy to the system location:

```bash
sudo mkdir -p /etc/guardian
sudo cp guardian.yaml.example /etc/guardian/guardian.yaml
```

Or specify an explicit path:

```bash
python -m agent.main --config /path/to/my/guardian.yaml
```

Remember to edit the file and set your API token before running.

---

## gRPC Connection Refused

**Symptom:**

```
ERROR    agent.sender  gRPC send failed (StatusCode.UNAVAILABLE: ...): buffering N events
```

or:

```
grpc._channel._InactiveRpcError: <_InactiveRpcError of RPC that terminated with:
    status = StatusCode.UNAVAILABLE
    details = "Connection refused"
```

**Diagnosis Steps:**

1. Check the `control_plane` value in `guardian.yaml`:

```bash
grep control_plane guardian.yaml
```

It should be `grpc.viriatosecurity.com:443` for production, or `localhost:50051` for local testing.

2. Verify outbound connectivity to the control plane:

```bash
curl -v https://grpc.viriatosecurity.com
# Should connect (may show HTTP/2 upgrade or TLS)
```

3. Check if a local test server should be running (for development):

```bash
# Start the demo with the test server:
python tools/demo.py --scene 6
```

4. If using `localhost` or `127.x.x.x`, ensure TLS is disabled:

```bash
GUARDIAN_INSECURE_GRPC=1 python -m agent.main
```

Guardian auto-detects `localhost` and `127.` addresses and uses insecure gRPC. For other local addresses (e.g., `192.168.1.x`), set `GUARDIAN_INSECURE_GRPC=1` explicitly.

**Behaviour when gRPC is unavailable:** Events are buffered to disk. The agent does not crash. When connectivity is restored, the buffer drains automatically on the next successful send. See [Disk Buffer](disk-buffer.md).

---

## "Guardian Token is Not Set or is Still the Placeholder"

**Symptom:**

```
WARNING  agent.config  Guardian token is not set or is still the placeholder — events will be rejected by the platform
```

**Cause:** The `token` field in `guardian.yaml` is still `YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE`.

**Solution:**

1. Get your token from [viriatosecurity.com](https://viriatosecurity.com)
2. Edit `guardian.yaml`:

```yaml
agent:
  token: "grd_live_abc123xyz789..."
```

The agent continues running with a WARNING when the token is the placeholder. Events are signed with the placeholder token and will be rejected by the platform (HTTP 401). They accumulate in the disk buffer. Once you set the correct token and restart the agent, the buffer drains and events are accepted.

---

## Chain Verification Failed

**Symptom:**

```
WARNING  agent.signer  Chain verification failed: event 0 prev_hash mismatch (expected 000000..., got a3f7c9...)
```

**Cause:** The agent restarted. The `Signer` starts a new chain from `GENESIS_HASH` (`0000...000`) on each startup. If the platform receives a batch whose first event's `prev_hash` is not `GENESIS_HASH` and does not follow from the previous batch, it detects a chain break.

**Is this a problem?** A chain break on agent restart is expected and not a security incident. The platform logs it as an informational event (agent restarted at timestamp T). A chain break without a restart is a security signal.

**What to do:**

- If the agent recently restarted (e.g., updated, server rebooted, systemd restart): no action needed. The platform records the restart event.
- If the agent did not restart and chain breaks are occurring repeatedly: investigate. This may indicate events are being tampered with in transit, the buffer is being replayed out of order, or there is a bug in the signer.

---

## BCC Import Error

**Symptom:**

```
WARNING  agent.loader  EbpfLoader unavailable: No module named 'bcc'
INFO     agent.main    Falling back to FakeEventGenerator
```

or:

```
ImportError: /usr/lib/python3/dist-packages/bcc/__init__.py: cannot import from 'ctypes'
```

**Cause:** The BCC (BPF Compiler Collection) Python library is not installed, or you are running on macOS where BPF is not available.

**Is this a problem?**

- **On macOS**: No. BCC requires a Linux kernel. Use `--fake` flag or `GUARDIAN_FAKE_EVENTS=1` for development on macOS. This is the expected and supported development workflow.
- **On Linux in Phase 1**: No. Phase 1 uses `FakeEventGenerator` and does not require BCC. The WARNING is informational.
- **On Linux in Phase 2**: Yes. Install BCC:

```bash
# Ubuntu 22.04
sudo apt-get install -y python3-bcc linux-headers-$(uname -r) clang-14
python3 -c "import bcc; print('BCC OK')"
```

---

## Tests Fail with Import Errors

**Symptom:**

```
ImportError: No module named 'agent'
```

or:

```
ImportError: No module named 'pytest'
```

**Cause:** The virtual environment is not activated.

**Solution:**

```bash
cd /path/to/guardian
source .venv/bin/activate
pip install -r requirements.txt
pytest tests/ -v
```

Verify you are using the venv Python:

```bash
which python
# Should print: /path/to/guardian/.venv/bin/python
```

If `.venv` does not exist:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Debug Mode

Enable full DEBUG logging to diagnose any issue:

```bash
python -m agent.main --fake --dry-run --log-level DEBUG
```

This emits detailed messages from all modules including:
- Config loading path and parsed values
- Agent ID file location and read/write operations
- Each event signed (with hash values)
- Each batch sent or buffered
- gRPC channel state

For systemd, view debug logs:

```bash
journalctl -u guardian -f --no-pager
```

To enable debug for a running service, edit the unit file to add `--log-level DEBUG` to `ExecStart`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl restart guardian
```

---

## Reading the Disk Buffer

Inspect buffered events without draining them:

```bash
# Development / macOS
cat ~/.guardian/buffer/pending.jsonl | python -m json.tool | head -50

# Linux production
cat /var/lib/guardian/buffer/pending.jsonl | python -m json.tool | head -50
```

Each line is one batch:

```json
{
  "agent_id": "3f7c1b2a-...",
  "signature": "a3f7c9d1e2b4f8a0...",
  "events": [
    {
      "timestamp": "2026-04-10T12:00:00.000000000Z",
      "pid": 1234,
      "process": "python",
      "syscall": "read",
      ...
    }
  ]
}
```

Count buffered batches:

```bash
wc -l ~/.guardian/buffer/pending.jsonl
```

Count total buffered events:

```bash
python3 -c "
import json
total = 0
with open('$HOME/.guardian/buffer/pending.jsonl') as f:
    for line in f:
        total += len(json.loads(line)['events'])
print(f'{total} buffered events')
"
```

---

## Checking the Agent ID

Guardian persists its agent ID across restarts. The location depends on the environment:

**Production (Linux, root)**:

```bash
cat /var/lib/guardian/.agent_id
```

**Development (macOS or non-root)**:

```bash
cat ~/.guardian_agent_id
```

Expected format: a UUID4 string, e.g., `3f7c1b2a-4d5e-6f7a-8b9c-0d1e2f3a4b5c`.

If the file is missing, Guardian generates a new UUID on startup and writes it. This causes a new agent registration in the Viriato Security console. The old agent ID will appear as inactive.

---

## Safely Clearing the Disk Buffer

Only clear the buffer after the Viriato Security platform has confirmed receipt of all buffered events. Clearing prematurely means those events are lost permanently.

To check if the platform has received all events, verify via the console dashboard that event count matches your expectation.

To clear:

```bash
# Development
> ~/.guardian/buffer/pending.jsonl
# or
rm ~/.guardian/buffer/pending.jsonl

# Production
sudo > /var/lib/guardian/buffer/pending.jsonl
```

Do not delete the directory itself, only the `pending.jsonl` file. The Sender recreates the file on the next buffered batch.

---

## Related Documents

- [Disk Buffer](disk-buffer.md)
- [Installation](installation.md)
- [Configuration](configuration.md)
- [Deployment](deployment.md)
- [Running Tests](../08-testing/running-tests.md)
