# Migration Guide — Moving Between Phases

> How to upgrade Guardian between phases with zero event loss and maintained chain integrity.

Guardian's three-phase architecture is designed for seamless migration. Each phase uses the same `guardian.yaml` configuration, the same protobuf wire format, and the same disk buffer format. Moving from Phase 1 to Phase 2 to Phase 3 requires changing one component at a time, with easy rollback at every step.

---

## Overview

Guardian migrations are designed around three principles:

1. **Incremental**: Each migration changes the minimum possible — one component (the event source, then the runtime) while keeping everything else identical.
2. **Safe rollback**: Every phase supports rollback to the previous phase in seconds, with no data loss.
3. **Chain continuity semantics**: Agent restarts start fresh chains from `GENESIS_HASH`. This is expected behavior, not a gap in coverage. The platform tracks chains by `agent_id` + session timestamp.

Before any migration, ensure the current phase is running correctly: events are arriving on the platform, chain verification is passing, and local alerts are firing as expected.

---

## Phase 1 → Phase 2 Migration

### What Changes

The event source changes from `FakeEventGenerator` (Python, synthetic) to `EbpfLoader` (Python + BCC, real kernel events). Everything downstream — enricher, signer, sender, local alerts, gRPC transport, disk buffer, proto schema, and `guardian.yaml` format — is identical.

### Prerequisites Check

Before beginning, verify all Phase 2 requirements are met on the target Linux host:

**1. Linux kernel version:**
```bash
uname -r
```
Output must be `5.8.0` or higher. Ubuntu 22.04 ships with 5.15; Fedora 35+ ships with 5.14+; most cloud provider instances (AWS, GCP, Azure) on recent AMIs have 5.15+.

**2. BTF availability:**
```bash
ls -la /sys/kernel/btf/vmlinux
```
Must exist. If absent, the kernel was compiled without `CONFIG_DEBUG_INFO_BTF=y`. This is unlikely on any modern cloud instance but can occur on custom-compiled kernels or some embedded Linux distributions.

**3. clang version:**
```bash
clang --version
```
Must report version 14 or higher. Install if needed: `sudo apt-get install clang-14` (Ubuntu).

**4. BCC Python bindings:**
```bash
python3 -c "import bcc; print(bcc.__version__)"
```
Must succeed. Install: `sudo apt-get install python3-bcc` or `pip install bcc`. The system package is preferred because BCC needs access to kernel headers and the system Python's path configuration.

**5. EbpfLoader availability check:**
```bash
cd /path/to/guardian
python3 -c "from agent.loader import EbpfLoader; print('Available:', EbpfLoader.is_available())"
```
Must print `Available: True`. If False, one of the above checks is failing — re-run each check to identify the issue.

**6. BPF probe compilation (verify guardian.bpf.c compiles):**
```bash
# Generate vmlinux.h for this kernel
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > probe/vmlinux.h

# Compile the probe
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I/usr/include/bpf -I./probe \
    -c probe/guardian.bpf.c -o probe/guardian.bpf.o

echo "Exit code: $?"  # Must be 0
```
A non-zero exit code indicates a compilation error. Review the clang output — it will identify the specific BPF verifier or compiler issue.

### Step-by-Step: Phase 1 → Phase 2

**Step 1: While Phase 1 is still running, verify prerequisites (above).**

Keep the Phase 1 agent running during this step. Do not stop it until Phase 2 is verified.

**Step 2: Test Phase 2 loads correctly in dry-run.**

In a second terminal, run Phase 2 in dry-run mode (does not send events to the platform, does not write to the buffer):

```bash
sudo python3 -m agent.main \
    --config guardian.yaml \
    --dry-run \
    --log-level DEBUG \
    2>&1 | tee /tmp/phase2-dryrun.log
```

Look for these lines in the output:
- `"Event source: eBPF probe"` — confirms EbpfLoader is active
- `"Attached tracepoint: syscalls:sys_enter_read"` (and openat, execve)
- `"Watching N PIDs for M processes"` — confirms PID discovery worked
- Event log lines with real PIDs and real process names

If you see `"Falling back to fake event generator"`, one of the prerequisites failed — check the `EbpfLoader.is_available()` result.

**Step 3: Verify event schema.**

Inspect the dry-run log for event structure. Every event should have:
- `pid`: A real process PID (verify with `ps aux | grep python`)
- `process`: Matches a configured `watch` entry
- `syscall`: One of `read`, `openat`, `execve`
- `timestamp`: Close to current time (within a few seconds)
- `fd_path`: A real file path for `openat` events (e.g., `/usr/lib/python3.12/...`)
- `prev_hash` and `this_hash`: 64-character hex strings

**Step 4: Event parity comparison (optional but recommended).**

Run both agents simultaneously in dry-run and compare event structure:

```bash
# Terminal 1: Phase 1 (fake) in dry-run
GUARDIAN_FAKE_EVENTS=1 python3 -m agent.main \
    --dry-run --log-level DEBUG > /tmp/phase1-events.log &

# Terminal 2: Phase 2 (real eBPF) in dry-run
sudo python3 -m agent.main \
    --dry-run --log-level DEBUG > /tmp/phase2-events.log &

# After 30 seconds, stop both and compare field structure
kill %1 %2
```

Both logs should show events with the same 16-field structure. The content will differ (synthetic vs real) but field names and types must be identical.

**Step 5: Stop Phase 1, start Phase 2 in production.**

Drain the Phase 1 disk buffer before stopping (wait for a successful flush log line), then:

```bash
# Stop Phase 1 cleanly (SIGTERM allows final flush)
systemctl stop guardian
# or: kill -TERM $(pgrep -f "agent.main")

# Wait 5 seconds for final flush
sleep 5

# Start Phase 2
sudo systemctl start guardian
# or: sudo python3 -m agent.main --config guardian.yaml &
```

The Phase 1 disk buffer (if any) is automatically drained by Phase 2 on the first successful gRPC send.

**Step 6: Monitor for 24 hours.**

Check the platform UI for:
- Events arriving continuously from the agent
- `sandbox_escape` alerts firing correctly (trigger a test `execve` to `/bin/bash` in a watched process)
- Chain verification passing (no "chain integrity violation" alerts)
- No unexpected increase in error rates

**Step 7: Confirm rollback path works (optional).**

Test that rollback works:
```bash
# Switch to fake events instantly
sudo systemctl stop guardian
GUARDIAN_FAKE_EVENTS=1 sudo python3 -m agent.main --config guardian.yaml &
# Verify fake events appear in platform, then switch back
```

---

## Phase 2 → Phase 3 Migration

### What Changes

The agent runtime changes from Python to Rust. The BPF program changes from BCC-compiled C (`guardian.bpf.c`) to Aya-compiled Rust (`guardian-ebpf/src/main.rs`). The binary distribution changes from `python3 -m agent.main` to a single static binary.

Everything else is identical: proto schema, `guardian.yaml` format, disk buffer JSONL format, cryptographic algorithms, platform API. No platform changes are required.

### Prerequisites for Phase 3

- The Phase 3 binary compiled (`cargo build --release`) and tested on a non-production system
- Same Linux kernel requirements as Phase 2 (5.8+, BTF) — Phase 3 uses the same ring buffer and tracepoints
- No Python or BCC required on the target — the Phase 3 binary is self-contained

### Step-by-Step: Phase 2 → Phase 3

**Step 1: Download or build the Phase 3 binary.**

From a release (when available):
```bash
curl -L \
    https://github.com/Viriato-Security/guardian/releases/download/v3.0.0/guardian-linux-x86_64 \
    -o /usr/local/bin/guardian-v3
chmod +x /usr/local/bin/guardian-v3
```

From source (requires Rust toolchain with `bpfel-unknown-none` target):
```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install nightly
rustup target add bpfel-unknown-none --toolchain nightly

# Build
cd /path/to/guardian/guardian-agent
cargo build --release
# Binary at: target/release/guardian
```

**Step 2: Test Phase 3 in dry-run alongside Phase 2.**

```bash
# Phase 3 dry-run (different buffer directory to avoid conflicts)
sudo GUARDIAN_BUFFER_DIR=/tmp/guardian-v3-buffer \
    /usr/local/bin/guardian-v3 \
    --config guardian.yaml \
    --dry-run \
    --log-level debug
```

Verify the same checks as Phase 1→2: events have correct fields, process names match watched processes, timestamps are current.

**Step 3: Verify disk buffer compatibility.**

If Phase 2 has buffered events in `pending.jsonl`, Phase 3 must read and drain them correctly. Test this explicitly:

```bash
# Check existing buffer
wc -l ~/.guardian/buffer/pending.jsonl

# If buffer exists, run Phase 3 (not dry-run) briefly to drain it
sudo /usr/local/bin/guardian-v3 --config guardian.yaml --log-level debug &
# Watch for "Drained buffered batch" log lines
sleep 10
kill %1
```

**Step 4: Run the full Phase 3 agent alongside Phase 2.**

For maximum confidence, run both agents simultaneously (different buffer paths, same gRPC endpoint) for 30 minutes. Compare events in the platform UI. Both should produce events with identical field structure.

```bash
# Phase 2 (Python, production)
sudo python3 -m agent.main --config guardian.yaml &

# Phase 3 (Rust, validation)
sudo GUARDIAN_BUFFER_DIR=/tmp/guardian-v3 \
    /usr/local/bin/guardian-v3 --config guardian.yaml &
```

The platform will show two chains for the same `agent_id` — one from Phase 2 and one from Phase 3. This is expected during the side-by-side validation period.

**Step 5: Stop Phase 2, start Phase 3 as the sole agent.**

```bash
# Stop Phase 2 cleanly
sudo systemctl stop guardian
sleep 5

# Update systemd service file
sudo tee /etc/systemd/system/guardian.service > /dev/null <<'EOF'
[Unit]
Description=Guardian eBPF AI Observability Agent
After=network.target

[Service]
ExecStart=/usr/local/bin/guardian-v3 --config /etc/guardian/guardian.yaml
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_BPF CAP_SYS_ADMIN CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl start guardian
sudo systemctl enable guardian
```

**Step 6: Remove Phase 2 dependencies.**

Once Phase 3 is confirmed stable (24 hours, events flowing, alerts correct):

```bash
# Remove BCC and clang (only if not needed by other tools)
sudo apt-get remove python3-bcc clang-14

# Optionally remove Python and related packages
# (only if no other Python workloads on this host)
```

### Rollback: Phase 3 → Phase 2

```bash
sudo systemctl stop guardian

sudo tee /etc/systemd/system/guardian.service > /dev/null <<'EOF'
[Unit]
Description=Guardian eBPF AI Observability Agent
After=network.target

[Service]
ExecStart=/usr/bin/python3 -m agent.main --config /etc/guardian/guardian.yaml
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl start guardian
```

The disk buffer written by Phase 3 (`pending.jsonl`) is compatible with Phase 2 — both read and write the same JSON format.

---

## Event Parity Verification

Event parity verification confirms that Phase N and Phase N+1 produce structurally identical `RawEvent` instances. This is the core correctness check for any migration.

### Automated Parity Test

The schema parity test in Phase 2 integration tests (`tests/integration/test_schema_parity.py`) automates this check. Run it before any migration:

```bash
sudo pytest tests/integration/test_schema_parity.py -v
```

### Manual Field-by-Field Verification

For each field, compare the Phase 1 fake vs Phase 2 real event:

| Field | Phase 1 Fake | Phase 2 Real | Verification |
|-------|-------------|-------------|--------------|
| `timestamp` | ISO 8601 UTC string | ISO 8601 UTC string | Same format — compare regex match |
| `pid` | 1000–65535 synthetic int | Real process PID | Phase 2 PID exists in `ps aux` output |
| `uid` | 0–1000 synthetic int | Real effective UID | Phase 2 UID matches `id -u` for the process |
| `process` | From watch list | task_comm (15 chars max) | Both are in configured watch list |
| `syscall` | Weighted random string | Real syscall name | Both from the same set of known syscall names |
| `fd_path` | Pre-defined path pool | Real file path (openat) or /proc readlink (read) | Phase 2 paths exist on filesystem |
| `bytes` | 512–65536 synthetic | Real count argument | Phase 2 bytes match actual data transferred |
| `network_addr` | Pre-defined address pool | Real sockaddr formatted as IP:port | Phase 2 addresses are reachable network endpoints |
| `return_val` | "0" or errno string | "0" (sys_enter; sys_exit TODO) | Same default value in both phases |
| `agent_id` | UUID from enricher | UUID from enricher (same logic) | Same agent_id across both sources |
| `prev_hash` | 64-char hex from signer | 64-char hex from signer | Same GENESIS_HASH at start; chain matches |
| `this_hash` | SHA-256 of fields | SHA-256 of same fields | Same hash for same field values |

### Timestamp Bounds Check

Phase 2 timestamps come from `bpf_ktime_get_real_ns()` (kernel wall-clock time). Phase 1 timestamps come from Python's `datetime.now(timezone.utc)`. Both should be within 1 second of each other. A Phase 2 event with a timestamp more than 5 seconds in the past indicates a slow ring buffer drain — tune the poll interval.

---

## Chain Integrity Across Restarts

Every Guardian restart begins a new chain with `prev_hash = GENESIS_HASH` ("0" × 64). This is by design.

### Why Chains Restart on Agent Restart

The chain represents a continuous run of the agent. The chain hash links each event to the previous one, creating tamper-evident evidence for a specific time window. When the agent restarts (upgrade, crash, intentional stop), the previous chain closes and a new one begins.

The platform tracks chains by:
- `agent_id` (UUID): Identifies which Guardian instance sent the events (stable across restarts — persisted to disk)
- Chain session: The sequence of events from one GENESIS_HASH to the end of that run

An `agent_id` can have multiple chains over its lifetime — one per agent run. The platform UI shows chains as sessions for each agent.

### What the Platform Sees During Migration

**During Phase 1 → Phase 2 migration** (brief side-by-side period):
- Phase 1 chain continues until SIGTERM
- Phase 1 agent sends its final batch and closes the chain
- Phase 2 agent starts with a new GENESIS_HASH chain
- Platform shows: two chains for the same `agent_id`, with a brief gap at the restart time

**Expected platform behavior**:
- Chain gap (restart gap): Normal, logged as an informational event, not an alert
- New GENESIS_HASH: Expected on every agent restart
- Multiple chains per `agent_id`: Normal — one per agent lifecycle

### What Counts as Tamper Evidence

The platform raises a chain integrity alert when — within a continuous chain — any of these are detected:

- An event's `this_hash` does not match the SHA-256 recomputation from its fields
- An event's `prev_hash` does not match the previous event's `this_hash`
- Events are reordered within a batch (compared to submission order)
- An event is deleted from a batch that the platform has already received and stored
- The batch HMAC signature does not match the token

**A restart that begins a fresh chain from GENESIS_HASH is not tamper evidence.** The platform expects this. Only within-chain anomalies trigger alerts.

### Preserving Chain Integrity During Migration

If you want to minimise the chain gap during migration:

1. Allow all in-memory events to flush (wait for a `"batch flushed"` log line after the last event)
2. Allow all disk-buffered events to drain (wait for `"buffer drained"` log line)
3. Stop the old agent cleanly with SIGTERM (not SIGKILL — SIGTERM triggers a final flush)
4. Start the new agent immediately

The gap between the last batch of the old chain and the first batch of the new chain will be approximately 0–2 seconds. The platform logs this as a session boundary, not an alert.

---

## Rollback Procedure

### Phase 2 → Phase 1 (Any Time)

If Phase 2 causes issues (BPF verifier errors, unexpected events, higher-than-expected CPU), rollback to Phase 1 takes seconds:

```bash
# Option 1: Restart with --fake flag
sudo systemctl stop guardian
sudo -E env GUARDIAN_FAKE_EVENTS=1 python3 -m agent.main --config guardian.yaml &

# Option 2: Add to systemd service and restart
sudo systemctl edit guardian
# Add: Environment=GUARDIAN_FAKE_EVENTS=1
sudo systemctl restart guardian
```

The `--fake` flag or `GUARDIAN_FAKE_EVENTS=1` bypasses `EbpfLoader.is_available()` and forces `FakeEventGenerator`. This is identical to Phase 1 behavior. No code changes, no package changes, no configuration changes.

The `pending.jsonl` disk buffer survives the restart and is drained when connectivity returns. No events are lost during rollback.

### Phase 3 → Phase 2 (Any Time)

Roll back by switching the systemd service to the Python agent:

```bash
sudo systemctl stop guardian
# Update ExecStart back to python3 -m agent.main
sudo systemctl start guardian
```

The JSONL disk buffer written by Phase 3 Rust is compatible with Phase 2 Python — both use the same JSON format. Buffered events written during Phase 3 are drained by Phase 2 after rollback.

---

## Troubleshooting Common Migration Issues

### `EbpfLoader.is_available()` returns False

**Check 1**: Not Linux → Expected on macOS.
**Check 2**: `/sys/kernel/btf/vmlinux` missing → Kernel compiled without BTF. Use a different kernel or OS image.
**Check 3**: `import bcc` fails → BCC not installed. `sudo apt-get install python3-bcc` or `pip install bcc`.
**Check 4**: Kernel version < 5.8 → Upgrade the kernel.

### BPF program load fails with verifier error

The BPF verifier rejected `guardian.bpf.c`. The verifier log will identify the exact instruction and reason. Common causes:
- Missing null check after `bpf_map_lookup_elem()` → Add a null guard
- Stack overflow (struct too large for stack) → Use `bpf_ringbuf_reserve()` pattern (already done in guardian)
- Uninitialized memory read → Zero-initialize the struct before filling fields

### Events appear with wrong PID

The `watched_pids` map may contain stale PIDs (from processes that exited). The 5-second PID discovery loop cleans these up. If many stale PIDs accumulate (rapid process churn), reduce the discovery interval.

### No events appearing after Phase 2 start

1. Verify `watched_pids` map is populated: `sudo bpftool map dump name watched_pids`
2. Verify the watched process is running: `ps aux | grep python`
3. Verify the process is actually making syscalls: `sudo strace -c -p $(pgrep python3) sleep 5`
4. Check ring buffer isn't filling up: Look for `"ring buffer full"` log lines

### Chain verification fails on platform

This occurs if event fields are not being hashed in the correct order or with the correct JSON serialisation. The hash must be computed over the JSON serialisation of the fields with `sort_keys=True` and `separators=(",", ":")`. Verify with `python3 -c "from agent.signer import Signer; ..."`.

---

## Summary

Guardian migrations are designed to be safe, incremental, and reversible:

- **Phase 1 → Phase 2**: Change the event source (fake → real eBPF). Prerequisites check, dry-run validation, then cutover. Rollback: set `GUARDIAN_FAKE_EVENTS=1`.
- **Phase 2 → Phase 3**: Change the runtime (Python → Rust). Dry-run validation, side-by-side comparison, then cutover. Rollback: revert systemd service.
- **Chain restarts**: Expected on every agent restart — not tamper evidence. Platform tracks by `agent_id` + session.
- **Disk buffer**: JSONL format is language-agnostic — buffered events survive migrations between phases.

---

## Related Documents

- [Phase 1: Python Agent](phase1-python-agent.md)
- [Phase 2: Real eBPF](phase2-real-ebpf.md)
- [Phase 3: Rust Rewrite](phase3-rust-rewrite.md)
- [Phase 1 vs Phase 2](../06-ebpf/phase1-vs-phase2.md)
- [Event Chaining](../04-security/event-chaining.md)
- [Cryptographic Design](../04-security/cryptographic-design.md)
- [Disk Buffer](../09-operations/disk-buffer.md)
- [Deployment](../09-operations/deployment.md)
