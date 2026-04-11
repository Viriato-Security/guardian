# Frequently Asked Questions

---

## General

**What is Guardian?**

Guardian is an eBPF-based AI observability agent. It captures kernel-level syscall
events from AI inference processes, enriches them with model and container context,
chains them cryptographically (SHA-256 per-event), signs each batch with HMAC-SHA256,
and streams them to the Viriato Security compliance platform. The result is a
tamper-evident audit log of what your AI model reads, writes, and connects to —
suitable as evidence for EU AI Act Article 12 compliance.

**Who is it for?**

Guardian is for organisations operating high-risk AI systems under the EU AI Act —
healthcare, finance, insurance, HR automation — who need to demonstrate to auditors
that their AI models are operating as intended and that the evidence record has not
been tampered with. It is also for AI infrastructure teams who want visibility into
what their models are doing at the kernel level without modifying application code.

**Is it open source?**

Guardian's source code is publicly available on GitHub. It is licensed under
BUSL-1.1 (Business Source License 1.1), which is source-available but not an
OSI-certified open-source license. You can read, study, and contribute to the code.
Production use requires a commercial license from Viriato Security. Each release
automatically converts to Apache 2.0 four years after its release date. See
[why-busl-not-mit.md](../11-alternatives/why-busl-not-mit.md).

**What does "dumb by design" mean?**

Guardian agents deliberately have no decision-making logic beyond local alert rules.
They capture, enrich, sign, and stream events — that is all. They do not:
- Enforce access controls.
- Block syscalls.
- Interpret compliance policy.
- Make judgements about whether behaviour is acceptable.

All policy interpretation and compliance analysis lives in the viriato-platform. This
keeps the agent small, auditable, and trustworthy. An agent that "acts" on compliance
data is more dangerous (and harder to audit) than one that only observes.

---

## Security

**Does Guardian slow my AI model?**

In Phase 1 (fake event generator, used on macOS and in CI), there is no kernel
overhead — events are synthesised in Python. In Phase 2 (eBPF on Linux), the
overhead is approximately 1% of CPU for typical AI inference workloads at 1,000–10,000
syscalls per second. eBPF probes run in kernel JIT-compiled code with no process
interruption. Compare this to ptrace, which adds 10–100x overhead. See
[why-not-ptrace.md](../11-alternatives/why-not-ptrace.md).

**How does the cryptographic chain work?**

Each event has two hash fields:

- `prev_hash`: The `this_hash` of the preceding event. The first event's `prev_hash`
  is `GENESIS_HASH` (64 zeros).
- `this_hash`: SHA-256 of all fields in this event (excluding `this_hash` itself),
  JSON-serialised with sorted keys.

This creates a linked chain. If any event is deleted, reordered, or modified, every
subsequent `prev_hash` will not match and the chain fails verification. The platform
runs `verify_chain()` on every batch received.

**What happens if someone deletes events from the platform database?**

Deletion is detectable. Each batch carries a cryptographic chain. The platform stores
the chain hashes independently of the event content. A gap in sequence numbers or a
hash mismatch in a stored batch is evidence of tampering. Additionally, the HMAC
batch signature was generated using the customer's token — the platform cannot
forge a valid signature for a modified or fabricated batch.

**What if the agent itself is compromised by root?**

A root-level attacker who controls the agent machine can forge events. Guardian does
not claim to defend against a compromised host. What Guardian provides is evidence
for the normal operating case and detection of tampering after the fact (via chain
verification). If the agent is compromised, the customer should treat all events from
that `agent_id` as suspect and investigate via other means.

**Why HMAC not a digital signature (Ed25519)?**

HMAC-SHA256 with the customer's API token was chosen because:
1. Both parties (agent and platform) already hold the token — no key distribution
   problem.
2. HMAC is simpler than asymmetric cryptography — no key generation, no certificate
   management, no key rotation ceremony.
3. HMAC-SHA256 is not vulnerable to length extension attacks (unlike bare SHA-256).
4. The compliance use case does not require non-repudiation between parties (the
   customer is both the signer and the beneficiary of the signature).

Ed25519 would be appropriate if Guardian needed to prove to a third party (e.g. an
auditor) that events were signed by the agent without revealing the signing key.
That is a potential future feature for platform-issued agent certificates.

---

## Installation

**What Python version do I need?**

Python 3.12 or later. Guardian uses `from __future__ import annotations` and
`datetime.now(timezone.utc)` (not the deprecated `datetime.utcnow()`), both of
which require Python 3.12+ for best compatibility. Strict mypy is run with
`python_version = "3.12"`.

**Do I need root to run Guardian?**

- **Phase 1 (fake generator)**: No root required. Runs anywhere Python 3.12 runs.
- **Phase 2 (eBPF on Linux)**: Yes. Loading eBPF programs requires `CAP_BPF +
  CAP_PERFMON` (Linux 5.8+) or `CAP_SYS_ADMIN` (older kernels). In production,
  Guardian runs as root in a DaemonSet pod with the appropriate Linux capabilities.

**What do I do if proto stubs are missing?**

Run:

```bash
bash scripts/gen_proto.sh
```

This requires `grpcio-tools` (installed via `pip install -r requirements.txt`). The
stubs are `.gitignore`d and never committed — they must be generated locally. If you
see `ImportError: cannot import name 'guardian_pb2'`, the stubs are missing.

---

## Configuration

**What processes should I watch?**

List the process names of your AI serving processes in `guardian.yaml` under `watch`:

```yaml
watch:
  - process: "python"
    model_name: "patient-diagnosis-v2"
  - process: "torchserve"
    model_name: "fraud-detection-v1"
```

Use the exact process name as it appears in `ps aux` (the `COMMAND` column, without
path). Guardian matches on process name, not path.

**What syscalls should I monitor?**

For AI inference workloads, the standard set is:

```yaml
syscalls:
  - read       # model weight reads, feature reads
  - write      # log writes, result writes
  - openat     # file opens
  - sendto     # outbound data
  - recvfrom   # inbound data
  - connect    # outbound connections
  - execve     # process execution (required for sandbox_escape alert)
  - clone      # thread creation
  - socket     # socket creation
```

`execve` must be in the list for the `sandbox_escape` alert to function. The fake
generator injects `execve` automatically regardless of this list, but the eBPF probe
in Phase 2 will filter by the configured list.

**What is the network_allowlist?**

A list of `host:port` strings specifying which outbound network addresses your AI
model is expected to connect to. An empty list disables the `unexpected_network`
alert. A non-empty list enables it — any `connect` or `sendto` to an unlisted
address fires the alert.

Example for a model that only talks to an internal feature store and a logging endpoint:

```yaml
network_allowlist:
  - "10.0.0.1:8080"
  - "10.0.1.45:5000"
```

---

## Operations

**What happens if the platform goes down?**

Guardian buffers events to `{buffer_path}/pending.jsonl` (JSONL format, one batch
per line, capped at 10,000 lines). On the next successful gRPC connection, the buffer
is drained oldest-first before new events are sent. If the buffer fills (10,000
lines), new batches are dropped with a log warning. The drop is visible in the logs
and can be monitored.

**How do I check if Guardian is working?**

```bash
# Check the process is running
ps aux | grep "agent.main"

# Check logs (if using systemd)
journalctl -u guardian -f

# Check the disk buffer (events accumulate here when platform is unreachable)
cat ~/.guardian/buffer/pending.jsonl | python -m json.tool | head -50

# Run in dry-run mode with debug logging
python -m agent.main --fake --dry-run --log-level DEBUG
```

A healthy agent logs `DRY RUN: batch ready — N events` (in dry-run mode) or
`Drained buffered batch (N events)` when successfully connecting.

**How do I read the disk buffer?**

The buffer file is JSONL — one JSON object per line. Each line contains:
- `agent_id`: The UUID of this Guardian installation.
- `signature`: The HMAC-SHA256 batch signature.
- `events`: A list of event dicts (same fields as `RawEvent`).

```bash
# Pretty-print the first buffered batch
head -1 ~/.guardian/buffer/pending.jsonl | python -m json.tool
```

**What is the agent_id?**

A UUID that uniquely identifies this Guardian installation. It is generated on first
run and persisted to `/var/lib/guardian/.agent_id` (Linux) or `~/.guardian_agent_id`
(macOS/dev). The platform uses it to group events by node. Do not delete or modify
this file — if it is lost, the platform will treat the next run as a new installation.

---

## Development

**How do I add a new syscall?**

Follow the step-by-step guide: [adding-a-syscall.md](../10-development/adding-a-syscall.md).
Summary: add to `guardian.yaml.example`, add weight to `_SYSCALL_WEIGHTS` in
`generator.py`, add field logic to `_make_syscall_event()`, add tests, add BCC
stub for Phase 2.

**How do I add a new alert?**

Follow the step-by-step guide: [adding-an-alert.md](../10-development/adding-an-alert.md).
Summary: design the rule, add `_check_<name>()` to `LocalAlertEngine`, register it
in `evaluate()`, add a `_<name>_enabled` constructor flag, add to
`guardian.yaml.example`, add tests covering fires/no-fires/custom-handler cases.

**How do I run a single test?**

```bash
# By test function name
python -m pytest tests/test_local_alerts.py::test_sandbox_escape_fires_on_bin_bash -v

# By keyword
python -m pytest tests/ -v -k "sandbox_escape"

# All tests in one file
python -m pytest tests/test_generator.py -v
```

---

## Phase Roadmap

**When is Phase 2?**

Phase 2 introduces the real eBPF event source using BCC. It requires Linux 5.8+
with BTF enabled. The Phase 2 ETA is on the internal roadmap; check the GitHub
milestones for the current target.

**Do I need to change anything when upgrading to Phase 2?**

No changes are required to `guardian.yaml` or the pipeline code. Phase 2 swaps the
event source (fake generator → eBPF probe) while keeping the same `RawEvent` schema,
enricher, signer, and sender. The `--fake` flag will continue to work for development
and testing.

**What is Phase 3?**

Phase 3 is a full rewrite of the agent in Rust, using Aya for eBPF and Tokio for
async I/O. It produces a statically linked binary with no Python runtime dependency.
The pipeline design (reader → enricher → signer → sender) and proto schema remain
the same. Phase 3 targets production deployments at high syscall rates where the
Python GIL becomes a bottleneck.

---

## EU AI Act

**Which articles does Guardian cover?**

Guardian's event capture supports evidence collection for:

| Article | Topic | How Guardian helps |
|---------|-------|--------------------|
| Article 12 | Record keeping | Provides tamper-evident event log |
| Article 13 | Transparency | Captures what data the model processes |
| Article 15 | Accuracy and robustness | Logs file access and network patterns |
| Article 17 | Quality management | Provides audit trail for operational review |
| Article 72 | Post-market monitoring | Continuous event stream from production |

**Does Guardian make me compliant?**

No. Guardian provides evidence. Compliance requires that evidence to be reviewed,
analysed, and reported by qualified persons, and that your organisation has the
policies and procedures the EU AI Act requires. Guardian is a tool, not a compliance
programme. Viriato Security's platform generates compliance reports from Guardian's
evidence, but the customer is responsible for their compliance posture.

**What is Article 12?**

Article 12 of the EU AI Act requires that high-risk AI systems "automatically record
events ('logs') throughout the lifetime of the AI system" sufficient to ensure
traceability and post-deployment monitoring. It specifically requires that logs
enable identification of situations presenting risk and facilitate post-market
monitoring. Guardian's cryptographically chained event log is designed to satisfy
this requirement.

---

## Related Documents

- [glossary.md](glossary.md)
- [api-reference.md](api-reference.md)
- [error-codes.md](error-codes.md)
- [../10-development/local-setup.md](../10-development/local-setup.md)
