# Guardian Threat Model

## Overview

This document describes the threat model for the Guardian eBPF AI observability agent. It identifies the assets Guardian protects, the threat actors considered in the design, concrete threats with their mitigations and residual risks, explicit non-goals, trust boundaries, and the precise set of things Guardian trusts versus does not trust.

Guardian is a host agent. It runs as a privileged process on a Linux host (or as a fake-event generator on macOS/CI), reads kernel events, enriches them with context, chains them cryptographically, and forwards signed batches to the Viriato Security control plane. Each of these stages introduces attack surface that must be reasoned about explicitly.

---

## Assets

### 1. Event Stream Integrity

The ordered stream of syscall events that Guardian records constitutes a tamper-evident audit log of AI model behaviour. If an attacker can silently delete, insert, reorder, or mutate events before they reach the control plane, a security investigation could be misled or compliance evidence could be forged.

Guardian protects this asset with a SHA-256 hash chain (every event commits to all previous events) and an HMAC-SHA256 batch signature. See `docs/04-security/event-chaining.md` and `docs/04-security/batch-signing.md` for full details.

### 2. API Token

The API token in `guardian.yaml` is the HMAC signing key. Anyone who obtains this token can forge valid batch signatures, undermining the authenticity property of the event stream. The token is also the credential used to authenticate to `grpc.viriatosecurity.com:443`.

### 3. Customer Process Data

The events Guardian captures contain process names, file paths, network addresses, PIDs, UIDs, and timestamps. In regulated environments (healthcare, finance) these fields may constitute sensitive operational data subject to privacy and compliance obligations. The EU AI Act compliance fields in `ComplianceConfig` reflect this explicitly.

---

## Threat Actors

### A. Malicious AI Model Process

A compromised or adversarially fine-tuned model running as a monitored process that attempts to evade Guardian's detection by spawning shells, exfiltrating data through unexpected network connections, or manipulating the Guardian agent itself.

**Capability level:** Can execute arbitrary code within its container or process namespace. May attempt to write to Guardian's buffer path, signal the agent process, or use side channels.

### B. Compromised Container

A container that has been taken over (e.g. supply-chain attack, CVE exploitation) and whose attacker wants to hide activity from Guardian's audit log. Distinct from the AI model actor in that the attacker may have broader container capabilities including filesystem writes to shared volumes.

**Capability level:** Full process execution within the container, possible access to shared volumes. Cannot typically escape the kernel namespaces without a kernel exploit.

### C. Network Attacker

An attacker with access to the network between the Guardian agent and `grpc.viriatosecurity.com:443`. May attempt man-in-the-middle interception to read event data, replay stale batches, or inject fabricated batches.

**Capability level:** Passive interception and active injection on the network path. Cannot modify kernel memory directly.

### D. Insider Threat

A legitimate user or operator with access to the Viriato Security console, a customer's `guardian.yaml`, or the host filesystem. May attempt to rotate the token to break the audit chain, delete the buffer file, or read sensitive event data.

**Capability level:** Read access to `guardian.yaml` and the disk buffer. May have shell access to the host.

### E. Compromised Platform (Viriato Control Plane)

The Viriato Security control plane itself is compromised. An attacker who controls the platform can read all ingested event data, but cannot retroactively forge events that were signed with a valid token before the compromise was possible.

**Capability level:** Full access to ingested data and the ability to forge responses. Cannot produce valid HMAC signatures for past events without the customer's token.

---

## Threats, Mitigations, and Residual Risks

### T-1: Event Deletion

**Description:** An attacker (actors B, D) deletes events from the disk buffer (`pending.jsonl`) or tampers with the event stream after signing but before transmission.

**Mitigation:** The hash chain means any deletion of an interior event breaks chain continuity. `verify_chain()` will detect the gap because `events[i].prev_hash` will not match `events[i-1].this_hash`. The batch signature also changes if the hash list changes.

**Residual Risk:** An attacker who deletes the _tail_ of the stream (the most recent, not-yet-sent events) cannot be detected cryptographically because those events were never committed into a chain that the platform holds. Guardian mitigates this by sending frequently (default `batch_interval_ms=100`) to reduce the window.

---

### T-2: Event Insertion

**Description:** An attacker inserts fabricated events into the stream to manufacture a false audit trail.

**Mitigation:** Inserting an event between event _i_ and event _i+1_ requires recomputing all subsequent hashes (since each event commits to the previous). The attacker would also need the HMAC signing key (the API token) to produce a valid batch signature for the modified set. Without the token, the batch signature will be invalid and the control plane will reject the batch.

**Residual Risk:** If the attacker has the API token (see T-5), they can compute valid hashes for a fabricated chain from any insertion point. Key rotation (see `docs/04-security/batch-signing.md`) limits the window of exposure.

---

### T-3: Event Mutation

**Description:** An attacker modifies a field in an existing event (e.g. changing `fd_path` from `/bin/bash` to `/usr/bin/python` to conceal a sandbox escape).

**Mitigation:** `this_hash` is computed over all event fields except itself (see `docs/04-security/event-chaining.md`). Mutating any field changes the hash, breaking the chain from that event onward. Detection is the same as T-2.

**Residual Risk:** Same as T-2: possession of the API token enables a complete chain rewrite.

---

### T-4: Event Replay

**Description:** A network attacker (actor C) captures a valid signed batch and replays it to the control plane to confuse the audit timeline or trigger duplicate alerts.

**Mitigation:** Each batch contains events with timestamps and a monotonically advancing hash chain. The control plane can detect replay by checking whether the `prev_hash` of the replayed batch's first event has already been seen in a previous batch for this `agent_id`.

**Residual Risk:** Guardian itself does not implement replay detection — this is a control plane responsibility. The batch signature does not include a nonce or wall-clock time, so pure signature verification cannot distinguish a replayed batch from a genuine one. This is a known limitation documented in `docs/04-security/batch-signing.md`.

---

### T-5: API Token Compromise

**Description:** An attacker reads `guardian.yaml` and extracts the API token, gaining the ability to forge batch signatures.

**Mitigation:** The token should be stored in a secrets manager and injected as an environment variable or via a restricted file permission (`chmod 600 guardian.yaml`, owned by the Guardian service account). Guardian logs a warning if the token is still the placeholder `YOUR_API_TOKEN_FROM_VIRIATO_CONSOLE`.

**Residual Risk:** Guardian does not enforce filesystem permissions on `guardian.yaml`. Token rotation invalidates all signatures produced under the old token; old audit logs must be re-verified under the old token before it is retired.

---

### T-6: Agent Process Termination

**Description:** An attacker kills the Guardian process to create a gap in the audit log.

**Mitigation:** Process supervision (systemd, Kubernetes liveness probe) should restart Guardian automatically. The disk buffer preserves events across restarts. On restart, the Signer reinitialises `prev_hash` to `GENESIS_HASH`, so each agent run starts a new chain. The control plane can detect unexpected chain restarts by observing a new chain starting before the expected next event for a known `agent_id`.

**Residual Risk:** Events generated between the kill and the restart are lost. This window is bounded by `batch_interval_ms` (default 100 ms) for events that were buffered; events still in memory at kill time are unrecoverable.

---

### T-7: Root Compromise of the Host

**Description:** An attacker with root on the host can do anything: kill Guardian, modify the kernel, read memory, forge events at the kernel level, or delete the entire buffer.

**Mitigation:** None within Guardian's scope. This is an explicit non-goal (see below). Trusted Execution Environments (TEEs) or hardware attestation are out of scope for Phase 1.

**Residual Risk:** Complete. A root attacker can produce an arbitrary audit trail indistinguishable from a legitimate one.

---

### T-8: AI Model Reads Guardian Config

**Description:** A malicious model process reads `guardian.yaml` to obtain the API token and its own watch entry configuration.

**Mitigation:** `guardian.yaml` should be owned by the Guardian service account and not readable by model process UIDs. The `uid` field on every event makes it possible to detect if a model process UID accessed sensitive paths.

**Residual Risk:** If the model runs as root or as the same UID as Guardian (misconfiguration), it can read the token.

---

### T-9: Unexpected Network Allowlist Bypass

**Description:** A model process makes network connections that are not in the `network_allowlist` but are not flagged because the allowlist is empty.

**Mitigation:** An empty `network_allowlist` is an explicit design choice meaning "no network restriction". Operators who want restriction must configure a non-empty list. Guardian logs all network events regardless.

**Residual Risk:** If an operator forgets to configure the allowlist, `unexpected_network` alerts will never fire. The events are still recorded and can be analysed post-hoc by the control plane.

---

## Explicit Non-Goals

Guardian does **not** protect against:

1. **Root compromise of the host.** A root attacker can modify kernel code, tamper with `/proc`, kill Guardian, and rewrite the disk buffer. Hardware-based attestation is planned for a future phase.
2. **Kernel exploits.** Guardian relies on the Linux kernel's integrity. A kernel-level rootkit can suppress eBPF events at source.
3. **Physical access attacks.** Cold-boot attacks, direct memory access (DMA), and hardware implants are out of scope.
4. **Compromise of the Viriato Security control plane.** Guardian signs events with the customer's token; it cannot prevent the platform operator from reading ingested data. Encryption of event content is a planned future feature.
5. **Denial of service against Guardian itself.** Resource exhaustion attacks that starve Guardian of CPU, memory, or disk space may cause event loss. Rate limiting and resource quotas are an operational concern outside this document.
6. **Forward secrecy of the API token.** HMAC with a static long-lived token does not provide forward secrecy. Ed25519 per-event signing planned for Phase 3 will address this.

---

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│  Host (trusted kernel)                                          │
│                                                                 │
│  ┌───────────────────────┐    ┌──────────────────────────────┐  │
│  │   AI Model Process    │    │   Guardian Agent Process     │  │
│  │   (NOT trusted)       │    │   (trusted by operator)      │  │
│  │                       │    │                              │  │
│  │  execve, connect,     │───>│  reader → enricher →        │  │
│  │  read, write, ...     │    │  signer → sender             │  │
│  └───────────────────────┘    └──────────────────────────────┘  │
│                                          │                      │
└──────────────────────────────────────────┼──────────────────────┘
                                           │ TLS gRPC
                              ┌────────────▼────────────┐
                              │  Viriato Control Plane  │
                              │  grpc.viriatosecurity   │
                              │  .com:443               │
                              │  (trusted for delivery, │
                              │  not for data privacy)  │
                              └─────────────────────────┘
```

The trust boundary between the AI model process and the Guardian agent is enforced by the kernel (Linux namespaces, capabilities, eBPF program isolation). The Guardian agent itself is assumed not to be compromised; if it is, all bets are off.

---

## What Guardian Trusts

| Component | Trust Rationale |
|---|---|
| Linux kernel | Source of eBPF events. If the kernel is compromised, no userspace security tool can compensate. |
| Customer's API token | The HMAC signing key. The customer is responsible for its confidentiality and rotation. |
| `guardian.yaml` contents | Guardian parses and acts on this file as an authoritative configuration source. |
| `/proc` filesystem | Used by Enricher for container ID lookups. Trusted because it is kernel-managed. |
| Kubernetes Downward API env vars | `KUBERNETES_POD_NAME`, `KUBERNETES_NAMESPACE` are trusted as injected by the kubelet. |
| `/var/lib/guardian/.agent_id` or `~/.guardian_agent_id` | Trusted as the persistent identity of this installation. |

---

## What Guardian Does Not Trust

| Component | Reason |
|---|---|
| AI model process | The entire point of Guardian is to monitor this process. It is assumed potentially hostile. |
| Network (between agent and control plane) | TLS provides confidentiality and server authentication, but the network path is not trusted to be free of active attackers. |
| Disk buffer contents on read | `_drain_buffer()` parses JSONL defensively; malformed lines are skipped rather than crashing the agent. |
| Environment variables set by monitored processes | Only `KUBERNETES_POD_NAME` and `KUBERNETES_NAMESPACE` (set by kubelet, not user processes) are consumed. |
| `guardian.yaml` token value correctness | Guardian warns but does not abort if the token is the placeholder. It is the operator's responsibility to set a real token. |

---

## Related Documents

- `docs/04-security/cryptographic-design.md` — cryptographic primitives, GENESIS_HASH, key management
- `docs/04-security/event-chaining.md` — exact hash function and chain verification algorithm
- `docs/04-security/batch-signing.md` — HMAC construction, replay resistance, token rotation
- `docs/04-security/local-alerts.md` — local detection engine, sandbox escape, unexpected network
- `docs/02-architecture/` — system architecture and data flow
