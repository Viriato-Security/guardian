# Why Not Falco

**Status: DECIDED — not using Falco as the base for Guardian.**

Falco is the most widely-deployed open-source runtime security tool for Kubernetes
workloads. The question of whether to build on top of Falco, or to use it alongside
Guardian, was evaluated carefully. This document records that evaluation.

---

## What Falco Does

[Falco](https://falco.org/) is a CNCF incubating project that detects unexpected
behaviour in containerised workloads at runtime. Its core capabilities:

- **Rule language**: Falco rules are written in YAML with a custom condition syntax
  (e.g. `evt.type = execve and proc.name = bash`). Rules fire alerts when conditions
  match kernel events.
- **Falcosidekick**: A companion service that routes Falco alerts to downstream
  sinks (Slack, PagerDuty, Elasticsearch, etc.).
- **Kernel drivers**: Falco supports three collection backends — a kernel module
  (high performance, requires module loading), an eBPF probe (modern kernels), and
  a userspace library (lower performance, no root needed).
- **Pre-built rule sets**: Falco ships with community-maintained rules covering
  common attack patterns (shell spawning, unexpected outbound connections, privilege
  escalation, etc.).

Falco is production-ready, well-documented, and widely deployed. It is a serious tool.

---

## What Falco Does NOT Do

Falco was designed for **real-time security alerting**, not **compliance evidence
collection**. It lacks several capabilities that Guardian requires:

| Capability | Falco | Guardian |
|------------|-------|---------|
| Cryptographic event chaining (per-event SHA-256 chain) | No | Yes |
| Tamper-evident batch signatures (HMAC-SHA256) | No | Yes |
| EU AI Act article mapping (`articles: [12, 13, 15]`) | No | Yes |
| AI workload-specific syscall patterns | No (generic) | Yes |
| Structured gRPC streaming to a compliance platform | No (Falcosidekick webhooks) | Yes |
| Model name / container context in every event | No | Yes |
| Proto3 serialisation for long-term storage fidelity | No | Yes |

The absence of cryptographic chaining is the most critical gap. Guardian's entire
compliance value proposition rests on the claim that the event log cannot be silently
tampered with. Falco provides no mechanism for this.

---

## Why Falco Produces Noise for AI Workloads

Falco's rules are tuned for general security threats in Kubernetes — detecting
shell spawning, outbound SSH, unusual file reads, etc. AI inference workloads are
inherently noisy relative to these patterns:

- PyTorch and TensorFlow routinely `clone()` threads and `mmap()` large files —
  patterns that Falco's default rules flag or that require extensive whitelisting.
- ML inference servers make frequent outbound connections to model registries,
  feature stores, and logging endpoints — triggering unexpected network rules.
- GPU kernel drivers cause unusual `/proc` and `/dev` access patterns.

Tuning Falco for an AI workload requires writing and maintaining a large corpus of
exception rules. The effort is comparable to building the detection layer from
scratch — without any of the compliance-specific features Guardian needs.

---

## Why Building on Falco Was Rejected

The proposal was to use Falco as the collection layer and add Guardian's compliance
features on top (chaining, signing, EU AI Act mapping). This was rejected for two
reasons:

1. **The compliance layer is as much work as Guardian itself.** The cryptographic
   event chain, the proto schema, the gRPC transport, the disk buffer, the enricher,
   and the alert engine together represent the core Guardian value. None of these
   could be delegated to Falco. The work savings from Falco's collection layer are
   not significant compared to the compliance layer.

2. **Falco's data model constrains Guardian's.** Falco's event structure is optimised
   for its rule engine, not for structured long-term storage. Mapping Falco's event
   fields to the Guardian proto schema would be a brittle translation layer with no
   upside — we would inherit Falco's field limitations without being able to add
   Guardian-specific fields (like `model_name`, `agent_id`, `prev_hash`, `this_hash`)
   cleanly.

---

## Could Falco Run Alongside Guardian?

Yes — and this is the recommended deployment for organisations that want both
real-time security alerting and compliance evidence collection.

Falco and Guardian are **complementary, not competing**:

| Tool | Primary purpose | Signal type |
|------|----------------|-------------|
| Falco | Real-time security alerting (SIEM integration) | Immediate alert on rule match |
| Guardian | Compliance evidence collection (audit log) | Tamper-evident structured record |

A process can run both simultaneously. Falco provides the real-time paging for
security operations; Guardian provides the cryptographically verifiable record
for auditors and regulators.

There is no technical conflict — both tools attach to the kernel independently.
The overhead of running both is additive but small (eBPF probes have ~1% overhead
each).

---

## Summary

| Question | Answer |
|----------|--------|
| Is Falco a good tool? | Yes, for real-time security alerting |
| Can Falco replace Guardian? | No — no crypto chaining, no compliance mapping, no gRPC compliance transport |
| Should we build on Falco? | No — compliance layer is as much work as Guardian; data model mismatch |
| Can Falco run alongside Guardian? | Yes — recommended for security-conscious deployments |

---

## Related Documents

- [alternatives-considered.md](alternatives-considered.md)
- [why-not-opentelemetry.md](why-not-opentelemetry.md)
- [why-not-ptrace.md](why-not-ptrace.md)
