# Problem Statement

Guardian exists because deploying AI models in production creates a class of observability and compliance problems that existing tools cannot adequately address. The problem operates at three distinct levels — business, technical, and operational — and solutions that address only one or two levels are insufficient.

---

## Level 1: The Business Problem

### Regulated Industries Are Deploying AI Without Audit Trails

Healthcare providers are using AI models to assist with patient diagnosis. Financial institutions are using AI models for credit scoring and fraud detection. Government agencies are using AI models to assess eligibility for services. These are high-stakes decisions, made by systems that have no obligation — under current deployment practice — to leave any record of what they did, when, or how.

This is changing.

### The EU AI Act Creates a Forensic Evidence Requirement

The EU AI Act (Regulation (EU) 2024/1689) establishes legally binding requirements for high-risk AI systems. High-risk AI includes systems used in healthcare, financial services, employment, critical infrastructure, and law enforcement — essentially all the domains where AI models are being most aggressively deployed today.

The Act requires organisations to:

- **Log events** relating to high-risk AI system operation (Article 12)
- **Provide transparency** about AI system capabilities and limitations (Article 13)
- **Maintain accuracy and robustness** over time, with monitoring to verify this (Article 15)
- **Implement quality management systems** covering design, testing, and monitoring (Article 17)
- **Comply with additional obligations** for general-purpose AI models (Article 72)

These are not aspirational guidelines. Non-compliance exposes organisations to fines of up to €30 million or 6% of global annual turnover.

### The Evidence Gap

When compliance officers or auditors ask organisations to demonstrate compliance with these requirements, the typical answer is: "We have model cards, internal testing reports, and our developers believe the model is behaving correctly."

This is not evidence. It is assertion.

Evidence means: on date X at time Y, the model did Z, and here is a signed record that cannot have been fabricated after the fact. Without that record, organisations face one of three uncomfortable positions:

1. **Assert and hope.** Claim compliance without being able to demonstrate it. This works until there is an incident.
2. **Retrospective reconstruction.** Try to reconstruct what happened from application logs, which capture what the application layer chose to log — not what the model actually did at the system level.
3. **Proactive instrumentation.** Deploy a monitoring system before an incident occurs, so that when an auditor asks, there is a real record to produce.

Guardian enables option 3.

### The Competitive Dimension

Beyond regulatory compliance, customers operating AI systems in competitive markets have a business reason to want audit trails: they want to be able to demonstrate to their customers and partners that their AI systems are behaving as specified. "We have Guardian deployed and here is the signed event record" is a stronger statement than "we believe our model is fine."

---

## Level 2: The Technical Problem

### AI Models Are Transparent at the Syscall Layer

An AI model — regardless of how complex its internal architecture — is a process running on an operating system. When it reads training data, it calls `read()`. When it writes a prediction to a socket, it calls `sendto()`. When it opens a configuration file, it calls `openat()`. When it spawns a subprocess, it calls `clone()` or `execve()`.

These syscalls are facts. They cannot be disguised or omitted by the model itself (short of compromising the kernel, which is a different threat model). The kernel sees everything a process does.

This means the kernel is the ideal observability layer for AI systems: it is below the application layer (where the model could theoretically obscure its behaviour), it is universal across frameworks, and it produces ground-truth records.

### Traditional Monitoring Misses Kernel Behaviour

The observability stack that most organisations deploy is built for application-layer visibility:

- **APM tools** (Datadog, New Relic, Dynatrace) instrument the application via SDK or agent injection. They see what the application layer exposes — function calls, HTTP requests, database queries. They do not see what the process does at the syscall level without additional kernel integration.
- **Log aggregation** (ELK, Loki, Splunk) collects what the application writes to stdout, stderr, or log files. It captures only what the application chooses to log. A model that is silently exfiltrating data by writing to a socket will not appear in application logs unless the application explicitly logs that behaviour.
- **Metrics systems** (Prometheus, Grafana) collect numerical metrics exposed by the application. They are invaluable for performance monitoring but capture nothing about syscall behaviour.

None of these tools can answer: "Did this AI model process access `/etc/passwd` at 14:32 on March 14th?" The only system that can answer that question is one that was watching at the kernel level when it happened.

### Existing Kernel-Level Tools Produce Noise

The tools that do operate at the kernel level have significant limitations when applied to AI observability:

**auditd**

Linux's built-in audit daemon can capture syscalls. It produces records like:

```
type=SYSCALL msg=audit(1710422400.123:456): arch=c000003e syscall=257 success=yes
  exit=3 a0=ffffff9c a1=7f8a2b3c4d50 a2=0 a3=0 items=1 ppid=1234 pid=5678
  auid=1000 uid=1000 gid=1000 euid=1000 egid=1000 ...
```

This is a raw syscall record with no awareness of:
- Which AI model is running in the process
- Which container or pod the process is in
- Whether this read was from an inference request or a model weight load
- What the cryptographic identity of the event is (could be tampered with in log storage)

auditd also has well-documented performance issues at high syscall rates, which is exactly the scenario of a busy AI inference server.

**Falco**

Falco is an excellent runtime security tool for detecting known-bad patterns (e.g., "a container spawned a shell"). It is rule-based and alert-oriented — it fires when something looks suspicious and is silent otherwise.

For compliance purposes, this is insufficient. Compliance requires a continuous record of normal behaviour, not just an alert record of anomalies. An auditor needs to see that the model was behaving normally for 99.97% of requests as much as they need to see the 0.03% that triggered alerts.

Falco also has no concept of AI model identity. A Falco rule that detects a `connect()` syscall does not know whether it came from `patient-diagnosis-v2` or `fraud-detection-v1`.

**Tetragon**

Tetragon (from Cilium/Isovalent) is the closest existing tool to what Guardian does — it captures kernel events with process identity. However, it is designed for general security observability, not AI compliance. It has no concept of model names, no HMAC-signed batch export, no EU AI Act article mapping, and no integration with compliance reporting workflows.

### The Missing Layer: AI-Aware Kernel Observability

What does not exist in the current tooling landscape is a kernel-level observability agent that:

1. Understands AI model identity (process → model name mapping)
2. Produces a continuous, signed, tamper-evident event record
3. Enriches events with container and Kubernetes metadata
4. Exports via a structured protocol designed for compliance ingestion
5. Is designed to produce compliance evidence, not just operational metrics

Guardian fills that gap.

---

## Level 3: The Operational Problem

### Cannot Modify AI Model Code

The most obvious solution to AI observability — "instrument the model to log its own behaviour" — is often not available in practice.

**Third-party models.** An organisation that deploys a commercial AI model (purchased as a binary, accessed via a managed API, or downloaded from a model hub) cannot modify that model's source code. Any observability solution that requires code changes is immediately incompatible with a large fraction of real deployments.

**Contractual constraints.** Even for models where the organisation has access to source code, contracts with AI vendors or partners may prohibit modification.

**Operational risk.** Modifying a model that is in production — even to add logging — introduces risk. The model needs to be retested, re-validated, and redeployed. For high-stakes models (medical diagnosis, financial decisions), this is a substantial undertaking.

**Multi-team ownership.** In large organisations, the team operating the model is often different from the team that built it. The operations team may not have the skills or authorisation to modify the model code.

Guardian's eBPF approach completely sidesteps this constraint. The model process is never modified, never restarted, and never aware that Guardian is watching.

### Must Work With Any Framework

The AI model ecosystem is highly fragmented:

- Training frameworks: PyTorch, TensorFlow, JAX, MXNet
- Serving frameworks: TorchServe, TensorFlow Serving, Triton Inference Server, vLLM, Hugging Face Inference Endpoints, BentoML, Ray Serve
- Custom serving: Flask, FastAPI, gRPC servers written by the customer's team

Each of these frameworks has different internal architectures, different logging conventions, and different ways of expressing model identity. An observability solution that provides a plugin for each framework requires constant maintenance and has permanent gaps when new frameworks emerge.

Guardian observes at the syscall layer, which is identical across all frameworks. `openat()` works the same way whether the process is TorchServe or a custom Flask server.

### Must Not Add Latency

AI inference latency is a first-order concern for production deployments. A model that adds 50ms of overhead is unacceptable for real-time applications. Any observability solution that intercepts syscalls synchronously (in the execution path of the model process) is a non-starter.

This rules out ptrace-based approaches, which intercept each syscall in the model process's execution path and require a context switch to the tracing process. At the syscall rates of a busy inference server, this adds substantial latency.

eBPF programs run in the kernel with a ring buffer architecture: the kernel writes events to a shared memory ring buffer, and a userspace consumer reads from that buffer asynchronously. The model process never waits for the observability system. If the consumer falls behind, events are dropped — but the model process is never slowed.

This is the only architecture that satisfies all three operational constraints simultaneously.

---

## Summary

| Level | Problem | Why Existing Tools Fail | Guardian's Approach |
|-------|---------|------------------------|---------------------|
| Business | No forensic evidence of AI model behaviour; EU AI Act requires it | Application logs are incomplete; assertions are not evidence | Kernel-level, continuous, cryptographically signed event record |
| Technical | Kernel behaviour invisible to APM/log tools; existing kernel tools produce noise without AI context | No AI model identity; no continuous record; no compliance export | AI-aware eBPF with model name enrichment, hash chain signing, gRPC export |
| Operational | Cannot modify AI model code; must work across all frameworks; must add zero latency | SDK/agent injection requires code changes; ptrace adds latency | eBPF operates outside the process; ring buffer adds no synchronous latency |

---

## Related Documents

- [What Is Guardian](what-is-guardian.md) — The design philosophy and what Guardian produces
- [Solution Architecture](solution-architecture.md) — How Guardian addresses the problem
- [EU AI Act Context](eu-ai-act-context.md) — Articles 12, 13, 15, 17, 72 in detail
- [Alternatives Comparison](../11-alternatives/comparison.md) — Side-by-side comparison with Falco, auditd, Tetragon
- [eBPF Probes](../06-ebpf/probes.md) — What the kernel layer actually captures
