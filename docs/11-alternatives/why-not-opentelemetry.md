# Why Not OpenTelemetry

**Status: DECIDED — not using OTel for event capture. Could be used at the
platform layer for customer-facing OTel endpoints.**

OpenTelemetry (OTel) is the CNCF standard for observability — traces, metrics, and
logs. It is widely deployed and well-supported across languages and platforms. This
document explains why it was not chosen as Guardian's event capture mechanism.

---

## What OpenTelemetry Does

[OpenTelemetry](https://opentelemetry.io/) is a vendor-neutral observability
framework. Its core capabilities:

- **Traces**: Distributed request traces (spans with parent-child relationships)
  for understanding latency and call paths.
- **Metrics**: Time-series counters and gauges (request rate, error rate, latency
  percentiles).
- **Logs**: Structured log records with trace context attached.
- **SDKs**: Language-specific libraries (Python, Java, Go, Rust, etc.) that
  instrument application code.
- **OTel Collector**: A sidecar or standalone agent that receives, processes, and
  exports telemetry to backends (Jaeger, Prometheus, Grafana, etc.).
- **OTLP**: The OTel Protocol for transmitting telemetry data.

OTel is production-ready, has excellent community support, and is the industry
standard for application-level observability.

---

## The Core Problem: OTel Requires Code Changes

Guardian's fundamental requirement is **zero code changes to the monitored
application**. The application owner should not need to add OTel instrumentation
to their PyTorch serving code, modify their Dockerfile, or change their deployment
pipeline. Guardian must be entirely transparent to the workload.

OTel's instrumentation SDKs work by wrapping application code:

```python
# This requires changes to the application
from opentelemetry import trace
tracer = trace.get_tracer(__name__)

with tracer.start_as_current_span("model-inference"):
    result = model.predict(input_data)
```

Even OTel's automatic instrumentation for popular frameworks (Django, Flask, gRPC)
works by monkey-patching library code at import time — which requires the OTel SDK
to be installed and configured in the application's Python environment. This is not
zero-code-change deployment.

---

## What OTel Does NOT Capture

Even with full OTel instrumentation, the following are not available through OTel:

- **Kernel syscalls**: `read`, `write`, `openat`, `connect`, `sendto`, `execve`.
  These happen below the application layer and are invisible to OTel.
- **File paths accessed**: `/var/lib/models/patient-diagnosis-v2/model.pt`
- **Network addresses at the socket level**: `10.0.0.1:8080` (OTel may capture
  HTTP host headers, but not raw socket connections).
- **Process identity at the OS level**: PID, UID, actual executable path.

Guardian's compliance value comes from capturing kernel-level evidence that the
application cannot falsify. OTel captures application-level events that the
application controls and could manipulate.

---

## OTel eBPF Auto-Instrumentation

The OTel project includes an experimental eBPF-based auto-instrumentation operator
for Kubernetes:

- **What it is**: An operator that injects eBPF probes into pods to capture HTTP
  and gRPC traces without code changes.
- **Current state (as of 2026)**: Experimental. Supports HTTP/1.1, HTTP/2, and
  gRPC traces. Not syscall events.
- **What it does NOT capture**: File access patterns, raw network addresses at
  the socket level, `execve` events, or the other syscalls Guardian monitors.
- **Maturity**: Not yet recommended for production compliance use cases.

Even if the OTel eBPF operator matured to capture raw syscall events, it would
produce OTel spans — not the Guardian proto schema with cryptographic chaining.
Adapting the output to Guardian's format would be as much work as writing the
eBPF probes directly.

---

## Could OTel Be Used at the Platform Layer?

Yes — and this is worth exploring for the viriato-platform.

Organisations with existing OTel infrastructure (OTel Collector deployed, Grafana
or another backend configured) would benefit from being able to receive Guardian
compliance events through their existing OTel pipeline. The platform could expose:

- An OTLP endpoint that accepts Guardian events formatted as OTel log records.
- OTel-compatible metrics (events per second, alert counts, chain verification
  failures) that flow into the customer's Grafana dashboards.

This would be an additive integration — Guardian agents continue to use the gRPC
`GuardianIngest` protocol; the platform converts internally and re-exports via OTLP.

---

## Summary

| Question | Answer |
|----------|--------|
| Does OTel require code changes? | Yes (SDKs) or experimental eBPF (HTTP only, not syscalls) |
| Can OTel capture kernel syscalls? | No |
| Does OTel provide crypto chaining? | No |
| Should Guardian use OTel for capture? | No |
| Could the platform expose OTel endpoints? | Yes — future roadmap item |

---

## Related Documents

- [alternatives-considered.md](alternatives-considered.md)
- [why-not-falco.md](why-not-falco.md)
- [why-not-ptrace.md](why-not-ptrace.md)
