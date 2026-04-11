# Why BUSL-1.1, Not MIT or AGPL

**Status: DECIDED — BUSL-1.1 with 4-year Apache 2.0 conversion.**

Guardian is licensed under the Business Source License 1.1 (BUSL-1.1). This is a
deliberate choice. Three alternatives were seriously evaluated: MIT, Apache 2.0,
and AGPL. This document records why each was not chosen and what BUSL-1.1 provides.

---

## What BUSL-1.1 Means

BUSL-1.1 is a **source-available license** — not an OSI-certified open-source
license. The key terms:

- **You can read the code**: The full source is public on GitHub.
- **You can use it non-commercially and non-productively**: Study it, contribute
  to it, run it in development or testing.
- **Production use requires a commercial license**: Running Guardian in production
  (i.e. collecting compliance evidence for a real AI deployment) requires a
  commercial agreement with Viriato Security.
- **Automatic conversion**: After **4 years** from the date of each release,
  that release converts to **Apache 2.0** automatically. This is hardcoded in the
  license text.

This means Guardian's codebase will eventually be fully open source. It is not
"closed source forever" — it is "delayed open source."

---

## The 4-Year Apache 2.0 Conversion

The conversion clause is not a promise — it is part of the license text itself:

> "The Licensed Work will convert to the Apache License, Version 2.0 on the
> Change Date specified for the Licensed Work."

Examples of projects using this model:
- **MariaDB**: Used BUSL-1.1 for MaxScale. After 4 years, MaxScale releases became
  GPL.
- **HashiCorp (pre-controversy)**: Used BSL (effectively the same model) for
  Terraform, Vault, and Consul before the community fork (OpenTofu). The 4-year
  conversion was always present.
- **Sentry**: Uses BSL for some self-hosted components while keeping the cloud
  product proprietary.

The pattern is well-established. Enterprise security teams understand BUSL-1.1 and
are generally comfortable with it for infrastructure software.

---

## Why Not MIT or Apache 2.0

MIT and Apache 2.0 are permissive licenses. Anyone can take the code, modify it,
and use it for any purpose — including building a competing product.

The risk for Guardian specifically:

- The Guardian **agent** runs on the customer's infrastructure, collects kernel
  events, signs them, and streams them to a compliance platform.
- The Guardian **agent** is the **trust anchor** of the product. Customers need to
  audit what is running as root on their machines.
- If the agent were MIT-licensed, a competitor could take the agent code
  (which represents months of engineering: eBPF probes, cryptographic chain,
  proto schema, gRPC transport, disk buffer, local alerts) and build a competing
  SaaS compliance platform on top of it, without contributing any improvements
  back to Guardian.

**The agent is the trust layer; the platform is the business.** MIT licensing
would allow competitors to extract the trust layer for free and undercut Viriato
Security with an identical technical product.

This is not a theoretical risk. Several well-known infrastructure projects
(Elasticsearch, MongoDB, Redis) have experienced exactly this scenario with AWS
and other hyperscalers, leading them to change their licenses.

---

## Why Not AGPL

AGPL (GNU Affero General Public License) is a strong copyleft license. Any
modifications to AGPL-licensed software, including when it is provided as a
service over a network, must be released under AGPL.

The case for AGPL:
- It is an OSI-certified open-source license.
- It would prevent competitors from building proprietary products on top of Guardian.
- It is used by many successful open-source projects (MongoDB before their own
  switch, Grafana before AGPL became controversial, etc.).

Why AGPL was rejected:

**Enterprise legal teams flag copyleft as license contamination risk.**

Many enterprise legal policies require that any AGPL-licensed software used in
production either be fully isolated or go through a lengthy legal review. The
concern is that AGPL code "infects" adjacent code that interacts with it. This
concern is often overstated, but the legal review process is real and slows
enterprise sales cycles significantly.

Guardian's primary customers are regulated enterprises (healthcare, finance,
insurance) deploying AI models for compliance-sensitive applications. These
organisations have conservative legal policies. AGPL creates a procurement
obstacle that BUSL-1.1 does not.

Additionally, AGPL's "network use" trigger is complex to interpret. When does
a company running Guardian internally trigger the AGPL source-distribution
requirement? Legal uncertainty is a sales blocker.

---

## Why Not Fully Closed Source

The strongest commercial protection would be to ship Guardian as a compiled binary
with no source available. This was rejected for a single decisive reason:

**Security teams need to audit code running as root with kernel access.**

Guardian runs as root. It attaches eBPF probes to the kernel. It reads file paths,
network addresses, and process metadata for every syscall made by the monitored
workload. A security-conscious enterprise CISO will ask: "What is this code doing
exactly, and how do we know it is not exfiltrating data?"

Without source code, that question cannot be answered. An audit firm cannot review
a binary. A security team cannot verify claims in a white paper.

**Open agent code builds trust.** Customers can read exactly what Guardian collects,
how it hashes events, what it sends over gRPC, and what credentials it uses.
The HMAC signing key is the customer's own token — Guardian cannot fabricate
events that would pass signature verification on the customer's side.

Full source availability is not just nice to have — it is a prerequisite for
adoption in regulated industries.

---

## Viriato Business Model

The model is standard for developer-facing security infrastructure:

| Component | License | Revenue model |
|-----------|---------|--------------|
| Guardian agent | BUSL-1.1 (→ Apache 2.0 in 4 years) | Free to use; source available |
| viriato-platform | Proprietary SaaS | Subscription; where the business lives |
| Support, SLAs, compliance reports | Commercial | Enterprise contracts |

The agent is the trust anchor and the distribution mechanism. The platform is the
product. Customers pay for verified compliance dashboards, EU AI Act article
mapping, audit reports, and the storage of tamper-evident event logs — not for the
agent binary itself.

---

## Summary

| Option | Why rejected | Key concern |
|--------|-------------|-------------|
| MIT | Competitors take agent, build rival platform for free | No protection for trust layer |
| Apache 2.0 | Same as MIT | No protection for trust layer |
| AGPL | Enterprise legal teams flag copyleft; slows procurement | License contamination risk |
| Fully closed | Cannot audit code running as root | Blocks adoption in regulated industries |
| **BUSL-1.1** | **Chosen** | Source visible, production requires license, converts to Apache 2.0 in 4 years |

---

## Related Documents

- [alternatives-considered.md](alternatives-considered.md)
- [../../LICENSE](../../LICENSE)
- [../../SECURITY.md](../../SECURITY.md)
