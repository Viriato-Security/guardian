# EU AI Act Context

> **This document is for informational purposes only and does not constitute legal advice. Compliance with the EU AI Act requires assessment by qualified legal counsel familiar with your specific deployment context, organisational structure, and applicable national implementing legislation.**

The EU AI Act (Regulation (EU) 2024/1689, entering into force 1 August 2024, with phased applicability dates) is the world's first comprehensive horizontal legal framework governing artificial intelligence. It establishes obligations for AI providers, deployers, and importers across the European Union, with particular stringency for systems classified as "high-risk."

Guardian's design is shaped directly by the evidence requirements these articles create. This document explains what each relevant article requires, why existing monitoring approaches fail to satisfy those requirements, and how Guardian's event stream maps to each article's evidentiary needs.

---

## Why Article Compliance Requires Evidence, Not Assertion

A recurring failure mode in AI compliance preparation is the conflation of *having a policy* with *having evidence of compliance*. An organisation might have:

- Internal guidelines that say models must be monitored
- A model card that describes the model's intended behaviour
- Testing reports from before deployment
- A statement from the development team that the model is behaving correctly

None of these constitute evidence of compliance with the EU AI Act's ongoing operational requirements. The Act requires organisations to demonstrate, on demand, that specific obligations were met during specific periods of operation. That demonstration requires records that:

1. Were created at the time of the events they describe (not reconstructed afterwards)
2. Are tamper-evident (cannot have been altered after the fact)
3. Are specific enough to answer concrete questions (which system, which event, at what time)

Guardian's signed event stream is designed to produce precisely this kind of evidence.

---

## Article 12 — Record-Keeping

### What the Article Requires

Article 12 requires providers of high-risk AI systems to ensure that their systems are designed and built with capabilities to automatically generate logs of events throughout the system's lifetime. Specifically, it requires logging that enables:

- Monitoring of the system's operation
- Detection of situations that may result in risk
- Post-market surveillance by the provider
- Monitoring by the AI system's deployer

The Article specifies that logs must include, at minimum:

- The period of each use (start and end date and time)
- The input data against which the system was used (or a reference enabling identification of the input)
- Any natural person involved in the verification of results
- The AI system's output

For high-risk systems in specific sectors (law enforcement, migration, border control), additional requirements apply.

### How Guardian Addresses Article 12

Guardian provides the continuous automated logging infrastructure that Article 12 requires. Each `RawEvent` in the Guardian stream includes:

- **`timestamp`**: Nanosecond-precision UTC timestamp of the syscall, providing exact time of each operational event. Combined with the event stream's continuity, this establishes the period of each use.
- **`syscall`**: The operation performed (read, write, openat, connect, etc.), enabling classification of events by type.
- **`fd_path`**: The file path involved in the operation, which for inference workloads typically identifies input data files, model weight files, or output destinations.
- **`bytes`**: The byte count of I/O operations, enabling quantitative monitoring of data volumes.
- **`network_addr`**: The network destination for outbound connections, enabling monitoring of external communications.

The continuous nature of the stream — every watched syscall from every watched process, with no sampling — provides the coverage needed for post-market surveillance.

### Evidence Produced

An organisation asked to demonstrate Article 12 compliance can produce from the Guardian event stream:

- A complete timeline of all I/O operations by model `fraud-detection-v1` between any two timestamps
- The total volume of data read and written in a given period
- All file paths accessed during a specific inference session
- All network connections made and to which addresses

---

## Article 13 — Transparency and Provision of Information to Deployers

### What the Article Requires

Article 13 requires that high-risk AI systems be designed and developed in such a way that their operation is sufficiently transparent for deployers to understand the system's output and use it appropriately. Providers must accompany high-risk AI systems with instructions for use that include:

- The identity and contact details of the provider
- The characteristics, capabilities, and limitations of the AI system
- The level of accuracy, robustness, and cybersecurity performance
- The expected outputs of the system and their interpretation
- Circumstances that may lead to risks

For deployers (organisations that use high-risk AI systems in their operations), the Article requires that they understand what the system does and monitor its operation accordingly.

### How Guardian Addresses Article 13

The transparency requirement in Article 13 applies to both the AI system itself and to the monitoring infrastructure around it. Guardian contributes to Article 13 compliance in two ways:

**Operational transparency for deployers.** The Guardian event stream gives deployers real-time and historical visibility into what the AI system is actually doing at the syscall level. A deployer who has Guardian running can answer questions like:
- Is the model reading from the expected data sources?
- Is it making outbound network connections it should not be making?
- How much data is it processing per inference?
- Is it spawning subprocesses?

This operational transparency is a component of what Article 13 requires deployers to have.

**Model identity enrichment.** Guardian's enricher resolves process names to model names (`model_name` field in every event). This means the event stream is not just "process 5678 made a syscall" — it is "`patient-diagnosis-v2` made a syscall." The explicit association of kernel activity with named, versioned AI models is a direct contribution to the transparency requirement.

### Evidence Produced

An organisation asked to demonstrate Article 13 compliance can show:

- That they have a system capable of real-time monitoring of AI system behaviour
- That they can identify which model generated which kernel events
- That they have records showing the model's actual runtime behaviour compared to its documented expected behaviour

---

## Article 15 — Accuracy, Robustness, and Cybersecurity

### What the Article Requires

Article 15 requires that high-risk AI systems are designed and developed to achieve an appropriate level of accuracy, robustness, and cybersecurity, and to perform consistently throughout their lifecycle. Specifically:

- Systems must be resilient against attempts to alter their performance by adversarial parties
- Systems must be able to identify cases where their outputs may be insufficiently reliable
- Technical measures must be taken to protect against adversarial attacks

For the ongoing operational period (not just at deployment time), organisations must maintain monitoring that would detect degradation in accuracy or robustness.

### How Guardian Addresses Article 15

Article 15 is the most technically nuanced article from a monitoring perspective. Guardian contributes primarily to the **cybersecurity** and **adversarial robustness** dimensions.

**Detecting anomalous syscall patterns.** While Guardian itself does not perform anomaly detection (that happens in the platform), the data it captures is precisely what anomaly detection for cybersecurity purposes requires. A model that has been compromised — for example, through adversarial input that triggers a prompt injection leading to code execution — will exhibit syscall-level anomalies: unexpected `execve` calls, unexpected network connections, unexpected file access patterns. Guardian captures these syscalls; the platform identifies the anomalies.

**Sandbox escape detection.** Guardian's local alert engine detects `execve` calls targeting shell binaries (`/bin/bash`, `/bin/sh`, `/usr/bin/bash`, `/usr/bin/sh`). This is a direct implementation of adversarial robustness monitoring: a model that has been induced to spawn a shell via prompt injection or code execution vulnerability is detected and alerted on immediately.

**Network integrity monitoring.** The `unexpected_network` alert type detects outbound connections to addresses not in the `network_allowlist`. An AI model that has been compromised to exfiltrate data via an outbound connection is detected at the moment of the `connect()` or `sendto()` syscall.

**Evidence for accuracy degradation investigations.** When an AI system's outputs appear to have degraded (detected through application-layer monitoring), the Guardian event stream provides the forensic data needed to investigate what changed at the system level during the degradation period: were there changes in data access patterns? Were there unexpected process spawning events? Did I/O volumes change?

### Evidence Produced

An organisation demonstrating Article 15 compliance can show:

- That they have runtime monitoring for adversarial attack vectors (sandbox escape, unexpected network)
- That any detected anomalies are recorded with tamper-evident timestamps
- That they have the forensic data needed to investigate reported accuracy degradation

---

## Article 17 — Quality Management System

### What the Article Requires

Article 17 requires providers of high-risk AI systems to put in place a quality management system that covers, at minimum:

- A strategy for regulatory compliance, including compliance with this Regulation
- Techniques, procedures, and systematic actions for the design and development of the AI system
- Systems for examining, testing, and validating procedures
- A technical documentation system
- A post-market monitoring system
- Procedures for reporting serious incidents and malfunctions

The post-market monitoring system is the most directly relevant to Guardian. It must be based on a post-market monitoring plan that collects and analyses data on the system's performance throughout its lifetime.

### How Guardian Addresses Article 17

The post-market monitoring requirement in Article 17 is perhaps the strongest justification for Guardian's existence. "Post-market monitoring" in the EU AI Act context means ongoing, systematic collection of evidence that a deployed AI system is performing as intended.

Guardian provides the data collection infrastructure for this monitoring system. Specifically:

**Continuous data collection.** Every watched syscall from every watched process is captured continuously, not sampled. This provides the density of data needed for meaningful statistical analysis of model behaviour over time.

**Tamper-evident records for audit.** The hash chain ensures that the records produced by the post-market monitoring system cannot be altered after the fact. If an incident occurs, the organisation can demonstrate that the records they are presenting to regulators are the original records, not reconstructed or amended versions.

**Compliance metadata.** `guardian.yaml` includes `compliance.articles` and `compliance.data_categories` fields that tag the deployment with the specific EU AI Act articles it is targeting and the categories of data the system handles. This metadata flows into the platform and can be used for compliance reporting.

**Integration with the quality management framework.** Guardian does not replace the quality management system — it provides one essential component: the automated, continuous, tamper-evident data collection layer. The quality management system itself (procedures, documentation, incident reporting) is a broader organisational process that Guardian feeds data into.

### Evidence Produced

An organisation demonstrating Article 17 compliance can show:

- That they have a post-market monitoring system for their high-risk AI systems
- That the system collects data continuously and stores it with tamper-evident provenance
- That data is tagged with the relevant EU AI Act articles and data categories
- That they can produce records for any period within the system's deployment lifetime

---

## Article 72 — Obligations for Providers of General-Purpose AI Models

### What the Article Requires

Article 72 applies to providers of general-purpose AI (GPAI) models — large-scale foundation models intended for a wide range of downstream tasks. Its requirements include:

- Drawing up and keeping up-to-date technical documentation about the model
- Making available to downstream providers information and documentation to enable them to understand the model's capabilities and limitations
- Establishing a policy to comply with Union law on copyright
- Publishing a summary of the content used for training
- For models with systemic risk: additional obligations including adversarial testing, incident reporting, and cybersecurity protection

For GPAI models with systemic risk (those trained with computation exceeding 10^25 FLOPs), Article 72 imposes the most stringent monitoring requirements in the regulation.

### How Guardian Addresses Article 72

Article 72 is primarily directed at foundation model providers rather than deployers. However, organisations that deploy GPAI models (e.g., deploying LLaMA, Mistral, or other open-source foundation models) have obligations as downstream providers.

Guardian addresses the operational monitoring dimension of Article 72:

**Cybersecurity monitoring for systemic risk models.** Article 72(2)(d) requires adversarial testing and cybersecurity measures for models with systemic risk. Guardian's sandbox escape and unexpected network detection provide the runtime monitoring layer for these requirements.

**Incident reporting data.** Article 72(2)(c) requires incident reporting for serious incidents. Guardian provides the tamper-evident event stream that documents what the model was doing before, during, and after any incident — essential data for incident reports submitted to national competent authorities.

**Technical documentation of runtime behaviour.** Article 72(1) requires technical documentation. Guardian provides the runtime behavioural data (actual syscall patterns, resource usage, network activity) that supplements the pre-deployment technical documentation with evidence of actual operational behaviour.

---

## Article Coverage Summary

| Article | Requirement | Guardian contribution | Confidence |
|---------|-------------|----------------------|------------|
| 12 | Automated event logging throughout system lifetime | Continuous, nanosecond-precision syscall stream; every watched event captured | Direct |
| 12 | Log input data, period of use, outputs | `fd_path` (inputs), `timestamp` (period), `network_addr` (outputs) | Partial — input/output content requires platform |
| 13 | Operational transparency for deployers | Real-time visibility into model syscall behaviour; model name in every event | Direct |
| 13 | Understanding AI system outputs | Provides behavioural evidence; interpretation at platform | Indirect |
| 15 | Resilience against adversarial attacks | Sandbox escape detection, unexpected network detection | Direct |
| 15 | Monitoring for accuracy degradation | Forensic syscall data for post-incident investigation | Indirect |
| 17 | Post-market monitoring system | Continuous tamper-evident data collection infrastructure | Direct |
| 17 | Incident investigation capability | Full event history with chain of custody | Direct |
| 72 | Incident reporting data | Tamper-evident pre/during/post-incident event records | Direct |
| 72 | Cybersecurity protection for systemic risk models | Runtime monitoring for anomalous execution patterns | Direct |

---

## What Compliance Means in Practice

Compliance with the EU AI Act is not a binary state. It is a continuous posture that requires:

1. **Having the right data.** You cannot demonstrate compliance with Article 12 after the fact without records that were created at the time. Guardian creates those records.

2. **Storing it correctly.** Records must be retained for at least 10 years (Article 12(1)). The platform tier is responsible for long-term storage and retention policy enforcement.

3. **Being able to produce it.** In a regulatory inquiry or audit, you need to be able to retrieve records for specific time periods and specific AI systems quickly. The hash chain means you can prove the records are authentic.

4. **Acting on it.** Having records is necessary but not sufficient. The quality management system (Article 17) requires that monitoring data is actually reviewed and acted on. The platform tier provides the analysis and alerting infrastructure for this.

Guardian is a necessary component of EU AI Act compliance for organisations deploying high-risk AI. It is not sufficient on its own — the platform, quality management processes, and legal counsel are all required. But without Guardian (or an equivalent kernel-level monitoring system), the compliance posture cannot be established.

---

## Deployment Configuration for Compliance

The `guardian.yaml` compliance section records the regulatory context of a deployment:

```yaml
compliance:
  organization: "Acme Healthcare AI"
  data_categories:
    - medical_records
    - PII
  articles: [12, 13, 15, 17, 72]
```

This metadata flows through the event stream and into the platform, where it informs:
- Which compliance dashboards are active in the web interface
- Which policy rules are evaluated against the event stream
- What is included in compliance export reports

Setting `articles: [12, 13, 15, 17, 72]` indicates that this deployment is targeting all five articles discussed above. The `data_categories` field (`medical_records`, `PII`) triggers additional handling rules in the platform appropriate for sensitive data.

---

## Related Documents

- [What Is Guardian](what-is-guardian.md) — The design philosophy and non-goals
- [Problem Statement](problem-statement.md) — The business case for compliance monitoring
- [Solution Architecture](solution-architecture.md) — How the three-layer system satisfies these requirements
- [Signing & Chain of Custody](../04-security/signing.md) — How tamper evidence is established
- [RawEvent Schema](../03-data/raw-event-schema.md) — The specific fields that map to each article
- [guardian.yaml Reference](../12-reference/config-reference.md) — The compliance configuration keys
- [Local Alert Engine](../05-components/local-alerts.md) — Article 15 runtime monitoring
