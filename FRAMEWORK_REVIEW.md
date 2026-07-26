# BAIT EDR Framework Review

**Reviewed release:** 0.2.0  
**Review date:** July 25, 2026  
**Scope:** Python framework, rules, response controls, tests, GitHub configuration, diagrams, GitHub Pages site, and external website integration.

## Executive assessment

BAIT is a coherent, audit-first EDR reference framework with a clear separation between telemetry collection, rule evaluation, evidence storage, analyst access, and response policy. The implementation is appropriate for open-source research, defensive demonstrations, and controlled audit-mode pilots.

It is not ready to operate as a privileged enterprise endpoint agent. Native operating-system telemetry, service hardening, tamper resistance, authenticated fleet management, signed updates, and independent penetration testing remain required.

## Findings resolved in version 0.2.0

| Priority | Finding | Resolution |
|---|---|---|
| High | The portable network collector labeled every established TCP connection as outbound, which `psutil` cannot verify. | The collector now reports `network.direction: unknown` and records that direction is unavailable from a snapshot. The starter port rule no longer depends on invented direction. |
| High | Process termination relied on an alert PID and process name without checking PID reuse immediately before execution. | Active termination now reopens the process and verifies the current name and creation time before termination. |
| Medium | The verification report said parent-process enrichment was absent, but `ProcessCollector` already implemented it. | Documentation and tests now reflect the implemented parent-process enrichment. |
| Medium | Rule loading accepted unsupported response actions, invalid regular expressions, and unknown condition selections. | Rule validation now checks IDs, required metadata, ATT&CK tags, operators, regex syntax, response actions, and condition references. |
| Medium | A normal wheel installation did not have a durable default path to the starter rules. | The canonical rules are included as package data, the CLI resolves the installed copy by default, and a wheel smoke test confirms five rules load outside the repository. |
| Medium | Quarantine filenames could collide when the same file hash was quarantined more than once. | Quarantine names now include both the SHA-256 and alert identifier, with restricted file permissions on non-Windows systems. |
| Low | GitHub Pages used an older artifact action. | The Pages workflow now uses the current documented artifact action and updated official GitHub actions. |
| Low | The repository had a short license notice rather than the full Apache License 2.0 text. | The full license text and a project notice are included. |
| Low | Repository presentation lacked durable diagrams, governance files, and automated documentation checks. | Version 0.2.0 adds rendered and source diagrams, CodeQL, Dependabot, a pull request template, site validation, and a redesigned GitHub Pages site. |

## Verified component flow

<p align="center">
  <img src="docs/assets/architecture-modern.png" alt="Verified BAIT EDR component flow">
</p>

| Diagram component | Implemented code | Verification |
|---|---|---|
| Process snapshots | `bait_edr.collectors.processes.ProcessCollector` | Unit test verifies process event creation and parent name enrichment. |
| TCP snapshots | `bait_edr.collectors.network.NetworkCollector` | Unit test verifies new connections and `direction: unknown`. |
| External events | `POST /events` in `bait_edr.api` | API test ingests a normalized event and confirms alert generation. |
| Normalized event | `bait_edr.models.EndpointEvent` | Pydantic validation and storage round-trip tests. |
| Detection engine | `bait_edr.detection.engine.DetectionEngine` | Positive, negative, threshold, and uncommon-port tests. |
| Rule validation | `bait_edr.detection.rules.load_rules` | Tests reject invalid regex, unknown selections, and unsupported actions. |
| Correlation | `bait_edr.correlation.Correlator` | Test confirms bounded repeated alerts raise risk. |
| Evidence store | `bait_edr.storage.SQLiteStorage` | Event, alert, response, count, and retrieval tests. |
| Analyst surfaces | `bait_edr.api` and `bait_edr.cli` | API authentication, health, ingest, list, and response tests. |
| Response dispatch | `bait_edr.response.actions.ResponseManager` | Triage, unknown action, indicator, quarantine, and identity mismatch tests. |
| Policy gate | `bait_edr.response.policy.ResponsePolicy` | Audit mode, protected process, enabled action, and approved path tests. |

## Detection design review

Version 0.2.0 uses deterministic rules rather than an opaque machine-learning classifier. This is the correct choice for the current maturity level. A new EDR needs reliable telemetry, known field semantics, reproducible detections, benign negative fixtures, and measured false positives before anomaly models are added.

The rule language is intentionally small. It supports equality, containment, prefix and suffix matching, regular expressions, membership, and numeric comparisons. Conditions support named selections, simple `and` or `or`, and `all of`, `1 of`, or `any of` patterns. It does not claim full Sigma compatibility.

ATT&CK mappings are contextual labels. They do not prove detection coverage or prevention. Port-only and path-only detections remain low-context signals that require tuning and correlation.

## Response design review

The response model applies a low-regret sequence:

1. validate the requested action
2. check required target fields
3. apply audit or active mode
4. require explicit action enablement
5. enforce protected-process and approved-path boundaries
6. re-resolve the target immediately before execution
7. execute the action
8. store the result and evidence

<p align="center">
  <img src="docs/assets/response-flow.svg" alt="BAIT response decision flow">
</p>

`collect_triage` is non-disruptive and executes directly from the triggering event. Process termination and file quarantine require active mode. Host isolation and indicator blocking remain plans for an approved external enforcement layer.

## Trust-boundary review

<p align="center">
  <img src="docs/assets/trust-boundaries.svg" alt="BAIT trust boundaries and protected assets">
</p>

The critical assets are rule integrity, policy integrity, endpoint evidence, quarantine metadata, API authorization, and control over disruptive actions. The agent, local database, rule bundle, API clients, and operating-system controls are separate trust boundaries and should not share unrestricted credentials.

## Repository and website review

The repository now includes the files expected for a healthy public project:

- complete README and Apache 2.0 license
- security policy and threat model
- contribution and conduct guidance
- issue forms and pull request template
- CI, CodeQL, Dependabot, and Pages workflows
- source-controlled diagrams and rendered assets
- verification evidence and file hashes
- a responsive GitHub Pages site with accessibility and security headers guidance
- an isolated web component for an external website

The GitHub Pages site is static. It does not require a third-party JavaScript framework, analytics service, external font, or CDN dependency.

## Residual risks and production blockers

| Area | Residual gap | Required production control |
|---|---|---|
| Telemetry | `psutil` snapshots can miss short-lived activity and cannot prove connection direction. | Native Windows, Linux, and macOS event sources with sequence and loss monitoring. |
| Agent security | No protected service, anti-tamper, secure update channel, or kernel self-protection. | Signed service installation, protected process design, update verification, and tamper alerts. |
| API | Bearer token only, no TLS termination, RBAC, identity attribution, or rate limiting. | mTLS or identity-aware proxy, short-lived credentials, RBAC, audit identities, and rate controls. |
| Data protection | Local SQLite evidence is not encrypted or integrity chained. | Encryption at rest, append-only remote storage, integrity signatures, and retention enforcement. |
| Rule operations | No suppression, baseline, approval workflow, or formal Sigma converter. | Rule lifecycle management, test fixtures, signing, staged rollout, and coverage reporting. |
| Response | No rollback orchestration, two-person approval, or platform-specific isolation. | Approved plugins, rollback testing, case linkage, and human approval for high-impact actions. |
| Fleet | No central inventory, policy distribution, tenancy, or health monitoring. | Authenticated control plane with tenant isolation and signed policy delivery. |
| Assurance | Unit tests do not establish vulnerability absence. | Secure code review, dependency review, fuzzing, penetration testing, and pilot evaluation. |

## Release recommendation

Version 0.2.0 can be published as a **development preview** with the limitations displayed prominently. Keep active response disabled in public demonstrations and initial pilots. Do not market this release as production-ready, certified, autonomous, or equivalent to a commercial EDR.
