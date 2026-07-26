# Standards and Defensive References

**References verified:** July 25, 2026

BAIT uses established defensive concepts while avoiding unsupported claims of certification or conformance.

## NIST incident response

NIST SP 800-61 Revision 3 was finalized in April 2025 and supersedes Revision 2. It frames incident response as part of organization-wide cybersecurity risk management aligned with the six functions of the NIST Cybersecurity Framework 2.0.

BAIT supports a limited endpoint-side subset: event collection, detection, analysis evidence, policy-controlled response requests, and response records. It does not implement an entire organizational incident response program.

- NIST SP 800-61 Rev. 3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- DOI: https://doi.org/10.6028/NIST.SP.800-61r3
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework
- NIST SP 800-94, Guide to Intrusion Detection and Prevention Systems: https://csrc.nist.gov/pubs/sp/800/94/final

## MITRE ATT&CK

The current ATT&CK website version at the review date is v19.1. ATT&CK v18 replaced technique-page detections with Detection Strategies and Analytics and deprecated legacy Data Sources. BAIT therefore treats ATT&CK technique tags as behavioral context and does not claim coverage based only on a tag.

- ATT&CK version history: https://attack.mitre.org/resources/versions/
- ATT&CK Enterprise techniques: https://attack.mitre.org/techniques/enterprise/
- ATT&CK Detection Strategies: https://attack.mitre.org/detectionstrategies/
- ATT&CK v18 defensive-content changes: https://attack.mitre.org/resources/updates/updates-october-2025/

Starter rule mappings used in this release:

- PowerShell, T1059.001: https://attack.mitre.org/techniques/T1059/001/
- Command and Scripting Interpreter, T1059: https://attack.mitre.org/techniques/T1059/
- User Execution: Malicious File, T1204.002: https://attack.mitre.org/techniques/T1204/002/
- Non-Application Layer Protocol, T1095: https://attack.mitre.org/techniques/T1095/
- Brute Force, T1110: https://attack.mitre.org/techniques/T1110/

## Sigma-inspired rules

BAIT uses readable YAML selections, field modifiers, log-source metadata, false-positive guidance, ATT&CK tags, and conditions inspired by Sigma. BAIT does not implement the full Sigma rule, correlation, filter, conversion, or backend specifications.

The project must not be represented as Sigma-compatible until a formal converter and conformance suite exist.

- Sigma specification: https://sigmahq.io/sigma-specification/
- Sigma rules specification: https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html

## OCSF-friendly event model

BAIT uses common event, process, file, network, user, authentication, and metadata objects to reduce future mapping effort. The current model is OCSF-friendly, not OCSF-conformant. Formal conformance requires class, category, activity, type, severity, and object mapping tests against a declared OCSF schema version.

- Open Cybersecurity Schema Framework: https://ocsf.io/

## YARA integration

The optional file scanner can compile and apply administrator-provided YARA rules. BAIT does not ship malware-family signatures, download untrusted rules automatically, or claim that a YARA match proves maliciousness.

- YARA documentation: https://yara.readthedocs.io/en/latest/

## osquery and OpenTelemetry roadmap

osquery is a planned telemetry source. OpenTelemetry logs and OTLP are planned transport options for structured events and operational telemetry.

- osquery: https://osquery.io/
- OpenTelemetry logs data model: https://opentelemetry.io/docs/specs/otel/logs/data-model/

## GitHub repository and Pages practices

The repository includes a README, license, security policy, contribution guidance, issue forms, pull request template, automated tests, dependency updates, code scanning, and a GitHub Pages workflow. Administrators should also enable secret scanning, push protection, private vulnerability reporting, branch protection, and required reviews in repository settings.

- Repository best practices: https://docs.github.com/en/repositories/creating-and-managing-repositories/best-practices-for-repositories
- GitHub Pages custom workflows: https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages
- Repository security quickstart: https://docs.github.com/en/code-security/getting-started/quickstart-for-securing-your-repository

## Usage statement

These references inform design decisions. They do not represent certification, endorsement, affiliation, or independent validation by NIST, MITRE, SigmaHQ, OCSF, VirusTotal, osquery, OpenTelemetry, GitHub, or any other organization.
