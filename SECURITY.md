# Security Policy

## Supported versions

| Version | Status |
|---|---|
| `0.2.x` | Development preview, security fixes accepted on the latest release and `main` |
| `0.1.x` | Superseded, upgrade to `0.2.x` |

BAIT does not currently provide a long-term support branch or guaranteed remediation service level.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability that could expose users or enable unsafe response behavior.

Use the repository's **Private vulnerability reporting** or open a private GitHub Security Advisory. Include:

- affected version or commit
- operating system and relevant configuration
- impact and realistic attack prerequisites
- minimal reproduction steps using synthetic data
- suggested mitigation, when available

Do not include real credentials, customer data, private endpoint telemetry, unauthorized access results, or live malware samples.

If private vulnerability reporting is not enabled, the repository owner should enable it before announcing the project publicly.

## Deployment requirements

- Keep the API bound to `127.0.0.1` until TLS, authentication, network access controls, and rate limits are configured.
- Set `BAIT_API_TOKEN` when the API is reachable by another host.
- Keep response mode set to `audit` during evaluation and initial pilots.
- Grant only the operating-system permissions required by enabled collectors.
- Protect the SQLite database because it can contain usernames, paths, command lines, process details, and IP addresses.
- Store quarantine data outside user-writable application paths.
- Review every third-party rule and response recommendation before deployment.
- Sign release artifacts, rule bundles, and configuration before production distribution.
- Do not embed the administrative bearer token in a browser, mobile app, or static website.

## Security features to enable on GitHub

Repository administrators should enable:

- private vulnerability reporting
- Dependabot alerts and security updates
- secret scanning and push protection
- CodeQL or equivalent code scanning
- branch protection with required CI and reviews
- signed tags or releases

## Defensive use

BAIT is intended only for systems you own or are authorized to monitor and administer. Response functions must not be used to interfere with systems outside your control.

## Scope exclusions

A clean unit-test or CodeQL result does not establish the absence of vulnerabilities. BAIT has not completed an independent penetration test, formal verification, production certification, or third-party security audit.
