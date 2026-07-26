# Verification Report

**Release:** 0.2.1  
**Verification date:** July 25, 2026  
**Local environment:** Linux container, Python 3.13.5, Graphviz 2.42.4; retested on Windows, Python 3.14.4

## Result

The reviewed repository passed the available functional, packaging, rule, diagram, and static-site checks. The release is suitable for research, demonstrations, rule development, and controlled audit-mode evaluation. These checks do not certify production readiness or prove that the software is free of vulnerabilities.

## Checks completed

| Area | Command or method | Result |
|---|---|---|
| Unit and integration tests | `pytest --cov=bait_edr --cov-report=term-missing --cov-fail-under=75` | 39 passed |
| Line coverage | `pytest-cov` | 80 percent |
| Python syntax | `python -m compileall -q bait_edr tests scripts` | Passed |
| Built-in rule validation | `bait validate-rules` | 5 rules passed |
| Safe synthetic demonstration | `bait demo` | 2 expected alerts, no payload execution |
| Live portable collection | One `BAITAgent.run_once()` cycle | 31 events, 0 alerts in the final test environment, audit mode retained |
| Editable packaging | `pip install --no-deps --no-build-isolation -e .` | Passed |
| Wheel packaging | Build, install to an isolated target, and load default rules outside the repository | Passed, 5 packaged rules loaded |
| Diagram source parity | `python scripts/render_diagrams.py --check` | 3 diagrams passed |
| Static website structure | `python scripts/validate_site.py` | Passed |
| API behavior | FastAPI tests for health, token enforcement, event ingestion, alert retrieval, and response requests | Passed |

## Security properties verified

1. The default response mode is `audit`.
2. Process termination and file quarantine are disabled independently by default.
3. PID 1 and the BAIT process cannot be termination targets.
4. Protected process names are rejected case-insensitively.
5. Process termination re-resolves the process and checks name and creation time before execution.
6. Quarantine requires an approved source root, canonical-path revalidation, and a valid file.
7. Quarantine records the SHA-256 digest, original path, destination, and alert identifier.
8. Host isolation is a recorded external-enforcement plan, not an implemented firewall change.
9. Indicator blocking is a recorded external-enforcement plan and requires an indicator.
10. API bearer-token checks apply when the configured token environment variable is set.
11. Portable TCP snapshots use `network.direction: unknown` rather than inventing direction.
12. Rule loading rejects invalid IDs, unsupported operators or response actions, invalid regular expressions, unknown condition selections, and regex patterns matching known catastrophic-backtracking shapes.
13. Regex matching is bounded to a fixed subject length regardless of the attacker-controlled command-line or path length.
14. An unauthenticated API (no token environment variable set) logs a startup warning and reports `auth_enabled: false` on `/health` rather than allowing access silently.

## Diagram verification

The following diagrams were proofread against the implementation and regenerated from Graphviz source:

- `docs/diagrams/architecture.dot`
- `docs/diagrams/response-flow.dot`
- `docs/diagrams/trust-boundaries.dot`

The response diagram distinguishes non-disruptive triage, external enforcement plans, and local disruptive actions. The local path includes target presence, active mode, explicit enablement, protected-target checks, live identity revalidation, execution, and persisted results.

## Documentation and repository checks

The static-site validator confirms required page metadata, a main landmark, a level-one heading, image alternative-text attributes, valid internal fragments, and existing local assets. GitHub Actions separately runs Ruff, the 75 percent coverage gate, rule validation, diagram parity checks, and site validation across the configured jobs.

The local environment did not provide a Ruff binary, and its package index did not expose the pinned Ruff distribution. Ruff was therefore not executed locally. The CI workflow remains the enforcement point for Ruff after the repository is pushed to GitHub.

## Remaining limitations

- `psutil` snapshots can miss short-lived activity and do not replace native kernel or operating-system telemetry.
- The portable network collector cannot prove connection direction.
- Starter rules have not been evaluated against a representative benign enterprise dataset.
- The local SQLite store is not encrypted or protected by an append-only integrity chain.
- The API does not provide TLS termination, RBAC, identity attribution, or rate limiting.
- The agent has no anti-tamper protection, signed update channel, or central fleet control plane.
- Active response has not undergone platform certification, rollback testing, or independent penetration testing.
- A passing test suite does not establish detection completeness, absence of vulnerabilities, or operational safety in every environment.

## Required production gates

Before any production deployment:

1. add native Windows, Linux, and macOS telemetry with event-loss monitoring
2. run a representative audit-mode pilot and measure false positives
3. add authenticated and encrypted fleet communications
4. sign releases, configurations, and rule bundles
5. add durable evidence protection and retention enforcement
6. test response rollback and require human approval for high-impact actions
7. complete privacy, legal, threat-model, secure-code, dependency, and penetration reviews
