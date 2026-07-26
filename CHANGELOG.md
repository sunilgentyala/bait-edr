# Changelog

All notable changes are documented here. The project follows semantic versioning during the development-preview stage where practical.

## 0.2.1 - 2026-07-25

### Security and correctness

- Made the unauthenticated API state observable instead of silent: a startup log warning and a new `auth_enabled` field on `/health` report when no bearer token is configured, rather than every endpoint quietly accepting unauthenticated requests.
- Added a static rejection of nested-quantifier catastrophic-backtracking regex shapes at rule-load time, and bounded the text length evaluated by rule regexes, to reduce ReDoS exposure from attacker-influenced command lines and paths.
- Documented the residual PID-reuse race between final identity verification and process termination, and the residual unauthenticated-by-default API state, as explicit threat-model entries rather than leaving them implicit.

### Verification

- Expanded the suite from 26 to 39 tests, adding direct coverage of the response-policy admissibility predicate in isolation (audit-mode-only, action-disabled-only, protected-process-only), the previously untested successful `terminate_process` execution path, the PID-reuse block path, the `all of` / `1 of` / `any of` / wildcard condition grammar, and positive-match tests for rules BAIT-1002 and BAIT-1003.
- Increased measured line coverage from 77 to 80 percent.

## 0.2.0 - 2026-07-25

### Security and correctness

- Corrected portable network telemetry so established TCP snapshots use `direction: unknown` instead of an unverified outbound label.
- Added process name and creation-time verification before active process termination.
- Added canonical path revalidation and collision-resistant quarantine filenames.
- Added rule validation for IDs, required metadata, ATT&CK tags, operators, regex syntax, response actions, and condition references.
- Added validation for response mode and configuration document structure.
- Blocked indicator actions when no indicator is present.

### Detection content

- Proofread all built-in rules and added status, author, dates, references, log-source metadata, output fields, and improved false-positive guidance.
- Updated the uncommon-port rule to a clearly labeled low-context TCP heuristic mapped to T1095.

### Verification

- Expanded the suite from 13 to 26 tests.
- Increased measured line coverage from 68 percent to 77 percent.
- Added collector accuracy, rule-validation, response-target, quarantine, configuration, and API response tests.
- Added automated diagram rendering and static-site validation.
- Built and installed a wheel, then loaded all five packaged rules outside the repository.

### Packaging

- Included the canonical starter rules as Python package data.
- Updated the CLI so `bait validate-rules` uses the installed rule bundle by default.

### Repository and website

- Added verified architecture, response-flow, and trust-boundary diagrams with Graphviz source.
- Redesigned the README, GitHub Pages site, social preview, and external website widget.
- Added CodeQL, Dependabot, pull request guidance, complete Apache 2.0 licensing, and repository security recommendations.
- Updated GitHub Actions and Pages workflows.

## 0.1.0 - 2026-07-25

- Added normalized endpoint event and alert models.
- Added process and network collectors.
- Added a Sigma-inspired detection engine and five starter rules.
- Added correlation, SQLite storage, API, CLI, and safe synthetic demonstration.
- Added audit-first response policy with triage, quarantine, termination, isolation planning, and indicator-block planning.
- Added tests, CI, GitHub Pages, security policy, threat model, and website integration examples.
