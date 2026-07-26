# Contributing to BAIT

Thank you for improving BAIT. Contributions must preserve the project's defensive scope, explainability, and audit-first safety model.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
make verify
```

On Windows PowerShell, activate with `.\.venv\Scripts\Activate.ps1`.

Graphviz is required only when changing diagram source files.

## Pull request expectations

- Explain the security behavior and trust-boundary impact, not only the code change.
- Add tests for new operators, rules, collectors, storage behavior, API endpoints, or response actions.
- Use synthetic events and harmless fixtures.
- Do not commit malware, exploit payloads, credentials, private logs, customer data, or proprietary signatures.
- Keep disruptive response actions disabled by default.
- Document rollback behavior for every new disruptive action.
- Update the threat model and diagrams when a trust boundary or control flow changes.
- Run `make verify` before requesting review.

## Detection rule quality checklist

Every rule must include:

- unique and stable BAIT rule ID
- title-cased title and precise description
- status, author, date, severity, and log-source metadata
- ATT&CK mapping supported by the observed behavior
- bounded conditions and documented field semantics
- at least one positive synthetic test
- at least one benign negative test
- likely false positives and tuning guidance
- response recommendations proportional to confidence

A technique tag is context, not proof of coverage.

## Response action checklist

A new response action must:

- have an explicit policy flag
- default to disabled or planned
- validate all required target fields
- protect critical operating-system and BAIT targets
- re-resolve stale identifiers immediately before execution
- preserve evidence and return a structured result
- define failure, rollback, and partial-execution behavior
- include unit tests for allowed, blocked, planned, and failed states

## Diagrams and website

Diagram source lives in `docs/diagrams/*.dot`. Rendered SVG files live in `docs/assets/`.

```bash
make diagrams
python scripts/validate_site.py
```

Commit both the source and rendered diagram changes. CI verifies that rendered files match the source.

## Security reports

Use the private process in [SECURITY.md](SECURITY.md). Do not disclose an exploitable issue in a public discussion, issue, or pull request.
