"""Rule loading and validation."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from bait_edr.fields import parse_rule_key
from bait_edr.models import DetectionRule

RULE_ID_PATTERN = re.compile(r"^BAIT-[A-Z0-9][A-Z0-9.-]{2,}$")
ATTACK_TAG_PATTERN = re.compile(r"^attack\.(?:t\d{4}(?:\.\d{3})?|[a-z][a-z0-9-]*)$")
ALLOWED_OPERATORS = {
    "equals",
    "contains",
    "startswith",
    "endswith",
    "regex",
    "in",
    "gt",
    "gte",
    "lt",
    "lte",
}
ALLOWED_RESPONSE_ACTIONS = {
    "collect_triage",
    "terminate_process",
    "quarantine_file",
    "isolate_host",
    "block_indicator",
}


class RuleLoadError(ValueError):
    """Raised when a rule file cannot be parsed or validated."""


def _selection_names(condition: str) -> list[str] | None:
    condition = condition.strip()
    for prefix in ("all of ", "1 of ", "any of "):
        if condition.startswith(prefix):
            return None
    if " and " in condition:
        return [part.strip() for part in condition.split(" and ")]
    if " or " in condition:
        return [part.strip() for part in condition.split(" or ")]
    return [condition]


def _validate_rule(rule: DetectionRule) -> None:
    if not RULE_ID_PATTERN.fullmatch(rule.id):
        raise RuleLoadError(f"Rule {rule.id!r} has an invalid ID format")
    if not rule.title.strip():
        raise RuleLoadError(f"Rule {rule.id} must have a non-empty title")
    if not rule.description.strip():
        raise RuleLoadError(f"Rule {rule.id} must have a non-empty description")
    if not rule.logsource:
        raise RuleLoadError(f"Rule {rule.id} must declare logsource metadata")
    if not rule.false_positives:
        raise RuleLoadError(f"Rule {rule.id} must document likely false positives")

    invalid_tags = [tag for tag in rule.tags if not ATTACK_TAG_PATTERN.fullmatch(tag)]
    if invalid_tags:
        raise RuleLoadError(f"Rule {rule.id} has invalid ATT&CK tags: {invalid_tags}")

    invalid_actions = [action for action in rule.response if action not in ALLOWED_RESPONSE_ACTIONS]
    if invalid_actions:
        raise RuleLoadError(f"Rule {rule.id} has unsupported response actions: {invalid_actions}")

    detection = rule.detection
    condition = str(detection.get("condition", "")).strip()
    if not condition:
        raise RuleLoadError(f"Rule {rule.id} is missing detection.condition")

    selections = {name: clauses for name, clauses in detection.items() if name != "condition"}
    if not selections:
        raise RuleLoadError(f"Rule {rule.id} must define at least one detection selection")

    for name, clauses in selections.items():
        if not isinstance(clauses, dict) or not clauses:
            raise RuleLoadError(f"Rule {rule.id} selection {name!r} must be a non-empty mapping")
        for rule_key, expected in clauses.items():
            _, operator = parse_rule_key(str(rule_key))
            if operator not in ALLOWED_OPERATORS:
                raise RuleLoadError(
                    f"Rule {rule.id} selection {name!r} uses unsupported operator {operator!r}"
                )
            if operator == "regex":
                values = expected if isinstance(expected, list) else [expected]
                for pattern in values:
                    try:
                        re.compile(str(pattern), re.IGNORECASE)
                    except re.error as exc:
                        raise RuleLoadError(
                            f"Rule {rule.id} contains invalid regex {pattern!r}: {exc}"
                        ) from exc

    names = _selection_names(condition)
    if names is not None:
        unknown = [name for name in names if name not in selections]
        if unknown:
            raise RuleLoadError(
                f"Rule {rule.id} condition references unknown selections: {unknown}"
            )
        return

    prefix, pattern = condition.split(" of ", 1)
    if prefix not in {"all", "1", "any"}:
        raise RuleLoadError(f"Rule {rule.id} uses unsupported condition: {condition}")
    pattern = pattern.strip()
    if pattern == "them":
        return
    if pattern.endswith("*"):
        stem = pattern[:-1]
        if not any(name.startswith(stem) for name in selections):
            raise RuleLoadError(
                f"Rule {rule.id} condition pattern matches no selections: {pattern}"
            )
        return
    if pattern not in selections:
        raise RuleLoadError(f"Rule {rule.id} condition references unknown selection: {pattern}")


def load_rules(path: str | Path) -> list[DetectionRule]:
    rule_path = Path(path)
    if not rule_path.exists():
        raise RuleLoadError(f"Rule file not found: {rule_path}")
    try:
        with rule_path.open("r", encoding="utf-8") as handle:
            payload: Any = yaml.safe_load(handle) or []
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"Invalid YAML in {rule_path}: {exc}") from exc

    if not isinstance(payload, list):
        raise RuleLoadError("Rule file must contain a YAML list")

    rules: list[DetectionRule] = []
    seen: set[str] = set()
    for index, item in enumerate(payload, start=1):
        try:
            rule = DetectionRule.model_validate(item)
        except ValidationError as exc:
            raise RuleLoadError(f"Rule entry {index} failed schema validation: {exc}") from exc
        if rule.id in seen:
            raise RuleLoadError(f"Duplicate rule ID: {rule.id}")
        _validate_rule(rule)
        seen.add(rule.id)
        rules.append(rule)
    return rules
