"""Field access and matching helpers for detection rules."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any


def get_field(payload: dict[str, Any], dotted_path: str) -> Any:
    current: Any = payload
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _values(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [value]


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def match_value(actual: Any, expected: Any, operator: str) -> bool:
    """Evaluate one rule field using a conservative set of operators."""

    candidates = _values(expected)
    actual_text = _as_text(actual)
    actual_lower = actual_text.lower()

    if operator == "equals":
        return any(actual == candidate for candidate in candidates)
    if operator == "contains":
        return any(_as_text(candidate).lower() in actual_lower for candidate in candidates)
    if operator == "startswith":
        return any(actual_lower.startswith(_as_text(candidate).lower()) for candidate in candidates)
    if operator == "endswith":
        return any(actual_lower.endswith(_as_text(candidate).lower()) for candidate in candidates)
    if operator == "regex":
        return any(
            re.search(_as_text(candidate), actual_text, re.IGNORECASE) is not None
            for candidate in candidates
        )
    if operator == "in":
        if isinstance(actual, Iterable) and not isinstance(actual, (str, bytes, dict)):
            return any(candidate in actual for candidate in candidates)
        return any(actual == candidate for candidate in candidates)
    if operator == "gt":
        return any(float(actual) > float(candidate) for candidate in candidates)
    if operator == "gte":
        return any(float(actual) >= float(candidate) for candidate in candidates)
    if operator == "lt":
        return any(float(actual) < float(candidate) for candidate in candidates)
    if operator == "lte":
        return any(float(actual) <= float(candidate) for candidate in candidates)
    raise ValueError(f"Unsupported detection operator: {operator}")


def parse_rule_key(key: str) -> tuple[str, str]:
    if "|" not in key:
        return key, "equals"
    field, operator = key.rsplit("|", 1)
    return field, operator
