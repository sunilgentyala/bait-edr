"""Explainable rule matching and alert creation."""

from __future__ import annotations

from typing import Any

from bait_edr.fields import get_field, match_value, parse_rule_key
from bait_edr.models import Alert, DetectionRule, EndpointEvent

SEVERITY_SCORE = {
    "informational": 10,
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 95,
}


class DetectionEngine:
    """Evaluate endpoint events against validated detection rules."""

    def __init__(self, rules: list[DetectionRule]) -> None:
        self.rules = rules

    def evaluate(self, event: EndpointEvent) -> list[Alert]:
        alerts: list[Alert] = []
        event_payload = {"event": event.model_dump(mode="json"), **event.model_dump(mode="json")}
        for rule in self.rules:
            matched, explanation = self._matches(rule, event_payload)
            if not matched:
                continue
            mitre = [
                tag.split("attack.", 1)[1].upper()
                for tag in rule.tags
                if tag.startswith("attack.t")
            ]
            alerts.append(
                Alert(
                    rule_id=rule.id,
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    risk_score=SEVERITY_SCORE[rule.severity],
                    tags=rule.tags,
                    mitre_attack=mitre,
                    event=event,
                    recommended_actions=rule.response,
                    explanation=explanation,
                )
            )
        return alerts

    def _matches(self, rule: DetectionRule, payload: dict[str, Any]) -> tuple[bool, list[str]]:
        detection = rule.detection
        condition = str(detection["condition"]).strip()
        selections = {name: value for name, value in detection.items() if name != "condition"}
        results: dict[str, tuple[bool, list[str]]] = {
            name: self._match_selection(payload, clauses) for name, clauses in selections.items()
        }

        if condition in results:
            return results[condition]
        if condition.startswith("all of "):
            pattern = condition.removeprefix("all of ").strip()
            chosen = self._choose(results, pattern)
            return all(item[0] for item in chosen), self._explanations(chosen)
        if condition.startswith("1 of ") or condition.startswith("any of "):
            prefix = "1 of " if condition.startswith("1 of ") else "any of "
            pattern = condition.removeprefix(prefix).strip()
            chosen = self._choose(results, pattern)
            return any(item[0] for item in chosen), self._explanations(chosen)
        if " and " in condition:
            names = [part.strip() for part in condition.split(" and ")]
            chosen = [results[name] for name in names]
            return all(item[0] for item in chosen), self._explanations(chosen)
        if " or " in condition:
            names = [part.strip() for part in condition.split(" or ")]
            chosen = [results[name] for name in names]
            return any(item[0] for item in chosen), self._explanations(chosen)
        raise ValueError(f"Unsupported condition in rule {rule.id}: {condition}")

    @staticmethod
    def _choose(
        results: dict[str, tuple[bool, list[str]]], pattern: str
    ) -> list[tuple[bool, list[str]]]:
        if pattern == "them":
            return list(results.values())
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return [result for name, result in results.items() if name.startswith(prefix)]
        return [results[pattern]]

    @staticmethod
    def _explanations(items: list[tuple[bool, list[str]]]) -> list[str]:
        return [message for matched, messages in items if matched for message in messages]

    @staticmethod
    def _match_selection(payload: dict[str, Any], clauses: Any) -> tuple[bool, list[str]]:
        if not isinstance(clauses, dict):
            raise ValueError("Each detection selection must be a mapping")
        explanation: list[str] = []
        for rule_key, expected in clauses.items():
            field, operator = parse_rule_key(rule_key)
            actual = get_field(payload, field)
            try:
                matched = match_value(actual, expected, operator)
            except (TypeError, ValueError):
                matched = False
            if not matched:
                return False, []
            explanation.append(f"{field} matched {operator}")
        return True, explanation
