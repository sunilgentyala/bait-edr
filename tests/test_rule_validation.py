from pathlib import Path

import pytest
import yaml

from bait_edr.detection.rules import RuleLoadError, load_rules


def write_rule(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "rules.yml"
    path.write_text(yaml.safe_dump([payload], sort_keys=False), encoding="utf-8")
    return path


def base_rule() -> dict:
    return {
        "id": "BAIT-TEST-1",
        "title": "Synthetic Test Rule",
        "description": "Detects a safe synthetic event for validation tests.",
        "severity": "low",
        "tags": ["attack.execution", "attack.t1059"],
        "logsource": {"category": "process_creation", "product": "any"},
        "detection": {"selection": {"event.category": "process"}, "condition": "selection"},
        "response": ["collect_triage"],
        "false_positives": ["Synthetic test data"],
    }


def test_invalid_response_action_is_rejected(tmp_path) -> None:
    payload = base_rule()
    payload["response"] = ["delete_system"]
    with pytest.raises(RuleLoadError, match="unsupported response"):
        load_rules(write_rule(tmp_path, payload))


def test_invalid_regex_is_rejected(tmp_path) -> None:
    payload = base_rule()
    payload["detection"]["selection"] = {"process.name|regex": "[unterminated"}
    with pytest.raises(RuleLoadError, match="invalid regex"):
        load_rules(write_rule(tmp_path, payload))


def test_unknown_condition_selection_is_rejected(tmp_path) -> None:
    payload = base_rule()
    payload["detection"]["condition"] = "missing_selection"
    with pytest.raises(RuleLoadError, match="unknown selections"):
        load_rules(write_rule(tmp_path, payload))
