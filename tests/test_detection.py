from pathlib import Path

from bait_edr.detection.engine import DetectionEngine
from bait_edr.detection.rules import load_rules
from bait_edr.models import DetectionRule, EndpointEvent

RULES = Path(__file__).parents[1] / "rules" / "builtin.yml"


def test_encoded_powershell_rule_matches() -> None:
    engine = DetectionEngine(load_rules(RULES))
    event = EndpointEvent(
        category="process",
        action="start",
        process={
            "name": "PowerShell.EXE",
            "command_line": "powershell.exe -NoP -EncodedCommand TEST_ONLY",
        },
    )
    alerts = engine.evaluate(event)
    assert {alert.rule_id for alert in alerts} == {"BAIT-1001"}
    assert alerts[0].risk_score == 75


def test_benign_process_does_not_match() -> None:
    engine = DetectionEngine(load_rules(RULES))
    event = EndpointEvent(
        category="process",
        action="start",
        process={
            "name": "python",
            "command_line": "python app.py",
            "executable": "/usr/bin/python",
        },
    )
    assert engine.evaluate(event) == []


def test_authentication_threshold() -> None:
    engine = DetectionEngine(load_rules(RULES))
    event = EndpointEvent(
        category="authentication",
        action="logon",
        outcome="failure",
        authentication={"failure_count": 6},
    )
    assert [alert.rule_id for alert in engine.evaluate(event)] == ["BAIT-1005"]


def test_uncommon_remote_port_rule_matches_unknown_direction() -> None:
    engine = DetectionEngine(load_rules(RULES))
    event = EndpointEvent(
        category="network",
        action="connection",
        process={"pid": 42, "name": "demo.exe"},
        network={
            "protocol": "tcp",
            "direction": "unknown",
            "remote_ip": "192.0.2.10",
            "remote_port": 4444,
        },
    )
    assert [alert.rule_id for alert in engine.evaluate(event)] == ["BAIT-1004"]


def test_script_interpreter_from_browser_rule_matches() -> None:
    engine = DetectionEngine(load_rules(RULES))
    event = EndpointEvent(
        category="process",
        action="start",
        process={"parent_name": "chrome.exe", "name": "powershell.exe"},
    )
    assert [alert.rule_id for alert in engine.evaluate(event)] == ["BAIT-1002"]


def test_script_interpreter_rule_requires_both_selections() -> None:
    engine = DetectionEngine(load_rules(RULES))
    event = EndpointEvent(
        category="process",
        action="start",
        process={"parent_name": "explorer.exe", "name": "powershell.exe"},
    )
    assert engine.evaluate(event) == []


def test_temp_directory_executable_rule_matches() -> None:
    engine = DetectionEngine(load_rules(RULES))
    event = EndpointEvent(
        category="process",
        action="start",
        process={"executable": r"C:\Users\demo\AppData\Local\Temp\payload.exe"},
    )
    assert [alert.rule_id for alert in engine.evaluate(event)] == ["BAIT-1003"]


def test_temp_directory_rule_requires_matching_extension() -> None:
    engine = DetectionEngine(load_rules(RULES))
    event = EndpointEvent(
        category="process",
        action="start",
        process={"executable": r"C:\Users\demo\AppData\Local\Temp\notes.txt"},
    )
    assert engine.evaluate(event) == []


def _rule_with_condition(condition: str) -> DetectionRule:
    return DetectionRule(
        id="BAIT-9001",
        title="Condition grammar fixture",
        description="Fixture rule used to exercise condition grammar forms.",
        logsource={"category": "process_creation"},
        detection={
            "selection_a": {"process.name": "a.exe"},
            "selection_b": {"process.name": "b.exe"},
            "condition": condition,
        },
        false_positives=["n/a"],
    )


def test_condition_all_of_them_requires_every_selection() -> None:
    engine = DetectionEngine([_rule_with_condition("all of them")])
    both = EndpointEvent(category="process", action="start", process={"name": "a.exe"})
    assert engine.evaluate(both) == []  # only selection_a can match a single process name


def test_condition_1_of_them_matches_any_selection() -> None:
    engine = DetectionEngine([_rule_with_condition("1 of them")])
    event = EndpointEvent(category="process", action="start", process={"name": "b.exe"})
    assert [alert.rule_id for alert in engine.evaluate(event)] == ["BAIT-9001"]


def test_condition_any_of_wildcard_matches_prefixed_selection() -> None:
    engine = DetectionEngine([_rule_with_condition("any of selection_*")])
    event = EndpointEvent(category="process", action="start", process={"name": "a.exe"})
    assert [alert.rule_id for alert in engine.evaluate(event)] == ["BAIT-9001"]
    unmatched = EndpointEvent(category="process", action="start", process={"name": "c.exe"})
    assert engine.evaluate(unmatched) == []
