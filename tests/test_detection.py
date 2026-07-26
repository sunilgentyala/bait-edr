from pathlib import Path

from bait_edr.detection.engine import DetectionEngine
from bait_edr.detection.rules import load_rules
from bait_edr.models import EndpointEvent

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
