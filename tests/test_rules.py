from pathlib import Path

from bait_edr.detection.rules import load_rules


def test_builtin_rules_are_valid_and_unique() -> None:
    path = Path(__file__).parents[1] / "rules" / "builtin.yml"
    rules = load_rules(path)
    assert len(rules) >= 5
    assert len({rule.id for rule in rules}) == len(rules)
    assert all(rule.tags for rule in rules)
