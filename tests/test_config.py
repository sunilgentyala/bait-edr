from pathlib import Path

import pytest
from pydantic import ValidationError

from bait_edr.config import Settings, default_rules_path, load_settings


def test_invalid_response_mode_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(response={"mode": "automatic"})


def test_non_mapping_configuration_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.yml"
    path.write_text("- not\n- a\n- mapping\n", encoding="utf-8")
    with pytest.raises(ValueError, match="YAML mapping"):
        load_settings(path)


def test_packaged_default_rules_exist() -> None:
    packaged = Path(default_rules_path())
    source = Path(__file__).parents[1] / "rules" / "builtin.yml"
    assert packaged.is_file()
    assert packaged.read_bytes() == source.read_bytes()
