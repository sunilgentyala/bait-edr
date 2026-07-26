from bait_edr.config import ResponseConfig
from bait_edr.response.policy import ResponsePolicy


def test_protected_process_cannot_be_terminated() -> None:
    policy = ResponsePolicy(
        ResponseConfig(
            mode="active",
            allow_process_termination=True,
            protected_process_names=["lsass.exe"],
        )
    )
    allowed, reason = policy.may_terminate("LSASS.EXE")
    assert allowed is False
    assert "protected" in reason.lower()


def test_quarantine_path_requires_approved_root(tmp_path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    policy = ResponsePolicy(
        ResponseConfig(
            mode="active",
            allow_file_quarantine=True,
            allowed_quarantine_roots=[str(approved)],
        )
    )
    allowed, _ = policy.may_quarantine(str(approved / "sample.bin"))
    denied, _ = policy.may_quarantine(str(tmp_path / "outside.bin"))
    assert allowed is True
    assert denied is False


def test_audit_mode_blocks_termination_even_when_action_enabled() -> None:
    """M_active term: audit mode must deny regardless of E_a or target validity."""

    policy = ResponsePolicy(ResponseConfig(mode="audit", allow_process_termination=True))
    allowed, reason = policy.may_terminate("notepad.exe")
    assert allowed is False
    assert "audit" in reason.lower()


def test_active_mode_blocks_termination_when_action_disabled() -> None:
    """E_a term: active mode alone must not be sufficient without the feature switch."""

    policy = ResponsePolicy(ResponseConfig(mode="active", allow_process_termination=False))
    allowed, reason = policy.may_terminate("notepad.exe")
    assert allowed is False
    assert "disabled" in reason.lower()


def test_active_mode_blocks_quarantine_when_action_disabled(tmp_path) -> None:
    policy = ResponsePolicy(
        ResponseConfig(
            mode="active",
            allow_file_quarantine=False,
            allowed_quarantine_roots=[str(tmp_path)],
        )
    )
    allowed, reason = policy.may_quarantine(str(tmp_path / "sample.bin"))
    assert allowed is False
    assert "disabled" in reason.lower()


def test_protected_process_blocked_even_in_active_enabled_mode() -> None:
    """Protected(x,c) must deny even when M_active and E_a both hold."""

    policy = ResponsePolicy(
        ResponseConfig(
            mode="active",
            allow_process_termination=True,
            protected_process_names=["lsass.exe"],
        )
    )
    allowed, reason = policy.may_terminate("lsass.exe")
    assert allowed is False
    assert "protected" in reason.lower()
