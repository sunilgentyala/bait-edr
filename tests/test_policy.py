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
