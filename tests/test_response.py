from pathlib import Path

from bait_edr.config import ResponseConfig
from bait_edr.models import Alert, EndpointEvent
from bait_edr.response.actions import ResponseManager


def make_alert() -> Alert:
    return Alert(
        rule_id="BAIT-TEST",
        title="Test alert",
        severity="high",
        risk_score=75,
        event=EndpointEvent(
            category="process",
            action="start",
            process={"pid": 424242, "name": "demo.exe", "executable": "/tmp/demo.exe"},
        ),
    )


def test_audit_mode_never_terminates() -> None:
    manager = ResponseManager(
        ResponseConfig(mode="audit", allow_process_termination=True, protected_process_names=[])
    )
    result = manager.execute(make_alert(), "terminate_process")
    assert result.status == "planned"
    assert "audit" in result.message.lower()


def test_unknown_action_is_blocked() -> None:
    manager = ResponseManager(ResponseConfig())
    result = manager.execute(make_alert(), "unknown")
    assert result.status == "blocked"


def test_active_termination_blocks_changed_process_identity(monkeypatch) -> None:
    class FakeProcess:
        terminated = False

        def __init__(self, pid: int) -> None:
            self.pid = pid

        def name(self) -> str:
            return "different.exe"

        def create_time(self) -> float:
            return 100.0

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: int) -> None:
            return None

    monkeypatch.setattr("bait_edr.response.actions.psutil.Process", FakeProcess)
    manager = ResponseManager(
        ResponseConfig(mode="active", allow_process_termination=True, protected_process_names=[])
    )
    result = manager.execute(make_alert(), "terminate_process")
    assert result.status == "blocked"
    assert "identity changed" in result.message.lower()


def test_active_termination_blocks_reused_pid_with_stale_create_time(monkeypatch) -> None:
    """IdentityStable(x,z): same name, but the live create_time no longer matches the
    alert's reported create_time, meaning the PID was recycled onto a new process."""

    class FakeProcess:
        def __init__(self, pid: int) -> None:
            self.pid = pid

        def name(self) -> str:
            return "demo.exe"

        def create_time(self) -> float:
            return 999999.0

        def terminate(self) -> None:  # pragma: no cover - must not be reached
            raise AssertionError("terminate() must not run when identity is unstable")

        def wait(self, timeout: int) -> None:  # pragma: no cover
            return None

    monkeypatch.setattr("bait_edr.response.actions.psutil.Process", FakeProcess)
    alert = make_alert()
    alert.event.process["create_time"] = 100.0
    manager = ResponseManager(
        ResponseConfig(mode="active", allow_process_termination=True, protected_process_names=[])
    )
    result = manager.execute(alert, "terminate_process")
    assert result.status == "blocked"
    assert "reused" in result.message.lower()


def test_active_termination_executes_when_identity_is_stable(monkeypatch) -> None:
    """The single highest-consequence success path: audit->active, target valid,
    not protected, identity stable, action actually dispatched to psutil."""

    class FakeProcess:
        def __init__(self, pid: int) -> None:
            self.pid = pid
            self.terminated = False

        def name(self) -> str:
            return "demo.exe"

        def create_time(self) -> float:
            return 100.0

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: int) -> None:
            return None

    monkeypatch.setattr("bait_edr.response.actions.psutil.Process", FakeProcess)
    alert = make_alert()
    alert.event.process["create_time"] = 100.0
    manager = ResponseManager(
        ResponseConfig(mode="active", allow_process_termination=True, protected_process_names=[])
    )
    result = manager.execute(alert, "terminate_process")
    assert result.status == "executed"
    assert result.evidence["pid"] == alert.event.process["pid"]


def test_active_quarantine_preserves_hash_and_metadata(tmp_path) -> None:
    approved = tmp_path / "approved"
    quarantine = tmp_path / "quarantine"
    approved.mkdir()
    sample = approved / "sample.bin"
    sample.write_bytes(b"safe synthetic content")
    alert = make_alert()
    alert.event.process["executable"] = str(sample)
    manager = ResponseManager(
        ResponseConfig(
            mode="active",
            allow_file_quarantine=True,
            allowed_quarantine_roots=[str(approved)],
            quarantine_directory=str(quarantine),
        )
    )

    result = manager.execute(alert, "quarantine_file")

    assert result.status == "executed"
    assert not sample.exists()
    destination = Path(result.evidence["destination"])
    assert destination.exists()
    assert destination.with_suffix(".json").exists()
    assert result.evidence["sha256"]


def test_block_indicator_requires_an_indicator() -> None:
    alert = make_alert()
    alert.event.network = {}
    alert.event.file = {}
    result = ResponseManager(ResponseConfig()).execute(alert, "block_indicator")
    assert result.status == "blocked"
