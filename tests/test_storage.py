from bait_edr.models import Alert, EndpointEvent
from bait_edr.storage import SQLiteStorage


def test_storage_round_trip(tmp_path) -> None:
    storage = SQLiteStorage(tmp_path / "bait.db")
    event = EndpointEvent(category="process", action="start", process={"name": "demo"})
    alert = Alert(
        rule_id="BAIT-TEST",
        title="Test",
        severity="low",
        risk_score=25,
        event=event,
    )
    storage.save_event(event)
    storage.save_alert(alert)
    loaded = storage.get_alert(alert.alert_id)
    assert loaded is not None
    assert loaded.rule_id == "BAIT-TEST"
    assert storage.counts() == {"events": 1, "alerts": 1, "responses": 0}
