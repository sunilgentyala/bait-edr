from bait_edr.correlation import Correlator
from bait_edr.models import Alert, EndpointEvent


def test_repeated_alerts_raise_risk() -> None:
    correlator = Correlator(window_minutes=10, threshold=3)
    alert = Alert(
        rule_id="BAIT-REPEAT",
        title="Repeated behavior",
        severity="medium",
        risk_score=50,
        event=EndpointEvent(category="process", action="start"),
    )
    correlator.enrich(alert.model_copy(deep=True))
    correlator.enrich(alert.model_copy(deep=True))
    third = correlator.enrich(alert.model_copy(deep=True))
    assert third.risk_score == 65
    assert any("Correlated 3" in line for line in third.explanation)
