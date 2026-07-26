"""Simple time-window correlation for repeated detections."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from bait_edr.models import Alert, utc_now


class Correlator:
    """Increase risk when the same host and rule recur in a short window."""

    def __init__(self, window_minutes: int = 10, threshold: int = 3) -> None:
        self.window = timedelta(minutes=window_minutes)
        self.threshold = threshold
        self._history: dict[tuple[str, str], deque] = defaultdict(deque)

    def enrich(self, alert: Alert) -> Alert:
        now = utc_now()
        key = (alert.event.host, alert.rule_id)
        history = self._history[key]
        history.append(now)
        while history and now - history[0] > self.window:
            history.popleft()
        if len(history) >= self.threshold:
            alert.risk_score = min(100, alert.risk_score + 15)
            alert.explanation.append(
                "Correlated "
                f"{len(history)} matching alerts within "
                f"{self.window.seconds // 60} minutes"
            )
        return alert
