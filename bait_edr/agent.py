"""BAIT agent orchestration."""

from __future__ import annotations

import logging
import time

from bait_edr.collectors.base import Collector
from bait_edr.collectors.network import NetworkCollector
from bait_edr.collectors.processes import ProcessCollector
from bait_edr.config import Settings
from bait_edr.correlation import Correlator
from bait_edr.detection.engine import DetectionEngine
from bait_edr.detection.rules import load_rules
from bait_edr.models import Alert, EndpointEvent
from bait_edr.storage import SQLiteStorage

LOGGER = logging.getLogger(__name__)


class BAITAgent:
    def __init__(self, settings: Settings, collectors: list[Collector] | None = None) -> None:
        self.settings = settings
        self.storage = SQLiteStorage(settings.agent.database_path)
        self.engine = DetectionEngine(load_rules(settings.agent.rules_path))
        self.correlator = Correlator()
        self.collectors = collectors or [
            ProcessCollector(
                capture_command_line=settings.privacy.capture_command_line,
                capture_username=settings.privacy.capture_username,
            ),
            NetworkCollector(),
        ]

    def process_event(self, event: EndpointEvent) -> list[Alert]:
        self.storage.save_event(event)
        alerts = [self.correlator.enrich(alert) for alert in self.engine.evaluate(event)]
        for alert in alerts:
            self.storage.save_alert(alert)
            LOGGER.warning(
                "alert rule=%s severity=%s host=%s title=%s",
                alert.rule_id,
                alert.severity,
                alert.event.host,
                alert.title,
            )
        return alerts

    def run_once(self) -> tuple[int, int]:
        event_count = 0
        alert_count = 0
        for collector in self.collectors:
            for event in collector.collect():
                event_count += 1
                alert_count += len(self.process_event(event))
        return event_count, alert_count

    def run_forever(self) -> None:
        LOGGER.info("BAIT agent started with interval=%s", self.settings.agent.interval_seconds)
        while True:
            events, alerts = self.run_once()
            LOGGER.info("cycle complete events=%s alerts=%s", events, alerts)
            time.sleep(self.settings.agent.interval_seconds)
