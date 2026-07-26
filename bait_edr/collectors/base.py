"""Collector interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from bait_edr.models import EndpointEvent


class Collector(ABC):
    @abstractmethod
    def collect(self) -> list[EndpointEvent]:
        """Return newly observed endpoint events."""
