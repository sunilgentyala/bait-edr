"""Normalized data models used across BAIT."""

from __future__ import annotations

import platform as platform_module
import socket
import uuid
from datetime import UTC, date as Date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["informational", "low", "medium", "high", "critical"]


def utc_now() -> datetime:
    return datetime.now(UTC)


class EndpointEvent(BaseModel):
    """A normalized endpoint event with OCSF-friendly field names."""

    model_config = ConfigDict(extra="allow")

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=utc_now)
    host: str = Field(default_factory=socket.gethostname)
    platform: str = Field(default_factory=platform_module.system)
    category: str
    action: str
    outcome: str = "unknown"
    user: dict[str, Any] = Field(default_factory=dict)
    process: dict[str, Any] = Field(default_factory=dict)
    file: dict[str, Any] = Field(default_factory=dict)
    network: dict[str, Any] = Field(default_factory=dict)
    authentication: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DetectionRule(BaseModel):
    """A compact, Sigma-inspired detection rule."""

    id: str
    title: str
    description: str = ""
    status: str = "experimental"
    author: str = "BAIT Contributors"
    date: Date | None = None
    modified: Date | None = None
    severity: Severity = "medium"
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    logsource: dict[str, Any] = Field(default_factory=dict)
    detection: dict[str, Any]
    fields: list[str] = Field(default_factory=list)
    response: list[str] = Field(default_factory=lambda: ["collect_triage"])
    false_positives: list[str] = Field(default_factory=list)


class Alert(BaseModel):
    """A detection result created from one event and one matching rule."""

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=utc_now)
    rule_id: str
    title: str
    description: str = ""
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    tags: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    event: EndpointEvent
    recommended_actions: list[str] = Field(default_factory=list)
    status: Literal["open", "investigating", "contained", "closed"] = "open"
    explanation: list[str] = Field(default_factory=list)


class ResponseResult(BaseModel):
    """Result of a policy-evaluated response action."""

    response_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=utc_now)
    alert_id: str
    action: str
    status: Literal["planned", "executed", "blocked", "failed"]
    message: str
    evidence: dict[str, Any] = Field(default_factory=dict)
