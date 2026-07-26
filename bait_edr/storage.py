"""SQLite persistence for events, alerts, and response records."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Any

from bait_edr.models import Alert, EndpointEvent, ResponseResult


class SQLiteStorage:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._initialize()

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    category TEXT NOT NULL,
                    host TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS responses (
                    response_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
                """
            )

    def save_event(self, event: EndpointEvent) -> None:
        payload = event.model_dump_json()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO events VALUES (?, ?, ?, ?, ?)",
                (event.event_id, event.timestamp.isoformat(), event.category, event.host, payload),
            )

    def save_alert(self, alert: Alert) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO alerts VALUES (?, ?, ?, ?, ?, ?)",
                (
                    alert.alert_id,
                    alert.created_at.isoformat(),
                    alert.rule_id,
                    alert.severity,
                    alert.status,
                    alert.model_dump_json(),
                ),
            )

    def save_response(self, response: ResponseResult) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO responses VALUES (?, ?, ?, ?, ?, ?)",
                (
                    response.response_id,
                    response.timestamp.isoformat(),
                    response.alert_id,
                    response.action,
                    response.status,
                    response.model_dump_json(),
                ),
            )

    def list_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def get_alert(self, alert_id: str) -> Alert | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
        return Alert.model_validate_json(row["payload"]) if row else None

    def counts(self) -> dict[str, int]:
        with self._connect() as conn:
            events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            responses = conn.execute("SELECT COUNT(*) FROM responses").fetchone()[0]
        return {"events": events, "alerts": alerts, "responses": responses}
