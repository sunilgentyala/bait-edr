"""FastAPI service for local ingestion, health, alert review, and responses."""

from __future__ import annotations

import logging
import secrets
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query

from bait_edr.agent import BAITAgent
from bait_edr.config import Settings, load_settings
from bait_edr.models import EndpointEvent, ResponseResult
from bait_edr.response.actions import ResponseManager

LOGGER = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    agent = BAITAgent(settings)
    responder = ResponseManager(settings.response)
    auth_enabled = settings.api_token is not None
    if not auth_enabled:
        LOGGER.warning(
            "BAIT API starting with no bearer token configured (%s unset). "
            "Every endpoint, including /alerts and /alerts/{id}/respond, is unauthenticated.",
            settings.api.token_env,
        )
    app = FastAPI(
        title="BAIT EDR API",
        version="0.2.1",
        description="Defensive endpoint telemetry, detection, and policy-controlled response API.",
    )

    def authorize(authorization: Annotated[str | None, Header()] = None) -> None:
        expected = settings.api_token
        if not expected:
            return
        supplied = ""
        if authorization and authorization.lower().startswith("bearer "):
            supplied = authorization[7:]
        if not secrets.compare_digest(supplied, expected):
            raise HTTPException(status_code=401, detail="Invalid or missing bearer token")

    @app.get("/health")
    def health() -> dict:
        return {
            "status": "ok",
            "agent_id": settings.agent.id,
            "response_mode": settings.response.mode,
            "auth_enabled": auth_enabled,
            **agent.storage.counts(),
        }

    @app.get("/alerts", dependencies=[Depends(authorize)])
    def alerts(limit: int = Query(default=100, ge=1, le=1000)) -> list[dict]:
        return agent.storage.list_alerts(limit=limit)

    @app.post("/events", dependencies=[Depends(authorize)])
    def ingest(event: EndpointEvent) -> dict:
        generated = agent.process_event(event)
        return {
            "event_id": event.event_id,
            "alerts": [item.model_dump(mode="json") for item in generated],
        }

    @app.post("/alerts/{alert_id}/respond", dependencies=[Depends(authorize)])
    def respond(alert_id: str, action: str) -> ResponseResult:
        alert = agent.storage.get_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        result = responder.execute(alert, action)
        agent.storage.save_response(result)
        return result

    return app
