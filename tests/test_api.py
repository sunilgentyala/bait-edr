from pathlib import Path

from fastapi.testclient import TestClient

from bait_edr.api import create_app
from bait_edr.config import AgentConfig, Settings


def make_client(tmp_path: Path, monkeypatch, token: str | None = None) -> TestClient:
    if token:
        monkeypatch.setenv("BAIT_API_TOKEN", token)
    settings = Settings(
        agent=AgentConfig(
            database_path=str(tmp_path / "api.db"),
            rules_path=str(Path(__file__).parents[1] / "rules" / "builtin.yml"),
        )
    )
    return TestClient(create_app(settings))


def test_health_and_detection_ingest(tmp_path, monkeypatch) -> None:
    client = make_client(tmp_path, monkeypatch)
    assert client.get("/health").status_code == 200
    response = client.post(
        "/events",
        json={
            "category": "process",
            "action": "start",
            "process": {
                "pid": 3333,
                "name": "powershell.exe",
                "command_line": "powershell.exe -EncodedCommand TEST_ONLY",
            },
        },
    )
    assert response.status_code == 200
    assert response.json()["alerts"][0]["rule_id"] == "BAIT-1001"
    assert len(client.get("/alerts").json()) == 1


def test_api_token_is_enforced(tmp_path, monkeypatch) -> None:
    client = make_client(tmp_path, monkeypatch, token="secret-test-token")
    assert client.get("/alerts").status_code == 401
    assert (
        client.get("/alerts", headers={"Authorization": "Bearer secret-test-token"}).status_code
        == 200
    )


def test_alert_response_records_triage(tmp_path, monkeypatch) -> None:
    client = make_client(tmp_path, monkeypatch)
    ingested = client.post(
        "/events",
        json={
            "category": "process",
            "action": "start",
            "process": {
                "pid": 3333,
                "name": "powershell.exe",
                "command_line": "powershell.exe -EncodedCommand TEST_ONLY",
            },
        },
    ).json()
    alert_id = ingested["alerts"][0]["alert_id"]

    response = client.post(f"/alerts/{alert_id}/respond", params={"action": "collect_triage"})

    assert response.status_code == 200
    assert response.json()["status"] == "executed"
    assert client.get("/health").json()["responses"] == 1
