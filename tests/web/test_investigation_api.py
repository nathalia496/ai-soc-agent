"""
Unit tests for the minimal HTTP API wrapping investigate_alert().

Mocks investigate_alert() itself (already covered end-to-end by
tests/orchestrator/test_investigate_alert.py) to verify the web layer:
auth enforcement, the success response shape, and that an alert-not-found
failure surfaces as an HTTP error (404) rather than a 500.
"""

from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from src.core.errors import IntegrationError
from src.web import investigation_api

ADMIN_SECRET = "test-admin-secret"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(investigation_api, "ADMIN_SECRET", ADMIN_SECRET)
    # Bypass the real startup (`lifespan`/`load_config_from_file`) and
    # populate the module-level client registry directly.
    monkeypatch.setattr(
        investigation_api,
        "_clients",
        {
            "siem_client": Mock(name="siem_client"),
            "cti_clients": [],
            "misp_client": None,
            "attack_mapper": None,
            "llm_client": Mock(name="llm_client"),
            "case_client": None,
            "storage_client": None,
        },
    )
    return TestClient(investigation_api.app)


def _auth_headers():
    return {"X-Admin-Secret": ADMIN_SECRET}


def test_health_reports_configured_clients(client):
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["integrations"]["siem"] is True
    assert body["integrations"]["llm"] is True
    assert body["integrations"]["misp"] is False
    assert body["integrations"]["case_management"] is False


def test_investigate_requires_auth(client):
    response = client.post("/investigate/verify-alert-0001")

    assert response.status_code == 401


def test_investigate_rejects_wrong_secret(client):
    response = client.post(
        "/investigate/verify-alert-0001",
        headers={"X-Admin-Secret": "wrong-secret"},
    )

    assert response.status_code == 401


def test_investigate_success(client, monkeypatch):
    expected_report = {
        "report": {
            "timeline": [],
            "observables": [],
            "hypothesis": "Likely malicious PowerShell activity.",
            "next_steps": ["Isolate the endpoint for review (human action required)."],
        },
        "alert": {"id": "verify-alert-0001"},
        "warnings": [],
    }
    mock_investigate = Mock(return_value=expected_report)
    monkeypatch.setattr(investigation_api, "investigate_alert", mock_investigate)

    response = client.post(
        "/investigate/verify-alert-0001",
        headers=_auth_headers(),
        json={"case_id": "case-123", "minutes_before": 15},
    )

    assert response.status_code == 200
    assert response.json() == expected_report

    assert mock_investigate.call_count == 1
    _, kwargs = mock_investigate.call_args
    assert kwargs["alert_id"] == "verify-alert-0001"
    assert kwargs["case_id"] == "case-123"
    assert kwargs["minutes_before"] == 15
    assert kwargs["siem_client"] is investigation_api._clients["siem_client"]
    assert kwargs["llm_client"] is investigation_api._clients["llm_client"]


def test_investigate_alert_not_found_returns_404(client, monkeypatch):
    mock_investigate = Mock(
        side_effect=IntegrationError("Failed to get security alert: Alert bogus-id not found")
    )
    monkeypatch.setattr(investigation_api, "investigate_alert", mock_investigate)

    response = client.post("/investigate/bogus-id", headers=_auth_headers())

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_investigate_upstream_failure_returns_502(client, monkeypatch):
    mock_investigate = Mock(side_effect=IntegrationError("Ollama request timed out"))
    monkeypatch.setattr(investigation_api, "investigate_alert", mock_investigate)

    response = client.post("/investigate/verify-alert-0001", headers=_auth_headers())

    assert response.status_code == 502


def test_investigate_without_siem_configured_returns_503(client, monkeypatch):
    monkeypatch.setattr(
        investigation_api,
        "_clients",
        {
            "siem_client": None,
            "cti_clients": [],
            "misp_client": None,
            "attack_mapper": None,
            "llm_client": Mock(),
            "case_client": None,
            "storage_client": None,
        },
    )

    response = client.post("/investigate/verify-alert-0001", headers=_auth_headers())

    assert response.status_code == 503
