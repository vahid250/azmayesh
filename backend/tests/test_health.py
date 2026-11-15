from fastapi import HTTPException
from fastapi.testclient import TestClient

import app.main as main
from app.config import settings


def test_health_reports_mock_mode_as_not_ready_for_real_provisioning(monkeypatch):
    monkeypatch.setattr(settings, "mock_mode", True)
    response = TestClient(main.app).get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["mock_mode"] is True
    assert payload["real_provisioning_configured"] is False
    assert payload["provisioning_reason"] == "mock_mode_enabled"
    assert payload["connectivity_verified"] is False


def test_health_does_not_claim_readiness_when_wireguard_interface_is_unavailable(monkeypatch):
    monkeypatch.setattr(settings, "mock_mode", False)

    def unavailable():
        raise HTTPException(status_code=503, detail="Configured WireGuard interface is not available")

    monkeypatch.setattr(main, "_validate_real_server", unavailable)
    response = TestClient(main.app).get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["real_provisioning_configured"] is False
    assert payload["provisioning_reason"] == "Configured WireGuard interface is not available"
    assert payload["connectivity_verified"] is False


def test_health_reports_provisioning_ready_only_after_wireguard_readiness_check(monkeypatch):
    monkeypatch.setattr(settings, "mock_mode", False)
    monkeypatch.setattr(main, "_validate_real_server", lambda: None)
    response = TestClient(main.app).get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["real_provisioning_configured"] is True
    assert payload["provisioning_reason"] is None
    assert payload["connectivity_verified"] is False
