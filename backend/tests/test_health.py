from fastapi import HTTPException
from fastapi.testclient import TestClient
from types import SimpleNamespace

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



def test_database_diagnostic_runs_only_read_only_probe_for_authenticated_request():
    class FakeSession:
        def execute(self, statement):
            assert str(statement) == "SELECT 1"
            return SimpleNamespace(scalar_one=lambda: 1)

    original_overrides = main.app.dependency_overrides.copy()

    def override_db():
        yield FakeSession()

    main.app.dependency_overrides[main.get_db] = override_db
    main.app.dependency_overrides[main.require_authenticated_request] = lambda: {
        "auth_method": "test"
    }
    try:
        response = TestClient(main.app).get("/api/v1/diagnostics/database")
    finally:
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(original_overrides)

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "database": "reachable",
        "probe": "SELECT 1",
        "read_only": True,
    }


def test_database_diagnostic_hides_database_driver_errors():
    class FailingSession:
        def execute(self, statement):
            assert str(statement) == "SELECT 1"
            raise RuntimeError("sensitive host and password details")

    original_overrides = main.app.dependency_overrides.copy()

    def override_db():
        yield FailingSession()

    main.app.dependency_overrides[main.get_db] = override_db
    main.app.dependency_overrides[main.require_authenticated_request] = lambda: {
        "auth_method": "test"
    }
    try:
        response = TestClient(main.app).get("/api/v1/diagnostics/database")
    finally:
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(original_overrides)

    assert response.status_code == 503
    assert response.json() == {"detail": "Database connectivity check failed"}
    assert "password" not in response.text


def test_public_service_status_announces_thirty_day_trial_and_referral_reward(monkeypatch):
    monkeypatch.setattr(settings, "service_mode", "trial")
    monkeypatch.setattr(settings, "trial_duration_days", 30)
    monkeypatch.setattr(settings, "referral_reward_bytes", 104857600)
    response = TestClient(main.app).get("/api/v1/public/service-status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["mode"] == "trial"
    assert payload["trial_duration_days"] == 30
    assert payload["referral_reward_bytes"] == 100 * 1024 * 1024
    assert payload["accepting_new_activations"] is True


def test_paused_service_announces_return_and_blocks_new_orders(monkeypatch):
    monkeypatch.setattr(settings, "service_mode", "paused")
    original_overrides = main.app.dependency_overrides.copy()
    main.app.dependency_overrides[main.require_authenticated_request] = lambda: {
        "auth_method": "test", "user": {"id": 12345}
    }
    try:
        status = TestClient(main.app).get("/api/v1/public/service-status")
        assert status.status_code == 200
        assert status.json()["mode"] == "paused"
        assert "زمان بازگشت" in status.json()["message"]
        order = TestClient(main.app).post(
            "/api/v1/orders",
            headers={"Idempotency-Key": "paused-order-key-0001"},
            json={"plan_code": "sample-30d", "payment_method": "crypto"},
        )
        assert order.status_code == 503
        assert "موقتاً متوقف" in order.json()["detail"]
    finally:
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(original_overrides)
