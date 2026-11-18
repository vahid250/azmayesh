from fastapi import HTTPException
from fastapi.testclient import TestClient
from types import SimpleNamespace
from datetime import timedelta
from decimal import Decimal

from app.models import PaymentAsset
from app.quote_engine import RateObservation

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
    main.app.dependency_overrides[main.authenticate_request] = lambda: {
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
    main.app.dependency_overrides[main.authenticate_request] = lambda: {
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


def test_public_service_status_reports_prelaunch_and_blocks_new_activations(monkeypatch):
    monkeypatch.setattr(settings, "service_mode", "prelaunch")
    monkeypatch.setattr(settings, "trial_duration_days", 30)
    monkeypatch.setattr(settings, "referral_reward_bytes", 104857600)
    response = TestClient(main.app).get("/api/v1/public/service-status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["mode"] == "prelaunch"
    assert payload["trial_duration_days"] == 30
    assert payload["referral_reward_bytes"] == 100 * 1024 * 1024
    assert payload["accepting_new_activations"] is False
    assert "هنوز دوره آزمایشی آغاز نشده" in payload["message"]


def test_paused_service_announces_return_and_blocks_new_orders(monkeypatch):
    monkeypatch.setattr(settings, "service_mode", "paused")
    original_overrides = main.app.dependency_overrides.copy()
    main.app.dependency_overrides[main.authenticate_request] = lambda: {
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
        config = TestClient(main.app).post(
            "/api/v1/wireguard/configs",
            headers={"X-Telegram-Init-Data": "test"},
            json={"client_name": "paused-lab"},
        )
        assert config.status_code == 503
        assert "موقتاً متوقف" in config.json()["detail"]
    finally:
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(original_overrides)



def test_public_payment_rate_returns_best_validated_source_without_creating_invoice(monkeypatch):
    asset = PaymentAsset(
        id=7, currency="USDT", network="TRC20", asset_type="token",
        decimals=6, min_confirmations=20, is_enabled=True,
    )

    class FakeSession:
        def execute(self, statement):
            return SimpleNamespace(scalar_one_or_none=lambda: asset)

    original_overrides = main.app.dependency_overrides.copy()

    def override_db():
        yield FakeSession()

    async def fake_fetch(*, payment_currency, mappings, now, **kwargs):
        assert payment_currency == "USDT"
        assert len(mappings) == 3
        return [
            RateObservation("coinbase", Decimal("0.9990"), now - timedelta(seconds=1)),
            RateObservation("kraken", Decimal("1.0010"), now - timedelta(seconds=1)),
        ]

    monkeypatch.setattr(main, "load_enabled_market_specs", lambda *args, **kwargs: (
        SimpleNamespace(source="coinbase"),
        SimpleNamespace(source="kraken"),
        SimpleNamespace(source="bitstamp"),
    ))
    monkeypatch.setattr(main, "fetch_payment_asset_observations", fake_fetch)
    main.app.dependency_overrides[main.get_db] = override_db
    try:
        response = TestClient(main.app).get(
            "/api/v1/public/payment-rate?currency=USDT&network=TRC20"
        )
    finally:
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(original_overrides)

    assert response.status_code == 200
    payload = response.json()
    assert payload["currency"] == "USDT"
    assert payload["network"] == "TRC20"
    assert payload["display_rate"]["source"] == "coinbase"
    assert Decimal(payload["display_rate"]["usd_per_unit"]) == Decimal(1) / Decimal("0.9990")
    assert payload["quote_benchmark"]["selected_sources"] == ["coinbase", "kraken"]
    assert payload["informational_only"] is True
    assert payload["invoice_rate_locked"] is False


def test_public_payment_rate_rejects_disabled_or_unknown_asset(monkeypatch):
    class FakeSession:
        def execute(self, statement):
            return SimpleNamespace(scalar_one_or_none=lambda: None)

    original_overrides = main.app.dependency_overrides.copy()

    def override_db():
        yield FakeSession()

    main.app.dependency_overrides[main.get_db] = override_db
    try:
        response = TestClient(main.app).get(
            "/api/v1/public/payment-rate?currency=USDT&network=TRC20"
        )
    finally:
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(original_overrides)

    assert response.status_code == 404
    assert response.json() == {"detail": "Payment asset or network is not available"}


def test_public_payment_rate_fails_closed_when_market_mappings_are_not_ready(monkeypatch):
    asset = PaymentAsset(
        id=7, currency="USDT", network="TRC20", asset_type="token",
        decimals=6, min_confirmations=20, is_enabled=True,
    )

    class FakeSession:
        def execute(self, statement):
            return SimpleNamespace(scalar_one_or_none=lambda: asset)

    original_overrides = main.app.dependency_overrides.copy()

    def override_db():
        yield FakeSession()

    def missing_mappings(*args, **kwargs):
        raise ValueError("unreviewed market mapping")

    monkeypatch.setattr(main, "load_enabled_market_specs", missing_mappings)
    main.app.dependency_overrides[main.get_db] = override_db
    try:
        response = TestClient(main.app).get(
            "/api/v1/public/payment-rate?currency=USDT&network=TRC20"
        )
    finally:
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(original_overrides)

    assert response.status_code == 503
    assert response.json() == {"detail": "A validated market rate is temporarily unavailable"}



def test_public_payment_assets_lists_only_enabled_assets_with_complete_reviewed_mappings(monkeypatch):
    asset = PaymentAsset(
        id=9, currency="USDC", network="BASE", asset_type="token",
        decimals=6, min_confirmations=12, is_enabled=True,
    )

    class FakeResult:
        def scalars(self):
            return SimpleNamespace(all=lambda: [asset])

    class FakeSession:
        def execute(self, statement):
            return FakeResult()

    original_overrides = main.app.dependency_overrides.copy()
    def override_db():
        yield FakeSession()

    main.app.dependency_overrides[main.get_db] = override_db
    monkeypatch.setattr(main, "load_enabled_market_specs", lambda *args, **kwargs: (
        SimpleNamespace(source="coinbase"),
        SimpleNamespace(source="kraken"),
        SimpleNamespace(source="bitstamp"),
    ))
    try:
        response = TestClient(main.app).get("/api/v1/public/payment-assets")
    finally:
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(original_overrides)

    assert response.status_code == 200
    assert response.json() == {
        "assets": [{
            "currency": "USDC",
            "network": "BASE",
            "asset_type": "token",
            "decimals": 6,
        }]
    }


def test_public_payment_assets_hides_assets_without_complete_reviewed_mappings(monkeypatch):
    asset = PaymentAsset(
        id=10, currency="USDT", network="TRC20", asset_type="token",
        decimals=6, min_confirmations=20, is_enabled=True,
    )

    class FakeResult:
        def scalars(self):
            return SimpleNamespace(all=lambda: [asset])

    class FakeSession:
        def execute(self, statement):
            return FakeResult()

    original_overrides = main.app.dependency_overrides.copy()
    main.app.dependency_overrides[main.get_db] = lambda: iter([FakeSession()])
    monkeypatch.setattr(
        main, "load_enabled_market_specs",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("mapping missing")),
    )
    try:
        response = TestClient(main.app).get("/api/v1/public/payment-assets")
    finally:
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(original_overrides)

    assert response.status_code == 200
    assert response.json() == {"assets": []}
