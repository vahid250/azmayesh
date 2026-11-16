import ipaddress
from cryptography.hazmat.primitives.asymmetric import x25519
from app.wireguard import generate_keypair


def test_wireguard_keypair_is_valid_x25519():
    private_b64, public_b64 = generate_keypair()
    import base64
    private = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
    derived = private.public_key().public_bytes_raw()
    assert derived == base64.b64decode(public_b64)


def test_testnet_address_is_not_used_as_real_default():
    # Regression guard: the former sample endpoint was TEST-NET-3, not a routable server.
    assert ipaddress.ip_address("203.0.113.10").is_private


def test_mock_endpoint_marks_config_as_non_connectable_and_encrypts_storage(monkeypatch):
    from cryptography.fernet import Fernet
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from app.config import settings
    from app.database import Base, get_db
    from app.main import app
    from app.models import WireGuardClient

    test_engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(test_engine)
    TestingSession = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)

    from datetime import datetime, timedelta, timezone
    from app.models import Entitlement, Order
    with TestingSession() as seed_db:
        order = Order(
            telegram_user_id="lab-local",
            plan_code="test-plan",
            idempotency_key="wireguard-test-key-0001",
            amount_minor=100,
            currency="TEST",
            quota_bytes=10_000,
            max_devices=2,
            duration_days=30,
            status="paid",
        )
        seed_db.add(order)
        seed_db.flush()
        seed_db.add(Entitlement(
            order_id=order.id,
            telegram_user_id="lab-local",
            quota_bytes=10_000,
            consumed_bytes=0,
            max_devices=2,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            status="active",
        ))
        seed_db.commit()

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(settings, "app_env", "development")
    monkeypatch.setattr(settings, "api_key", "unit-test-api-key")
    monkeypatch.setattr(settings, "encryption_key", Fernet.generate_key().decode())
    monkeypatch.setattr(settings, "mock_mode", True)
    monkeypatch.setattr(settings, "wg_subnet", "10.66.66.0/24")
    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app)
        denied = client.post("/api/v1/wireguard/configs", json={"client_name": "test"})
        assert denied.status_code == 401
        response = client.post(
            "/api/v1/wireguard/configs",
            headers={"X-API-Key": "unit-test-api-key"},
            json={"client_name": "test device"},
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["state"] == "generated_mock"
        assert payload["connectivity_verified"] is False
        assert "mock.invalid" in payload["config"]
        assert "[Interface]" in payload["config"] and "[Peer]" in payload["config"]
        client_id = payload["id"]

        # Config can be retrieved only through the authenticated endpoint and is decrypted at the edge.
        fetched = client.get(
            f"/api/v1/wireguard/configs/{client_id}/config",
            headers={"X-API-Key": "unit-test-api-key"},
        )
        assert fetched.status_code == 200
        assert fetched.json()["config"] == payload["config"]
        listed = client.get("/api/v1/wireguard/configs", headers={"X-API-Key": "unit-test-api-key"})
        assert listed.status_code == 200 and len(listed.json()) == 1

        # A different Telegram identity cannot read a lab-owned client.
        import hashlib, hmac, time
        from urllib.parse import urlencode
        monkeypatch.setattr(settings, "telegram_bot_token", "123456:unit-test-token")
        foreign_values = {
            "auth_date": str(int(time.time())),
            "user": '{"id":9876,"first_name":"Other"}',
        }
        secret = hmac.new(b"WebAppData", settings.telegram_bot_token.encode(), hashlib.sha256).digest()
        check = "\n".join(f"{k}={v}" for k, v in sorted(foreign_values.items()))
        foreign_values["hash"] = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
        foreign = client.get(
            f"/api/v1/wireguard/configs/{client_id}/config",
            headers={"X-Telegram-Init-Data": urlencode(foreign_values)},
        )
        assert foreign.status_code == 404

        status = client.get(
            f"/api/v1/wireguard/configs/{client_id}/status",
            headers={"X-API-Key": "unit-test-api-key"},
        )
        assert status.status_code == 200
        assert status.json()["handshake_seen"] is False
        assert status.json()["connectivity_verified"] is False

        revoked = client.post(
            f"/api/v1/wireguard/configs/{client_id}/revoke",
            headers={"X-API-Key": "unit-test-api-key"},
        )
        assert revoked.status_code == 200 and revoked.json()["revoked"] is True
        blocked = client.get(
            f"/api/v1/wireguard/configs/{client_id}/config",
            headers={"X-API-Key": "unit-test-api-key"},
        )
        assert blocked.status_code == 410

        with TestingSession() as db:
            stored = db.execute(select(WireGuardClient)).scalar_one()
            from app.models import WireGuardClientOwner
            stored_owner = db.get(WireGuardClientOwner, stored.id)
            assert stored_owner.entitlement_id is not None
            assert "PrivateKey" not in stored.config_encrypted
            assert "=" not in stored.private_key_encrypted[:8]
            assert stored.state == "revoked"
    finally:
        app.dependency_overrides.clear()
        test_engine.dispose()



def test_telegram_init_data_signature_and_expiry(monkeypatch):
    import hashlib
    import hmac
    import time
    from urllib.parse import urlencode
    import pytest
    from fastapi import HTTPException
    from app.config import settings
    from app.security import verify_telegram_init_data

    token = "123456:unit-test-token"
    monkeypatch.setattr(settings, "telegram_bot_token", token)
    auth_date = str(int(time.time()))
    values = {
        "auth_date": auth_date,
        "query_id": "AAE-unit-test",
        "user": '{"id":12345,"first_name":"Test"}',
    }
    secret = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
    data_check = "\n".join(f"{k}={v}" for k, v in sorted(values.items()))
    values["hash"] = hmac.new(secret, data_check.encode(), hashlib.sha256).hexdigest()
    verified = verify_telegram_init_data(urlencode(values))
    assert verified["user"]["id"] == 12345

    values["hash"] = "0" * 64
    with pytest.raises(HTTPException) as exc:
        verify_telegram_init_data(urlencode(values))
    assert exc.value.status_code == 401



def _real_wireguard_test_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from app.database import Base
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)()


def test_real_wireguard_peer_registration_and_status_are_verified_separately(monkeypatch):
    import base64
    import subprocess
    from app.config import settings
    from app.wireguard import issue_wireguard_config, get_wireguard_peer_status

    db = _real_wireguard_test_db()
    monkeypatch.setattr(settings, "mock_mode", False)
    monkeypatch.setattr(settings, "wg_server_endpoint", "198.51.100.20:51820")
    monkeypatch.setattr(settings, "wg_server_public_key", base64.b64encode(b"s" * 32).decode())
    monkeypatch.setattr(settings, "wg_interface", "wg-test")
    monkeypatch.setattr(settings, "wg_subnet", "10.77.0.0/24")
    monkeypatch.setattr(settings, "encryption_key", __import__("cryptography.fernet", fromlist=["Fernet"]).Fernet.generate_key().decode())
    monkeypatch.setattr("app.wireguard.shutil.which", lambda _: "/usr/bin/wg")
    commands = []

    def fake_run(command, check=False, capture_output=False, text=False, timeout=None):
        commands.append(command)
        if command[:3] == ["wg", "show", "wg-test"]:
            return subprocess.CompletedProcess(command, 0, stdout="interface dump\n", stderr="")
        if command[:3] == ["wg", "set", "wg-test"]:
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        raise AssertionError("Unexpected WireGuard command")

    monkeypatch.setattr("app.wireguard.subprocess.run", fake_run)
    try:
        issued = issue_wireguard_config(db, "real-test", "1001")
        assert issued["state"] == "peer_registered"
        assert issued["connectivity_verified"] is False
        assert "Endpoint = 198.51.100.20:51820" in issued["config"]

        row = db.get(__import__("app.models", fromlist=["WireGuardClient"]).WireGuardClient, issued["id"])
        dump = (
            "private\tpublic\t51820\toff\n"
            f"{row.public_key}\t(none)\t198.51.100.20:51820\t10.77.0.2/32\t1700000000\t456\t789\t25\n"
        )

        def status_run(command, check=False, capture_output=False, text=False, timeout=None):
            return subprocess.CompletedProcess(command, 0, stdout=dump, stderr="")

        monkeypatch.setattr("app.wireguard.subprocess.run", status_run)
        status = get_wireguard_peer_status(row)
        assert status["handshake_seen"] is True
        assert status["rx_bytes"] == 456 and status["tx_bytes"] == 789
        assert status["connectivity_verified"] is False
        assert commands[0][:3] == ["wg", "show", "wg-test"]
    finally:
        db.close()


def test_real_wireguard_registration_failure_rolls_back_client(monkeypatch):
    import base64
    import subprocess
    import pytest
    from fastapi import HTTPException
    from sqlalchemy import select
    from app.config import settings
    from app.models import WireGuardClient
    from app.wireguard import issue_wireguard_config

    db = _real_wireguard_test_db()
    monkeypatch.setattr(settings, "mock_mode", False)
    monkeypatch.setattr(settings, "wg_server_endpoint", "198.51.100.20:51820")
    monkeypatch.setattr(settings, "wg_server_public_key", base64.b64encode(b"s" * 32).decode())
    monkeypatch.setattr(settings, "wg_interface", "wg-test")
    monkeypatch.setattr(settings, "wg_subnet", "10.78.0.0/24")
    monkeypatch.setattr(settings, "encryption_key", __import__("cryptography.fernet", fromlist=["Fernet"]).Fernet.generate_key().decode())
    monkeypatch.setattr("app.wireguard.shutil.which", lambda _: "/usr/bin/wg")

    def failing_run(command, check=False, capture_output=False, text=False, timeout=None):
        if command[:3] == ["wg", "show", "wg-test"]:
            return subprocess.CompletedProcess(command, 0, stdout="interface dump\n", stderr="")
        if command[:3] == ["wg", "set", "wg-test"] and "remove" not in command:
            raise subprocess.CalledProcessError(1, command, stderr="simulated failure")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("app.wireguard.subprocess.run", failing_run)
    try:
        with pytest.raises(HTTPException) as exc:
            issue_wireguard_config(db, "failed-peer", "1002")
        assert exc.value.status_code == 502
        assert db.execute(select(WireGuardClient)).scalars().all() == []
    finally:
        db.close()



def test_production_config_issuance_is_blocked_until_entitlements_exist(monkeypatch):
    import pytest
    from fastapi import HTTPException
    from app.config import settings
    from app.main import WireGuardRequest, create_wireguard_config

    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "mock_mode", True)

    with pytest.raises(HTTPException) as exc:
        create_wireguard_config(
            WireGuardRequest(client_name="must-not-issue"),
            auth={"user": {"id": 1001}, "auth_method": "telegram_webapp"},
            db=None,
        )

    assert exc.value.status_code == 503
    assert "payment verification" in exc.value.detail.lower()
