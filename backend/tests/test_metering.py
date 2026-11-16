import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.database import Base, get_db
from app.metering import METERING_PATH, verify_metering_signature
from app.models import Entitlement, Order, WireGuardClient, WireGuardClientOwner


SECRET = "unit-test-metering-secret-with-more-than-32-bytes"


def sign(body: bytes, timestamp: str, event_id: str, secret: str = SECRET) -> str:
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(["POST", METERING_PATH, timestamp, event_id, body_hash])
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def test_metering_signature_accepts_valid_fresh_request():
    timestamp = str(int(time.time()))
    body = b'{"entitlement_id":1,"bytes_used":128}'
    event_id = "wg-agent-event-001"
    verify_metering_signature(
        secret=SECRET,
        timestamp=timestamp,
        event_id=event_id,
        signature=sign(body, timestamp, event_id),
        body=body,
    )


def test_metering_signature_rejects_tampered_body_and_stale_timestamp():
    timestamp = str(int(time.time()))
    event_id = "wg-agent-event-002"
    signature = sign(b'{"entitlement_id":1,"bytes_used":128}', timestamp, event_id)

    with pytest.raises(HTTPException) as tampered:
        verify_metering_signature(
            secret=SECRET,
            timestamp=timestamp,
            event_id=event_id,
            signature=signature,
            body=b'{"entitlement_id":1,"bytes_used":129}',
        )
    assert tampered.value.status_code == 401

    with pytest.raises(HTTPException) as stale:
        verify_metering_signature(
            secret=SECRET,
            timestamp="1700000000",
            event_id=event_id,
            signature=signature,
            body=b'{"entitlement_id":1,"bytes_used":128}',
        )
    assert stale.value.status_code == 401


def test_metering_signature_fails_closed_without_strong_secret():
    with pytest.raises(HTTPException) as exc:
        verify_metering_signature(
            secret="",
            timestamp=str(int(time.time())),
            event_id="wg-agent-event-003",
            signature="0" * 64,
            body=b"{}",
        )
    assert exc.value.status_code == 503


def test_signed_usage_endpoint_applies_quota_once_and_rejects_event_reuse(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with TestingSession() as db:
        order = Order(
            telegram_user_id="metering-user",
            plan_code="metering-test",
            idempotency_key="metering-test-order-0001",
            amount_minor=1,
            currency="TEST",
            quota_bytes=1000,
            max_devices=1,
            duration_days=30,
            status="paid",
        )
        db.add(order)
        db.flush()
        entitlement = Entitlement(
            order_id=order.id,
            telegram_user_id="metering-user",
            quota_bytes=1000,
            consumed_bytes=0,
            max_devices=1,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            status="active",
        )
        db.add(entitlement)
        db.flush()
        client = WireGuardClient(
            client_name="metering-test-device",
            client_ip="10.99.0.2/32",
            public_key="metering-test-public-key",
            private_key_encrypted="encrypted-private-key",
            config_encrypted="encrypted-config",
            state="peer_registered",
        )
        db.add(client)
        db.flush()
        db.add(WireGuardClientOwner(
            client_id=client.id,
            telegram_user_id="metering-user",
            entitlement_id=entitlement.id,
        ))
        db.commit()
        client_id = client.id

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(settings, "metering_shared_secret", SECRET)
    from app.main import app
    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app)
        timestamp = str(int(time.time()))
        event_id = "wg-agent-event-004"
        body = json.dumps(
            {"client_id": client_id, "bytes_used": 350},
            separators=(",", ":"),
        ).encode()
        headers = {
            "X-RMA-Timestamp": timestamp,
            "X-RMA-Event-Id": event_id,
            "X-RMA-Signature": sign(body, timestamp, event_id),
            "Content-Type": "application/json",
        }

        first = client.post(METERING_PATH, content=body, headers=headers)
        assert first.status_code == 200
        assert first.json()["consumed_bytes"] == 350
        assert first.json()["remaining_bytes"] == 650

        repeated = client.post(METERING_PATH, content=body, headers=headers)
        assert repeated.status_code == 200
        assert repeated.json()["consumed_bytes"] == 350

        unknown_event_id = "wg-agent-event-unknown"
        unknown_body = json.dumps(
            {"client_id": 999999, "bytes_used": 1},
            separators=(",", ":"),
        ).encode()
        unknown_headers = {
            "X-RMA-Timestamp": timestamp,
            "X-RMA-Event-Id": unknown_event_id,
            "X-RMA-Signature": sign(unknown_body, timestamp, unknown_event_id),
            "Content-Type": "application/json",
        }
        unknown = client.post(METERING_PATH, content=unknown_body, headers=unknown_headers)
        assert unknown.status_code == 404

        changed_body = json.dumps(
            {"client_id": client_id, "bytes_used": 351},
            separators=(",", ":"),
        ).encode()
        changed_headers = {
            **headers,
            "X-RMA-Signature": sign(changed_body, timestamp, event_id),
        }
        conflict = client.post(METERING_PATH, content=changed_body, headers=changed_headers)
        assert conflict.status_code == 409
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_signed_peer_registry_only_returns_current_entitlements(monkeypatch):
    from app.metering import METERING_REGISTRY_PATH
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with TestingSession() as db:
        order = Order(
            telegram_user_id="registry-user",
            plan_code="registry-test",
            idempotency_key="registry-test-order-0001",
            amount_minor=1,
            currency="TEST",
            quota_bytes=1000,
            max_devices=2,
            duration_days=30,
            status="paid",
        )
        db.add(order)
        db.flush()
        entitlement = Entitlement(
            order_id=order.id,
            telegram_user_id="registry-user",
            quota_bytes=1000,
            consumed_bytes=0,
            max_devices=2,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            status="active",
        )
        db.add(entitlement)
        db.flush()
        peer = WireGuardClient(
            client_name="registry-peer",
            client_ip="10.99.0.8/32",
            public_key="registry-test-public-key",
            private_key_encrypted="encrypted",
            config_encrypted="encrypted",
            state="peer_registered",
        )
        db.add(peer)
        db.flush()
        db.add(WireGuardClientOwner(
            client_id=peer.id,
            telegram_user_id="registry-user",
            entitlement_id=entitlement.id,
        ))
        db.commit()
        peer_id = peer.id
        entitlement_id = entitlement.id

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(settings, "metering_shared_secret", SECRET)
    monkeypatch.setattr(settings, "wg_interface", "wg0")
    from app.main import app
    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app)
        timestamp = str(int(time.time()))
        event_id = "registry-event-0001"
        body = b'{"interface":"wg0"}'
        canonical = "\n".join([
            "POST", METERING_REGISTRY_PATH, timestamp, event_id,
            hashlib.sha256(body).hexdigest(),
        ])
        signature = hmac.new(SECRET.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        headers = {
            "X-RMA-Timestamp": timestamp,
            "X-RMA-Event-Id": event_id,
            "X-RMA-Signature": signature,
            "Content-Type": "application/json",
        }
        response = client.post(METERING_REGISTRY_PATH, content=body, headers=headers)
        assert response.status_code == 200
        assert response.json()["interface"] == "wg0"
        assert response.json()["peers"] == [{
            "client_id": peer_id,
            "public_key": "registry-test-public-key",
            "allowed_ips": "10.99.0.8/32",
            "state": "peer_registered",
        }]
        assert response.json()["remove_peers"] == []

        with TestingSession() as db:
            db.get(Entitlement, entitlement_id).status = "exhausted"
            db.commit()
        second_id = "registry-event-0002"
        second_canonical = "\n".join([
            "POST", METERING_REGISTRY_PATH, timestamp, second_id,
            hashlib.sha256(body).hexdigest(),
        ])
        second_headers = {
            **headers,
            "X-RMA-Event-Id": second_id,
            "X-RMA-Signature": hmac.new(
                SECRET.encode(), second_canonical.encode(), hashlib.sha256
            ).hexdigest(),
        }
        excluded = client.post(METERING_REGISTRY_PATH, content=body, headers=second_headers)
        assert excluded.status_code == 200
        assert excluded.json()["peers"] == []
        assert excluded.json()["remove_peers"] == [{
            "client_id": peer_id,
            "public_key": "registry-test-public-key",
            "state": "suspended",
        }]
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
