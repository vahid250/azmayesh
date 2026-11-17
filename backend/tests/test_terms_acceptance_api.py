import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as main
from app.database import Base, get_db
from app.models import Entitlement, Order, OrderTermsAcceptance, Plan


@pytest.fixture
def client_and_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = factory()
    session.add(Plan(code="api-terms-plan", title="Test", amount_minor=100, currency="TEST", quota_bytes=1000,
                     max_devices=1, duration_days=30, is_active=True))
    session.commit()
    original = main.app.dependency_overrides.copy()

    def override_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[get_db] = override_db
    main.app.dependency_overrides[main.require_authenticated_request] = lambda: {
        "auth_method": "test", "user": {"id": 24680}
    }
    try:
        yield TestClient(main.app), session
    finally:
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(original)
        session.close()
        engine.dispose()


def _post_order(client, *, terms_version, key="api-terms-idempotency-0001"):
    return client.post(
        "/api/v1/orders",
        headers={"Idempotency-Key": key},
        json={"plan_code": "api-terms-plan", "payment_method": "crypto", "terms_version": terms_version},
    )


def test_order_api_requires_current_terms_version(client_and_db):
    client, db = client_and_db
    missing = _post_order(client, terms_version=None)
    stale = _post_order(client, terms_version="0.1", key="api-terms-idempotency-0002")
    assert missing.status_code == 409
    assert stale.status_code == 409
    assert db.execute(select(OrderTermsAcceptance)).scalars().all() == []


def test_order_api_refuses_pending_orders_during_prelaunch(client_and_db):
    client, db = client_and_db
    response = _post_order(client, terms_version=main.CURRENT_TERMS_VERSION)
    assert response.status_code == 503
    assert "هیچ سفارش یا وجهی دریافت نمی‌شود" in response.json()["detail"]
    assert db.execute(select(OrderTermsAcceptance)).scalars().all() == []


def test_public_terms_metadata_identifies_draft_and_canonical_document():
    response = TestClient(main.app).get("/api/v1/public/terms")
    assert response.status_code == 200
    payload = response.json()
    assert payload["version"] == main.CURRENT_TERMS_VERSION
    assert payload["status"] == "draft_testing_only"
    assert payload["privacy_document_path"].endswith("docs/PRIVACY_POLICY_FA.md")
    assert payload["acceptance_enabled"] is True
    assert payload["legal_effect"] == "not_final_terms_or_a_payment_authorization"



def test_orders_and_entitlements_are_isolated_by_authenticated_telegram_user(client_and_db):
    client, db = client_and_db
    own_order = Order(
        telegram_user_id="24680",
        plan_code="api-terms-plan",
        idempotency_key="account-isolation-own-order",
        amount_minor=100,
        currency="TEST",
        quota_bytes=1000,
        max_devices=1,
        duration_days=30,
        status="paid",
    )
    foreign_order = Order(
        telegram_user_id="13579",
        plan_code="api-terms-plan",
        idempotency_key="account-isolation-foreign-order",
        amount_minor=100,
        currency="TEST",
        quota_bytes=1000,
        max_devices=1,
        duration_days=30,
        status="paid",
    )
    db.add_all([own_order, foreign_order])
    db.flush()
    db.add_all([
        Entitlement(
            order_id=own_order.id,
            telegram_user_id="24680",
            quota_bytes=1000,
            consumed_bytes=100,
            max_devices=1,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            status="active",
        ),
        Entitlement(
            order_id=foreign_order.id,
            telegram_user_id="13579",
            quota_bytes=1000,
            consumed_bytes=900,
            max_devices=1,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            status="active",
        ),
    ])
    db.commit()

    orders = client.get("/api/v1/orders")
    entitlements = client.get("/api/v1/entitlements")

    assert orders.status_code == 200
    assert [item["id"] for item in orders.json()] == [own_order.id]
    assert entitlements.status_code == 200
    assert [item["id"] for item in entitlements.json()] == [
        db.query(Entitlement).filter_by(telegram_user_id="24680").one().id
    ]
    assert all(item["id"] == own_order.id for item in orders.json())
    assert len(entitlements.json()) == 1
    assert entitlements.json()[0]["remaining_bytes"] == 900
