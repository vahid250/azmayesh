import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as main
from app.database import Base, get_db
from app.models import OrderTermsAcceptance, Plan


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


def test_order_api_persists_authenticated_acceptance_with_order(client_and_db):
    client, db = client_and_db
    response = _post_order(client, terms_version=main.CURRENT_TERMS_VERSION)
    assert response.status_code == 200
    payload = response.json()
    acceptance = db.execute(select(OrderTermsAcceptance).where(OrderTermsAcceptance.order_id == payload["id"])).scalar_one()
    assert acceptance.telegram_user_id == "24680"
    assert acceptance.terms_version == main.CURRENT_TERMS_VERSION
    assert acceptance.accepted_at is not None


def test_public_terms_metadata_identifies_draft_and_canonical_document():
    response = TestClient(main.app).get("/api/v1/public/terms")
    assert response.status_code == 200
    payload = response.json()
    assert payload["version"] == main.CURRENT_TERMS_VERSION
    assert payload["status"] == "draft_testing_only"
    assert payload["privacy_document_path"].endswith("docs/PRIVACY_POLICY_FA.md")
    assert payload["acceptance_enabled"] is True
    assert payload["legal_effect"] == "not_final_terms_or_a_payment_authorization"

def test_order_api_idempotent_retry_keeps_single_acceptance(client_and_db):
    client, db = client_and_db
    first = _post_order(client, terms_version=main.CURRENT_TERMS_VERSION)
    assert first.status_code == 200

    retry = _post_order(client, terms_version=main.CURRENT_TERMS_VERSION)
    assert retry.status_code == 200
    assert retry.json()["id"] == first.json()["id"]

    acceptances = db.execute(
        select(OrderTermsAcceptance).where(OrderTermsAcceptance.order_id == first.json()["id"])
    ).scalars().all()
    assert len(acceptances) == 1
    assert acceptances[0].telegram_user_id == "24680"
    assert acceptances[0].terms_version == main.CURRENT_TERMS_VERSION

def test_order_api_idempotent_retry_rejects_missing_acceptance(client_and_db):
    client, db = client_and_db
    first = _post_order(client, terms_version=main.CURRENT_TERMS_VERSION)
    assert first.status_code == 200

    acceptance = db.execute(
        select(OrderTermsAcceptance).where(OrderTermsAcceptance.order_id == first.json()["id"])
    ).scalar_one()
    db.delete(acceptance)
    db.commit()

    retry = _post_order(client, terms_version=main.CURRENT_TERMS_VERSION)
    assert retry.status_code == 409
    assert retry.json()["detail"] == "Terms acceptance is missing or does not match this order"
