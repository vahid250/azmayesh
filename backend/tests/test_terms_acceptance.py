import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.billing import create_order
from app.database import Base
from app.models import Order, OrderTermsAcceptance, Plan


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False, autocommit=False)()
    session.add(Plan(code="terms-plan", title="Test", amount_minor=100, currency="TEST", quota_bytes=1000,
                     max_devices=1, duration_days=30, is_active=True))
    session.commit()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def test_acceptance_is_saved_atomically_with_order(db):
    order = create_order(db, "tg-terms-1", "terms-plan", "terms-idempotency-0001", terms_version="0.2")
    acceptance = db.execute(select(OrderTermsAcceptance).where(OrderTermsAcceptance.order_id == order.id)).scalar_one()
    assert acceptance.telegram_user_id == "tg-terms-1"
    assert acceptance.terms_version == "0.2"
    assert acceptance.accepted_at is not None


def test_idempotent_retry_requires_same_recorded_terms_version(db):
    order = create_order(db, "tg-terms-2", "terms-plan", "terms-idempotency-0002", terms_version="0.2")
    repeated = create_order(db, "tg-terms-2", "terms-plan", "terms-idempotency-0002", terms_version="0.2")
    assert repeated.id == order.id
    with pytest.raises(HTTPException) as exc:
        create_order(db, "tg-terms-2", "terms-plan", "terms-idempotency-0002", terms_version="0.3")
    assert exc.value.status_code == 409


def test_legacy_order_without_acceptance_cannot_be_reused_as_accepted(db):
    order = create_order(db, "tg-terms-3", "terms-plan", "terms-idempotency-0003")
    with pytest.raises(HTTPException) as exc:
        create_order(db, "tg-terms-3", "terms-plan", "terms-idempotency-0003", terms_version="0.2")
    assert exc.value.status_code == 409
    assert db.get(Order, order.id) is not None
    assert db.execute(select(OrderTermsAcceptance)).scalars().all() == []
