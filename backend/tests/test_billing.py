from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.billing import (
    confirm_verified_payment,
    create_order,
    record_verified_usage,
)
from app.database import Base
from app.models import Entitlement, Order, PaymentEvent, Plan, UsageRecord


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = TestingSession()
    session.add(Plan(
        code="sample-30d",
        title="Test plan",
        amount_minor=12500,
        currency="TEST",
        quota_bytes=1_000,
        max_devices=2,
        duration_days=30,
        is_active=True,
    ))
    session.commit()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def test_order_snapshots_plan_and_idempotency_is_stable(db):
    first = create_order(db, "telegram-1", "sample-30d", "order-key-00000001")
    retry = create_order(db, "telegram-1", "sample-30d", "order-key-00000001")

    assert first.id == retry.id
    assert first.status == "pending"
    assert first.amount_minor == 12500
    assert first.quota_bytes == 1000

    second = create_order(db, "telegram-1", "sample-30d", "order-key-00000002")
    assert second.id != first.id


def test_rial_payment_is_rejected_before_an_order_is_created(db):
    with pytest.raises(HTTPException) as exc:
        create_order(db, "iran-user", "sample-30d", "order-key-rial-00001", "rial")
    assert exc.value.status_code == 409
    assert "به‌زودی فعال" in exc.value.detail
    assert db.execute(select(Order)).scalars().all() == []


def test_crypto_payment_method_is_persisted_on_order(db):
    order = create_order(db, "crypto-user", "sample-30d", "order-key-crypto-0001", "crypto")
    assert order.payment_method == "crypto"


def test_idempotency_key_cannot_be_reused_for_a_different_plan(db):
    create_order(db, "telegram-2", "sample-30d", "order-key-00000003")
    with pytest.raises(HTTPException) as exc:
        create_order(db, "telegram-2", "another-plan", "order-key-00000003")
    assert exc.value.status_code == 409


def test_payment_amount_must_match_before_entitlement_is_granted(db):
    order = create_order(db, "telegram-3", "sample-30d", "order-key-00000004")
    with pytest.raises(HTTPException) as exc:
        confirm_verified_payment(
            db,
            order_id=order.id,
            provider="test-provider",
            provider_event_id="evt-amount-mismatch",
            amount_minor=12499,
            currency="TEST",
        )
    assert exc.value.status_code == 409
    assert db.execute(select(Entitlement)).scalars().all() == []
    assert db.get(Order, order.id).status == "pending"


def test_verified_payment_creates_one_entitlement_and_is_idempotent(db):
    order = create_order(db, "telegram-4", "sample-30d", "order-key-00000005")
    entitlement = confirm_verified_payment(
        db,
        order_id=order.id,
        provider="test-provider",
        provider_event_id="evt-payment-1",
        amount_minor=12500,
        currency="TEST",
    )
    repeated = confirm_verified_payment(
        db,
        order_id=order.id,
        provider="test-provider",
        provider_event_id="evt-payment-1",
        amount_minor=12500,
        currency="TEST",
    )

    assert entitlement.id == repeated.id
    assert repeated.telegram_user_id == "telegram-4"
    assert repeated.quota_bytes == 1000
    assert repeated.consumed_bytes == 0
    assert db.get(Order, order.id).status == "paid"
    assert len(db.execute(select(PaymentEvent)).scalars().all()) == 1
    assert len(db.execute(select(Entitlement)).scalars().all()) == 1


def test_paid_order_rejects_a_second_distinct_payment_event(db):
    order = create_order(db, "telegram-4b", "sample-30d", "order-key-00000005b")
    confirm_verified_payment(
        db,
        order_id=order.id,
        provider="test-provider",
        provider_event_id="evt-payment-original",
        amount_minor=12500,
        currency="TEST",
    )
    with pytest.raises(HTTPException) as exc:
        confirm_verified_payment(
            db,
            order_id=order.id,
            provider="test-provider",
            provider_event_id="evt-payment-second",
            amount_minor=12500,
            currency="TEST",
        )
    assert exc.value.status_code == 409
    events = db.execute(select(PaymentEvent).where(PaymentEvent.order_id == order.id)).scalars().all()
    assert len(events) == 1
    assert events[0].provider_event_id == "evt-payment-original"


def test_same_provider_event_cannot_pay_another_order(db):
    first = create_order(db, "telegram-5", "sample-30d", "order-key-00000006")
    second = create_order(db, "telegram-5", "sample-30d", "order-key-00000007")
    confirm_verified_payment(
        db,
        order_id=first.id,
        provider="test-provider",
        provider_event_id="evt-reused",
        amount_minor=12500,
        currency="TEST",
    )
    with pytest.raises(HTTPException) as exc:
        confirm_verified_payment(
            db,
            order_id=second.id,
            provider="test-provider",
            provider_event_id="evt-reused",
            amount_minor=12500,
            currency="TEST",
        )
    assert exc.value.status_code == 409


def test_usage_event_is_idempotent_and_does_not_double_debit(db):
    order = create_order(db, "telegram-6", "sample-30d", "order-key-00000008")
    entitlement = confirm_verified_payment(
        db,
        order_id=order.id,
        provider="test-provider",
        provider_event_id="evt-payment-2",
        amount_minor=12500,
        currency="TEST",
    )
    first = record_verified_usage(
        db,
        entitlement_id=entitlement.id,
        source="wireguard-meter",
        source_event_id="wg-event-001",
        bytes_used=400,
    )
    repeated = record_verified_usage(
        db,
        entitlement_id=entitlement.id,
        source="wireguard-meter",
        source_event_id="wg-event-001",
        bytes_used=400,
    )

    assert first.consumed_bytes == repeated.consumed_bytes == 400
    assert len(db.execute(select(UsageRecord)).scalars().all()) == 1


def test_overquota_interval_is_recorded_but_consumption_is_capped(db):
    order = create_order(db, "telegram-7", "sample-30d", "order-key-00000009")
    entitlement = confirm_verified_payment(
        db,
        order_id=order.id,
        provider="test-provider",
        provider_event_id="evt-payment-3",
        amount_minor=12500,
        currency="TEST",
    )
    record_verified_usage(
        db,
        entitlement_id=entitlement.id,
        source="wireguard-meter",
        source_event_id="wg-event-002",
        bytes_used=700,
    )
    exhausted = record_verified_usage(
        db,
        entitlement_id=entitlement.id,
        source="wireguard-meter",
        source_event_id="wg-event-003",
        bytes_used=301,
    )
    replay = record_verified_usage(
        db,
        entitlement_id=entitlement.id,
        source="wireguard-meter",
        source_event_id="wg-event-003",
        bytes_used=301,
    )
    assert exhausted.consumed_bytes == replay.consumed_bytes == 1000
    assert exhausted.status == replay.status == "exhausted"
    records = db.execute(select(UsageRecord).order_by(UsageRecord.id)).scalars().all()
    assert [record.bytes_used for record in records] == [700, 301]


def test_exact_quota_usage_marks_entitlement_exhausted(db):
    order = create_order(db, "telegram-7b", "sample-30d", "order-key-00000009b")
    entitlement = confirm_verified_payment(
        db,
        order_id=order.id,
        provider="test-provider",
        provider_event_id="evt-payment-3b",
        amount_minor=12500,
        currency="TEST",
    )
    result = record_verified_usage(
        db,
        entitlement_id=entitlement.id,
        source="wireguard-meter",
        source_event_id="wg-event-exact",
        bytes_used=1000,
    )
    assert result.consumed_bytes == 1000
    assert result.status == "exhausted"

def test_expired_entitlement_rejects_usage(db):
    order = create_order(db, "telegram-8", "sample-30d", "order-key-00000010")
    entitlement = confirm_verified_payment(
        db,
        order_id=order.id,
        provider="test-provider",
        provider_event_id="evt-payment-4",
        amount_minor=12500,
        currency="TEST",
    )
    entitlement.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()

    with pytest.raises(HTTPException) as exc:
        record_verified_usage(
            db,
            entitlement_id=entitlement.id,
            source="wireguard-meter",
            source_event_id="wg-event-expired",
            bytes_used=1,
        )
    assert exc.value.status_code == 409
    db.refresh(entitlement)
    assert entitlement.status == "expired"
