from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.billing import create_order
from app.database import Base
from app.models import PaymentAsset, PaymentIntent, Plan
from app.payment_checkout import create_payment_intent_for_order
from app.quote_engine import RateObservation


NOW = datetime(2026, 11, 18, 8, 30, tzinfo=timezone.utc)


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = session_factory()
    session.add(Plan(
        code="usd-plan",
        title="USD test plan",
        amount_minor=0,
        currency="LEGACY",
        price_usd_minor=100,
        quota_bytes=1024,
        max_devices=2,
        duration_days=30,
        is_active=True,
    ))
    session.add(PaymentAsset(
        currency="USDT",
        network="TRC20",
        asset_type="token",
        decimals=6,
        min_confirmations=20,
        is_enabled=True,
    ))
    session.commit()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def observations(rate="1.0005", now=NOW):
    return [
        RateObservation("coinbase", Decimal(rate), now - timedelta(seconds=2)),
        RateObservation("kraken", Decimal(rate), now - timedelta(seconds=2)),
    ]


def make_order(db, user="user-1"):
    return create_order(db, user, "usd-plan", "checkout-order-key-0001")


def create_quote(db, order, user="user-1", *, now=NOW, rate="1.0005", currency="USDT", network="TRC20"):
    return create_payment_intent_for_order(
        db,
        order_id=order.id,
        telegram_user_id=user,
        payment_currency=currency,
        payment_network=network,
        observations=observations(rate, now),
        admin_margin_bps=0,
        now=now,
    )


def test_order_snapshots_usd_price_and_quote_links_to_owned_order(db):
    order = make_order(db)
    assert order.price_usd_minor == 100

    intent = create_quote(db, order)

    assert intent.order_id == order.id
    assert intent.telegram_user_id == "user-1"
    assert intent.price_usd_minor == 100
    assert intent.payment_currency == "USDT"
    assert intent.payment_network == "TRC20"
    assert intent.payment_amount_minor == 1_000_500
    assert intent.status == "quoted"
    assert intent.quote_expires_at - intent.quote_issued_at == timedelta(minutes=15)
    assert intent.source_snapshot
    assert db.execute(select(PaymentIntent)).scalars().all() == [intent]


def test_repeated_request_returns_same_live_quote_without_repricing(db):
    order = make_order(db)
    first = create_quote(db, order, rate="1.0005")
    retry = create_quote(db, order, rate="1.0100")

    assert retry.id == first.id
    assert retry.payment_amount_minor == first.payment_amount_minor
    assert len(db.execute(select(PaymentIntent)).scalars().all()) == 1


def test_expired_quote_is_preserved_and_replaced_by_new_locked_quote(db):
    order = make_order(db)
    first = create_quote(db, order)
    later = NOW + timedelta(minutes=16)

    second = create_quote(db, order, now=later, rate="1.0010")

    assert second.id != first.id
    assert second.payment_amount_minor == 1_001_000
    db.refresh(first)
    assert first.status == "expired"
    assert len(db.execute(select(PaymentIntent)).scalars().all()) == 2


def test_order_owner_is_checked_without_disclosing_foreign_order(db):
    order = make_order(db)
    with pytest.raises(HTTPException) as exc:
        create_quote(db, order, user="another-user")
    assert exc.value.status_code == 404
    assert db.execute(select(PaymentIntent)).scalars().all() == []


def test_disabled_or_unknown_asset_network_is_rejected(db):
    order = make_order(db)
    with pytest.raises(HTTPException) as exc:
        create_quote(db, order, currency="USDT", network="TON")
    assert exc.value.status_code == 409
    assert db.execute(select(PaymentIntent)).scalars().all() == []


def test_unpriced_legacy_plan_cannot_create_payment_quote(db):
    plan = db.get(Plan, "usd-plan")
    plan.price_usd_minor = None
    db.commit()
    order = make_order(db)

    with pytest.raises(HTTPException) as exc:
        create_quote(db, order)
    assert exc.value.status_code == 409
    assert db.execute(select(PaymentIntent)).scalars().all() == []


def test_only_one_live_asset_quote_can_exist_per_order(db):
    db.add(PaymentAsset(
        currency="USDC",
        network="BASE",
        asset_type="token",
        decimals=6,
        min_confirmations=20,
        is_enabled=True,
    ))
    db.commit()
    order = make_order(db)
    create_quote(db, order)

    with pytest.raises(HTTPException) as exc:
        create_quote(db, order, currency="USDC", network="BASE")
    assert exc.value.status_code == 409
    assert len(db.execute(select(PaymentIntent)).scalars().all()) == 1


def test_bad_or_disagreeing_rate_observations_fail_closed(db):
    order = make_order(db)
    with pytest.raises(HTTPException) as exc:
        create_payment_intent_for_order(
            db,
            order_id=order.id,
            telegram_user_id="user-1",
            payment_currency="USDT",
            payment_network="TRC20",
            observations=[
                RateObservation("coinbase", Decimal("1.0"), NOW),
                RateObservation("kraken", Decimal("1.1"), NOW),
            ],
            admin_margin_bps=0,
            now=NOW,
        )
    assert exc.value.status_code == 503
    assert db.execute(select(PaymentIntent)).scalars().all() == []
