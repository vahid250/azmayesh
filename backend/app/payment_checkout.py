"""Order-bound checkout quote creation.

This module deliberately does not allocate deposit addresses, contact a payment
provider, accept client-supplied rates, or mark an order paid. It only creates an
immutable quote from trusted server-side observations and an enabled asset.
"""
from datetime import datetime, timezone
from typing import Iterable

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Order, PaymentAsset, PaymentIntent
from app.quote_engine import RateObservation, build_locked_quote


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def create_payment_intent_for_order(
    db: Session,
    *,
    order_id: int,
    telegram_user_id: str,
    payment_currency: str,
    payment_network: str,
    observations: Iterable[RateObservation],
    admin_margin_bps: int,
    now: datetime | None = None,
) -> PaymentIntent:
    """Create or return the one live quote for an owned pending order.

    `observations` and `admin_margin_bps` are trusted internal inputs. They
    must never be copied from a Mini App request. The order row lock serializes
    concurrent quote creation on PostgreSQL.
    """
    owner = str(telegram_user_id).strip()
    currency = str(payment_currency).strip().upper()
    network = str(payment_network).strip().upper()
    if not owner or not currency or len(currency) > 12 or not network or len(network) > 32:
        raise HTTPException(status_code=422, detail="Payment asset selection is invalid")

    order = db.execute(
        select(Order).where(Order.id == order_id).with_for_update()
    ).scalar_one_or_none()
    if order is None or order.telegram_user_id != owner:
        # Avoid disclosing whether another user's order exists.
        raise HTTPException(status_code=404, detail="Order not found")
    if order.status != "pending" or order.payment_method != "crypto":
        raise HTTPException(status_code=409, detail="Order is not available for crypto checkout")
    if order.price_usd_minor is None or order.price_usd_minor <= 0:
        raise HTTPException(status_code=409, detail="This plan has no verified USD list price configured")

    asset = db.execute(
        select(PaymentAsset).where(
            PaymentAsset.currency == currency,
            PaymentAsset.network == network,
            PaymentAsset.is_enabled.is_(True),
        ).with_for_update()
    ).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=409, detail="Selected payment asset or network is not enabled")

    current = _utc(now or datetime.now(timezone.utc))
    live_quotes = db.execute(
        select(PaymentIntent)
        .where(
            PaymentIntent.order_id == order.id,
            PaymentIntent.status == "quoted",
            PaymentIntent.quote_expires_at > current,
        )
        .order_by(PaymentIntent.id.desc())
        .with_for_update()
    ).scalars().all()
    if live_quotes:
        latest = live_quotes[0]
        if latest.payment_currency == currency and latest.payment_network == network:
            return latest
        raise HTTPException(status_code=409, detail="A different payment quote is already active for this order")

    # Expired quotes remain in history; only their lifecycle state changes.
    expired_quotes = db.execute(
        select(PaymentIntent).where(
            PaymentIntent.order_id == order.id,
            PaymentIntent.status == "quoted",
            PaymentIntent.quote_expires_at <= current,
        ).with_for_update()
    ).scalars().all()
    for expired in expired_quotes:
        expired.status = "expired"

    try:
        quote = build_locked_quote(
            price_usd_minor=order.price_usd_minor,
            payment_decimals=asset.decimals,
            observations=observations,
            now=current,
            admin_margin_bps=admin_margin_bps,
        )
    except (ValueError, ArithmeticError) as exc:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail="A safe payment quote is temporarily unavailable; please retry shortly",
        ) from exc

    intent = PaymentIntent(
        order_id=order.id,
        telegram_user_id=order.telegram_user_id,
        plan_code=order.plan_code,
        price_usd_minor=order.price_usd_minor,
        payment_currency=currency,
        payment_network=network,
        payment_amount_minor=quote.payment_amount_minor,
        payment_decimals=asset.decimals,
        units_per_usd=quote.units_per_usd,
        source_snapshot=quote.source_snapshot,
        rate_spread_bps=quote.rate_spread_bps,
        admin_margin_bps=admin_margin_bps,
        quote_issued_at=quote.issued_at,
        quote_expires_at=quote.expires_at,
        status="quoted",
    )
    db.add(intent)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    db.refresh(intent)
    return intent
