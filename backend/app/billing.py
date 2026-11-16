from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Entitlement, Order, PaymentEvent, Plan, UsageRecord


def create_order(db: Session, telegram_user_id: str, plan_code: str, idempotency_key: str) -> Order:
    key = (idempotency_key or "").strip()
    if len(key) < 16 or len(key) > 128:
        raise HTTPException(status_code=422, detail="Idempotency-Key must contain 16 to 128 characters")

    existing = db.execute(
        select(Order).where(
            Order.telegram_user_id == telegram_user_id,
            Order.idempotency_key == key,
        )
    ).scalar_one_or_none()
    if existing:
        if existing.plan_code != plan_code:
            raise HTTPException(status_code=409, detail="Idempotency-Key was already used for another plan")
        return existing

    plan = db.execute(select(Plan).where(Plan.code == plan_code, Plan.is_active.is_(True))).scalar_one_or_none()
    if plan is None:
        raise HTTPException(status_code=404, detail="Active plan not found")

    order = Order(
        telegram_user_id=telegram_user_id,
        plan_code=plan.code,
        idempotency_key=key,
        amount_minor=plan.amount_minor,
        currency=plan.currency,
        quota_bytes=plan.quota_bytes,
        max_devices=plan.max_devices,
        duration_days=plan.duration_days,
        status="pending",
    )
    db.add(order)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.execute(
            select(Order).where(
                Order.telegram_user_id == telegram_user_id,
                Order.idempotency_key == key,
            )
        ).scalar_one_or_none()
        if existing and existing.plan_code == plan_code:
            return existing
        raise HTTPException(status_code=409, detail="Order idempotency conflict")
    db.refresh(order)
    return order


def confirm_verified_payment(
    db: Session,
    *,
    order_id: int,
    provider: str,
    provider_event_id: str,
    amount_minor: int,
    currency: str,
) -> Entitlement:
    """Internal trust boundary: call only after provider signature and settlement are verified."""
    provider = provider.strip().lower()
    event_id = provider_event_id.strip()
    currency = currency.strip().upper()
    if not provider or len(provider) > 40 or not event_id or len(event_id) > 160:
        raise HTTPException(status_code=422, detail="Payment provider reference is invalid")
    if amount_minor < 0 or not currency or len(currency) > 12:
        raise HTTPException(status_code=422, detail="Payment amount or currency is invalid")

    existing_event = db.execute(
        select(PaymentEvent).where(
            PaymentEvent.provider == provider,
            PaymentEvent.provider_event_id == event_id,
        )
    ).scalar_one_or_none()
    if existing_event:
        if existing_event.order_id != order_id or existing_event.amount_minor != amount_minor or existing_event.currency != currency:
            raise HTTPException(status_code=409, detail="Payment event was already used with different details")
        entitlement = db.execute(
            select(Entitlement).where(Entitlement.order_id == order_id)
        ).scalar_one_or_none()
        if entitlement is None:
            raise HTTPException(status_code=409, detail="Paid order is missing its entitlement")
        return entitlement

    order = db.execute(select(Order).where(Order.id == order_id).with_for_update()).scalar_one_or_none()
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    if order.status != "pending":
        raise HTTPException(status_code=409, detail="Order is not awaiting payment")
    if order.amount_minor != amount_minor or order.currency.upper() != currency:
        raise HTTPException(status_code=409, detail="Settled payment does not match the order amount and currency")

    event = PaymentEvent(
        order_id=order.id,
        provider=provider,
        provider_event_id=event_id,
        amount_minor=amount_minor,
        currency=currency,
    )
    now = datetime.now(timezone.utc)
    order.status = "paid"
    order.paid_at = now
    entitlement = Entitlement(
        order_id=order.id,
        telegram_user_id=order.telegram_user_id,
        quota_bytes=order.quota_bytes,
        consumed_bytes=0,
        max_devices=order.max_devices,
        expires_at=now + timedelta(days=order.duration_days),
        status="active",
    )
    db.add_all([event, entitlement])
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Provider retries and simultaneous callbacks are safe: read the committed result.
        entitlement = db.execute(
            select(Entitlement).where(Entitlement.order_id == order_id)
        ).scalar_one_or_none()
        if entitlement is not None:
            return entitlement
        raise HTTPException(status_code=409, detail="Payment event conflicts with an existing settlement")
    db.refresh(entitlement)
    return entitlement


def record_verified_usage(
    db: Session,
    *,
    entitlement_id: int,
    source: str,
    source_event_id: str,
    bytes_used: int,
) -> Entitlement:
    """Apply byte counters only from a trusted server-side metering adapter, never a client."""
    source = source.strip().lower()
    event_id = source_event_id.strip()
    if not source or len(source) > 40 or not event_id or len(event_id) > 160:
        raise HTTPException(status_code=422, detail="Usage source reference is invalid")
    if bytes_used <= 0:
        raise HTTPException(status_code=422, detail="Usage bytes must be positive")

    existing = db.execute(
        select(UsageRecord).where(
            UsageRecord.source == source,
            UsageRecord.source_event_id == event_id,
        )
    ).scalar_one_or_none()
    if existing:
        if existing.entitlement_id != entitlement_id or existing.bytes_used != bytes_used:
            raise HTTPException(status_code=409, detail="Usage event was already applied with different details")
        return db.get(Entitlement, entitlement_id)

    now = datetime.now(timezone.utc)
    result = db.execute(
        update(Entitlement)
        .where(
            Entitlement.id == entitlement_id,
            Entitlement.status == "active",
            Entitlement.expires_at > now,
            Entitlement.consumed_bytes + bytes_used <= Entitlement.quota_bytes,
        )
        .values(consumed_bytes=Entitlement.consumed_bytes + bytes_used)
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        db.rollback()
        entitlement = db.get(Entitlement, entitlement_id)
        if entitlement is None:
            raise HTTPException(status_code=404, detail="Entitlement not found")
        raise HTTPException(status_code=409, detail="Entitlement expired, inactive, or quota exceeded")

    db.add(UsageRecord(
        entitlement_id=entitlement_id,
        source=source,
        source_event_id=event_id,
        bytes_used=bytes_used,
    ))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.execute(
            select(UsageRecord).where(
                UsageRecord.source == source,
                UsageRecord.source_event_id == event_id,
            )
        ).scalar_one_or_none()
        if existing and existing.entitlement_id == entitlement_id and existing.bytes_used == bytes_used:
            return db.get(Entitlement, entitlement_id)
        raise HTTPException(status_code=409, detail="Usage event conflicts with an existing record")
    return db.get(Entitlement, entitlement_id)


def active_entitlement_for_user(db: Session, telegram_user_id: str) -> Entitlement:
    now = datetime.now(timezone.utc)
    entitlement = db.execute(
        select(Entitlement)
        .where(
            Entitlement.telegram_user_id == telegram_user_id,
            Entitlement.status == "active",
            Entitlement.expires_at > now,
            Entitlement.consumed_bytes < Entitlement.quota_bytes,
        )
        .order_by(Entitlement.expires_at.asc(), Entitlement.id.asc())
        .with_for_update()
    ).scalars().first()
    if entitlement is None:
        raise HTTPException(status_code=403, detail="No active entitlement with remaining quota")
    return entitlement
