#!/usr/bin/env python3
"""Create a strictly guarded, zero-value entitlement for an isolated R&MA staging lab."""
from __future__ import annotations

import argparse
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

from app.config import get_settings
from app.database import SessionLocal
from app.models import Entitlement, Order, PaymentEvent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--telegram-user-id", required=True)
    parser.add_argument("--quota-bytes", type=int, required=True)
    parser.add_argument("--duration-hours", type=int, required=True)
    parser.add_argument("--max-devices", type=int, required=True)
    parser.add_argument("--confirm-lab-only", action="store_true")
    args = parser.parse_args()

    settings = get_settings()
    if settings.app_env != "staging":
        parser.error("This helper is permitted only when APP_ENV=staging")
    if settings.mock_mode:
        parser.error("Set MOCK_MODE=false for the isolated real-server lab")
    if os.environ.get("RMA_ALLOW_TEST_ENTITLEMENTS") != "1":
        parser.error("Set RMA_ALLOW_TEST_ENTITLEMENTS=1 explicitly in staging")
    if not args.confirm_lab_only:
        parser.error("Pass --confirm-lab-only; this creates a zero-value test settlement")
    if args.quota_bytes < 1024 or args.duration_hours < 1 or not 1 <= args.max_devices <= 5:
        parser.error("Use quota >= 1024 bytes, duration >= 1 hour, and 1-5 devices")
    if not args.telegram_user_id.strip() or len(args.telegram_user_id) > 128:
        parser.error("telegram-user-id is invalid")

    now = datetime.now(timezone.utc)
    suffix = uuid.uuid4().hex
    with SessionLocal() as db:
        order = Order(
            telegram_user_id=args.telegram_user_id,
            plan_code="isolated-host-lab",
            idempotency_key="lab-order-" + suffix,
            amount_minor=0,
            currency="TEST",
            quota_bytes=args.quota_bytes,
            max_devices=args.max_devices,
            duration_days=max(1, (args.duration_hours + 23) // 24),
            status="paid",
            paid_at=now,
        )
        db.add(order)
        db.flush()
        payment = PaymentEvent(
            order_id=order.id,
            provider="lab-only",
            provider_event_id="lab-event-" + suffix,
            amount_minor=0,
            currency="TEST",
        )
        entitlement = Entitlement(
            order_id=order.id,
            telegram_user_id=args.telegram_user_id,
            quota_bytes=args.quota_bytes,
            consumed_bytes=0,
            max_devices=args.max_devices,
            expires_at=now + timedelta(hours=args.duration_hours),
            status="active",
        )
        db.add_all([payment, entitlement])
        db.commit()
        db.refresh(entitlement)
        print(json.dumps({
            "lab_only": True,
            "order_id": order.id,
            "entitlement_id": entitlement.id,
            "telegram_user_id": args.telegram_user_id,
            "quota_bytes": entitlement.quota_bytes,
            "max_devices": entitlement.max_devices,
            "expires_at": entitlement.expires_at.isoformat(),
            "currency": "TEST",
            "amount_minor": 0,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
