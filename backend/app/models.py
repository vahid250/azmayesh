from datetime import datetime, timezone
from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class WireGuardClient(Base):
    __tablename__ = "wireguard_clients"
    __table_args__ = (
        UniqueConstraint("client_ip", name="uq_wg_client_ip"),
        UniqueConstraint("public_key", name="uq_wg_public_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    client_name: Mapped[str] = mapped_column(String(64), nullable=False)
    client_ip: Mapped[str] = mapped_column(String(48), nullable=False)
    public_key: Mapped[str] = mapped_column(String(64), nullable=False)
    private_key_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    config_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class WireGuardClientOwner(Base):
    __tablename__ = "wireguard_client_owners"

    client_id: Mapped[int] = mapped_column(ForeignKey("wireguard_clients.id", ondelete="CASCADE"), primary_key=True)
    telegram_user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entitlement_id: Mapped[int | None] = mapped_column(ForeignKey("entitlements.id", ondelete="RESTRICT"), nullable=True, index=True)


class Plan(Base):
    __tablename__ = "plans"
    __table_args__ = (
        CheckConstraint("amount_minor >= 0", name="ck_plan_amount_nonnegative"),
        CheckConstraint("quota_bytes > 0", name="ck_plan_quota_positive"),
        CheckConstraint("max_devices > 0", name="ck_plan_devices_positive"),
        CheckConstraint("duration_days > 0", name="ck_plan_duration_positive"),
    )

    code: Mapped[str] = mapped_column(String(40), primary_key=True)
    title: Mapped[str] = mapped_column(String(100), nullable=False)
    amount_minor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(12), nullable=False)
    quota_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    max_devices: Mapped[int] = mapped_column(Integer, nullable=False)
    duration_days: Mapped[int] = mapped_column(Integer, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class Order(Base):
    __tablename__ = "orders"
    __table_args__ = (
        UniqueConstraint("telegram_user_id", "idempotency_key", name="uq_order_user_idempotency"),
        CheckConstraint("amount_minor >= 0", name="ck_order_amount_nonnegative"),
        CheckConstraint("quota_bytes > 0", name="ck_order_quota_positive"),
        CheckConstraint("max_devices > 0", name="ck_order_devices_positive"),
        CheckConstraint("duration_days > 0", name="ck_order_duration_positive"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    telegram_user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    plan_code: Mapped[str] = mapped_column(String(40), nullable=False)
    payment_method: Mapped[str] = mapped_column(String(16), default="crypto", nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    amount_minor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(12), nullable=False)
    quota_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    max_devices: Mapped[int] = mapped_column(Integer, nullable=False)
    duration_days: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PaymentEvent(Base):
    __tablename__ = "payment_events"
    __table_args__ = (
        UniqueConstraint("provider", "provider_event_id", name="uq_payment_provider_event"),
        UniqueConstraint("order_id", name="uq_payment_order"),
        CheckConstraint("amount_minor >= 0", name="ck_payment_amount_nonnegative"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    order_id: Mapped[int] = mapped_column(ForeignKey("orders.id", ondelete="RESTRICT"), nullable=False)
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    provider_event_id: Mapped[str] = mapped_column(String(160), nullable=False)
    amount_minor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(12), nullable=False)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class Entitlement(Base):
    __tablename__ = "entitlements"
    __table_args__ = (
        UniqueConstraint("order_id", name="uq_entitlement_order"),
        CheckConstraint("quota_bytes > 0", name="ck_entitlement_quota_positive"),
        CheckConstraint("consumed_bytes >= 0", name="ck_entitlement_consumed_nonnegative"),
        CheckConstraint("consumed_bytes <= quota_bytes", name="ck_entitlement_consumed_within_quota"),
        CheckConstraint("max_devices > 0", name="ck_entitlement_devices_positive"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    order_id: Mapped[int] = mapped_column(ForeignKey("orders.id", ondelete="RESTRICT"), nullable=False)
    telegram_user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    quota_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    consumed_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    max_devices: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class UsageRecord(Base):
    __tablename__ = "usage_records"
    __table_args__ = (
        UniqueConstraint("source", "source_event_id", name="uq_usage_source_event"),
        CheckConstraint("bytes_used > 0", name="ck_usage_bytes_positive"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entitlement_id: Mapped[int] = mapped_column(ForeignKey("entitlements.id", ondelete="RESTRICT"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    source_event_id: Mapped[str] = mapped_column(String(160), nullable=False)
    bytes_used: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class OrderTermsAcceptance(Base):
    """Audit record of a user accepting a specific terms version for an order."""
    __tablename__ = "order_terms_acceptances"
    __table_args__ = (
        UniqueConstraint("order_id", name="uq_order_terms_acceptance_order"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    order_id: Mapped[int] = mapped_column(ForeignKey("orders.id", ondelete="RESTRICT"), nullable=False)
    telegram_user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    terms_version: Mapped[str] = mapped_column(String(32), nullable=False)
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
