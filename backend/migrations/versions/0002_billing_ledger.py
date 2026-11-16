"""Add order, payment, entitlement, and usage ledgers."""

from alembic import op
import sqlalchemy as sa

revision = "0002_billing_ledger"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "plans",
        sa.Column("code", sa.String(length=40), primary_key=True),
        sa.Column("title", sa.String(length=100), nullable=False),
        sa.Column("amount_minor", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(length=12), nullable=False),
        sa.Column("quota_bytes", sa.BigInteger(), nullable=False),
        sa.Column("max_devices", sa.Integer(), nullable=False),
        sa.Column("duration_days", sa.Integer(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("amount_minor >= 0", name="ck_plan_amount_nonnegative"),
        sa.CheckConstraint("quota_bytes > 0", name="ck_plan_quota_positive"),
        sa.CheckConstraint("max_devices > 0", name="ck_plan_devices_positive"),
        sa.CheckConstraint("duration_days > 0", name="ck_plan_duration_positive"),
    )
    op.create_table(
        "orders",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("telegram_user_id", sa.String(length=64), nullable=False),
        sa.Column("plan_code", sa.String(length=40), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("amount_minor", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(length=12), nullable=False),
        sa.Column("quota_bytes", sa.BigInteger(), nullable=False),
        sa.Column("max_devices", sa.Integer(), nullable=False),
        sa.Column("duration_days", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("paid_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("telegram_user_id", "idempotency_key", name="uq_order_user_idempotency"),
        sa.CheckConstraint("amount_minor >= 0", name="ck_order_amount_nonnegative"),
        sa.CheckConstraint("quota_bytes > 0", name="ck_order_quota_positive"),
        sa.CheckConstraint("max_devices > 0", name="ck_order_devices_positive"),
        sa.CheckConstraint("duration_days > 0", name="ck_order_duration_positive"),
    )
    op.create_index("ix_orders_telegram_user_id", "orders", ["telegram_user_id"])
    op.create_table(
        "payment_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("order_id", sa.Integer(), sa.ForeignKey("orders.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("provider_event_id", sa.String(length=160), nullable=False),
        sa.Column("amount_minor", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(length=12), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("provider", "provider_event_id", name="uq_payment_provider_event"),
        sa.UniqueConstraint("order_id", name="uq_payment_order"),
        sa.CheckConstraint("amount_minor >= 0", name="ck_payment_amount_nonnegative"),
    )
    op.create_table(
        "entitlements",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("order_id", sa.Integer(), sa.ForeignKey("orders.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("telegram_user_id", sa.String(length=64), nullable=False),
        sa.Column("quota_bytes", sa.BigInteger(), nullable=False),
        sa.Column("consumed_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("max_devices", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("order_id", name="uq_entitlement_order"),
        sa.CheckConstraint("quota_bytes > 0", name="ck_entitlement_quota_positive"),
        sa.CheckConstraint("consumed_bytes >= 0", name="ck_entitlement_consumed_nonnegative"),
        sa.CheckConstraint("consumed_bytes <= quota_bytes", name="ck_entitlement_consumed_within_quota"),
        sa.CheckConstraint("max_devices > 0", name="ck_entitlement_devices_positive"),
    )
    op.create_index("ix_entitlements_telegram_user_id", "entitlements", ["telegram_user_id"])
    op.create_table(
        "usage_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("entitlement_id", sa.Integer(), sa.ForeignKey("entitlements.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("source_event_id", sa.String(length=160), nullable=False),
        sa.Column("bytes_used", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("source", "source_event_id", name="uq_usage_source_event"),
        sa.CheckConstraint("bytes_used > 0", name="ck_usage_bytes_positive"),
    )
    op.create_index("ix_usage_records_entitlement_id", "usage_records", ["entitlement_id"])
    op.add_column(
        "wireguard_client_owners",
        sa.Column("entitlement_id", sa.Integer(), nullable=True),
    )
    op.create_index("ix_wireguard_client_owners_entitlement_id", "wireguard_client_owners", ["entitlement_id"])
    op.create_foreign_key(
        "fk_wireguard_owner_entitlement",
        "wireguard_client_owners",
        "entitlements",
        ["entitlement_id"],
        ["id"],
        ondelete="RESTRICT",
    )


def downgrade() -> None:
    op.drop_constraint("fk_wireguard_owner_entitlement", "wireguard_client_owners", type_="foreignkey")
    op.drop_index("ix_wireguard_client_owners_entitlement_id", table_name="wireguard_client_owners")
    op.drop_column("wireguard_client_owners", "entitlement_id")
    op.drop_index("ix_usage_records_entitlement_id", table_name="usage_records")
    op.drop_table("usage_records")
    op.drop_index("ix_entitlements_telegram_user_id", table_name="entitlements")
    op.drop_table("entitlements")
    op.drop_table("payment_events")
    op.drop_index("ix_orders_telegram_user_id", table_name="orders")
    op.drop_table("orders")
    op.drop_table("plans")
