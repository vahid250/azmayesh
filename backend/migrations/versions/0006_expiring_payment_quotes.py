"""Add auditable FX observations, enabled payment assets, and expiring quotes."""

from alembic import op
import sqlalchemy as sa

revision = "0006_expiring_payment_quotes"
down_revision = "0005_user_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "exchange_rates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("base_currency", sa.String(length=12), nullable=False),
        sa.Column("quote_currency", sa.String(length=12), nullable=False),
        sa.Column("units_per_base", sa.Numeric(precision=28, scale=12), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by_admin_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("units_per_base > 0", name="ck_exchange_rates_positive"),
        sa.CheckConstraint("valid_until > observed_at", name="ck_exchange_rates_valid_window"),
    )
    op.create_index(
        "ix_exchange_rates_pair_source_observed",
        "exchange_rates",
        ["base_currency", "quote_currency", "source", "observed_at"],
    )

    op.create_table(
        "payment_assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("currency", sa.String(length=12), nullable=False),
        sa.Column("network", sa.String(length=32), nullable=False),
        sa.Column("asset_type", sa.String(length=16), nullable=False),
        sa.Column("decimals", sa.Integer(), nullable=False),
        sa.Column("min_confirmations", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("currency", "network", name="uq_payment_assets_currency_network"),
        sa.CheckConstraint("decimals >= 0 AND decimals <= 18", name="ck_payment_assets_decimals"),
        sa.CheckConstraint("min_confirmations > 0", name="ck_payment_assets_confirmations"),
    )

    op.create_table(
        "payment_intents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("telegram_user_id", sa.String(length=64), nullable=False),
        sa.Column("plan_code", sa.String(length=40), nullable=False),
        sa.Column("price_usd_minor", sa.BigInteger(), nullable=False),
        sa.Column("payment_currency", sa.String(length=12), nullable=False),
        sa.Column("payment_network", sa.String(length=32), nullable=False),
        sa.Column("payment_amount_minor", sa.BigInteger(), nullable=False),
        sa.Column("payment_decimals", sa.Integer(), nullable=False),
        sa.Column("units_per_usd", sa.Numeric(precision=28, scale=12), nullable=False),
        sa.Column("source_snapshot", sa.JSON(), nullable=False),
        sa.Column("rate_spread_bps", sa.Integer(), nullable=False),
        sa.Column("admin_margin_bps", sa.Integer(), nullable=False),
        sa.Column("quote_issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("quote_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payment_first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("transaction_hash", sa.String(length=160), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="quoted"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("price_usd_minor > 0", name="ck_payment_intents_usd_price_positive"),
        sa.CheckConstraint("payment_amount_minor > 0", name="ck_payment_intents_amount_positive"),
        sa.CheckConstraint("units_per_usd > 0", name="ck_payment_intents_rate_positive"),
        sa.CheckConstraint("rate_spread_bps >= 0", name="ck_payment_intents_spread_nonnegative"),
        sa.CheckConstraint("admin_margin_bps >= 0", name="ck_payment_intents_margin_nonnegative"),
        sa.CheckConstraint("quote_expires_at > quote_issued_at", name="ck_payment_intents_expiry_after_issue"),
    )
    op.create_index(
        "ix_payment_intents_user_status_expiry",
        "payment_intents",
        ["telegram_user_id", "status", "quote_expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_payment_intents_user_status_expiry", table_name="payment_intents")
    op.drop_table("payment_intents")
    op.drop_table("payment_assets")
    op.drop_index("ix_exchange_rates_pair_source_observed", table_name="exchange_rates")
    op.drop_table("exchange_rates")
