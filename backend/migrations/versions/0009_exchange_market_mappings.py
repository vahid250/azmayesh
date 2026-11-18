"""Add explicit, reviewed exchange-market mappings for payment assets."""

from alembic import op
import sqlalchemy as sa

revision = "0009_exchange_market_mappings"
down_revision = "0008_usd_plan_order_prices"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "exchange_market_mappings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "payment_asset_id",
            sa.Integer(),
            sa.ForeignKey("payment_assets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("market_symbol", sa.String(length=64), nullable=False),
        sa.Column("market_base_currency", sa.String(length=12), nullable=False),
        sa.Column("market_quote_currency", sa.String(length=12), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "payment_asset_id",
            "source",
            name="uq_market_mapping_asset_source",
        ),
        sa.CheckConstraint(
            "source IN ('coinbase', 'kraken', 'bitstamp')",
            name="ck_market_mapping_supported_source",
        ),
        sa.CheckConstraint(
            "market_base_currency <> market_quote_currency",
            name="ck_market_mapping_distinct_currencies",
        ),
        sa.CheckConstraint(
            "is_enabled = false OR reviewed_at IS NOT NULL",
            name="ck_market_mapping_enabled_requires_review",
        ),
    )
    op.create_index(
        "ix_exchange_market_mappings_payment_asset_id",
        "exchange_market_mappings",
        ["payment_asset_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_exchange_market_mappings_payment_asset_id",
        table_name="exchange_market_mappings",
    )
    op.drop_table("exchange_market_mappings")
