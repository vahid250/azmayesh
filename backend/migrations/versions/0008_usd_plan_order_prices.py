"""Add nullable USD list-price snapshots without converting legacy amounts."""

from alembic import op
import sqlalchemy as sa

revision = "0008_usd_plan_order_prices"
down_revision = "0007_payment_intent_order_link"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing prices are intentionally left NULL: their historical currency
    # and exchange-rate basis cannot be safely inferred or auto-converted.
    with op.batch_alter_table("plans") as batch_op:
        batch_op.add_column(sa.Column("price_usd_minor", sa.BigInteger(), nullable=True))
    with op.batch_alter_table("orders") as batch_op:
        batch_op.add_column(sa.Column("price_usd_minor", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("orders") as batch_op:
        batch_op.drop_column("price_usd_minor")
    with op.batch_alter_table("plans") as batch_op:
        batch_op.drop_column("price_usd_minor")
