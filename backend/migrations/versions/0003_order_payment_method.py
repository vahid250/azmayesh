"""Record the selected payment rail on each order."""

from alembic import op
import sqlalchemy as sa

revision = "0003_order_payment_method"
down_revision = "0002_billing_ledger"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "orders",
        sa.Column("payment_method", sa.String(length=16), nullable=False, server_default="crypto"),
    )


def downgrade() -> None:
    op.drop_column("orders", "payment_method")
