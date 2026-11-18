"""Link payment quote intents to their originating orders.

The nullable link preserves existing quote rows and allows multiple quote attempts
for one order (for example, after a quote expires). No historical rows are
rewritten and no payment flow is enabled by this migration.
"""

from alembic import op
import sqlalchemy as sa

revision = "0007_payment_intent_order_link"
down_revision = "0006_expiring_payment_quotes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("payment_intents") as batch_op:
        batch_op.add_column(sa.Column("order_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_payment_intents_order_id_orders",
            "orders",
            ["order_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_index(
            "ix_payment_intents_order_id",
            ["order_id"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("payment_intents") as batch_op:
        batch_op.drop_index("ix_payment_intents_order_id")
        batch_op.drop_constraint("fk_payment_intents_order_id_orders", type_="foreignkey")
        batch_op.drop_column("order_id")
