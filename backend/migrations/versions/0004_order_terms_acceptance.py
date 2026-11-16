"""Persist explicit terms acceptance with each order."""

from alembic import op
import sqlalchemy as sa

revision = "0004_order_terms_acceptance"
down_revision = "0003_order_payment_method"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "order_terms_acceptances",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("order_id", sa.Integer(), nullable=False),
        sa.Column("telegram_user_id", sa.String(length=64), nullable=False),
        sa.Column("terms_version", sa.String(length=32), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["order_id"], ["orders.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("order_id", name="uq_order_terms_acceptance_order"),
    )
    op.create_index(
        op.f("ix_order_terms_acceptances_telegram_user_id"),
        "order_terms_acceptances", ["telegram_user_id"], unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_order_terms_acceptances_telegram_user_id"), table_name="order_terms_acceptances")
    op.drop_table("order_terms_acceptances")
