"""Create initial R&MA WireGuard client schema."""

from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wireguard_clients",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("client_name", sa.String(length=64), nullable=False),
        sa.Column("client_ip", sa.String(length=48), nullable=False),
        sa.Column("public_key", sa.String(length=64), nullable=False),
        sa.Column("private_key_encrypted", sa.Text(), nullable=False),
        sa.Column("config_encrypted", sa.Text(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("client_ip", name="uq_wg_client_ip"),
        sa.UniqueConstraint("public_key", name="uq_wg_public_key"),
    )
    op.create_table(
        "wireguard_client_owners",
        sa.Column("client_id", sa.Integer(), nullable=False),
        sa.Column("telegram_user_id", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["client_id"], ["wireguard_clients.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("client_id"),
    )
    op.create_index(
        op.f("ix_wireguard_client_owners_telegram_user_id"),
        "wireguard_client_owners",
        ["telegram_user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_wireguard_client_owners_telegram_user_id"),
        table_name="wireguard_client_owners",
    )
    op.drop_table("wireguard_client_owners")
    op.drop_table("wireguard_clients")
