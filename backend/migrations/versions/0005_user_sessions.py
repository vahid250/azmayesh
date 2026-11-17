"""Add server-side Mini App sessions with hashed token verifiers."""

from alembic import op
import sqlalchemy as sa

revision = "0005_user_sessions"
down_revision = "0004_order_terms_acceptance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("telegram_user_id", sa.String(length=64), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("exchange_key_hash", sa.String(length=64), nullable=False),
        sa.Column("init_data_hash", sa.String(length=64), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_user_sessions_token_hash"),
        sa.UniqueConstraint("telegram_user_id", "exchange_key_hash", name="uq_user_sessions_user_exchange"),
    )
    op.create_index("ix_user_sessions_user_expires", "user_sessions", ["telegram_user_id", "expires_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_user_sessions_user_expires", table_name="user_sessions")
    op.drop_table("user_sessions")
