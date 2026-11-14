from datetime import datetime, timezone
from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
