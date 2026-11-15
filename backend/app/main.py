import os

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import Base, engine, get_db
from app.models import WireGuardClient, WireGuardClientOwner
from app.security import decrypt_secret, require_authenticated_request
from app.wireguard import (
    _validate_real_server,
    get_wireguard_peer_status,
    issue_wireguard_config,
    revoke_wireguard_peer,
)
from app.telegram_bot import router as telegram_router
from app import models  # noqa: F401 - register ORM metadata


app = FastAPI(title="R&MA Backend Lab", version="0.5.0")
app.include_router(telegram_router)

# SQLite is used only for local development and lightweight tests. A Worker
# must use the explicitly configured Hyperdrive binding; never create an
# ephemeral SQLite database in the Worker filesystem.
if (
    os.environ.get("RMA_CLOUDFLARE_WORKER") != "1"
    and engine.dialect.name == "sqlite"
):
    Base.metadata.create_all(bind=engine)


class WireGuardRequest(BaseModel):
    client_name: str = Field(default="R&MA Client", min_length=1, max_length=64)


def owner_id_from_auth(auth: dict) -> str:
    if auth.get("auth_method") == "lab_api_key":
        return "lab-local"
    user = auth.get("user") or {}
    telegram_id = user.get("id")
    if not isinstance(telegram_id, (int, str)) or not str(telegram_id).isdigit():
        raise HTTPException(status_code=401, detail="Telegram user identity is missing from initData")
    return str(telegram_id)


def get_client_or_404(db: Session, client_id: int, owner_id: str) -> WireGuardClient:
    row = db.get(WireGuardClient, client_id)
    if row is None:
        raise HTTPException(status_code=404, detail="WireGuard client not found")
    owner = db.get(WireGuardClientOwner, client_id)
    if owner is None or owner.telegram_user_id != owner_id:
        raise HTTPException(status_code=404, detail="WireGuard client not found")
    return row


@app.get("/health")
def health():
    provisioning_ready = False
    provisioning_reason = "mock_mode_enabled" if settings.mock_mode else None

    if not settings.mock_mode:
        try:
            # In Cloudflare Workers real provisioning is deliberately disabled;
            # WireGuard commands belong on a separate server.
            _validate_real_server()
            provisioning_ready = True
        except HTTPException as exc:
            provisioning_reason = exc.detail

    return {
        "status": "ok",
        "environment": settings.app_env,
        "mock_mode": settings.mock_mode,
        "real_provisioning_configured": provisioning_ready,
        "provisioning_reason": provisioning_reason,
        "connectivity_verified": False,
    }


@app.post("/api/v1/wireguard/configs")
def create_wireguard_config(
    request: WireGuardRequest,
    auth: dict = Depends(require_authenticated_request),
    db: Session = Depends(get_db),
):
    return issue_wireguard_config(db, request.client_name, owner_id_from_auth(auth))


@app.get("/api/v1/wireguard/configs")
def list_wireguard_configs(
    auth: dict = Depends(require_authenticated_request),
    db: Session = Depends(get_db),
):
    owner_id = owner_id_from_auth(auth)
    rows = db.execute(
        select(WireGuardClient)
        .join(WireGuardClientOwner, WireGuardClientOwner.client_id == WireGuardClient.id)
        .where(WireGuardClientOwner.telegram_user_id == owner_id)
        .order_by(WireGuardClient.id.desc())
    ).scalars().all()
    return [
        {
            "id": row.id,
            "client_name": row.client_name,
            "client_ip": row.client_ip,
            "public_key": row.public_key,
            "state": row.state,
            "created_at": row.created_at,
        }
        for row in rows
    ]


@app.get("/api/v1/wireguard/configs/{client_id}/config")
def get_wireguard_config(
    client_id: int,
    auth: dict = Depends(require_authenticated_request),
    db: Session = Depends(get_db),
):
    row = get_client_or_404(db, client_id, owner_id_from_auth(auth))
    if row.state == "revoked":
        raise HTTPException(status_code=410, detail="This WireGuard client has been revoked")
    return {
        "id": row.id,
        "client_name": row.client_name,
        "config": decrypt_secret(row.config_encrypted),
        "state": row.state,
        "connectivity_verified": False,
    }


@app.get("/api/v1/wireguard/configs/{client_id}/status")
def wireguard_status(
    client_id: int,
    auth: dict = Depends(require_authenticated_request),
    db: Session = Depends(get_db),
):
    return get_wireguard_peer_status(get_client_or_404(db, client_id, owner_id_from_auth(auth)))


@app.post("/api/v1/wireguard/configs/{client_id}/revoke")
def revoke_wireguard_config(
    client_id: int,
    auth: dict = Depends(require_authenticated_request),
    db: Session = Depends(get_db),
):
    return revoke_wireguard_peer(db, get_client_or_404(db, client_id, owner_id_from_auth(auth)))
