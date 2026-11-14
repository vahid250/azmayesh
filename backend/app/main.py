from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.config import settings
from app.database import Base, engine, get_db
from app.models import WireGuardClient
from app.security import decrypt_secret, require_api_key
from app.wireguard import get_wireguard_peer_status, issue_wireguard_config, revoke_wireguard_peer
from app import models  # noqa: F401 - register ORM metadata

app = FastAPI(title="R&MA Backend Lab", version="0.2.0")
Base.metadata.create_all(bind=engine)


class WireGuardRequest(BaseModel):
    client_name: str = Field(default="R&MA Client", min_length=1, max_length=64)


def get_client_or_404(db: Session, client_id: int) -> WireGuardClient:
    row = db.get(WireGuardClient, client_id)
    if row is None:
        raise HTTPException(status_code=404, detail="WireGuard client not found")
    return row


@app.get("/health")
def health():
    return {
        "status": "ok",
        "environment": settings.app_env,
        "mock_mode": settings.mock_mode,
        "real_provisioning_configured": bool(
            not settings.mock_mode and settings.wg_server_endpoint and settings.wg_server_public_key
        ),
        "connectivity_verified": False,
    }


@app.post("/api/v1/wireguard/configs", dependencies=[Depends(require_api_key)])
def create_wireguard_config(request: WireGuardRequest, db: Session = Depends(get_db)):
    return issue_wireguard_config(db, request.client_name)


@app.get("/api/v1/wireguard/configs", dependencies=[Depends(require_api_key)])
def list_wireguard_configs(db: Session = Depends(get_db)):
    rows = db.execute(select(WireGuardClient).order_by(WireGuardClient.id.desc())).scalars().all()
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


@app.get("/api/v1/wireguard/configs/{client_id}/config", dependencies=[Depends(require_api_key)])
def get_wireguard_config(client_id: int, db: Session = Depends(get_db)):
    row = get_client_or_404(db, client_id)
    if row.state == "revoked":
        raise HTTPException(status_code=410, detail="This WireGuard client has been revoked")
    return {
        "id": row.id,
        "client_name": row.client_name,
        "config": decrypt_secret(row.config_encrypted),
        "state": row.state,
        "connectivity_verified": False,
    }


@app.get("/api/v1/wireguard/configs/{client_id}/status", dependencies=[Depends(require_api_key)])
def wireguard_status(client_id: int, db: Session = Depends(get_db)):
    return get_wireguard_peer_status(get_client_or_404(db, client_id))


@app.post("/api/v1/wireguard/configs/{client_id}/revoke", dependencies=[Depends(require_api_key)])
def revoke_wireguard_config(client_id: int, db: Session = Depends(get_db)):
    return revoke_wireguard_peer(db, get_client_or_404(db, client_id))
