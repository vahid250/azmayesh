from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.config import settings
from app.database import Base, engine, get_db
from app.security import require_api_key
from app.wireguard import issue_wireguard_config
from app import models  # noqa: F401 - register ORM metadata

app = FastAPI(title="R&MA Backend Lab", version="0.1.0")
Base.metadata.create_all(bind=engine)


class WireGuardRequest(BaseModel):
    client_name: str = Field(default="R&MA Client", min_length=1, max_length=64)


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
