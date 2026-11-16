from fastapi import APIRouter, HTTPException
from app.config import settings
from app.security.telegram import TelegramInitDataError, validate_telegram_init_data

router = APIRouter()


@router.get("/health")
async def health():
    return {"status": "ok", "environment": settings.app_env}


@router.post("/auth/telegram")
async def telegram_auth(payload: dict):
    if not settings.telegram_bot_token:
        raise HTTPException(status_code=503, detail="Telegram authentication is not configured")
    init_data = payload.get("init_data")
    try:
        validated = validate_telegram_init_data(
            init_data,
            settings.telegram_bot_token,
            max_age_seconds=settings.telegram_initdata_max_age_seconds,
        )
    except (TelegramInitDataError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid Telegram authentication data")
    # Session issuance and user upsert are intentionally not enabled in this baseline.
    return {
        "authenticated": True,
        "telegram_user": {
            "id": validated["user"]["id"],
            "username": validated["user"].get("username"),
            "first_name": validated["user"].get("first_name"),
        },
        "session": None,
        "note": "Validated identity only; persistent sessions are not implemented yet.",
    }


@router.post("/configs")
async def create_configuration():
    raise HTTPException(
        status_code=503,
        detail="Configuration issuance is disabled until entitlement checks and real provisioning are implemented.",
    )
