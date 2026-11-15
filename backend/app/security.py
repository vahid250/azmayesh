import hashlib
import hmac
import json
import time
from urllib.parse import parse_qsl

from cryptography.fernet import Fernet
from fastapi import Header, HTTPException
from app.config import settings


def verify_telegram_init_data(init_data: str) -> dict:
    if not settings.telegram_bot_token:
        raise HTTPException(status_code=503, detail="Telegram WebApp authentication is not configured")
    try:
        pairs = parse_qsl(init_data, keep_blank_values=True, strict_parsing=True)
        values = dict(pairs)
        if len(values) != len(pairs):
            raise ValueError("duplicate fields")
        supplied_hash = values.pop("hash")
        auth_date = int(values["auth_date"])
        if len(supplied_hash) != 64:
            raise ValueError("invalid hash")
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=401, detail="Malformed Telegram initData") from exc

    secret_key = hmac.new(
        b"WebAppData", settings.telegram_bot_token.encode("utf-8"), hashlib.sha256
    ).digest()
    data_check_string = "\n".join(f"{key}={value}" for key, value in sorted(values.items()))
    calculated_hash = hmac.new(
        secret_key, data_check_string.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(calculated_hash, supplied_hash):
        raise HTTPException(status_code=401, detail="Telegram initData signature is invalid")

    now = int(time.time())
    if auth_date > now + 30 or now - auth_date > settings.telegram_init_data_max_age_seconds:
        raise HTTPException(status_code=401, detail="Telegram initData has expired")

    user = None
    if "user" in values:
        try:
            user = json.loads(values["user"])
            if not isinstance(user, dict):
                raise ValueError("Telegram user must be a JSON object")
        except (json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(status_code=401, detail="Telegram user data is invalid") from exc
    return {"auth_date": auth_date, "user": user, "query_id": values.get("query_id")}


def require_authenticated_request(
    x_api_key: str | None = Header(default=None),
    x_telegram_init_data: str | None = Header(default=None),
) -> dict:
    # API-key access is intentionally limited to non-production lab use.
    if settings.app_env != "production" and settings.api_key and x_api_key:
        if hmac.compare_digest(x_api_key, settings.api_key):
            return {"auth_method": "lab_api_key"}
    if x_telegram_init_data:
        result = verify_telegram_init_data(x_telegram_init_data)
        result["auth_method"] = "telegram_webapp"
        return result
    if not settings.telegram_bot_token and not settings.api_key:
        raise HTTPException(status_code=503, detail="Authentication is not configured")
    raise HTTPException(status_code=401, detail="Valid Telegram WebApp initData is required")


def get_cipher() -> Fernet:
    if not settings.encryption_key:
        raise HTTPException(status_code=503, detail="At-rest encryption key is not configured")
    try:
        return Fernet(settings.encryption_key.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        raise HTTPException(status_code=503, detail="At-rest encryption key is invalid")


def encrypt_secret(value: str) -> str:
    return get_cipher().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str) -> str:
    try:
        return get_cipher().decrypt(value.encode("ascii")).decode("utf-8")
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Stored encrypted data could not be decrypted") from exc
