import hashlib
import hmac
import json
import re
import time
from urllib.parse import parse_qsl

from cryptography.fernet import Fernet
from fastapi import Header, HTTPException
from app.config import get_settings


def verify_telegram_init_data(init_data: str) -> dict:
    """Verify Telegram's signed WebApp payload and require a usable user identity."""
    if not isinstance(init_data, str) or len(init_data) > 16384:
        raise HTTPException(status_code=401, detail="Telegram initData is invalid or too large")
    config = get_settings()
    if not config.telegram_bot_token:
        raise HTTPException(status_code=503, detail="Telegram WebApp authentication is not configured")

    try:
        # Telegram initData contains a small, fixed set of fields. Bound the
        # parser to avoid excessive-field CPU/memory abuse before HMAC checks.
        pairs = parse_qsl(
            init_data,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=32,
            encoding="utf-8",
            errors="strict",
        )
        values = dict(pairs)
        if len(values) != len(pairs):
            raise ValueError("duplicate fields")

        supplied_hash = values.pop("hash")
        auth_date_text = values["auth_date"]
        if not re.fullmatch(r"[0-9]{1,12}", auth_date_text):
            raise ValueError("invalid auth_date")
        auth_date = int(auth_date_text)
        if not re.fullmatch(r"[0-9a-f]{64}", supplied_hash):
            raise ValueError("invalid hash")
        if "user" not in values:
            raise ValueError("missing Telegram user")
    except (ValueError, KeyError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=401, detail="Malformed Telegram initData") from exc

    secret_key = hmac.new(
        b"WebAppData", config.telegram_bot_token.encode("utf-8"), hashlib.sha256
    ).digest()
    data_check_string = "\n".join(f"{key}={value}" for key, value in sorted(values.items()))
    calculated_hash = hmac.new(
        secret_key, data_check_string.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(calculated_hash, supplied_hash):
        raise HTTPException(status_code=401, detail="Telegram initData signature is invalid")

    max_age = config.telegram_init_data_max_age_seconds
    if isinstance(max_age, bool) or not isinstance(max_age, int) or not 1 <= max_age <= 3600:
        raise HTTPException(status_code=503, detail="Telegram initData age policy is misconfigured")

    now = int(time.time())
    if auth_date <= 0 or auth_date > now + 30 or now - auth_date > max_age:
        raise HTTPException(status_code=401, detail="Telegram initData has expired")

    try:
        user = json.loads(values["user"])
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        raise HTTPException(status_code=401, detail="Telegram user data is invalid") from None
    if not isinstance(user, dict):
        raise HTTPException(status_code=401, detail="Telegram user data is invalid")
    if (
        isinstance(user.get("id"), bool)
        or not isinstance(user.get("id"), int)
        or user["id"] <= 0
    ):
        raise HTTPException(status_code=401, detail="Telegram user identity is invalid")

    query_id = values.get("query_id")
    if query_id is not None and (not query_id or len(query_id) > 256):
        raise HTTPException(status_code=401, detail="Telegram query identity is invalid")

    return {"auth_date": auth_date, "user": user, "query_id": query_id}


def require_authenticated_request(
    x_api_key: str | None = Header(default=None),
    x_telegram_init_data: str | None = Header(default=None),
) -> dict:
    # API-key access is intentionally limited to non-production lab use.
    config = get_settings()
    if config.app_env.strip().lower() != "production" and config.api_key and x_api_key:
        if hmac.compare_digest(x_api_key.encode("utf-8"), config.api_key.encode("utf-8")):
            return {"auth_method": "lab_api_key"}
    if x_telegram_init_data:
        result = verify_telegram_init_data(x_telegram_init_data)
        result["auth_method"] = "telegram_webapp"
        return result
    if not config.telegram_bot_token and not config.api_key:
        raise HTTPException(status_code=503, detail="Authentication is not configured")
    raise HTTPException(status_code=401, detail="Valid Telegram WebApp initData is required")


def get_cipher() -> Fernet:
    if not get_settings().encryption_key:
        raise HTTPException(status_code=503, detail="At-rest encryption key is not configured")
    try:
        return Fernet(get_settings().encryption_key.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        raise HTTPException(status_code=503, detail="At-rest encryption key is invalid")


def encrypt_secret(value: str) -> str:
    return get_cipher().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str) -> str:
    try:
        return get_cipher().decrypt(value.encode("ascii")).decode("utf-8")
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Stored encrypted data could not be decrypted") from exc
