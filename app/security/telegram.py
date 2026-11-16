import hashlib
import hmac
import json
import time
from urllib.parse import parse_qsl


class TelegramInitDataError(ValueError):
    pass


def validate_telegram_init_data(
    init_data: str,
    bot_token: str,
    *,
    max_age_seconds: int = 300,
    now: int | None = None,
) -> dict:
    """Validate Telegram Mini App initData using Telegram's HMAC-SHA-256 scheme."""
    if not init_data or not bot_token:
        raise TelegramInitDataError("Missing initData or bot token")

    try:
        pairs = parse_qsl(init_data, keep_blank_values=True, strict_parsing=True)
        if len({key for key, _ in pairs}) != len(pairs):
            raise TelegramInitDataError("Duplicate initData fields")
        values = dict(pairs)
    except (ValueError, TypeError) as exc:
        raise TelegramInitDataError("Malformed initData") from exc

    received_hash = values.pop("hash", None)
    if (
        not received_hash
        or len(received_hash) != 64
        or any(ch not in "0123456789abcdefABCDEF" for ch in received_hash)
    ):
        raise TelegramInitDataError("Missing or invalid hash")

    data_check_string = "\n".join(
        f"{key}={value}" for key, value in sorted(values.items())
    )
    secret_key = hmac.new(
        b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256
    ).digest()
    expected_hash = hmac.new(
        secret_key, data_check_string.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_hash, received_hash.lower()):
        raise TelegramInitDataError("Invalid initData signature")

    try:
        auth_date = int(values["auth_date"])
    except (KeyError, ValueError) as exc:
        raise TelegramInitDataError("Missing or invalid auth_date") from exc

    current = int(time.time()) if now is None else now
    age = current - auth_date
    if age < -30 or age > max_age_seconds:
        raise TelegramInitDataError("Expired or future initData")

    if "user" not in values:
        raise TelegramInitDataError("Missing Telegram user")

    try:
        user = json.loads(values["user"])
        if (
            not isinstance(user, dict)
            or not isinstance(user.get("id"), int)
            or isinstance(user.get("id"), bool)
        ):
            raise ValueError("Invalid user object")
    except (json.JSONDecodeError, ValueError) as exc:
        raise TelegramInitDataError("Invalid Telegram user payload") from exc

    return {"user": user, "auth_date": auth_date, "query_id": values.get("query_id")}
