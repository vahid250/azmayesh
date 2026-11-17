import base64
import hashlib
import hmac
import json
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl

from cryptography.fernet import Fernet
from fastapi import Header, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
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
    if config.app_env.strip().lower() in {"development", "test"} and config.api_key and x_api_key:
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


SESSION_ABSOLUTE_SECONDS = 4 * 60 * 60
SESSION_IDLE_SECONDS = 30 * 60
SESSION_TOUCH_INTERVAL_SECONDS = 5 * 60
SESSION_KEY_VERSION = 1


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _session_token(config, telegram_user_id: str, exchange_key: str, init_data_hash: str) -> str:
    secret = config.session_derivation_key.encode("utf-8")
    if len(secret) < 32:
        raise HTTPException(status_code=503, detail="Session authentication is not configured")
    # Domain-separated and delimiter-safe inputs prevent cross-protocol ambiguity.
    message = b"RMA-SESSION-TOKEN\x00v1\x00" + b"\x00".join(
        (telegram_user_id.encode("ascii"), exchange_key.encode("ascii"), init_data_hash.encode("ascii"))
    )
    digest = hmac.new(secret, message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def issue_user_session(db: Session, telegram_user_id: str, init_data: str, exchange_key: str) -> dict:
    """Exchange verified initData for an idempotent opaque session token."""
    if not isinstance(exchange_key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", exchange_key):
        raise HTTPException(status_code=422, detail="Session exchange key must contain 256 random bits")
    try:
        decoded = base64.urlsafe_b64decode(exchange_key + "=")
    except Exception:
        raise HTTPException(status_code=422, detail="Session exchange key is invalid") from None
    if len(decoded) != 32:
        raise HTTPException(status_code=422, detail="Session exchange key is invalid")

    from app.models import UserSession

    config = get_settings()
    init_hash = hashlib.sha256(init_data.encode("utf-8")).hexdigest()
    exchange_hash = hashlib.sha256(exchange_key.encode("ascii")).hexdigest()
    token = _session_token(config, telegram_user_id, exchange_key, init_hash)
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    now = datetime.now(timezone.utc)
    row = db.execute(
        select(UserSession).where(
            UserSession.telegram_user_id == telegram_user_id,
            UserSession.exchange_key_hash == exchange_hash,
        )
    ).scalar_one_or_none()

    if row is not None:
        if not hmac.compare_digest(row.init_data_hash, init_hash):
            raise HTTPException(status_code=409, detail="This exchange key is already bound to different Telegram data")
        if row.revoked_at is not None:
            raise HTTPException(status_code=401, detail="This session has been revoked")
        expires = _utc(row.expires_at)
        last_seen = _utc(row.last_seen_at)
        if expires <= now or last_seen + timedelta(seconds=SESSION_IDLE_SECONDS) <= now:
            row.created_at = now
            row.last_seen_at = now
            row.expires_at = now + timedelta(seconds=SESSION_ABSOLUTE_SECONDS)
            row.token_hash = token_hash
            row.key_version = SESSION_KEY_VERSION
            db.commit()
        return {"access_token": token, "token_type": "Bearer", "expires_at": _utc(row.expires_at), "expires_in": SESSION_ABSOLUTE_SECONDS}

    row = UserSession(
        telegram_user_id=telegram_user_id,
        token_hash=token_hash,
        exchange_key_hash=exchange_hash,
        init_data_hash=init_hash,
        key_version=SESSION_KEY_VERSION,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(seconds=SESSION_ABSOLUTE_SECONDS),
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # A concurrent retry may have won the unique-key race. Only return
        # its token if the immutable binding matches exactly.
        existing = db.execute(
            select(UserSession).where(
                UserSession.telegram_user_id == telegram_user_id,
                UserSession.exchange_key_hash == exchange_hash,
            )
        ).scalar_one_or_none()
        if existing is None or not hmac.compare_digest(existing.init_data_hash, init_hash) or existing.revoked_at is not None:
            raise HTTPException(status_code=409, detail="Session exchange could not be completed safely") from None
        if _utc(existing.expires_at) <= now or _utc(existing.last_seen_at) + timedelta(seconds=SESSION_IDLE_SECONDS) <= now:
            raise HTTPException(status_code=401, detail="Session expired; create a new exchange key")
    return {"access_token": token, "token_type": "Bearer", "expires_at": now + timedelta(seconds=SESSION_ABSOLUTE_SECONDS), "expires_in": SESSION_ABSOLUTE_SECONDS}


def authenticate_session_token(db: Session, token: str) -> dict:
    from app.models import UserSession

    if not isinstance(token, str) or not 32 <= len(token) <= 128:
        raise HTTPException(status_code=401, detail="Bearer session is invalid")
    token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()
    row = db.execute(select(UserSession).where(UserSession.token_hash == token_hash)).scalar_one_or_none()
    if row is None or row.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Bearer session is invalid or revoked")
    now = datetime.now(timezone.utc)
    expires = _utc(row.expires_at)
    last_seen = _utc(row.last_seen_at)
    if expires <= now or last_seen + timedelta(seconds=SESSION_IDLE_SECONDS) <= now:
        raise HTTPException(status_code=401, detail="Bearer session has expired")
    if now - last_seen >= timedelta(seconds=SESSION_TOUCH_INTERVAL_SECONDS):
        row.last_seen_at = now
        db.commit()
    return {"auth_method": "bearer_session", "user": {"id": int(row.telegram_user_id)}}


def revoke_user_session(db: Session, token: str) -> None:
    from app.models import UserSession

    token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()
    row = db.execute(select(UserSession).where(UserSession.token_hash == token_hash)).scalar_one_or_none()
    if row is not None and row.revoked_at is None:
        row.revoked_at = datetime.now(timezone.utc)
        db.commit()
