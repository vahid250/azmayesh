import hmac
from cryptography.fernet import Fernet
from fastapi import Header, HTTPException
from app.config import settings


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if not settings.api_key:
        raise HTTPException(status_code=503, detail="API authentication is not configured")
    if not x_api_key or not hmac.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(status_code=401, detail="Invalid API key")


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
