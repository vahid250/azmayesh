import hashlib
import hmac
import re
import time

from fastapi import HTTPException

METERING_PATH = "/api/v1/internal/metering/usage"
MAX_CLOCK_SKEW_SECONDS = 300


def verify_metering_signature(
    *,
    secret: str,
    timestamp: str,
    event_id: str,
    signature: str,
    body: bytes,
    now: int | None = None,
) -> None:
    """Authenticate a server-to-server usage report; never accept client counters."""
    if not secret or len(secret) < 32:
        raise HTTPException(status_code=503, detail="Trusted usage metering is not configured")

    if not event_id or len(event_id) > 160 or not re.fullmatch(r"[A-Za-z0-9._:-]+", event_id):
        raise HTTPException(status_code=401, detail="Invalid metering event reference")
    if not re.fullmatch(r"[0-9]{10}", timestamp or ""):
        raise HTTPException(status_code=401, detail="Invalid metering timestamp")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", signature or ""):
        raise HTTPException(status_code=401, detail="Invalid metering signature")

    sent_at = int(timestamp)
    current = int(time.time()) if now is None else now
    if abs(current - sent_at) > MAX_CLOCK_SKEW_SECONDS:
        raise HTTPException(status_code=401, detail="Metering request timestamp is outside the allowed window")

    body_hash = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(
        ["POST", METERING_PATH, timestamp, event_id, body_hash]
    )
    expected = hmac.new(
        secret.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature.lower()):
        raise HTTPException(status_code=401, detail="Invalid metering signature")
