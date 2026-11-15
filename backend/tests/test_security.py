import hashlib
import hmac
import json
import time
from urllib.parse import urlencode

import pytest
from fastapi import HTTPException

from app.config import settings
from app.security import verify_telegram_init_data


TOKEN = "123456:unit-test-token"


def signed_init_data(values: dict[str, str], token: str = TOKEN) -> str:
    secret = hmac.new(b"WebAppData", token.encode("utf-8"), hashlib.sha256).digest()
    data_check_string = "\n".join(
        f"{key}={value}" for key, value in sorted(values.items())
    )
    values_with_hash = dict(values)
    values_with_hash["hash"] = hmac.new(
        secret, data_check_string.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return urlencode(values_with_hash)


def test_valid_telegram_init_data_returns_user(monkeypatch):
    monkeypatch.setattr(settings, "telegram_bot_token", TOKEN)
    monkeypatch.setattr(settings, "telegram_init_data_max_age_seconds", 3600)
    values = {
        "auth_date": str(int(time.time())),
        "query_id": "AAE-unit-test",
        "user": json.dumps({"id": 12345, "first_name": "Test"}, separators=(",", ":")),
    }

    result = verify_telegram_init_data(signed_init_data(values))

    assert result["user"]["id"] == 12345
    assert result["query_id"] == "AAE-unit-test"


def test_expired_telegram_init_data_is_rejected(monkeypatch):
    monkeypatch.setattr(settings, "telegram_bot_token", TOKEN)
    monkeypatch.setattr(settings, "telegram_init_data_max_age_seconds", 600)
    values = {"auth_date": str(int(time.time()) - 601)}

    with pytest.raises(HTTPException) as exc:
        verify_telegram_init_data(signed_init_data(values))

    assert exc.value.status_code == 401
    assert "expired" in exc.value.detail.lower()


def test_future_telegram_init_data_is_rejected(monkeypatch):
    monkeypatch.setattr(settings, "telegram_bot_token", TOKEN)
    monkeypatch.setattr(settings, "telegram_init_data_max_age_seconds", 3600)
    values = {"auth_date": str(int(time.time()) + 31)}

    with pytest.raises(HTTPException) as exc:
        verify_telegram_init_data(signed_init_data(values))

    assert exc.value.status_code == 401


def test_duplicate_telegram_init_data_fields_are_rejected(monkeypatch):
    monkeypatch.setattr(settings, "telegram_bot_token", TOKEN)
    values = {"auth_date": str(int(time.time()))}
    encoded = signed_init_data(values) + "&auth_date=" + values["auth_date"]

    with pytest.raises(HTTPException) as exc:
        verify_telegram_init_data(encoded)

    assert exc.value.status_code == 401
    assert "Malformed" in exc.value.detail


def test_invalid_telegram_init_data_signature_is_rejected(monkeypatch):
    monkeypatch.setattr(settings, "telegram_bot_token", TOKEN)
    values = {"auth_date": str(int(time.time()))}
    encoded = signed_init_data(values).replace("hash=", "hash=0", 1)

    with pytest.raises(HTTPException) as exc:
        verify_telegram_init_data(encoded)

    assert exc.value.status_code == 401
