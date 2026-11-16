import hashlib
import hmac
import json
from urllib.parse import urlencode
import pytest
from app.security.telegram import TelegramInitDataError, validate_telegram_init_data


def make_init_data(token: str, auth_date: int) -> str:
    values = {
        "auth_date": str(auth_date),
        "user": json.dumps({"id": 123456, "first_name": "Test"}, separators=(",", ":")),
    }
    check = "\n".join(f"{k}={v}" for k, v in sorted(values.items()))
    secret = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
    values["hash"] = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    return urlencode(values)


def test_valid_init_data():
    data = make_init_data("test-token", 1_700_000_000)
    result = validate_telegram_init_data(data, "test-token", now=1_700_000_100)
    assert result["user"]["id"] == 123456


def test_expired_init_data_rejected():
    data = make_init_data("test-token", 1_700_000_000)
    with pytest.raises(TelegramInitDataError):
        validate_telegram_init_data(data, "test-token", now=1_700_001_000)


def test_wrong_token_rejected():
    data = make_init_data("test-token", 1_700_000_000)
    with pytest.raises(TelegramInitDataError):
        validate_telegram_init_data(data, "wrong-token", now=1_700_000_100)


def test_missing_hash_rejected():
    with pytest.raises(TelegramInitDataError):
        validate_telegram_init_data("auth_date=1&user=%7B%7D", "test-token", now=1)
