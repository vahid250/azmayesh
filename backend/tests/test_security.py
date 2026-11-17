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


def test_oversized_telegram_init_data_is_rejected(monkeypatch):
    monkeypatch.setattr(settings, "telegram_bot_token", TOKEN)
    with pytest.raises(HTTPException) as exc:
        verify_telegram_init_data("a" * 16385)
    assert exc.value.status_code == 401
    assert "too large" in exc.value.detail.lower()


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


def test_non_object_telegram_user_payload_is_rejected(monkeypatch):
    monkeypatch.setattr(settings, "telegram_bot_token", TOKEN)
    values = {
        "auth_date": str(int(time.time())),
        "user": json.dumps(["not", "a", "user", "object"]),
    }

    with pytest.raises(HTTPException) as exc:
        verify_telegram_init_data(signed_init_data(values))

    assert exc.value.status_code == 401
    assert "user data" in exc.value.detail.lower()



def test_init_data_requires_auth_date_hash_and_user(monkeypatch):
    monkeypatch.setattr(settings, "telegram_bot_token", TOKEN)
    values = {"auth_date": str(int(time.time()))}
    with pytest.raises(HTTPException) as exc:
        verify_telegram_init_data(signed_init_data(values))
    assert exc.value.status_code == 401
    assert "Malformed" in exc.value.detail


@pytest.mark.parametrize("user_id", [0, -1, True, "12345", None])
def test_init_data_rejects_noncanonical_telegram_user_ids(monkeypatch, user_id):
    monkeypatch.setattr(settings, "telegram_bot_token", TOKEN)
    monkeypatch.setattr(settings, "telegram_init_data_max_age_seconds", 3600)
    values = {
        "auth_date": str(int(time.time())),
        "user": json.dumps({"id": user_id}, separators=(",", ":")),
    }
    with pytest.raises(HTTPException) as exc:
        verify_telegram_init_data(signed_init_data(values))
    assert exc.value.status_code == 401
    assert "identity" in exc.value.detail.lower()


def test_init_data_rejects_too_many_query_fields(monkeypatch):
    monkeypatch.setattr(settings, "telegram_bot_token", TOKEN)
    values = {"auth_date": str(int(time.time())), "user": json.dumps({"id": 12345})}
    values.update({f"extra_{i}": str(i) for i in range(40)})
    with pytest.raises(HTTPException) as exc:
        verify_telegram_init_data(signed_init_data(values))
    assert exc.value.status_code == 401


def test_lab_api_key_is_never_enabled_by_case_variant_of_production(monkeypatch):
    from app.security import require_authenticated_request

    monkeypatch.setattr(settings, "app_env", "Production")
    monkeypatch.setattr(settings, "api_key", "lab-secret")
    monkeypatch.setattr(settings, "telegram_bot_token", "")
    with pytest.raises(HTTPException) as exc:
        require_authenticated_request(x_api_key="lab-secret", x_telegram_init_data=None)
    assert exc.value.status_code == 401


def test_invalid_init_data_age_policy_fails_closed(monkeypatch):
    monkeypatch.setattr(settings, "telegram_bot_token", TOKEN)
    monkeypatch.setattr(settings, "telegram_init_data_max_age_seconds", 0)
    values = {
        "auth_date": str(int(time.time())),
        "user": json.dumps({"id": 12345}, separators=(",", ":")),
    }
    with pytest.raises(HTTPException) as exc:
        verify_telegram_init_data(signed_init_data(values))
    assert exc.value.status_code == 503
