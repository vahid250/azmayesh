import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.database import Base, get_db
from app.main import app
from app.models import UserSession
from app.security import authenticate_session_token, issue_user_session


BOT_TOKEN = "987654:session-test-token"


def signed_init_data(user_id=12345, auth_date=None):
    values = {
        "auth_date": str(auth_date or int(time.time())),
        "user": json.dumps({"id": user_id, "first_name": "Session Test"}, separators=(",", ":")),
    }
    secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    check = "\n".join(f"{key}={value}" for key, value in sorted(values.items()))
    values["hash"] = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    return urlencode(values)


def exchange_key(seed=b"rma-session-test-key"):
    return base64.urlsafe_b64encode(hashlib.sha256(seed).digest()).rstrip(b"=").decode()


@pytest.fixture
def db_factory(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'sessions.sqlite'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    yield factory
    engine.dispose()


def configure_settings(monkeypatch):
    monkeypatch.setattr(settings, "telegram_bot_token", BOT_TOKEN)
    monkeypatch.setattr(settings, "telegram_init_data_max_age_seconds", 3600)
    monkeypatch.setattr(settings, "session_derivation_key", "independent-test-session-secret-" * 2)
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "api_key", "")


def test_exchange_is_idempotent_and_only_hash_is_stored(db_factory, monkeypatch):
    configure_settings(monkeypatch)
    init_data = signed_init_data()
    key = exchange_key()
    with db_factory() as db:
        first = issue_user_session(db, "12345", init_data, key)
        second = issue_user_session(db, "12345", init_data, key)
        row = db.execute(select(UserSession)).scalar_one()

        assert first["access_token"] == second["access_token"]
        assert first["token_type"] == "Bearer"
        assert row.token_hash == hashlib.sha256(first["access_token"].encode()).hexdigest()
        assert first["access_token"] not in repr(row.__dict__)
        assert len(row.token_hash) == 64
        assert row.expires_at > row.created_at


def test_exchange_key_cannot_be_reused_with_different_init_data(db_factory, monkeypatch):
    configure_settings(monkeypatch)
    key = exchange_key()
    with db_factory() as db:
        issue_user_session(db, "12345", signed_init_data(auth_date=int(time.time())), key)
        with pytest.raises(HTTPException) as exc:
            issue_user_session(db, "12345", signed_init_data(auth_date=int(time.time()) - 1), key)
        assert exc.value.status_code == 409


def test_idle_expired_session_is_rejected_and_can_be_reissued(db_factory, monkeypatch):
    configure_settings(monkeypatch)
    init_data, key = signed_init_data(), exchange_key()
    with db_factory() as db:
        issued = issue_user_session(db, "12345", init_data, key)
        row = db.execute(select(UserSession)).scalar_one()
        row.last_seen_at = datetime.now(timezone.utc) - timedelta(minutes=31)
        db.commit()
        with pytest.raises(HTTPException) as exc:
            authenticate_session_token(db, issued["access_token"])
        assert exc.value.status_code == 401
        renewed = issue_user_session(db, "12345", init_data, key)
        assert renewed["access_token"] == issued["access_token"]
        last_seen = row.last_seen_at.replace(tzinfo=timezone.utc) if row.last_seen_at.tzinfo is None else row.last_seen_at
        assert last_seen > datetime.now(timezone.utc) - timedelta(seconds=10)


def test_absolute_expiry_and_revocation_are_enforced(db_factory, monkeypatch):
    configure_settings(monkeypatch)
    with db_factory() as db:
        issued = issue_user_session(db, "12345", signed_init_data(), exchange_key())
        row = db.execute(select(UserSession)).scalar_one()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
        with pytest.raises(HTTPException):
            authenticate_session_token(db, issued["access_token"])


def test_private_api_requires_bearer_session_and_logout_revokes_it(db_factory, monkeypatch):
    configure_settings(monkeypatch)
    init_data = signed_init_data()
    factory = db_factory

    def override_db():
        with factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as client:
            exchange = client.post(
                "/api/v1/auth/session",
                json={"init_data": init_data, "exchange_key": exchange_key()},
            )
            assert exchange.status_code == 200, exchange.text
            token = exchange.json()["access_token"]

            private = client.get("/api/v1/orders", headers={"Authorization": f"Bearer {token}"})
            assert private.status_code == 200
            assert private.json() == []

            legacy = client.get("/api/v1/orders", headers={"X-Telegram-Init-Data": init_data})
            assert legacy.status_code == 401

            logout = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
            assert logout.status_code == 200
            assert logout.json()["revoked"] is True

            rejected = client.get("/api/v1/orders", headers={"Authorization": f"Bearer {token}"})
            assert rejected.status_code == 401
    finally:
        app.dependency_overrides.pop(get_db, None)
