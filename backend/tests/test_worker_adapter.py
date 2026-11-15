import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.config import activate_worker_settings, reset_worker_settings, settings
from app.database import get_db
from app.wireguard import _validate_real_server


def test_worker_settings_are_request_scoped_and_read_cloudflare_values():
    env = SimpleNamespace(
        APP_ENV="production",
        MOCK_MODE="true",
        API_KEY="worker-test-key",
        TELEGRAM_INIT_DATA_MAX_AGE_SECONDS="3600",
        ENCRYPTION_KEY="worker-test-encryption-key",
    )
    previous_app_env = settings.app_env
    token = activate_worker_settings(env)
    try:
        assert settings.app_env == "production"
        assert settings.mock_mode is True
        assert settings.api_key == "worker-test-key"
        assert settings.telegram_init_data_max_age_seconds == 3600
        assert settings.encryption_key == "worker-test-encryption-key"
    finally:
        reset_worker_settings(token)
    assert settings.app_env == previous_app_env


def test_worker_database_fails_closed_without_hyperdrive(monkeypatch):
    monkeypatch.setenv("RMA_CLOUDFLARE_WORKER", "1")
    request = Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("localhost", 443),
        }
    )

    async def advance_dependency():
        dependency = get_db(request)
        await dependency.__anext__()

    with pytest.raises(HTTPException) as exc:
        asyncio.run(advance_dependency())
    assert exc.value.status_code == 503
    assert "HYPERDRIVE" in exc.value.detail


def test_worker_never_attempts_real_wireguard_commands(monkeypatch):
    monkeypatch.setenv("RMA_CLOUDFLARE_WORKER", "1")
    monkeypatch.setattr(settings, "mock_mode", False)

    with pytest.raises(HTTPException) as exc:
        _validate_real_server()

    assert exc.value.status_code == 503
    assert "separate WireGuard server" in exc.value.detail
