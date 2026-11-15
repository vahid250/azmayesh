from contextvars import ContextVar, Token
from functools import lru_cache
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "production"
    mock_mode: bool = True
    api_key: str = ""
    telegram_bot_token: str = ""
    telegram_webhook_secret: str = ""
    mini_app_url: str = ""
    # Telegram initData is static for an opened WebApp session. One hour is a
    # practical compromise; users can reopen the Mini App to obtain fresh data.
    telegram_init_data_max_age_seconds: int = 3600
    encryption_key: str = ""
    database_url: str = "sqlite:///./rma_backend.db"
    wg_interface: str = "wg0"
    wg_server_endpoint: str = ""
    wg_server_public_key: str = ""
    wg_subnet: str = "10.66.66.0/24"
    wg_dns: str = "1.1.1.1,8.8.8.8"
    wg_mtu: int = 1360

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache
def _default_settings() -> Settings:
    return Settings()


# Keep this normal Settings instance public for existing tests and local tools
# that patch settings fields. Worker requests use the ContextVar override.
settings = _default_settings()
_request_settings: ContextVar[Settings | None] = ContextVar("rma_request_settings", default=None)


def get_settings() -> Settings:
    """Return request-scoped Worker settings or the normal process settings."""
    return _request_settings.get() or settings


_WORKER_ENV_FIELDS = {
    "APP_ENV": "app_env",
    "MOCK_MODE": "mock_mode",
    "API_KEY": "api_key",
    "TELEGRAM_BOT_TOKEN": "telegram_bot_token",
    "TELEGRAM_WEBHOOK_SECRET": "telegram_webhook_secret",
    "MINI_APP_URL": "mini_app_url",
    "TELEGRAM_INIT_DATA_MAX_AGE_SECONDS": "telegram_init_data_max_age_seconds",
    "ENCRYPTION_KEY": "encryption_key",
    "WG_INTERFACE": "wg_interface",
    "WG_SERVER_ENDPOINT": "wg_server_endpoint",
    "WG_SERVER_PUBLIC_KEY": "wg_server_public_key",
    "WG_SUBNET": "wg_subnet",
    "WG_DNS": "wg_dns",
    "WG_MTU": "wg_mtu",
}


def build_worker_settings(env: Any) -> Settings:
    """Translate Cloudflare bindings into an isolated Settings object.

    Secret values are read from the runtime binding and are never copied to
    process-wide environment variables or logged.
    """
    values: dict[str, Any] = {}
    for binding_name, field_name in _WORKER_ENV_FIELDS.items():
        try:
            value = getattr(env, binding_name)
        except Exception:
            continue
        if value is not None:
            values[field_name] = str(value) if not isinstance(value, bool) else value
    return Settings(**values)


def activate_worker_settings(env: Any) -> Token:
    """Activate per-request Cloudflare settings; the caller must reset the token."""
    return _request_settings.set(build_worker_settings(env))


def reset_worker_settings(token: Token) -> None:
    _request_settings.reset(token)
