from functools import lru_cache
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
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
