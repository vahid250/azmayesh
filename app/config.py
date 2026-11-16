from functools import lru_cache
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    debug: bool = False
    app_secret: str = Field(min_length=32)
    database_url: str = "sqlite+aiosqlite:///./rma_dev.db"
    telegram_bot_token: str | None = None
    telegram_initdata_max_age_seconds: int = Field(default=300, ge=30, le=900)
    webapp_origins: list[str] = ["http://localhost:3000"]
    config_encryption_key: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    @field_validator("webapp_origins", mode="before")
    @classmethod
    def parse_origins(cls, value):
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
