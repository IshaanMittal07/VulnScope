"""Application settings loaded from environment variables (see .env.example)."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    database_url: str = "postgresql://vulnscope:vulnscope@localhost:5432/vulnscope"
    redis_url: str = "redis://localhost:6379/0"
    lab_mode: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
