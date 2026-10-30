"""Application settings loaded from environment variables (see .env.example)."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    database_url: str = "postgresql+psycopg://vulnscope:vulnscope@localhost:5432/vulnscope"
    redis_url: str = "redis://localhost:6379/0"
    # Lets the local lab targets (Juice Shop, DVWA) be verified without proof of ownership. Off
    # unless switched on: .env.example turns it on for development.
    lab_mode: bool = False

    # RQ queue that runs the pipeline stages (app/workers).
    pipeline_queue: str = "pipeline"
    # Phase 3 stages are stubs that sleep this long, so polling a scan shows each state.
    pipeline_step_delay_seconds: float = Field(default=1.0, ge=0)


@lru_cache
def get_settings() -> Settings:
    return Settings()
