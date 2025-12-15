from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # API Configuration
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_title: str = "The Vault API"
    api_version: str = "1.0.0"

    # Frontend Configuration
    frontend_url: str = "http://localhost:8501"

    # Storage Configuration
    redis_url: str | None = None
    sqlite_path: str = "vault.db"

    # Security Configuration
    max_secret_length: int = 50000
    max_ttl_minutes: int = 24 * 60
    min_ttl_minutes: int = 1
    default_ttl_minutes: int = 10

    # Rate Limiting (requests per minute)
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 30

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
