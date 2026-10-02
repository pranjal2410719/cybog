import os
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# Repo root resolved from this file's location, so fresh clones work with
# zero edits: defaults are absolute paths on ANY machine, overridable via
# environment or backend/.env (env > .env file > these defaults).
_REPO_ROOT = Path(__file__).resolve().parents[2]


class CybogBackendSettings(BaseSettings):
    """
    Configuration for the Cybog backend API.

    This MUST be a BaseSettings (not a plain BaseModel). `env_file` is a
    BaseSettings feature; on a plain BaseModel the key is inert, which meant
    neither the environment nor backend/.env was ever read and every setting
    silently fell back to its hardcoded default. Precedence is now the
    standard one: real environment variable > .env file > field default.
    """
    
    # Cybog integration settings
    CYBOG_RUNTIME: str = Field(
        default="development",
        description="Runtime environment: development, staging, production"
    )
    CYBOG_CONFIG_PATH: str = Field(
        default=str(_REPO_ROOT / "cybog" / "config.yaml"),
        description="Path to Cybog configuration file"
    )
    CYBOG_OUTPUT_ROOT: str = Field(
        default=str(_REPO_ROOT / "cybog" / "reports"),
        description="Root directory for Cybog output"
    )
    
    # API settings
    API_HOST: str = Field(default="0.0.0.0", description="API host")
    API_PORT: int = Field(default=8000, description="API port")
    API_RELOAD: bool = Field(default=True, description="Enable auto-reload in development")
    
    # CORS settings
    CORS_ORIGINS: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173"],
        description="Allowed CORS origins for frontend"
    )
    
    model_config = SettingsConfigDict(
        env_file = ".env",
        env_file_encoding = "utf-8",
        case_sensitive = True,
        extra = "allow"
    )


# Global settings instance
settings = CybogBackendSettings()


def get_settings() -> CybogBackendSettings:
    """Get the backend settings instance."""
    return settings