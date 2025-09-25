"""Configuration helpers for the Marty operator UI."""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class UiSettings(BaseSettings):
    """Environment-driven settings for the UI layer."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="allow",  # Allow extra fields for test configuration
    )

    title: str = Field(default="Marty Operator Console", alias="UI_TITLE")
    environment: str = Field(default="development", alias="UI_ENVIRONMENT")
    passport_engine_target: str = Field(default="localhost:8084", alias="UI_PASSPORT_ENGINE_ADDR")
    inspection_system_target: str = Field(
        default="localhost:8083", alias="UI_INSPECTION_SYSTEM_ADDR"
    )
    mdl_engine_target: str = Field(default="localhost:8085", alias="UI_MDL_ENGINE_ADDR")
    trust_anchor_target: str = Field(default="localhost:9080", alias="UI_TRUST_ANCHOR_ADDR")
    grpc_timeout_seconds: int = Field(default=5, alias="UI_GRPC_TIMEOUT_SECONDS")
    enable_mock_data: bool = Field(default=False, alias="UI_ENABLE_MOCK_DATA")
    theme: Literal["light", "dark"] = Field(default="light", alias="UI_THEME")


@lru_cache
def get_settings() -> UiSettings:
    """Return a cached settings instance."""

    return UiSettings()
