"""Trust Service Configuration Settings."""

import os
from enum import Enum
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LogLevel(str, Enum):
    """Log level enumeration."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Environment(str, Enum):
    """Environment enumeration."""

    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class TrustServiceSettings(BaseSettings):
    """Trust Service configuration settings."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False
    )

    # Application settings
    app_name: str = Field(default="trust-svc", alias="APP_NAME")
    environment: Environment = Field(default=Environment.DEVELOPMENT, alias="ENVIRONMENT")
    debug: bool = Field(default=False, alias="DEBUG")

    # Server configuration
    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8080, description="Server port")

    # gRPC server configuration
    grpc_port: int = Field(default=50051, description="gRPC server port")
    grpc_max_workers: int = Field(default=10, description="gRPC max worker threads")
    grpc_enable_reflection: bool = Field(default=True, description="Enable gRPC reflection")

    # Database configuration
    log_level: LogLevel = Field(default=LogLevel.INFO, alias="LOG_LEVEL")
    access_log: bool = Field(default=True, alias="ACCESS_LOG")

    # Database settings
    database_url: str | None = Field(default=None, alias="DATABASE_URL")
    database_pool_size: int = Field(default=10, alias="DATABASE_POOL_SIZE")
    database_pool_overflow: int = Field(default=20, alias="DATABASE_POOL_OVERFLOW")
    database_timeout: int = Field(default=30, alias="DATABASE_TIMEOUT")

    # gRPC settings
    grpc_port: int = Field(default=9090, alias="GRPC_PORT")
    grpc_max_workers: int = Field(default=10, alias="GRPC_MAX_WORKERS")

    # Metrics settings
    metrics_enabled: bool = Field(default=True, alias="METRICS_ENABLED")
    metrics_port: int = Field(default=8081, alias="METRICS_PORT")

    # PKD/HML ingestion settings
    pkd_sync_interval: int = Field(default=3600, alias="PKD_SYNC_INTERVAL")  # seconds
    hml_sync_interval: int = Field(default=1800, alias="HML_SYNC_INTERVAL")  # seconds
    max_retries: int = Field(default=3, alias="MAX_RETRIES")
    retry_delay: int = Field(default=300, alias="RETRY_DELAY")  # seconds

    # ICAO PKD settings
    icao_pkd_url: str | None = Field(default=None, alias="ICAO_PKD_URL")
    icao_pkd_username: str | None = Field(default=None, alias="ICAO_PKD_USERNAME")
    icao_pkd_password: str | None = Field(default=None, alias="ICAO_PKD_PASSWORD")

    # Trust settings
    trust_snapshot_retention_days: int = Field(default=90, alias="TRUST_SNAPSHOT_RETENTION_DAYS")
    max_cert_age_days: int = Field(default=1095, alias="MAX_CERT_AGE_DAYS")  # 3 years

    # Security settings
    cors_origins: list[str] = Field(default=["*"], alias="CORS_ORIGINS")
    cors_methods: list[str] = Field(default=["GET", "POST", "PUT", "DELETE"], alias="CORS_METHODS")
    cors_headers: list[str] = Field(default=["*"], alias="CORS_HEADERS")

    # Health check settings
    health_check_interval: int = Field(default=30, alias="HEALTH_CHECK_INTERVAL")


# Global settings instance - will be populated from environment variables
settings = TrustServiceSettings()
