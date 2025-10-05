"""Database models for the passport_engine service."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, DateTime, String, Text, Boolean, Integer, LargeBinary
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all passport_engine service models."""
    pass


class PassportEngineOutbox(Base):
    """Outbox pattern implementation for passport_engine service events."""
    
    __tablename__ = "passport_engine_outbox"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    topic: Mapped[str] = mapped_column(String(255), nullable=False)
    key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    headers: Mapped[dict[str, str] | None] = mapped_column(JSON, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)


class PassportValidationRequest(Base):
    """Passport validation requests processed by passport_engine."""
    
    __tablename__ = "passport_validation_requests"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    passport_number: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    country_code: Mapped[str] = mapped_column(String(3), nullable=False, index=True)
    document_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    mrz_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    rfid_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    validation_status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING", index=True)
    validation_result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    validation_errors: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    signature_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    certificate_chain_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    document_security_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    biometric_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    requested_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    request_source: Mapped[str] = mapped_column(String(64), nullable=False)  # API, BATCH, INSPECTION, etc.
    processing_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    extra_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PassportValidationCache(Base):
    """Cache for passport validation results to avoid redundant processing."""
    
    __tablename__ = "passport_validation_cache"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    cache_key: Mapped[str] = mapped_column(String(256), unique=True, nullable=False, index=True)
    passport_number: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    country_code: Mapped[str] = mapped_column(String(3), nullable=False, index=True)
    document_hash: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    validation_result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    validation_status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    signature_valid: Mapped[bool] = mapped_column(Boolean, nullable=False)
    certificate_chain_valid: Mapped[bool] = mapped_column(Boolean, nullable=False)
    document_security_valid: Mapped[bool] = mapped_column(Boolean, nullable=False)
    biometric_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    cache_ttl: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )