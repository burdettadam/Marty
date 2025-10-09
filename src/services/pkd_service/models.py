"""Database models for the pkd_service."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Integer, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all pkd_service models."""

    pass


class PkdOutbox(Base):
    """Outbox pattern implementation for pkd_service events."""

    __tablename__ = "pkd_outbox"

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


class PkdDownloadManifest(Base):
    """PKD download manifest cache managed by pkd_service."""

    __tablename__ = "pkd_download_manifest"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    manifest_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    country_code: Mapped[str] = mapped_column(
        String(3), nullable=False, index=True
    )  # ISO 3166-1 alpha-3
    source_url: Mapped[str] = mapped_column(String(512), nullable=False)
    manifest_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    total_certificates: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    downloaded_certificates: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_certificates: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    download_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PENDING", index=True
    )
    last_modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    etag: Mapped[str | None] = mapped_column(String(256), nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    download_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    download_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    download_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    extra_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class PkdCertificateEntry(Base):
    """Individual certificate entries from PKD manifests."""

    __tablename__ = "pkd_certificate_entries"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    entry_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    manifest_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    country_code: Mapped[str] = mapped_column(String(3), nullable=False, index=True)
    certificate_type: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # CSCA, DS, etc.
    file_name: Mapped[str] = mapped_column(String(256), nullable=False)
    file_url: Mapped[str] = mapped_column(String(512), nullable=False)
    file_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    certificate_data: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    certificate_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    certificate_fingerprint: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    download_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PENDING", index=True
    )
    download_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_download_attempt: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    downloaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    download_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    processing_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PENDING", index=True
    )
    processing_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    forwarded_to_csca: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    forwarded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    extra_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class PkdSyncJob(Base):
    """PKD synchronization job tracking."""

    __tablename__ = "pkd_sync_jobs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    job_type: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # FULL_SYNC, INCREMENTAL, etc.
    countries: Mapped[list[str] | None] = mapped_column(
        JSON, nullable=True
    )  # Specific countries or None for all
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING", index=True)
    total_manifests: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    processed_manifests: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_manifests: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_certificates: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    downloaded_certificates: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_certificates: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scheduled_for: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    job_config: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error_summary: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
