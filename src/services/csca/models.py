"""Database models for the csca service."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Integer, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all csca service models."""

    pass


class CscaOutbox(Base):
    """Outbox pattern implementation for csca service events."""

    __tablename__ = "csca_outbox"

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


class CscaCertificate(Base):
    """CSCA (Country Signing CA) certificates managed by the csca service."""

    __tablename__ = "csca_certificates"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    certificate_id: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False, index=True
    )
    country_code: Mapped[str] = mapped_column(
        String(3), nullable=False, index=True
    )  # ISO 3166-1 alpha-3
    issuer_name: Mapped[str] = mapped_column(String(256), nullable=False)
    subject_name: Mapped[str] = mapped_column(String(256), nullable=False)
    serial_number: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    fingerprint_sha256: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    certificate_pem: Mapped[str] = mapped_column(Text, nullable=False)
    certificate_der: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    public_key_algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    key_usage: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    extended_key_usage: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE", index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    trust_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="TRUSTED", index=True
    )
    trust_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    source: Mapped[str] = mapped_column(String(128), nullable=False)  # PKD, manual, etc.
    extra_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class CertificateChain(Base):
    """Certificate chains for validation, managed by csca service."""

    __tablename__ = "certificate_chains"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    chain_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    root_certificate_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    leaf_certificate_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    country_code: Mapped[str] = mapped_column(String(3), nullable=False, index=True)
    chain_certificates: Mapped[list[str]] = mapped_column(
        JSON, nullable=False
    )  # List of cert IDs in order
    validation_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="VALID", index=True
    )
    validation_errors: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    last_validated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    usage_purpose: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # DOCUMENT_SIGNER, PASSPORT, etc.
    trust_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="TRUSTED", index=True
    )
    extra_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class CrlCache(Base):
    """CRL (Certificate Revocation List) cache managed by csca service."""

    __tablename__ = "crl_cache"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    crl_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    issuer_certificate_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    crl_url: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    crl_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    crl_number: Mapped[str | None] = mapped_column(String(128), nullable=True)
    this_update: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    next_update: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_certificates: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    signature_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    download_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="SUCCESS", index=True
    )
    download_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    last_downloaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class OcspCache(Base):
    """OCSP (Online Certificate Status Protocol) response cache managed by csca service."""

    __tablename__ = "ocsp_cache"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ocsp_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    certificate_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    issuer_certificate_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    ocsp_url: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    ocsp_request: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    ocsp_response: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    certificate_status: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # GOOD, REVOKED, UNKNOWN
    revocation_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    this_update: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    next_update: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    produced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    response_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    signature_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    query_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="SUCCESS", index=True
    )
    query_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    last_queried_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
