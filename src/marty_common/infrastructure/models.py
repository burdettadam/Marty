"""Shared SQLAlchemy models used across services."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class TrustEntity(Base):
    __tablename__ = "trust_entities"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    entity_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    trusted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    attributes: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )


class CertificateRecord(Base):
    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    certificate_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    certificate_type: Mapped[str] = mapped_column(String(32), nullable=False)
    issuer: Mapped[str] = mapped_column(String(128), nullable=True)
    subject: Mapped[str] = mapped_column(String(128), nullable=True)
    pem: Mapped[str] = mapped_column(Text, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )


class DigitalTravelCredentialRecord(Base):
    __tablename__ = "digital_travel_credentials"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    dtc_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    passport_number: Mapped[str] = mapped_column(String(32), nullable=False)
    dtc_type: Mapped[str] = mapped_column(String(32), nullable=False)
    access_control: Mapped[str] = mapped_column(String(32), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    payload_location: Mapped[str] = mapped_column(String(256), nullable=False)
    signature: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)


class MobileDrivingLicenseRecord(Base):
    __tablename__ = "mobile_driving_licenses"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    mdl_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    license_number: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING_SIGNATURE")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    payload_location: Mapped[str] = mapped_column(String(256), nullable=False)
    disclosure_policies: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    signature: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)


class PassportRecord(Base):
    __tablename__ = "passports"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    passport_number: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ISSUED")
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    payload_location: Mapped[str] = mapped_column(String(256), nullable=False)
    signature: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
