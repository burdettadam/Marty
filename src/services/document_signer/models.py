"""Database models for the document_signer service."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all document_signer service models."""

    pass


class DocumentSignerOutbox(Base):
    """Outbox pattern implementation for document_signer service events."""

    __tablename__ = "document_signer_outbox"

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


class CredentialOffer(Base):
    """Credential offers managed by the document_signer service."""

    __tablename__ = "credential_offers"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    offer_id: Mapped[str] = mapped_column(String(96), unique=True, nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    credential_type: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="CREATED", index=True)
    offer_payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    base_claims: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    selective_disclosures: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    pre_authorized_code: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    pre_authorized_code_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    access_token: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    access_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    nonce: Mapped[str | None] = mapped_column(String(256), nullable=True)
    extra_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    wallet_attestation: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class AccessToken(Base):
    """Access tokens for OIDC4VCI flow managed by document_signer."""

    __tablename__ = "access_tokens"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    token_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    offer_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE", index=True)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    usage_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    extra_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class IssuedCredentialAudit(Base):
    """Audit log for issued credentials from document_signer service."""

    __tablename__ = "issued_credential_audit"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    credential_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    offer_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    credential_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    issuer: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    action: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # ISSUED, REVOKED, SUSPENDED, etc.
    reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    credential_location: Mapped[str | None] = mapped_column(String(512), nullable=True)
    disclosures_location: Mapped[str | None] = mapped_column(String(512), nullable=True)
    signature_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    wallet_attestation: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    extra_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    performed_by: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )  # User/system that performed action
    performed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
