"""Database models for Trust Service."""

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    ARRAY,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

Base = declarative_base()


class TrustLevel(str, Enum):
    """Trust levels for certificates and anchors."""

    STANDARD = "standard"
    HIGH = "high"
    EMERGENCY = "emergency"


class CertificateStatus(str, Enum):
    """Certificate status enumeration."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    REVOKED = "revoked"


class SourceType(str, Enum):
    """PKD source types."""

    ICAO_PKD = "icao_pkd"
    NATIONAL_PKI = "national_pki"
    MANUAL = "manual"


class MasterList(Base):
    """Master list entities from various PKD sources."""

    __tablename__ = "master_lists"
    __table_args__ = (
        Index("idx_master_lists_country_version", "country_code", "version"),
        Index("idx_master_lists_source_updated", "source_type", "updated_at"),
        {"schema": "trust_svc"},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    country_code: Mapped[str] = mapped_column(String(3), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    source_type: Mapped[SourceType] = mapped_column(String(20), nullable=False)
    source_url: Mapped[str | None] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    signature_data: Mapped[bytes | None] = mapped_column(LargeBinary)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    issued_by: Mapped[str | None] = mapped_column(Text)
    metadata: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class CSCA(Base):
    """Country Signing Certificate Authority certificates."""

    __tablename__ = "cscas"
    __table_args__ = (
        UniqueConstraint("certificate_hash"),
        Index("idx_cscas_country_status", "country_code", "status"),
        Index("idx_cscas_validity", "valid_from", "valid_to"),
        {"schema": "trust_svc"},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    country_code: Mapped[str] = mapped_column(String(3), nullable=False)
    certificate_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    certificate_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    subject_dn: Mapped[str] = mapped_column(Text, nullable=False)
    issuer_dn: Mapped[str] = mapped_column(Text, nullable=False)
    serial_number: Mapped[str] = mapped_column(Text, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    key_usage: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    signature_algorithm: Mapped[str | None] = mapped_column(String(50))
    public_key_algorithm: Mapped[str | None] = mapped_column(String(50))
    trust_level: Mapped[TrustLevel] = mapped_column(String(20), default=TrustLevel.STANDARD)
    status: Mapped[CertificateStatus] = mapped_column(String(20), default=CertificateStatus.ACTIVE)
    immutable_flag: Mapped[bool] = mapped_column(Boolean, default=False)
    master_list_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("trust_svc.master_lists.id")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    master_list: Mapped[Optional["MasterList"]] = relationship("MasterList", back_populates="cscas")
    dscs: Mapped[list["DSC"]] = relationship("DSC", back_populates="issuer_csca")


class DSC(Base):
    """Document Signing Certificates."""

    __tablename__ = "dscs"
    __table_args__ = (
        UniqueConstraint("certificate_hash"),
        Index("idx_dscs_country_status", "country_code", "status"),
        Index("idx_dscs_issuer", "issuer_csca_id"),
        Index("idx_dscs_validity", "valid_from", "valid_to"),
        {"schema": "trust_svc"},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    country_code: Mapped[str] = mapped_column(String(3), nullable=False)
    certificate_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    certificate_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    issuer_csca_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("trust_svc.cscas.id")
    )
    subject_dn: Mapped[str] = mapped_column(Text, nullable=False)
    issuer_dn: Mapped[str] = mapped_column(Text, nullable=False)
    serial_number: Mapped[str] = mapped_column(Text, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    key_usage: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    signature_algorithm: Mapped[str | None] = mapped_column(String(50))
    public_key_algorithm: Mapped[str | None] = mapped_column(String(50))
    status: Mapped[CertificateStatus] = mapped_column(String(20), default=CertificateStatus.ACTIVE)
    revocation_reason: Mapped[str | None] = mapped_column(String(50))
    revocation_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    master_list_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("trust_svc.master_lists.id")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    issuer_csca: Mapped[Optional["CSCA"]] = relationship("CSCA", back_populates="dscs")
    master_list: Mapped[Optional["MasterList"]] = relationship("MasterList", back_populates="dscs")


class CRL(Base):
    """Certificate Revocation Lists."""

    __tablename__ = "crls"
    __table_args__ = (
        Index("idx_crls_issuer_country", "issuer_dn", "country_code"),
        Index("idx_crls_validity", "this_update", "next_update"),
        {"schema": "trust_svc"},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    country_code: Mapped[str] = mapped_column(String(3), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    crl_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    issuer_dn: Mapped[str] = mapped_column(Text, nullable=False)
    this_update: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    next_update: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    signature_algorithm: Mapped[str | None] = mapped_column(String(50))
    extensions: Mapped[dict | None] = mapped_column(JSONB)
    revoked_certificates: Mapped[dict | None] = mapped_column(
        JSONB
    )  # Serialized revocation entries
    source_url: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Source(Base):
    """PKD and HML data sources configuration."""

    __tablename__ = "sources"
    __table_args__ = (
        UniqueConstraint("source_type", "country_code", "url"),
        Index("idx_sources_type_status", "source_type", "is_active"),
        {"schema": "trust_svc"},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_type: Mapped[SourceType] = mapped_column(String(20), nullable=False)
    country_code: Mapped[str | None] = mapped_column(String(3))
    url: Mapped[str] = mapped_column(Text, nullable=False)
    credentials: Mapped[dict | None] = mapped_column(JSONB)  # Encrypted credentials
    sync_interval: Mapped[int] = mapped_column(Integer, default=3600)  # seconds
    last_sync: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    metadata: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Provenance(Base):
    """Data provenance tracking for trust data lineage."""

    __tablename__ = "provenance"
    __table_args__ = (
        Index("idx_provenance_entity", "entity_type", "entity_id"),
        Index("idx_provenance_source", "source_id", "created_at"),
        {"schema": "trust_svc"},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    entity_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # 'master_list', 'csca', 'dsc', 'crl'
    entity_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    source_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("trust_svc.sources.id"), nullable=False
    )
    operation: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # 'create', 'update', 'delete'
    changes: Mapped[dict | None] = mapped_column(JSONB)  # What changed
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str | None] = mapped_column(Text)  # Digital signature of the change
    metadata: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    source: Mapped["Source"] = relationship("Source")


# Add back-references for relationships
MasterList.cscas = relationship("CSCA", back_populates="master_list")
MasterList.dscs = relationship("DSC", back_populates="master_list")
