"""Pydantic schemas for Trust Service API requests and responses."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class ApiResponse(BaseModel):
    """Base API response model."""

    success: bool = True
    message: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class TrustStatusResponse(BaseModel):
    """Trust service status response."""

    service_name: str
    status: str
    timestamp: datetime
    data_freshness_hours: float | None = None
    total_master_lists: int
    total_active_cscas: int
    total_active_dscs: int
    active_sources_count: int
    countries_covered: list[str]


class TrustAnchor(BaseModel):
    """Trust anchor (CSCA) information."""

    id: str
    country_code: str
    subject_dn: str
    issuer_dn: str
    serial_number: str
    certificate_hash: str
    valid_from: datetime
    valid_to: datetime
    trust_level: str
    status: str
    key_usage: list[str]
    signature_algorithm: str | None
    public_key_algorithm: str | None
    created_at: datetime
    updated_at: datetime


class TrustAnchorsResponse(BaseModel):
    """Trust anchors list response."""

    total_count: int
    limit: int
    offset: int
    country_filter: str | None
    trust_level_filter: str | None
    status_filter: str | None
    anchors: list[TrustAnchor]


class TrustSnapshotEntry(BaseModel):
    """Single entry in trust snapshot."""

    csca_id: str
    country_code: str
    csca_subject_dn: str
    csca_serial_number: str
    csca_valid_from: datetime
    csca_valid_to: datetime
    csca_status: str
    trust_level: str
    dsc_count: int
    dsc_ids: list[str]


class TrustSnapshotResponse(BaseModel):
    """Trust snapshot response."""

    snapshot_id: str
    generated_at: datetime
    country_filter: str | None
    include_inactive: bool
    total_cscas: int
    total_dscs: int
    entries: list[TrustSnapshotEntry]


class DSCInfo(BaseModel):
    """Document Signing Certificate information."""

    id: str
    country_code: str
    subject_dn: str
    issuer_dn: str
    serial_number: str
    certificate_hash: str
    valid_from: datetime
    valid_to: datetime
    status: str
    issuer_csca_id: str | None
    revocation_reason: str | None
    revocation_date: datetime | None
    created_at: datetime
    updated_at: datetime


class MasterListInfo(BaseModel):
    """Master list information."""

    id: str
    country_code: str
    version: int
    source_type: str
    source_url: str | None
    content_hash: str
    valid_from: datetime
    valid_to: datetime
    issued_by: str | None
    created_at: datetime
    updated_at: datetime


class CRLInfo(BaseModel):
    """Certificate Revocation List information."""

    id: str
    country_code: str
    content_hash: str
    issuer_dn: str
    this_update: datetime
    next_update: datetime | None
    signature_algorithm: str | None
    source_url: str | None
    created_at: datetime
    updated_at: datetime


class SourceInfo(BaseModel):
    """PKD/HML source information."""

    id: str
    name: str
    source_type: str
    country_code: str | None
    url: str
    sync_interval: int
    last_sync: datetime | None
    last_success: datetime | None
    last_error: str | None
    is_active: bool
    retry_count: int
    created_at: datetime
    updated_at: datetime


class ProvenanceInfo(BaseModel):
    """Data provenance information."""

    id: str
    entity_type: str
    entity_id: str
    source_id: str
    operation: str
    checksum: str
    signature: str | None
    created_at: datetime


class HealthCheckResponse(BaseModel):
    """Health check response."""

    status: str
    service: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    components: dict | None = None


class ValidationRequest(BaseModel):
    """Certificate validation request."""

    certificate_data: str = Field(..., description="Base64 encoded certificate")
    validation_time: datetime | None = None
    check_revocation: bool = True


class ValidationResponse(BaseModel):
    """Certificate validation response."""

    is_valid: bool
    validation_time: datetime
    trust_chain: list[str]
    revocation_status: str
    validation_errors: list[str]
    validation_warnings: list[str]
