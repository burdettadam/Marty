"""Pydantic schemas for Trust Service API requests and responses."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class ApiResponse(BaseModel):
    """Base API response model."""
    success: bool = True
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class TrustStatusResponse(BaseModel):
    """Trust service status response."""
    service_name: str
    status: str
    timestamp: datetime
    data_freshness_hours: Optional[float] = None
    total_master_lists: int
    total_active_cscas: int
    total_active_dscs: int
    active_sources_count: int
    countries_covered: List[str]


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
    key_usage: List[str]
    signature_algorithm: Optional[str]
    public_key_algorithm: Optional[str]
    created_at: datetime
    updated_at: datetime


class TrustAnchorsResponse(BaseModel):
    """Trust anchors list response."""
    total_count: int
    limit: int
    offset: int
    country_filter: Optional[str]
    trust_level_filter: Optional[str]
    status_filter: Optional[str]
    anchors: List[TrustAnchor]


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
    dsc_ids: List[str]


class TrustSnapshotResponse(BaseModel):
    """Trust snapshot response."""
    snapshot_id: str
    generated_at: datetime
    country_filter: Optional[str]
    include_inactive: bool
    total_cscas: int
    total_dscs: int
    entries: List[TrustSnapshotEntry]


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
    issuer_csca_id: Optional[str]
    revocation_reason: Optional[str]
    revocation_date: Optional[datetime]
    created_at: datetime
    updated_at: datetime


class MasterListInfo(BaseModel):
    """Master list information."""
    id: str
    country_code: str
    version: int
    source_type: str
    source_url: Optional[str]
    content_hash: str
    valid_from: datetime
    valid_to: datetime
    issued_by: Optional[str]
    created_at: datetime
    updated_at: datetime


class CRLInfo(BaseModel):
    """Certificate Revocation List information."""
    id: str
    country_code: str
    content_hash: str
    issuer_dn: str
    this_update: datetime
    next_update: Optional[datetime]
    signature_algorithm: Optional[str]
    source_url: Optional[str]
    created_at: datetime
    updated_at: datetime


class SourceInfo(BaseModel):
    """PKD/HML source information."""
    id: str
    name: str
    source_type: str
    country_code: Optional[str]
    url: str
    sync_interval: int
    last_sync: Optional[datetime]
    last_success: Optional[datetime]
    last_error: Optional[str]
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
    signature: Optional[str]
    created_at: datetime


class HealthCheckResponse(BaseModel):
    """Health check response."""
    status: str
    service: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    components: Optional[dict] = None


class ValidationRequest(BaseModel):
    """Certificate validation request."""
    certificate_data: str = Field(..., description="Base64 encoded certificate")
    validation_time: Optional[datetime] = None
    check_revocation: bool = True


class ValidationResponse(BaseModel):
    """Certificate validation response."""
    is_valid: bool
    validation_time: datetime
    trust_chain: List[str]
    revocation_status: str
    validation_errors: List[str]
    validation_warnings: List[str]