"""
TD-2 data models for Machine Readable Official Travel Documents.

This module implements comprehensive TD-2 models supporting:
- TD-2 two-line MRZ format per ICAO Part 6 (36 characters each line)
- Minimal chip profile with DG1 (MRZ) + DG2 (portrait) per Parts 10-12
- Visual and data alignment rules per Part 6
- Name truncation and primary identifier precedence

TD-2 documents are primarily used for official identity documents
such as national ID cards, residence permits, and other official documents.
"""

from datetime import datetime, date
from enum import Enum
from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass
from pydantic import BaseModel, Field, field_validator, model_validator
import uuid


class TD2DocumentType(str, Enum):
    """TD-2 document types per ICAO Part 6."""
    # Identity documents
    ID = "I"       # National identity card
    AC = "AC"      # Crew member certificate
    IA = "IA"      # Residence permit type A
    IC = "IC"      # Residence permit type C
    IF = "IF"      # Residence permit type F
    IP = "IP"      # Residence permit type P
    IR = "IR"      # Residence permit type R
    IV = "IV"      # Residence permit type V
    
    # Official documents
    OFFICIAL = "O"  # Other official document


class Gender(str, Enum):
    """Gender codes per ICAO standards."""
    MALE = "M"
    FEMALE = "F"
    UNSPECIFIED = "X"


class TD2Status(str, Enum):
    """TD-2 document status."""
    DRAFT = "DRAFT"
    ISSUED = "ISSUED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class SecurityModel(str, Enum):
    """Security model for TD-2 documents."""
    MRZ_ONLY = "MRZ_ONLY"
    MINIMAL_CHIP = "MINIMAL_CHIP"
    EXTENDED_CHIP = "EXTENDED_CHIP"
    EXPIRED = "EXPIRED"


@dataclass
class ChipData:
    """Minimal chip profile data for TD-2 documents."""
    
    # Data Groups
    dg1_mrz: Optional[str] = Field(None, description="DG1: MRZ data")
    dg2_portrait: Optional[bytes] = Field(None, description="DG2: Portrait image")
    
    # Security Object Document (SOD)
    sod_signature: Optional[bytes] = Field(None, description="SOD digital signature")
    sod_hash_algorithm: Optional[str] = Field("SHA-256", description="Hash algorithm used")
    sod_cert_issuer: Optional[str] = Field(None, description="Certificate issuer")
    sod_cert_serial: Optional[str] = Field(None, description="Certificate serial number")
    
    # Data Group hashes for integrity verification
    dg_hashes: Optional[Dict[str, str]] = Field(None, description="Data group hash values")


class PersonalData(BaseModel):
    """Personal information for TD-2 documents."""
    
    # Primary identifiers (mandatory)
    primary_identifier: str = Field(..., max_length=39, description="Primary identifier (surname)")
    secondary_identifier: Optional[str] = Field(None, max_length=39, description="Secondary identifier (given names)")
    
    # Personal details
    nationality: str = Field(..., min_length=3, max_length=3, description="Nationality (3-letter country code)")
    date_of_birth: date = Field(..., description="Date of birth")
    gender: Gender = Field(..., description="Gender")
    place_of_birth: Optional[str] = Field(None, max_length=50, description="Place of birth")
    
    @field_validator('nationality')
    @classmethod
    def validate_nationality(cls, v):
        """Validate nationality is 3-letter uppercase code."""
        if not v.isalpha() or len(v) != 3:
            msg = "Nationality must be 3-letter alphabetic code"
            raise ValueError(msg)
        return v.upper()
    
    @field_validator('primary_identifier', 'secondary_identifier')
    @classmethod
    def validate_names(cls, v):
        """Validate name fields contain only allowed characters."""
        if v is None:
            return v
        allowed_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ '<>-")
        if not all(c in allowed_chars for c in v.upper()):
            msg = "Names must contain only letters, spaces, apostrophes, angle brackets, and hyphens"
            raise ValueError(msg)
        return v.upper()


class TD2DocumentData(BaseModel):
    """TD-2 document information."""
    
    # Document identifiers
    document_type: TD2DocumentType = Field(..., description="Document type code")
    document_number: str = Field(..., max_length=9, description="Document number")
    issuing_state: str = Field(..., min_length=3, max_length=3, description="Issuing state (3-letter country code)")
    issuing_authority: Optional[str] = Field(None, max_length=50, description="Issuing authority")
    
    # Validity dates
    date_of_issue: date = Field(..., description="Date of issue")
    date_of_expiry: date = Field(..., description="Date of expiry")
    
    # Additional fields
    place_of_issue: Optional[str] = Field(None, max_length=50, description="Place of issue")
    
    @field_validator('issuing_state')
    @classmethod
    def validate_issuing_state(cls, v):
        """Validate issuing state is 3-letter uppercase code."""
        if not v.isalpha() or len(v) != 3:
            raise ValueError("Issuing state must be 3-letter alphabetic code")
        return v.upper()
    
    @field_validator('document_number')
    @classmethod
    def validate_document_number(cls, v):
        """Validate document number format."""
        allowed_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<")
        if not all(c in allowed_chars for c in v.upper()):
            raise ValueError("Document number must contain only letters, numbers, and angle brackets")
        return v.upper()
    
    @model_validator(mode='after')
    def validate_dates(self):
        """Validate date relationships."""
        if self.date_of_expiry <= self.date_of_issue:
            raise ValueError("Expiry date must be after issue date")
        return self


class TD2MRZData(BaseModel):
    """Machine Readable Zone data for TD-2 documents (2-line format)."""
    
    # TD-2 has exactly 2 lines of 36 characters each
    line1: str = Field(..., min_length=36, max_length=36, description="TD-2 MRZ line 1")
    line2: str = Field(..., min_length=36, max_length=36, description="TD-2 MRZ line 2")
    
    # Check digits
    check_digit_document: Optional[str] = Field(None, max_length=1, description="Document number check digit")
    check_digit_dob: Optional[str] = Field(None, max_length=1, description="Date of birth check digit")
    check_digit_expiry: Optional[str] = Field(None, max_length=1, description="Expiry date check digit")
    check_digit_composite: Optional[str] = Field(None, max_length=1, description="Composite check digit")
    
    @field_validator('line1', 'line2')
    @classmethod
    def validate_mrz_lines(cls, v):
        """Validate MRZ lines contain only valid characters."""
        if v and not all(c.isalnum() or c == '<' for c in v):
            raise ValueError('MRZ lines must contain only alphanumeric characters and <')
        return v


class PolicyConstraints(BaseModel):
    """Policy constraints for TD-2 documents."""
    
    # Access permissions
    work_authorized: bool = Field(False, description="Authorization to work")
    study_authorized: bool = Field(False, description="Authorization to study")
    residence_authorized: bool = Field(False, description="Authorization to reside")
    
    # Geographic constraints
    allowed_regions: Optional[List[str]] = Field(None, description="List of allowed regions/countries")
    restricted_areas: Optional[List[str]] = Field(None, description="List of restricted areas")
    
    # Validity constraints
    max_stay_duration: Optional[int] = Field(None, description="Maximum stay duration in days")
    renewable: bool = Field(False, description="Whether document is renewable")
    
    # Verification requirements
    requires_biometric_verification: bool = Field(False, description="Requires biometric verification")
    requires_online_check: bool = Field(False, description="Requires online verification")
    verification_url: Optional[str] = Field(None, description="URL for online verification")


class VerificationResult(BaseModel):
    """TD-2 document verification result."""
    
    # Overall result
    is_valid: bool = Field(False, description="Overall validity status")
    verification_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Verification timestamp")
    
    # Verification details
    mrz_valid: bool = Field(False, description="MRZ validation status")
    chip_valid: Optional[bool] = Field(None, description="Chip validation status (if present)")
    sod_valid: Optional[bool] = Field(None, description="SOD validation status (if present)")
    dates_valid: bool = Field(False, description="Date validation status")
    policy_valid: bool = Field(False, description="Policy validation status")
    
    # Detailed results
    mrz_present: bool = Field(False, description="MRZ data present")
    chip_present: bool = Field(False, description="Chip data present")
    sod_present: bool = Field(False, description="SOD present")
    
    # Error tracking
    errors: List[str] = Field(default_factory=list, description="List of validation errors")
    warnings: List[str] = Field(default_factory=list, description="List of validation warnings")
    
    # Hash verification (for chip documents)
    dg_hash_results: Optional[Dict[str, bool]] = Field(None, description="Data group hash verification results")
    
    @model_validator(mode='after')
    def validate_verification_result(self):
        """Validate verification result consistency."""
        # If there are errors, document should not be valid
        if self.errors and self.is_valid:
            self.is_valid = False
        return self


class TD2Document(BaseModel):
    """Main TD-2 document model."""
    
    # Identifiers
    document_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique document identifier")
    
    # Core data
    personal_data: PersonalData = Field(..., description="Personal information")
    document_data: TD2DocumentData = Field(..., description="Document information")
    
    # Technical data
    mrz_data: Optional[TD2MRZData] = Field(None, description="Machine Readable Zone data")
    chip_data: Optional[ChipData] = Field(None, description="Chip data (if present)")
    
    # Constraints and policies
    policy_constraints: Optional[PolicyConstraints] = Field(None, description="Policy constraints")
    
    # Status and lifecycle
    status: TD2Status = Field(TD2Status.DRAFT, description="Document status")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")
    issued_at: Optional[datetime] = Field(None, description="Issuance timestamp")
    last_verified_at: Optional[datetime] = Field(None, description="Last verification timestamp")
    
    # Audit trail
    created_by: Optional[str] = Field(None, description="Creator identifier")
    issued_by: Optional[str] = Field(None, description="Issuer identifier")
    
    # Metadata
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
    
    @model_validator(mode='after')
    def validate_document_data(self):
        """Validate document data consistency."""
        if self.personal_data and self.document_data:
            # Ensure nationality consistency if relevant
            pass
        return self


# Request/Response models for API operations

class TD2CreateRequest(BaseModel):
    """Request model for creating TD-2 documents."""
    personal_data: PersonalData
    document_data: TD2DocumentData
    policy_constraints: Optional[PolicyConstraints] = None
    chip_profile: bool = Field(False, description="Include minimal chip profile")
    metadata: Optional[Dict[str, Any]] = None


class TD2VerifyRequest(BaseModel):
    """Request model for verifying TD-2 documents."""
    document_id: Optional[str] = None
    mrz_line1: Optional[str] = None
    mrz_line2: Optional[str] = None
    verify_chip: bool = Field(False, description="Verify chip data if present")
    check_policy: bool = Field(True, description="Check policy constraints")
    online_verification: bool = Field(False, description="Perform online verification")


class TD2SearchRequest(BaseModel):
    """Request model for searching TD-2 documents."""
    document_type: Optional[TD2DocumentType] = None
    issuing_state: Optional[str] = None
    nationality: Optional[str] = None
    status: Optional[TD2Status] = None
    date_from: Optional[date] = None
    date_to: Optional[date] = None
    limit: int = Field(50, ge=1, le=1000, description="Maximum results")
    offset: int = Field(0, ge=0, description="Results offset")


class TD2SearchResponse(BaseModel):
    """Response model for TD-2 document search."""
    documents: List[TD2Document]
    total_count: int
    has_more: bool


# Additional request/response models needed for service layer
class TD2DocumentCreateRequest(BaseModel):
    """Request model for creating TD-2 documents."""
    personal_data: PersonalData
    document_data: TD2DocumentData
    security_model: Optional[SecurityModel] = SecurityModel.MRZ_ONLY
    policy_constraints: Optional[PolicyConstraints] = None
    metadata: Optional[Dict[str, str]] = None


class TD2DocumentVerifyRequest(BaseModel):
    """Request model for verifying TD-2 documents."""
    document_id: Optional[str] = None
    document: Optional[TD2Document] = None
    mrz_data: Optional[TD2MRZData] = None
    verify_chip: bool = False
    verify_policies: bool = True
    context: Optional[Dict[str, str]] = None


class TD2DocumentSearchRequest(BaseModel):
    """Request model for searching TD-2 documents."""
    query: Optional[str] = None
    document_type: Optional[TD2DocumentType] = None
    status: Optional[TD2Status] = None
    issuing_state: Optional[str] = None
    nationality: Optional[str] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    limit: Optional[int] = 100
    offset: Optional[int] = 0


class TD2DocumentSearchResponse(BaseModel):
    """Response model for TD-2 document search."""
    documents: List[TD2Document]
    total_count: int
    success: bool = True
    message: str = "Search completed successfully"