"""
Visa data models for Machine Readable Visa (MRV) and Digital Travel Authorization (e-visa).

This module implements comprehensive visa models supporting:
- MRV Type A (2-line MRZ) and Type B (3-line MRZ) 
- Digital Travel Authorization (e-visa) with VDS-NC encoding
- ICAO Part 7 compliance for visa data fields
- Full verification and validation support

Supports visa categories, document numbers, issuing states, personal data,
validity periods, and place of issue per ICAO standards.
"""

from datetime import datetime, date
from enum import Enum
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field, field_validator, model_validator, validator
import uuid


class VisaType(str, Enum):
    """Visa document types."""
    MRV_TYPE_A = "MRV_A"  # 2-line MRZ
    MRV_TYPE_B = "MRV_B"  # 3-line MRZ
    E_VISA = "E_VISA"     # Digital Travel Authorization
    DTA = "DTA"           # Digital Travel Authorization (alias)


class VisaCategory(str, Enum):
    """Visa categories per ICAO standards."""
    # Visitor visas
    B1 = "B1"  # Business visitor
    B2 = "B2"  # Tourist/pleasure
    B1_B2 = "B1/B2"  # Business/tourist combined
    
    # Transit visas
    C1 = "C1"  # Transit
    C1_D = "C1/D"  # Transit/crew
    
    # Crew visas
    D = "D"    # Crew member
    
    # Work visas
    H1B = "H1B"  # Specialty occupation
    H2A = "H2A"  # Temporary agricultural worker
    H2B = "H2B"  # Temporary non-agricultural worker
    L1 = "L1"    # Intracompany transferee
    
    # Student visas
    F1 = "F1"    # Academic student
    M1 = "M1"    # Vocational student
    J1 = "J1"    # Exchange visitor
    
    # Diplomatic visas
    A1 = "A1"    # Ambassador/diplomat
    A2 = "A2"    # Other diplomatic
    G1 = "G1"    # International organization representative
    
    # Other categories
    OTHER = "OTHER"


class Gender(str, Enum):
    """Gender codes per ICAO standards."""
    MALE = "M"
    FEMALE = "F"
    UNSPECIFIED = "X"


class VisaStatus(str, Enum):
    """Visa lifecycle status."""
    DRAFT = "DRAFT"
    ISSUED = "ISSUED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    SUSPENDED = "SUSPENDED"


class SecurityModel(str, Enum):
    """Security models for visa verification."""
    MRZ_ONLY = "MRZ_ONLY"        # MRZ with check digits only
    VDS_NC = "VDS_NC"            # VDS-NC barcode with signatures
    CHIP_LDS = "CHIP_LDS"        # RFID chip with LDS
    HYBRID = "HYBRID"            # Multiple security features


class PersonalData(BaseModel):
    """Personal information for visa holder."""
    surname: str = Field(..., min_length=1, max_length=39, description="Primary surname")
    given_names: str = Field(..., min_length=1, max_length=39, description="Given names")
    nationality: str = Field(..., min_length=3, max_length=3, description="3-letter nationality code")
    date_of_birth: date = Field(..., description="Date of birth")
    gender: Gender = Field(..., description="Gender code")
    place_of_birth: Optional[str] = Field(None, max_length=50, description="Place of birth")
    
    @field_validator('nationality')
    @classmethod
    def validate_nationality(cls, v):
        """Validate nationality is 3-letter uppercase code."""
        if not v.isalpha() or len(v) != 3:
            raise ValueError("Nationality must be 3-letter alphabetic code")
        return v.upper()
    
    @field_validator('surname', 'given_names')
    @classmethod
    def validate_names(cls, v):
        """Validate name fields contain only allowed characters."""
        allowed_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '<>-")
        if not all(c in allowed_chars for c in v.upper()):
            raise ValueError("Names must contain only letters, numbers, spaces, apostrophes, angle brackets, and hyphens")
        return v.upper()


class VisaDocumentData(BaseModel):
    """Core visa document information."""
    document_number: str = Field(..., min_length=1, max_length=9, description="Visa document number")
    document_type: str = Field(default="V", description="Document type code (V for visa)")
    issuing_state: str = Field(..., min_length=3, max_length=3, description="3-letter issuing country code")
    visa_category: VisaCategory = Field(..., description="Visa category/type")
    visa_type: VisaType = Field(..., description="Visa document type")
    
    # Validity and dates
    date_of_issue: date = Field(..., description="Date visa was issued")
    date_of_expiry: date = Field(..., description="Date visa expires")
    valid_from: Optional[date] = Field(None, description="Date visa becomes valid")
    valid_until: Optional[date] = Field(None, description="Date visa validity ends")
    
    # Location information
    place_of_issue: str = Field(..., max_length=50, description="Place where visa was issued")
    issuing_authority: Optional[str] = Field(None, max_length=50, description="Issuing authority")
    
    # Entry information
    number_of_entries: Optional[str] = Field(None, description="Number of allowed entries (S, M, etc.)")
    duration_of_stay: Optional[int] = Field(None, description="Maximum stay duration in days")
    
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
    
    @model_validator(mode='before')
    @classmethod
    def validate_dates(cls, values):
        """Validate date relationships."""
        date_of_issue = values.get('date_of_issue')
        date_of_expiry = values.get('date_of_expiry')
        valid_from = values.get('valid_from')
        valid_until = values.get('valid_until')
        
        if date_of_issue and date_of_expiry:
            if date_of_issue >= date_of_expiry:
                raise ValueError("Date of expiry must be after date of issue")
        
        if valid_from and valid_until:
            if valid_from >= valid_until:
                raise ValueError("Valid until date must be after valid from date")
        
        if valid_from and date_of_issue:
            if valid_from < date_of_issue:
                raise ValueError("Valid from date cannot be before issue date")
        
        if valid_until and date_of_expiry:
            if valid_until > date_of_expiry:
                raise ValueError("Valid until date cannot be after expiry date")
        
        return values


class MRZData(BaseModel):
    """Machine Readable Zone data for visa."""
    type_a_line1: Optional[str] = Field(None, max_length=44, description="Type A MRZ line 1")
    type_a_line2: Optional[str] = Field(None, max_length=44, description="Type A MRZ line 2")
    
    type_b_line1: Optional[str] = Field(None, max_length=36, description="Type B MRZ line 1")
    type_b_line2: Optional[str] = Field(None, max_length=36, description="Type B MRZ line 2")
    type_b_line3: Optional[str] = Field(None, max_length=36, description="Type B MRZ line 3")
    
    check_digit_document: Optional[str] = Field(None, max_length=1, description="Document number check digit")
    check_digit_dob: Optional[str] = Field(None, max_length=1, description="Date of birth check digit")
    check_digit_expiry: Optional[str] = Field(None, max_length=1, description="Expiry date check digit")
    check_digit_composite: Optional[str] = Field(None, max_length=1, description="Composite check digit")
    
    @field_validator("type_a_line1", "type_a_line2", "type_b_line1", "type_b_line2", "type_b_line3")
    @classmethod
    def validate_mrz_lines(cls, v):
        """Validate MRZ lines contain only allowed characters."""
        if v is None:
            return v
        allowed_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<")
        if not all(c in allowed_chars for c in v):
            raise ValueError("MRZ lines must contain only letters, numbers, and angle brackets")
        return v.upper()


class VDSNCData(BaseModel):
    """VDS-NC (Visible Digital Seal - Non-Constrained) data for e-visa."""
    header: Dict[str, Any] = Field(default_factory=dict, description="VDS-NC header")
    message: Dict[str, Any] = Field(default_factory=dict, description="VDS-NC message payload")
    signature: Optional[str] = Field(None, description="Digital signature")
    barcode_data: Optional[str] = Field(None, description="2D barcode encoded data")
    barcode_format: str = Field(default="QR", description="Barcode format (QR, DataMatrix, etc.)")
    
    # Signature verification
    issuer_certificate: Optional[str] = Field(None, description="Issuer certificate")
    signature_algorithm: str = Field(default="ES256", description="Signature algorithm")
    certificate_chain: Optional[List[str]] = Field(None, description="Certificate chain")


class PolicyConstraints(BaseModel):
    """Policy constraints and rules for visa."""
    allowed_countries: Optional[List[str]] = Field(None, description="Allowed destination countries")
    restricted_countries: Optional[List[str]] = Field(None, description="Restricted countries")
    purpose_restrictions: Optional[List[str]] = Field(None, description="Purpose restrictions")
    employment_authorized: bool = Field(default=False, description="Employment authorization")
    study_authorized: bool = Field(default=False, description="Study authorization")
    
    # Online verification
    requires_online_check: bool = Field(default=False, description="Requires online verification")
    verification_url: Optional[str] = Field(None, description="Online verification endpoint")
    verification_api_key: Optional[str] = Field(None, description="API key for verification")


class VerificationResult(BaseModel):
    """Results of visa verification process."""
    is_valid: bool = Field(..., description="Overall validity")
    verification_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Verification time")
    
    # MRZ verification
    mrz_valid: bool = Field(default=False, description="MRZ validation result")
    check_digits_valid: bool = Field(default=False, description="Check digits validation")
    mrz_errors: List[str] = Field(default_factory=list, description="MRZ validation errors")
    
    # VDS-NC verification
    vds_nc_present: bool = Field(default=False, description="VDS-NC barcode present")
    vds_nc_valid: bool = Field(default=False, description="VDS-NC validation result")
    signature_valid: bool = Field(default=False, description="Digital signature validation")
    field_consistency_valid: bool = Field(default=False, description="Field consistency validation")
    vds_nc_errors: List[str] = Field(default_factory=list, description="VDS-NC validation errors")
    
    # Policy verification
    policy_checks_passed: bool = Field(default=False, description="Policy checks result")
    validity_period_ok: bool = Field(default=False, description="Validity period check")
    category_constraints_ok: bool = Field(default=False, description="Category constraints check")
    online_verification_ok: Optional[bool] = Field(None, description="Online verification result")
    policy_errors: List[str] = Field(default_factory=list, description="Policy validation errors")
    
    # Additional details
    warnings: List[str] = Field(default_factory=list, description="Verification warnings")
    verification_details: Dict[str, Any] = Field(default_factory=dict, description="Additional verification details")


class Visa(BaseModel):
    """Complete visa document model."""
    # Identifiers
    visa_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique visa identifier")
    version: str = Field(default="1.0", description="Visa document version")
    
    # Core data
    personal_data: PersonalData = Field(..., description="Personal information")
    document_data: VisaDocumentData = Field(..., description="Document information")
    
    # Security and encoding
    security_model: SecurityModel = Field(..., description="Security model used")
    mrz_data: Optional[MRZData] = Field(None, description="MRZ data")
    vds_nc_data: Optional[VDSNCData] = Field(None, description="VDS-NC data")
    
    # Policy and constraints
    policy_constraints: Optional[PolicyConstraints] = Field(None, description="Policy constraints")
    
    # Status and lifecycle
    status: VisaStatus = Field(default=VisaStatus.DRAFT, description="Visa status")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")
    created_by: Optional[str] = Field(None, description="Creator identifier")
    
    # Verification history
    last_verification: Optional[VerificationResult] = Field(None, description="Last verification result")
    verification_history: List[VerificationResult] = Field(default_factory=list, description="Verification history")
    
    # Additional metadata
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    @model_validator(mode="before")
    @classmethod
    def validate_security_model_data(cls, values):
        """Validate that required data is present for security model."""
        security_model = values.get('security_model')
        mrz_data = values.get('mrz_data')
        vds_nc_data = values.get('vds_nc_data')
        status = values.get('status')
        visa_type = values.get('document_data', {}).get('visa_type') if isinstance(values.get('document_data'), dict) else getattr(values.get('document_data'), 'visa_type', None)
        
        # Only enforce strict validation for issued visas
        if status == VisaStatus.ISSUED:
            if security_model == SecurityModel.MRZ_ONLY and not mrz_data:
                raise ValueError("MRZ data required for MRZ_ONLY security model")
            
            if security_model == SecurityModel.VDS_NC and not vds_nc_data:
                raise ValueError("VDS-NC data required for VDS_NC security model")
            
            if visa_type == VisaType.E_VISA and not vds_nc_data:
                raise ValueError("VDS-NC data required for e-visa")
            
            if visa_type in [VisaType.MRV_TYPE_A, VisaType.MRV_TYPE_B] and not mrz_data:
                raise ValueError("MRZ data required for MRV visas")
        
        return values
    
    def update_timestamp(self):
        """Update the last modified timestamp."""
        self.updated_at = datetime.utcnow()
    
    def add_verification_result(self, result: VerificationResult):
        """Add a verification result to history."""
        self.last_verification = result
        self.verification_history.append(result)
        self.update_timestamp()
    
    def is_currently_valid(self) -> bool:
        """Check if visa is currently valid based on dates."""
        now = date.today()
        doc_data = self.document_data
        
        # Check basic validity period
        if now < doc_data.date_of_issue or now > doc_data.date_of_expiry:
            return False
        
        # Check specific validity window if set
        if doc_data.valid_from and now < doc_data.valid_from:
            return False
        
        if doc_data.valid_until and now > doc_data.valid_until:
            return False
        
        # Check status
        if self.status not in [VisaStatus.ISSUED, VisaStatus.ACTIVE]:
            return False
        
        return True


class VisaCreateRequest(BaseModel):
    """Request model for creating a new visa."""
    personal_data: PersonalData = Field(..., description="Personal information")
    document_data: VisaDocumentData = Field(..., description="Document information")
    security_model: SecurityModel = Field(..., description="Security model to use")
    policy_constraints: Optional[PolicyConstraints] = Field(None, description="Policy constraints")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class VisaVerifyRequest(BaseModel):
    """Request model for verifying a visa."""
    # Input methods
    visa_id: Optional[str] = Field(None, description="Visa ID for lookup")
    mrz_data: Optional[str] = Field(None, description="Raw MRZ data")
    barcode_data: Optional[str] = Field(None, description="Barcode/QR code data")
    
    # Verification options
    verify_signature: bool = Field(default=True, description="Verify digital signatures")
    check_policy: bool = Field(default=True, description="Check policy constraints")
    online_verification: bool = Field(default=False, description="Perform online verification")
    
    @model_validator(mode="before")
    @classmethod
    def validate_input_method(cls, values):
        """Validate that at least one input method is provided."""
        visa_id = values.get('visa_id')
        mrz_data = values.get('mrz_data')
        barcode_data = values.get('barcode_data')
        
        if not any([visa_id, mrz_data, barcode_data]):
            raise ValueError("At least one input method required: visa_id, mrz_data, or barcode_data")
        
        return values


class VisaSearchRequest(BaseModel):
    """Request model for searching visas."""
    document_number: Optional[str] = Field(None, description="Document number")
    surname: Optional[str] = Field(None, description="Surname")
    nationality: Optional[str] = Field(None, description="Nationality")
    issuing_state: Optional[str] = Field(None, description="Issuing state")
    visa_category: Optional[VisaCategory] = Field(None, description="Visa category")
    status: Optional[VisaStatus] = Field(None, description="Visa status")
    date_from: Optional[date] = Field(None, description="Search from date")
    date_to: Optional[date] = Field(None, description="Search to date")
    limit: int = Field(default=50, ge=1, le=1000, description="Maximum results")
    offset: int = Field(default=0, ge=0, description="Results offset")


class VisaSearchResponse(BaseModel):
    """Response model for visa search."""
    visas: List[Visa] = Field(..., description="Found visas")
    total_count: int = Field(..., description="Total matching visas")
    limit: int = Field(..., description="Results limit")
    offset: int = Field(..., description="Results offset")
    has_more: bool = Field(..., description="More results available")