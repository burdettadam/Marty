"""
TD-2 REST API implementation.

This module provides HTTP REST endpoints for TD-2 document operations,
offering an alternative to the gRPC interface for web-based integrations.
"""

import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, date
from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

from src.services.td2_service import TD2Service, TD2ServiceError, TD2IssueError, TD2VerificationError
from src.shared.models.td2 import (
    TD2Document, TD2DocumentCreateRequest, TD2DocumentVerifyRequest,
    TD2DocumentSearchRequest, TD2DocumentType, TD2Status, SecurityModel,
    PersonalData, TD2DocumentData, TD2MRZData, ChipData, PolicyConstraints, VerificationResult
)


logger = logging.getLogger(__name__)


# Pydantic models for REST API requests/responses
class PersonalDataRequest(BaseModel):
    """Personal data for REST API."""
    primary_identifier: str = Field(..., description="Surname")
    secondary_identifier: Optional[str] = Field(None, description="Given names")
    nationality: str = Field(..., description="Nationality code (3 chars)")
    date_of_birth: str = Field(..., description="Date of birth (YYYY-MM-DD)")
    gender: str = Field(..., description="Gender (M/F/X)")
    place_of_birth: Optional[str] = Field(None, description="Place of birth")


class TD2DocumentDataRequest(BaseModel):
    """Document data for REST API."""
    document_type: str = Field(..., description="Document type (I, AC, IA, etc.)")
    document_number: str = Field(..., description="Document number")
    issuing_state: str = Field(..., description="Issuing state code (3 chars)")
    date_of_issue: str = Field(..., description="Issue date (YYYY-MM-DD)")
    date_of_expiry: str = Field(..., description="Expiry date (YYYY-MM-DD)")
    place_of_issue: Optional[str] = Field(None, description="Place of issue")
    issuing_authority: Optional[str] = Field(None, description="Issuing authority")


class PolicyConstraintsRequest(BaseModel):
    """Policy constraints for REST API."""
    work_authorization: Optional[List[str]] = Field(None, description="Work permit restrictions")
    study_authorization: Optional[List[str]] = Field(None, description="Study permit restrictions")
    travel_restrictions: Optional[List[str]] = Field(None, description="Travel limitations")
    employment_sectors: Optional[List[str]] = Field(None, description="Allowed employment sectors")
    max_stay_duration: Optional[int] = Field(None, description="Maximum stay in days")
    renewable: Optional[bool] = Field(True, description="Whether document is renewable")


class CreateTD2DocumentRequest(BaseModel):
    """Create TD-2 document request."""
    personal_data: PersonalDataRequest
    document_data: TD2DocumentDataRequest
    security_model: Optional[str] = Field("MRZ_ONLY", description="Security model")
    policy_constraints: Optional[PolicyConstraintsRequest] = None
    metadata: Optional[Dict[str, str]] = None


class TD2MRZDataResponse(BaseModel):
    """MRZ data response."""
    line1: str
    line2: str
    check_digit_document: Optional[str] = None
    check_digit_dob: Optional[str] = None
    check_digit_expiry: Optional[str] = None
    check_digit_composite: Optional[str] = None


class TD2DocumentResponse(BaseModel):
    """TD-2 document response."""
    document_id: str
    personal_data: Dict[str, Any]
    document_data: Dict[str, Any]
    mrz_data: Optional[TD2MRZDataResponse] = None
    status: str
    security_model: str
    metadata: Optional[Dict[str, str]] = None
    created_by: Optional[str] = None
    created_at: str
    updated_at: str
    version: str


class VerifyTD2DocumentRequest(BaseModel):
    """Verify TD-2 document request."""
    document_id: Optional[str] = None
    mrz_line1: Optional[str] = None
    mrz_line2: Optional[str] = None
    verify_chip: bool = False
    verify_policies: bool = True
    context: Optional[Dict[str, str]] = None


class VerificationResultResponse(BaseModel):
    """Verification result response."""
    is_valid: bool
    mrz_valid: bool
    chip_valid: bool
    dates_valid: bool
    policy_valid: bool
    errors: List[str]
    warnings: List[str]
    details: Dict[str, str]
    verified_at: str


class SearchTD2DocumentsRequest(BaseModel):
    """Search TD-2 documents request."""
    query: Optional[str] = None
    document_type: Optional[str] = None
    status: Optional[str] = None
    issuing_state: Optional[str] = None
    nationality: Optional[str] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    limit: Optional[int] = 100
    offset: Optional[int] = 0


class TD2StatisticsResponse(BaseModel):
    """TD-2 statistics response."""
    total_documents: int
    active_documents: int
    expired_documents: int
    revoked_documents: int
    by_document_type: Dict[str, int]
    by_issuing_state: Dict[str, int]
    generated_at: str


class UpdateStatusRequest(BaseModel):
    """Update document status request."""
    new_status: str
    reason: Optional[str] = None
    metadata: Optional[Dict[str, str]] = None


class RenewDocumentRequest(BaseModel):
    """Renew document request."""
    new_expiry_date: str
    updated_constraints: Optional[PolicyConstraintsRequest] = None
    metadata: Optional[Dict[str, str]] = None


# REST API implementation
class TD2RestAPI:
    """REST API for TD-2 documents."""
    
    def __init__(self, td2_service: TD2Service):
        """
        Initialize REST API.
        
        Args:
            td2_service: TD-2 service instance
        """
        self.td2_service = td2_service
        self.app = FastAPI(
            title="TD-2 Document Management API",
            description="REST API for TD-2 machine-readable official travel documents",
            version="1.0.0"
        )
        self._setup_routes()
        logger.info("TD-2 REST API initialized")
    
    def _setup_routes(self):
        """Setup REST API routes."""
        
        @self.app.post("/td2/documents", response_model=TD2DocumentResponse, status_code=status.HTTP_201_CREATED)
        async def create_document(request: CreateTD2DocumentRequest):
            """Create a new TD-2 document."""
            try:
                # Convert REST request to internal model
                internal_request = self._convert_create_request(request)
                
                # Create document
                document = await self.td2_service.create_document(internal_request)
                
                # Convert to REST response
                response = self._convert_document_response(document)
                
                logger.info(f"TD-2 document created via REST: {document.document_id}")
            except TD2IssueError as e:
                logger.error(f"TD-2 creation error: {e}")
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                logger.error(f"Unexpected error in create_document: {e}")
                raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
            else:
                return response
        
        @self.app.post("/td2/documents/{document_id}/issue", response_model=TD2DocumentResponse)
        async def issue_document(document_id: str, generate_chip_data: bool = False):
            """Issue (finalize) a TD-2 document."""
            try:
                document = await self.td2_service.issue_document(document_id, generate_chip_data)
                response = self._convert_document_response(document)
                
                logger.info(f"TD-2 document issued via REST: {document_id}")
            except TD2ServiceError as e:
                logger.error(f"TD-2 issuance error: {e}")
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                logger.error(f"Unexpected error in issue_document: {e}")
                raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
            else:
                return response
        
        @self.app.post("/td2/verify", response_model=VerificationResultResponse)
        async def verify_document(request: VerifyTD2DocumentRequest):
            """Verify a TD-2 document."""
            try:
                # Convert REST request to internal model
                internal_request = self._convert_verify_request(request)
                
                # Verify document
                result = await self.td2_service.verify_document(internal_request)
                
                # Convert to REST response
                response = self._convert_verification_response(result)
                
                logger.info(f"TD-2 verification completed via REST: valid={result.is_valid}")
            except TD2VerificationError as e:
                logger.error(f"TD-2 verification error: {e}")
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                logger.error(f"Unexpected error in verify_document: {e}")
                raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
            else:
                return response
        
        @self.app.get("/td2/documents/{document_id}", response_model=TD2DocumentResponse)
        async def get_document(document_id: str, include_chip_data: bool = False):
            """Get a TD-2 document by ID."""
            try:
                document = await self.td2_service.get_document(document_id)
                response = self._convert_document_response(document, include_chip_data)
                
                logger.info(f"TD-2 document retrieved via REST: {document_id}")
            except TD2ServiceError as e:
                logger.error(f"TD-2 get error: {e}")
                if "not found" in str(e).lower():
                    raise HTTPException(status_code=404, detail=str(e))
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                logger.error(f"Unexpected error in get_document: {e}")
                raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
            else:
                return response
        
        @self.app.post("/td2/documents/search")
        async def search_documents(request: SearchTD2DocumentsRequest):
            """Search TD-2 documents."""
            try:
                # Convert REST request to internal model
                internal_request = self._convert_search_request(request)
                
                # Search documents
                search_response = await self.td2_service.search_documents(internal_request)
                
                # Convert to REST response
                response = {
                    "documents": [self._convert_document_response(doc) for doc in search_response.documents],
                    "total_count": search_response.total_count,
                    "success": search_response.success,
                    "message": search_response.message
                }
                
                logger.info(f"TD-2 search completed via REST: {len(search_response.documents)} results")
                return response
                
            except TD2ServiceError as e:
                logger.error(f"TD-2 search error: {e}")
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                logger.error(f"Unexpected error in search_documents: {e}")
                raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
        
        @self.app.get("/td2/documents")
        async def search_documents_get(
            query: Optional[str] = None,
            document_type: Optional[str] = None,
            status: Optional[str] = None,
            issuing_state: Optional[str] = None,
            nationality: Optional[str] = None,
            limit: int = Query(100, ge=1, le=1000),
            offset: int = Query(0, ge=0)
        ):
            """Search TD-2 documents via GET (query parameters)."""
            request = SearchTD2DocumentsRequest(
                query=query,
                document_type=document_type,
                status=status,
                issuing_state=issuing_state,
                nationality=nationality,
                limit=limit,
                offset=offset
            )
            return await search_documents(request)
        
        @self.app.put("/td2/documents/{document_id}/status", response_model=TD2DocumentResponse)
        async def update_status(document_id: str, request: UpdateStatusRequest):
            """Update TD-2 document status."""
            try:
                # Convert status string to enum
                status_enum = self._convert_status_string(request.new_status)
                
                # Update status
                document = await self.td2_service.update_status(document_id, status_enum, request.reason)
                response = self._convert_document_response(document)
                
                logger.info(f"TD-2 document status updated via REST: {document_id}")
                return response
                
            except TD2ServiceError as e:
                logger.error(f"TD-2 status update error: {e}")
                raise HTTPException(status_code=400, detail=str(e))
            except ValueError as e:
                logger.error(f"Invalid status: {e}")
                raise HTTPException(status_code=400, detail=f"Invalid status: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error in update_status: {e}")
                raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
        
        @self.app.post("/td2/documents/{document_id}/revoke", response_model=TD2DocumentResponse)
        async def revoke_document(document_id: str, reason: str):
            """Revoke a TD-2 document."""
            try:
                document = await self.td2_service.revoke_document(document_id, reason)
                response = self._convert_document_response(document)
                
                logger.info(f"TD-2 document revoked via REST: {document_id}")
                return response
                
            except TD2ServiceError as e:
                logger.error(f"TD-2 revocation error: {e}")
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                logger.error(f"Unexpected error in revoke_document: {e}")
                raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
        
        @self.app.post("/td2/documents/{document_id}/renew", response_model=TD2DocumentResponse)
        async def renew_document(document_id: str, request: RenewDocumentRequest):
            """Renew a TD-2 document."""
            try:
                # Parse new expiry date
                new_expiry_date = datetime.fromisoformat(request.new_expiry_date).date()
                
                # Convert policy constraints if provided
                updated_constraints = None
                if request.updated_constraints:
                    updated_constraints = self._convert_policy_constraints(request.updated_constraints)
                
                # Renew document
                document = await self.td2_service.renew_document(
                    document_id,
                    new_expiry_date,
                    updated_constraints
                )
                response = self._convert_document_response(document)
                
                logger.info(f"TD-2 document renewed via REST: {document_id}")
                return response
                
            except TD2ServiceError as e:
                logger.error(f"TD-2 renewal error: {e}")
                raise HTTPException(status_code=400, detail=str(e))
            except ValueError as e:
                logger.error(f"TD-2 renewal date error: {e}")
                raise HTTPException(status_code=400, detail=f"Invalid date format: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error in renew_document: {e}")
                raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
        
        @self.app.get("/td2/statistics", response_model=TD2StatisticsResponse)
        async def get_statistics():
            """Get TD-2 document statistics."""
            try:
                stats = await self.td2_service.get_statistics()
                response = TD2StatisticsResponse(**stats)
                
                logger.info("TD-2 statistics retrieved via REST")
                return response
                
            except Exception as e:
                logger.error(f"Unexpected error in get_statistics: {e}")
                raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
        
        @self.app.get("/td2/documents/expiring")
        async def get_expiring_documents(
            days_until_expiry: int = Query(30, ge=1, le=365),
            document_type: Optional[str] = None,
            issuing_state: Optional[str] = None,
            limit: int = Query(100, ge=1, le=1000),
            offset: int = Query(0, ge=0)
        ):
            """Get expiring TD-2 documents."""
            try:
                documents = await self.td2_service.get_expiring_documents(days_until_expiry)
                
                # Apply filters
                if document_type:
                    doc_type_enum = self._convert_document_type_string(document_type)
                    documents = [d for d in documents if d.document_data.document_type == doc_type_enum]
                
                if issuing_state:
                    documents = [d for d in documents if d.document_data.issuing_state == issuing_state]
                
                # Apply pagination
                paginated_documents = documents[offset:offset + limit]
                
                response = {
                    "documents": [self._convert_document_response(doc) for doc in paginated_documents],
                    "total_count": len(documents),
                    "success": True,
                    "message": f"Found {len(documents)} expiring documents"
                }
                
                logger.info(f"TD-2 expiring documents retrieved via REST: {len(paginated_documents)} results")
                return response
                
            except ValueError as e:
                logger.error(f"Invalid document type: {e}")
                raise HTTPException(status_code=400, detail=f"Invalid document type: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error in get_expiring_documents: {e}")
                raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
        
        @self.app.get("/td2/health")
        async def health_check():
            """Health check endpoint."""
            return {"status": "healthy", "service": "td2-api", "timestamp": datetime.utcnow().isoformat()}
        
        @self.app.get("/")
        async def root():
            """Root endpoint with API information."""
            return {
                "service": "TD-2 Document Management API",
                "version": "1.0.0",
                "description": "REST API for TD-2 machine-readable official travel documents",
                "endpoints": {
                    "create": "POST /td2/documents",
                    "issue": "POST /td2/documents/{id}/issue",
                    "verify": "POST /td2/verify",
                    "get": "GET /td2/documents/{id}",
                    "search": "GET /td2/documents",
                    "update_status": "PUT /td2/documents/{id}/status",
                    "revoke": "POST /td2/documents/{id}/revoke",
                    "renew": "POST /td2/documents/{id}/renew",
                    "statistics": "GET /td2/statistics",
                    "expiring": "GET /td2/documents/expiring",
                    "health": "GET /td2/health"
                }
            }
    
    # Conversion helper methods
    
    def _convert_create_request(self, request: CreateTD2DocumentRequest) -> TD2DocumentCreateRequest:
        """Convert REST create request to internal model."""
        # Convert personal data
        personal_data = PersonalData(
            primary_identifier=request.personal_data.primary_identifier,
            secondary_identifier=request.personal_data.secondary_identifier,
            nationality=request.personal_data.nationality,
            date_of_birth=datetime.fromisoformat(request.personal_data.date_of_birth).date(),
            gender=request.personal_data.gender,
            place_of_birth=request.personal_data.place_of_birth
        )
        
        # Convert document data
        document_data = TD2DocumentData(
            document_type=self._convert_document_type_string(request.document_data.document_type),
            document_number=request.document_data.document_number,
            issuing_state=request.document_data.issuing_state,
            date_of_issue=datetime.fromisoformat(request.document_data.date_of_issue).date(),
            date_of_expiry=datetime.fromisoformat(request.document_data.date_of_expiry).date(),
            place_of_issue=request.document_data.place_of_issue,
            issuing_authority=request.document_data.issuing_authority
        )
        
        # Convert security model
        security_model = self._convert_security_model_string(request.security_model or "MRZ_ONLY")
        
        # Convert policy constraints
        policy_constraints = None
        if request.policy_constraints:
            policy_constraints = self._convert_policy_constraints(request.policy_constraints)
        
        return TD2DocumentCreateRequest(
            personal_data=personal_data,
            document_data=document_data,
            security_model=security_model,
            policy_constraints=policy_constraints,
            metadata=request.metadata
        )
    
    def _convert_verify_request(self, request: VerifyTD2DocumentRequest) -> TD2DocumentVerifyRequest:
        """Convert REST verify request to internal model."""
        # Create MRZ data if provided
        mrz_data = None
        if request.mrz_line1 and request.mrz_line2:
            mrz_data = TD2MRZData(
                line1=request.mrz_line1,
                line2=request.mrz_line2
            )
        
        return TD2DocumentVerifyRequest(
            document_id=request.document_id,
            mrz_data=mrz_data,
            verify_chip=request.verify_chip,
            verify_policies=request.verify_policies,
            context=request.context or {}
        )
    
    def _convert_search_request(self, request: SearchTD2DocumentsRequest) -> TD2DocumentSearchRequest:
        """Convert REST search request to internal model."""
        # Convert document type string to enum if provided
        document_type = None
        if request.document_type:
            document_type = self._convert_document_type_string(request.document_type)
        
        # Convert status string to enum if provided
        status = None
        if request.status:
            status = self._convert_status_string(request.status)
        
        return TD2DocumentSearchRequest(
            query=request.query,
            document_type=document_type,
            status=status,
            issuing_state=request.issuing_state,
            nationality=request.nationality,
            date_from=request.date_from,
            date_to=request.date_to,
            limit=request.limit or 100,
            offset=request.offset or 0
        )
    
    def _convert_document_response(self, document: TD2Document, include_chip_data: bool = False) -> TD2DocumentResponse:
        """Convert internal document to REST response."""
        # Convert MRZ data
        mrz_data = None
        if document.mrz_data:
            mrz_data = TD2MRZDataResponse(
                line1=document.mrz_data.line1,
                line2=document.mrz_data.line2,
                check_digit_document=document.mrz_data.check_digit_document,
                check_digit_dob=document.mrz_data.check_digit_dob,
                check_digit_expiry=document.mrz_data.check_digit_expiry,
                check_digit_composite=document.mrz_data.check_digit_composite
            )
        
        return TD2DocumentResponse(
            document_id=document.document_id,
            personal_data={
                "primary_identifier": document.personal_data.primary_identifier,
                "secondary_identifier": document.personal_data.secondary_identifier,
                "nationality": document.personal_data.nationality,
                "date_of_birth": document.personal_data.date_of_birth.isoformat() if document.personal_data.date_of_birth else None,
                "gender": document.personal_data.gender,
                "place_of_birth": document.personal_data.place_of_birth
            },
            document_data={
                "document_type": document.document_data.document_type.value,
                "document_number": document.document_data.document_number,
                "issuing_state": document.document_data.issuing_state,
                "date_of_issue": document.document_data.date_of_issue.isoformat() if document.document_data.date_of_issue else None,
                "date_of_expiry": document.document_data.date_of_expiry.isoformat() if document.document_data.date_of_expiry else None,
                "place_of_issue": document.document_data.place_of_issue,
                "issuing_authority": document.document_data.issuing_authority
            },
            mrz_data=mrz_data,
            status=document.status.value,
            security_model=document.security_model.value if document.security_model else "MRZ_ONLY",
            metadata=document.metadata,
            created_by=document.created_by,
            created_at=document.created_at.isoformat() if document.created_at else None,
            updated_at=document.updated_at.isoformat() if document.updated_at else None,
            version=document.version
        )
    
    def _convert_verification_response(self, result: VerificationResult) -> VerificationResultResponse:
        """Convert internal verification result to REST response."""
        return VerificationResultResponse(
            is_valid=result.is_valid,
            mrz_valid=getattr(result, 'mrz_valid', False),
            chip_valid=getattr(result, 'chip_valid', False),
            dates_valid=getattr(result, 'dates_valid', False),
            policy_valid=getattr(result, 'policy_valid', False),
            errors=result.errors,
            warnings=getattr(result, 'warnings', []),
            details=getattr(result, 'details', {}),
            verified_at=result.verified_at.isoformat() if result.verified_at else datetime.utcnow().isoformat()
        )
    
    def _convert_document_type_string(self, type_str: str) -> TD2DocumentType:
        """Convert document type string to enum."""
        type_map = {
            "I": TD2DocumentType.ID,
            "AC": TD2DocumentType.AC,
            "IA": TD2DocumentType.IA,
            "IC": TD2DocumentType.IC,
            "IF": TD2DocumentType.IF,
            "IP": TD2DocumentType.IP,
            "IR": TD2DocumentType.IR,
            "IV": TD2DocumentType.IV
        }
        
        if type_str not in type_map:
            raise ValueError(f"Invalid document type: {type_str}")
        
        return type_map[type_str]
    
    def _convert_status_string(self, status_str: str) -> TD2Status:
        """Convert status string to enum."""
        status_map = {
            "DRAFT": TD2Status.DRAFT,
            "ISSUED": TD2Status.ISSUED,
            "ACTIVE": TD2Status.ACTIVE,
            "EXPIRED": TD2Status.EXPIRED,
            "REVOKED": TD2Status.REVOKED,
            "SUSPENDED": TD2Status.SUSPENDED
        }
        
        if status_str not in status_map:
            raise ValueError(f"Invalid status: {status_str}")
        
        return status_map[status_str]
    
    def _convert_security_model_string(self, model_str: str) -> SecurityModel:
        """Convert security model string to enum."""
        model_map = {
            "MRZ_ONLY": SecurityModel.MRZ_ONLY,
            "MINIMAL_CHIP": SecurityModel.MINIMAL_CHIP,
            "EXTENDED_CHIP": SecurityModel.EXTENDED_CHIP
        }
        
        if model_str not in model_map:
            raise ValueError(f"Invalid security model: {model_str}")
        
        return model_map[model_str]
    
    def _convert_policy_constraints(self, constraints: PolicyConstraintsRequest) -> PolicyConstraints:
        """Convert policy constraints from REST to internal model."""
        return PolicyConstraints(
            work_authorization=constraints.work_authorization or [],
            study_authorization=constraints.study_authorization or [],
            travel_restrictions=constraints.travel_restrictions or [],
            employment_sectors=constraints.employment_sectors or [],
            max_stay_duration=constraints.max_stay_duration,
            renewable=constraints.renewable if constraints.renewable is not None else True
        )


def create_td2_rest_api(td2_service: TD2Service) -> FastAPI:
    """
    Create TD-2 REST API application.
    
    Args:
        td2_service: TD-2 service instance
        
    Returns:
        FastAPI application
    """
    api = TD2RestAPI(td2_service)
    return api.app


def run_td2_rest_api(td2_service: TD2Service, host: str = "0.0.0.0", port: int = 8080):
    """
    Run TD-2 REST API server.
    
    Args:
        td2_service: TD-2 service instance
        host: Server host
        port: Server port
    """
    app = create_td2_rest_api(td2_service)
    
    logger.info(f"Starting TD-2 REST API server on {host}:{port}...")
    uvicorn.run(app, host=host, port=port, log_level="info")