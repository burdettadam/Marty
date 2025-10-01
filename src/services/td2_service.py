"""
TD-2 document service layer providing business logic for TD-2 operations.

This module implements comprehensive TD-2 document management including:
- Document creation and issuance for official travel documents
- Verification workflows with full ICAO Part 6 protocol support
- Lifecycle management (status updates, revocation, renewal)
- Policy enforcement and validation
- Integration with existing document management systems
"""

import uuid
from datetime import datetime, date, timedelta
from typing import Optional, List, Dict, Any, Union
from enum import Enum
import asyncio
import logging

from src.shared.models.td2 import (
    TD2Document, TD2DocumentCreateRequest, TD2DocumentVerifyRequest, 
    TD2DocumentSearchRequest, TD2DocumentSearchResponse,
    TD2DocumentType, TD2Status, SecurityModel, VerificationResult,
    PersonalData, TD2DocumentData, TD2MRZData, ChipData, PolicyConstraints
)
from src.shared.utils.td2_mrz import TD2MRZGenerator
from src.shared.services.td2_verification import TD2VerificationEngine


logger = logging.getLogger(__name__)


class TD2ServiceError(Exception):
    """Custom exception for TD-2 service errors."""
    pass


class TD2IssueError(TD2ServiceError):
    """Exception for TD-2 document issuance errors."""
    pass


class TD2VerificationError(TD2ServiceError):
    """Exception for TD-2 document verification errors."""
    pass


class TD2Service:
    """Main service for TD-2 document operations."""
    
    def __init__(
        self,
        verification_engine: Optional[TD2VerificationEngine] = None,
        issuer_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize TD-2 service.
        
        Args:
            verification_engine: Verification engine instance
            issuer_config: Issuer configuration
        """
        self.verification_engine = verification_engine or TD2VerificationEngine()
        self.issuer_config = issuer_config or {}
        
        # In-memory storage (in production, this would be a database)
        self.document_storage: Dict[str, TD2Document] = {}
        
        logger.info("TD-2 service initialized")
    
    async def create_document(self, request: TD2DocumentCreateRequest, created_by: Optional[str] = None) -> TD2Document:
        """
        Create a new TD-2 document.
        
        Args:
            request: Document creation request
            created_by: Creator identifier
            
        Returns:
            Created TD-2 document object
            
        Raises:
            TD2IssueError: If document creation fails
        """
        try:
            logger.info(f"Creating TD-2 document: type={request.document_data.document_type}")
            
            # Validate request
            await self._validate_create_request(request)
            
            # Create document object
            document = TD2Document(
                personal_data=request.personal_data,
                document_data=request.document_data,
                security_model=request.security_model or SecurityModel.MRZ_ONLY,
                policy_constraints=request.policy_constraints,
                metadata=request.metadata or {},
                created_by=created_by,
                document_id=str(uuid.uuid4()),
                status=TD2Status.DRAFT,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                version="1.0"
            )
            
            # Generate MRZ
            if not document.mrz_data:
                mrz_generator = TD2MRZGenerator()
                document.mrz_data = mrz_generator.generate_td2_mrz(document)
            
            # Store document
            self.document_storage[document.document_id] = document
            
            logger.info(f"TD-2 document created: {document.document_id}")
            return document
            
        except Exception as e:
            logger.error(f"Failed to create TD-2 document: {e}")
            raise TD2IssueError(f"Failed to create document: {str(e)}") from e
    
    async def issue_document(self, document_id: str, generate_chip_data: bool = False) -> TD2Document:
        """
        Issue (finalize) a TD-2 document.
        
        Args:
            document_id: Document identifier
            generate_chip_data: Whether to generate chip data
            
        Returns:
            Issued document
            
        Raises:
            TD2IssueError: If issuance fails
        """
        try:
            logger.info(f"Issuing TD-2 document: {document_id}")
            
            # Get document
            document = await self.get_document(document_id)
            
            # Validate document can be issued
            if document.status != TD2Status.DRAFT:
                raise TD2IssueError(f"Cannot issue document in status: {document.status}")
            
            # Generate chip data if requested
            if generate_chip_data:
                await self._generate_chip_data(document)
            
            # Update status and timestamps
            document.status = TD2Status.ISSUED
            document.updated_at = datetime.utcnow()
            
            # Store updated document
            self.document_storage[document_id] = document
            
            logger.info(f"TD-2 document issued: {document_id}")
            return document
            
        except TD2ServiceError:
            raise
        except Exception as e:
            logger.error(f"Failed to issue TD-2 document {document_id}: {e}")
            raise TD2IssueError(f"Failed to issue document: {str(e)}") from e
    
    async def verify_document(self, request: TD2DocumentVerifyRequest) -> VerificationResult:
        """
        Verify a TD-2 document.
        
        Args:
            request: Verification request
            
        Returns:
            Verification result
            
        Raises:
            TD2VerificationError: If verification fails
        """
        try:
            logger.info("Verifying TD-2 document")
            
            # Get document to verify
            document = None
            if hasattr(request, 'document_id') and request.document_id:
                document = await self.get_document(request.document_id)
            elif hasattr(request, 'document') and request.document:
                document = request.document
            else:
                # Create temporary document from MRZ data for verification
                if hasattr(request, 'mrz_data') and request.mrz_data:
                    document = await self._create_document_from_mrz(request.mrz_data)
                else:
                    raise TD2VerificationError("No document data provided for verification")
            
            # Perform verification
            result = await self.verification_engine.verify_document(
                document,
                verify_chip=getattr(request, 'verify_chip', False),
                verify_policies=getattr(request, 'verify_policies', True),
                context=getattr(request, 'context', {})
            )
            
            logger.info(f"TD-2 verification completed: valid={result.is_valid}")
            return result
            
        except TD2ServiceError:
            raise
        except Exception as e:
            logger.error(f"Failed to verify TD-2 document: {e}")
            raise TD2VerificationError(f"Verification failed: {str(e)}") from e
    
    async def get_document(self, document_id: str) -> TD2Document:
        """
        Get a TD-2 document by ID.
        
        Args:
            document_id: Document identifier
            
        Returns:
            TD-2 document
            
        Raises:
            TD2ServiceError: If document not found
        """
        document = self.document_storage.get(document_id)
        if not document:
            raise TD2ServiceError(f"TD-2 document not found: {document_id}")
        return document
    
    async def search_documents(self, request: TD2DocumentSearchRequest) -> TD2DocumentSearchResponse:
        """
        Search TD-2 documents.
        
        Args:
            request: Search request
            
        Returns:
            Search response with matching documents
            
        Raises:
            TD2ServiceError: If search fails
        """
        try:
            logger.info(f"Searching TD-2 documents: query={getattr(request, 'query', '')}")
            
            # Filter documents based on criteria
            filtered_documents = []
            for document in self.document_storage.values():
                if await self._matches_search_criteria(document, request):
                    filtered_documents.append(document)
            
            # Apply pagination
            offset = getattr(request, 'offset', 0)
            limit = getattr(request, 'limit', 100)
            paginated_documents = filtered_documents[offset:offset + limit]
            
            response = TD2DocumentSearchResponse(
                documents=paginated_documents,
                total_count=len(filtered_documents),
                success=True,
                message=f"Found {len(filtered_documents)} documents"
            )
            
            logger.info(f"TD-2 search completed: {len(paginated_documents)} results")
            return response
            
        except Exception as e:
            logger.error(f"Failed to search TD-2 documents: {e}")
            raise TD2ServiceError(f"Search failed: {str(e)}") from e
    
    async def update_status(self, document_id: str, new_status: TD2Status, reason: Optional[str] = None) -> TD2Document:
        """
        Update TD-2 document status.
        
        Args:
            document_id: Document identifier
            new_status: New status
            reason: Reason for status change
            
        Returns:
            Updated document
            
        Raises:
            TD2ServiceError: If update fails
        """
        try:
            logger.info(f"Updating TD-2 document status: {document_id} -> {new_status}")
            
            # Get document
            document = await self.get_document(document_id)
            
            # Validate status transition
            if not self._is_valid_status_transition(document.status, new_status):
                raise TD2ServiceError(f"Invalid status transition from {document.status} to {new_status}")
            
            # Update status
            document.status = new_status
            document.updated_at = datetime.utcnow()
            
            # Add metadata about status change
            if not document.metadata:
                document.metadata = {}
            document.metadata[f"status_change_{datetime.utcnow().isoformat()}"] = f"{new_status}:{reason or 'No reason provided'}"
            
            # Store updated document
            self.document_storage[document_id] = document
            
            logger.info(f"TD-2 document status updated: {document_id}")
            return document
            
        except TD2ServiceError:
            raise
        except Exception as e:
            logger.error(f"Failed to update TD-2 document status: {e}")
            raise TD2ServiceError(f"Failed to update status: {str(e)}") from e
    
    async def revoke_document(self, document_id: str, reason: str) -> TD2Document:
        """
        Revoke a TD-2 document.
        
        Args:
            document_id: Document identifier
            reason: Revocation reason
            
        Returns:
            Revoked document
        """
        return await self.update_status(document_id, TD2Status.REVOKED, reason)
    
    async def renew_document(
        self, 
        document_id: str, 
        new_expiry_date: date,
        updated_constraints: Optional[PolicyConstraints] = None
    ) -> TD2Document:
        """
        Renew a TD-2 document.
        
        Args:
            document_id: Document identifier
            new_expiry_date: New expiry date
            updated_constraints: Updated policy constraints
            
        Returns:
            Renewed document
            
        Raises:
            TD2ServiceError: If renewal fails
        """
        try:
            logger.info(f"Renewing TD-2 document: {document_id}")
            
            # Get document
            document = await self.get_document(document_id)
            
            # Validate document can be renewed
            if document.status not in [TD2Status.ISSUED, TD2Status.ACTIVE]:
                raise TD2ServiceError(f"Cannot renew document in status: {document.status}")
            
            # Check if document allows renewal
            if document.policy_constraints and not document.policy_constraints.renewable:
                raise TD2ServiceError("Document is not renewable according to policy")
            
            # Update expiry date
            document.document_data.date_of_expiry = new_expiry_date
            
            # Update policy constraints if provided
            if updated_constraints:
                document.policy_constraints = updated_constraints
            
            # Regenerate MRZ with new data
            mrz_generator = TD2MRZGenerator()
            document.mrz_data = mrz_generator.generate_td2_mrz(document)
            
            # Update timestamps and version
            document.updated_at = datetime.utcnow()
            version_parts = document.version.split('.')
            minor_version = int(version_parts[1]) + 1
            document.version = f"{version_parts[0]}.{minor_version}"
            
            # Store updated document
            self.document_storage[document_id] = document
            
            logger.info(f"TD-2 document renewed: {document_id}")
            return document
            
        except TD2ServiceError:
            raise
        except Exception as e:
            logger.error(f"Failed to renew TD-2 document {document_id}: {e}")
            raise TD2ServiceError(f"Failed to renew document: {str(e)}") from e
    
    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get TD-2 document statistics.
        
        Returns:
            Statistics dictionary
        """
        total_documents = len(self.document_storage)
        active_documents = len([d for d in self.document_storage.values() if d.status == TD2Status.ACTIVE])
        expired_documents = len([d for d in self.document_storage.values() if d.status == TD2Status.EXPIRED])
        revoked_documents = len([d for d in self.document_storage.values() if d.status == TD2Status.REVOKED])
        
        # Count by document type
        by_document_type = {}
        for document in self.document_storage.values():
            doc_type = document.document_data.document_type.value
            by_document_type[doc_type] = by_document_type.get(doc_type, 0) + 1
        
        # Count by issuing state
        by_issuing_state = {}
        for document in self.document_storage.values():
            state = document.document_data.issuing_state
            by_issuing_state[state] = by_issuing_state.get(state, 0) + 1
        
        return {
            "total_documents": total_documents,
            "active_documents": active_documents,
            "expired_documents": expired_documents,
            "revoked_documents": revoked_documents,
            "by_document_type": by_document_type,
            "by_issuing_state": by_issuing_state,
            "generated_at": datetime.utcnow().isoformat()
        }
    
    async def get_expiring_documents(self, days_until_expiry: int = 30) -> List[TD2Document]:
        """
        Get TD-2 documents expiring within specified days.
        
        Args:
            days_until_expiry: Days until expiry threshold
            
        Returns:
            List of expiring documents
        """
        cutoff_date = date.today() + timedelta(days=days_until_expiry)
        
        expiring_documents = []
        for document in self.document_storage.values():
            if (document.status in [TD2Status.ISSUED, TD2Status.ACTIVE] and
                document.document_data.date_of_expiry <= cutoff_date):
                expiring_documents.append(document)
        
        return expiring_documents
    
    # Private helper methods
    
    async def _validate_create_request(self, request: TD2DocumentCreateRequest) -> None:
        """Validate document creation request."""
        if not request.personal_data:
            raise TD2IssueError("Personal data is required")
        
        if not request.document_data:
            raise TD2IssueError("Document data is required")
        
        if not request.personal_data.primary_identifier:
            raise TD2IssueError("Primary identifier (surname) is required")
        
        if not request.personal_data.nationality:
            raise TD2IssueError("Nationality is required")
        
        if not request.document_data.document_number:
            raise TD2IssueError("Document number is required")
        
        if not request.document_data.issuing_state:
            raise TD2IssueError("Issuing state is required")
        
        # Validate dates
        if request.document_data.date_of_expiry <= request.document_data.date_of_issue:
            raise TD2IssueError("Expiry date must be after issue date")
    
    async def _generate_chip_data(self, document: TD2Document) -> None:
        """Generate chip data for document."""
        # This would implement actual chip data generation
        # For now, create minimal structure
        if not document.chip_data:
            document.chip_data = ChipData(
                dg1_mrz=document.mrz_data.line1.encode('utf-8') + document.mrz_data.line2.encode('utf-8'),
                dg2_portrait=b"",  # Would contain actual portrait data
                sod=b"",  # Would contain actual SOD
                hash_algorithm="SHA-256",
                certificate_chain=[]
            )
    
    async def _create_document_from_mrz(self, mrz_data: TD2MRZData) -> TD2Document:
        """Create temporary document from MRZ data for verification."""
        # Parse MRZ to extract basic information
        # This is a simplified implementation
        from src.shared.utils.td2_mrz import TD2MRZParser
        
        parser = TD2MRZParser()
        parsed_data = parser.parse_td2_mrz(mrz_data.line1, mrz_data.line2)
        
        # Create temporary document
        personal_data = PersonalData(
            primary_identifier=parsed_data.get('surname', ''),
            secondary_identifier=parsed_data.get('given_names', ''),
            nationality=parsed_data.get('nationality', ''),
            date_of_birth=parsed_data.get('date_of_birth'),
            gender=parsed_data.get('gender')
        )
        
        document_data = TD2DocumentData(
            document_type=TD2DocumentType(parsed_data.get('document_type', 'I')),
            document_number=parsed_data.get('document_number', ''),
            issuing_state=parsed_data.get('issuing_state', ''),
            date_of_issue=date.today(),  # Not available in MRZ
            date_of_expiry=parsed_data.get('date_of_expiry')
        )
        
        return TD2Document(
            personal_data=personal_data,
            document_data=document_data,
            mrz_data=mrz_data,
            document_id="temp_verify",
            status=TD2Status.ISSUED
        )
    
    async def _matches_search_criteria(self, document: TD2Document, request: TD2DocumentSearchRequest) -> bool:
        """Check if document matches search criteria."""
        # Document type filter
        if hasattr(request, 'document_type') and request.document_type:
            if document.document_data.document_type != request.document_type:
                return False
        
        # Status filter
        if hasattr(request, 'status') and request.status:
            if document.status != request.status:
                return False
        
        # Issuing state filter
        if hasattr(request, 'issuing_state') and request.issuing_state:
            if document.document_data.issuing_state != request.issuing_state:
                return False
        
        # Nationality filter
        if hasattr(request, 'nationality') and request.nationality:
            if document.personal_data.nationality != request.nationality:
                return False
        
        # Text query filter (simple implementation)
        if hasattr(request, 'query') and request.query:
            query_lower = request.query.lower()
            searchable_text = f"{document.personal_data.primary_identifier} {document.personal_data.secondary_identifier} {document.document_data.document_number}".lower()
            if query_lower not in searchable_text:
                return False
        
        return True
    
    def _is_valid_status_transition(self, from_status: TD2Status, to_status: TD2Status) -> bool:
        """Validate status transition."""
        valid_transitions = {
            TD2Status.DRAFT: [TD2Status.ISSUED, TD2Status.REVOKED],
            TD2Status.ISSUED: [TD2Status.ACTIVE, TD2Status.REVOKED, TD2Status.SUSPENDED],
            TD2Status.ACTIVE: [TD2Status.EXPIRED, TD2Status.REVOKED, TD2Status.SUSPENDED],
            TD2Status.SUSPENDED: [TD2Status.ACTIVE, TD2Status.REVOKED],
            TD2Status.EXPIRED: [TD2Status.REVOKED],
            TD2Status.REVOKED: []  # Final state
        }
        
        return to_status in valid_transitions.get(from_status, [])


class TD2BatchProcessor:
    """Batch processing for TD-2 documents."""
    
    def __init__(self, td2_service: TD2Service):
        """
        Initialize batch processor.
        
        Args:
            td2_service: Main TD-2 service
        """
        self.td2_service = td2_service
    
    async def create_documents_batch(self, requests: List[TD2DocumentCreateRequest], created_by: Optional[str] = None) -> List[TD2Document]:
        """
        Create multiple TD-2 documents in batch.
        
        Args:
            requests: List of creation requests
            created_by: Creator identifier
            
        Returns:
            List of created documents
        """
        results = []
        for request in requests:
            try:
                document = await self.td2_service.create_document(request, created_by)
                results.append(document)
            except Exception as e:
                logger.error(f"Failed to create document in batch: {e}")
                # Continue with other documents
                continue
        
        return results
    
    async def verify_documents_batch(self, requests: List[TD2DocumentVerifyRequest]) -> List[VerificationResult]:
        """
        Verify multiple TD-2 documents in batch.
        
        Args:
            requests: List of verification requests
            
        Returns:
            List of verification results
        """
        results = []
        for request in requests:
            try:
                result = await self.td2_service.verify_document(request)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to verify document in batch: {e}")
                # Create error result
                error_result = VerificationResult(
                    is_valid=False,
                    errors=[f"Verification failed: {str(e)}"],
                    verified_at=datetime.utcnow()
                )
                results.append(error_result)
        
        return results


class TD2ServiceManager:
    """Manager for TD-2 service operations and reporting."""
    
    def __init__(self, td2_service: TD2Service):
        """
        Initialize service manager.
        
        Args:
            td2_service: Main TD-2 service
        """
        self.td2_service = td2_service
    
    async def generate_compliance_report(self) -> Dict[str, Any]:
        """
        Generate ICAO Part 6 compliance report.
        
        Returns:
            Compliance report
        """
        stats = await self.td2_service.get_statistics()
        
        # Check compliance metrics
        total_docs = stats['total_documents']
        valid_mrz_count = 0
        policy_compliant_count = 0
        
        for document in self.td2_service.document_storage.values():
            # Check MRZ compliance
            if document.mrz_data and len(document.mrz_data.line1) == 36 and len(document.mrz_data.line2) == 36:
                valid_mrz_count += 1
            
            # Check policy compliance
            if document.policy_constraints:
                policy_compliant_count += 1
        
        compliance_rate = (valid_mrz_count / total_docs * 100) if total_docs > 0 else 0
        
        return {
            "total_documents": total_docs,
            "icao_part6_compliant": valid_mrz_count,
            "compliance_rate": compliance_rate,
            "policy_compliant": policy_compliant_count,
            "by_document_type": stats['by_document_type'],
            "by_issuing_state": stats['by_issuing_state'],
            "generated_at": stats['generated_at']
        }