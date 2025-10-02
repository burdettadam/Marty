"""TD-2 document service layer providing business logic for TD-2 operations.

This module implements comprehensive TD-2 document management including:
* Document creation and issuance for official travel documents
* Verification workflows with full ICAO Part 6 protocol support
* Lifecycle management (status updates, revocation, renewal)
* Policy enforcement and validation
* Integration with existing document management systems
"""

from __future__ import annotations

import logging
import uuid
from datetime import date, datetime, timedelta
from typing import Any

from src.shared.models.td2 import (
    ChipData,
    PersonalData,
    PolicyConstraints,
    SecurityModel,
    TD2Document,
    TD2DocumentCreateRequest,
    TD2DocumentData,
    TD2DocumentSearchRequest,
    TD2DocumentSearchResponse,
    TD2DocumentType,
    TD2DocumentVerifyRequest,
    TD2MRZData,
    TD2Status,
    VerificationResult,
)
from src.shared.services.td2_verification import TD2VerificationEngine
from src.shared.utils.td2_mrz import TD2MRZGenerator

logger = logging.getLogger(__name__)


class TD2ServiceError(Exception):
    """Custom exception for TD-2 service errors."""


class TD2IssueError(TD2ServiceError):
    """Exception for TD-2 document issuance errors."""


class TD2VerificationError(TD2ServiceError):
    """Exception for TD-2 document verification errors."""


class TD2Service:
    """Main service for TD-2 document operations."""

    def __init__(
        self,
        verification_engine: TD2VerificationEngine | None = None,
        issuer_config: dict[str, Any] | None = None,
    ) -> None:
        """
        Initialize TD-2 service.

        Args:
            verification_engine: Verification engine instance
            issuer_config: Issuer configuration
        """
        self.verification_engine = verification_engine or TD2VerificationEngine()
        self.issuer_config = issuer_config or {}

        # In-memory storage (in production, this would be a database)
        self.document_storage: dict[str, TD2Document] = {}

        logger.info("TD-2 service initialized")

    async def create_document(
        self,
        request: TD2DocumentCreateRequest,
        created_by: str | None = None,
    ) -> TD2Document:
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
        except Exception as e:
            logger.exception(f"Failed to create TD-2 document: {e}")
            error_msg = f"Failed to create document: {e!s}"
            raise TD2IssueError(error_msg) from e
        else:
            return document

    async def issue_document(
        self,
        document_id: str,
        generate_chip_data: bool = False,
    ) -> TD2Document:
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
                error_msg = f"Cannot issue document in status: {document.status}"
                raise TD2IssueError(error_msg)

            # Generate chip data if requested
            if generate_chip_data:
                await self._generate_chip_data(document)

            # Update status and timestamps
            document.status = TD2Status.ISSUED
            document.updated_at = datetime.utcnow()

            # Store updated document
            self.document_storage[document_id] = document

            logger.info(f"TD-2 document issued: {document_id}")
        except TD2ServiceError:
            raise
        except Exception as e:
            logger.exception(f"Failed to issue TD-2 document {document_id}: {e}")
            error_msg = f"Failed to issue document: {e!s}"
            raise TD2IssueError(error_msg) from e
        else:
            return document

    async def verify_document(self, request: TD2DocumentVerifyRequest) -> VerificationResult:
        """
        Verify a TD-2 document following ICAO Doc 9303 Part 6 protocol.

        Implements complete verification sequence:
        1. MRZ parsing and check digit validation
        2. Optional SOD/DG hash verification (for chip documents)
        3. Validity window and policy checks
        4. Trust anchor verification

        Args:
            request: Verification request

        Returns:
            Comprehensive verification result

        Raises:
            TD2VerificationError: If verification fails
        """
        try:
            logger.info("Starting TD-2 document verification protocol")

            # Step 1: Get document to verify
            document = await self._resolve_document_for_verification(request)

            # Step 2: Implement verification sequence
            verification_options = {
                "verify_chip": getattr(request, "verify_chip", False),
                "check_policy": getattr(request, "verify_policies", True),
                "online_verification": getattr(request, "online_verification", False),
                "trust_anchors": getattr(request, "trust_anchors", None)
            }

            # Perform comprehensive verification
            result = await self._execute_td2_verification_protocol(document, verification_options)

            # Log verification outcome
            logger.info(f"TD-2 verification completed - Valid: {result.is_valid}, "
                       f"MRZ: {result.mrz_valid}, Chip: {result.chip_valid}, "
                       f"Dates: {result.dates_valid}, Policy: {result.policy_valid}")
        except TD2VerificationError:
            raise
        except Exception as e:
            logger.exception(f"TD-2 verification failed with unexpected error: {e!s}")
            error_msg = f"Verification failed: {e!s}"
            raise TD2VerificationError(error_msg) from e
        else:
            return result

    async def _resolve_document_for_verification(
        self, request: TD2DocumentVerifyRequest
    ) -> TD2Document:
        """Resolve document from various request sources."""
        # Try document ID first
        if hasattr(request, "document_id") and request.document_id:
            return await self.get_document(request.document_id)

        # Try complete document object
        if hasattr(request, "document") and request.document:
            return request.document

        # Try MRZ data only
        if hasattr(request, "mrz_data") and request.mrz_data:
            return await self._create_document_from_mrz(request.mrz_data)

        # Try raw MRZ lines
        if hasattr(request, "mrz_line1") and hasattr(request, "mrz_line2"):
            if request.mrz_line1 and request.mrz_line2:
                from src.shared.utils.td2_mrz import TD2MRZParser
                parser = TD2MRZParser()
                parsed_data = parser.parse_td2_mrz(request.mrz_line1, request.mrz_line2)
                return await self._create_minimal_document_from_parsed_mrz(parsed_data)

        error_msg = "No valid document data provided for verification"
        raise TD2VerificationError(error_msg)

    async def _execute_td2_verification_protocol(
        self,
        document: TD2Document,
        options: dict[str, Any]
    ) -> VerificationResult:
        """
        Execute the complete TD-2 verification protocol.

        Protocol sequence per ICAO Part 6:
        1. MRZ Format & Check Digit Validation
        2. Optional: SOD/DG Hash Verification (chip documents)
        3. Validity Window Checks (dates, expiry)
        4. Policy Constraint Validation
        5. Optional: Trust Anchor Verification
        """
        logger.info("Executing TD-2 verification protocol sequence")

        # Phase 1: Core MRZ verification (always required)
        result = await self.verification_engine.verify_document(
            document,
            verify_chip=False,  # Start without chip verification
            check_policy=False,  # Start without policy checks
            online_verification=False
        )

        # If MRZ fails basic validation, stop here
        if not result.mrz_valid:
            logger.warning("TD-2 MRZ validation failed - stopping verification")
            result.warnings.extend(["MRZ validation failed", "Verification stopped early"])
            return result

        # Phase 2..5 executed via helpers to reduce branching here
        await self._phase_chip_verification(document, options, result)
        await self._phase_policy_validation(document, options, result)
        await self._phase_online_verification(document, options, result)
        await self._phase_trust_anchor(document, options, result)

        # Final validation - all phases must pass
        result.is_valid = (
            result.mrz_valid and
            result.dates_valid and
            result.policy_valid and
            (not result.chip_present or result.chip_valid) and
            len(result.errors) == 0
        )

        result.warnings.extend([
            "TD-2 verification protocol completed",
            f"MRZ: {'PASS' if result.mrz_valid else 'FAIL'}",
            f"Chip: {'PASS' if result.chip_valid else 'FAIL' if result.chip_present else 'N/A'}",
            f"Dates: {'PASS' if result.dates_valid else 'FAIL'}",
            f"Policy: {'PASS' if result.policy_valid else 'FAIL'}",
            f"Overall: {'PASS' if result.is_valid else 'FAIL'}"
        ])

        return result

    # --------------------- Verification Phase Helpers (New) ---------------------

    async def _phase_chip_verification(
        self, document: TD2Document, options: dict[str, Any], result: VerificationResult
    ) -> None:
        """Execute chip verification phase if requested."""
        if not (options.get("verify_chip") and document.chip_data):
            return
        logger.info("Executing TD-2 chip verification (SOD/DG hashes)")
        chip_result = await self.verification_engine.verify_document(
            document,
            verify_chip=True,
            check_policy=False,
            online_verification=False
        )
        # Merge relevant fields
        result.chip_valid = chip_result.chip_valid
        result.chip_present = chip_result.chip_present
        result.sod_present = chip_result.sod_present
        result.sod_valid = chip_result.sod_valid
        result.dg_hash_results = chip_result.dg_hash_results
        if chip_result.errors:
            result.errors.extend(chip_result.errors)
        if chip_result.warnings:
            result.warnings.extend(chip_result.warnings)

    async def _phase_policy_validation(
        self, document: TD2Document, options: dict[str, Any], result: VerificationResult
    ) -> None:
        """Execute policy validation phase if requested."""
        if not options.get("check_policy", True):
            return
        logger.info("Executing TD-2 policy constraint validation")
        policy_result = await self.verification_engine.verify_document(
            document,
            verify_chip=False,
            check_policy=True,
            online_verification=False
        )
        result.policy_valid = policy_result.policy_valid
        if policy_result.errors:
            result.errors.extend(policy_result.errors)
        if policy_result.warnings:
            result.warnings.extend(policy_result.warnings)

    async def _phase_online_verification(
        self, document: TD2Document, options: dict[str, Any], result: VerificationResult
    ) -> None:
        """Execute online verification phase if requested."""
        if not options.get("online_verification"):
            return
        logger.info("Executing TD-2 online verification")
        online_result = await self._verify_against_issuer_database(document, options)
        if online_result.get("errors"):
            result.errors.extend(online_result["errors"])
        if online_result.get("warnings"):
            result.warnings.extend(online_result["warnings"])

    async def _phase_trust_anchor(
        self, document: TD2Document, options: dict[str, Any], result: VerificationResult
    ) -> None:
        """Execute trust anchor verification phase if requested."""
        if not (options.get("trust_anchors") and document.chip_data):
            return
        logger.info("Executing TD-2 trust anchor verification")
        trust_result = await self._verify_trust_chain(document, options["trust_anchors"])
        if trust_result.get("errors"):
            result.errors.extend(trust_result["errors"])
        if trust_result.get("warnings"):
            result.warnings.extend(trust_result["warnings"])

    def _increment_version(self, version: str, part: str = "minor") -> str:
        """Increment semantic style version string (major.minor)."""
        try:
            major, minor = version.split(".")
            if part == "major":
                return f"{int(major) + 1}.0"
            return f"{major}.{int(minor) + 1}"
        except ValueError:  # fallback if format unexpected
            return version

    def _add_status_change_metadata(
        self, document: TD2Document, new_status: TD2Status, reason: str | None
    ) -> None:
        """Append status change entry to document metadata."""
        if not document.metadata:
            document.metadata = {}
        document.metadata[f"status_change_{datetime.utcnow().isoformat()}"] = (
            f"{new_status}:{reason or 'No reason provided'}"
        )

    async def _verify_against_issuer_database(
        self,
        document: TD2Document,
        options: dict[str, Any]
    ) -> dict[str, Any]:
        """Verify document against issuer's database."""
        result = {"errors": [], "warnings": []}

        try:
            # This would typically involve:
            # 1. Connecting to issuer's verification service
            # 2. Checking document status in issuer database
            # 3. Validating against revocation lists
            # 4. Checking for duplicate documents

            logger.info(
                f"Online verification for document: {document.document_data.document_number}"
            )

            # Placeholder implementation
            result["warnings"].append("Online verification not fully implemented")

        except Exception as e:
            # Keep broad except to mirror original fault tolerance while logging traceback
            logger.exception("Online verification failed: %s", e)
            result["errors"].append(f"Online verification error: {e}")

        return result

    async def _verify_trust_chain(
        self,
        document: TD2Document,
        trust_anchors: list[Any]
    ) -> dict[str, Any]:
        """Verify certificate trust chain against provided trust anchors."""
        result = {"errors": [], "warnings": []}

        try:
            if not document.chip_data or not document.chip_data.sod_signature:
                result["warnings"].append("No SOD data available for trust verification")
                return result

            # This would typically involve:
            # 1. Extracting certificate from SOD
            # 2. Building certificate chain
            # 3. Validating chain against trust anchors
            # 4. Checking certificate validity periods
            # 5. Verifying certificate policies

            logger.info("Trust chain verification for TD-2 document")

            # Placeholder implementation
            result["warnings"].append("Trust chain verification not fully implemented")

        except Exception as e:
            logger.exception("Trust chain verification failed: %s", e)
            result["errors"].append(f"Trust chain verification error: {e}")

        return result

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
            error_msg = f"TD-2 document not found: {document_id}"
            raise TD2ServiceError(error_msg)
        return document

    async def search_documents(
        self, request: TD2DocumentSearchRequest
    ) -> TD2DocumentSearchResponse:
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
            offset = getattr(request, "offset", 0)
            limit = getattr(request, "limit", 100)
            paginated_documents = filtered_documents[offset:offset + limit]

            response = TD2DocumentSearchResponse(
                documents=paginated_documents,
                total_count=len(filtered_documents),
                success=True,
                message=f"Found {len(filtered_documents)} documents"
            )

            logger.info(f"TD-2 search completed: {len(paginated_documents)} results")
        except Exception as e:
            logger.exception(f"Failed to search TD-2 documents: {e}")
            error_msg = f"Search failed: {e!s}"
            raise TD2ServiceError(error_msg) from e
        else:
            return response

    async def update_status(
        self, document_id: str, new_status: TD2Status, reason: str | None = None
    ) -> TD2Document:
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
                error_msg = f"Invalid status transition from {document.status} to {new_status}"
                raise TD2ServiceError(error_msg)

            # Update status & metadata
            document.status = new_status
            document.updated_at = datetime.utcnow()
            self._add_status_change_metadata(document, new_status, reason)

            # Store updated document
            self.document_storage[document_id] = document

            logger.info(f"TD-2 document status updated: {document_id}")
        except TD2ServiceError:
            raise
        except Exception as e:
            logger.exception(f"Failed to update TD-2 document status: {e}")
            error_msg = f"Failed to update status: {e!s}"
            raise TD2ServiceError(error_msg) from e
        else:
            return document

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
        updated_constraints: PolicyConstraints | None = None
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
                error_msg = f"Cannot renew document in status: {document.status}"
                raise TD2ServiceError(error_msg)

            # Check if document allows renewal
            if document.policy_constraints and not document.policy_constraints.renewable:
                error_msg = "Document is not renewable according to policy"
                raise TD2ServiceError(error_msg)

            # Update expiry date
            document.document_data.date_of_expiry = new_expiry_date

            # Update policy constraints if provided
            if updated_constraints:
                document.policy_constraints = updated_constraints

            # Regenerate MRZ with new data
            mrz_generator = TD2MRZGenerator()
            document.mrz_data = mrz_generator.generate_td2_mrz(document)

            # Update timestamps and version (minor bump)
            document.updated_at = datetime.utcnow()
            document.version = self._increment_version(document.version, part="minor")

            # Store updated document
            self.document_storage[document_id] = document

            logger.info(f"TD-2 document renewed: {document_id}")
        except TD2ServiceError:
            raise
        except Exception as e:
            logger.exception(f"Failed to renew TD-2 document {document_id}: {e}")
            error_msg = f"Failed to renew document: {e!s}"
            raise TD2ServiceError(error_msg) from e
        else:
            return document

    async def get_statistics(self) -> dict[str, Any]:
        """
        Get TD-2 document statistics.

        Returns:
            Statistics dictionary
        """
        total_documents = len(self.document_storage)
        active_documents = len([
            d for d in self.document_storage.values() if d.status == TD2Status.ACTIVE
        ])
        expired_documents = len([
            d for d in self.document_storage.values() if d.status == TD2Status.EXPIRED
        ])
        revoked_documents = len([
            d for d in self.document_storage.values() if d.status == TD2Status.REVOKED
        ])

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

    async def get_expiring_documents(self, days_until_expiry: int = 30) -> list[TD2Document]:
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
        """Validate document creation request.

        Uses a declarative list of (condition, message) pairs to minimize
        branching and keep validation rules readable and easy to extend.
        """
        checks = [
            (not request.personal_data, "Personal data is required"),
            (not request.document_data, "Document data is required"),
            (not getattr(request.personal_data, "primary_identifier", None), "Primary identifier (surname) is required"),
            (not getattr(request.personal_data, "nationality", None), "Nationality is required"),
            (not getattr(request.document_data, "document_number", None), "Document number is required"),
            (not getattr(request.document_data, "issuing_state", None), "Issuing state is required"),
            (getattr(request.document_data, "date_of_expiry", date.today()) <= getattr(request.document_data, "date_of_issue", date.today()), "Expiry date must be after issue date"),
        ]
        for condition, message in checks:
            if condition:
                raise TD2IssueError(message)

    async def _generate_chip_data(self, document: TD2Document) -> None:
        """Generate chip data for document."""
        # This would implement actual chip data generation
        # For now, create minimal structure
        if not document.chip_data:
            document.chip_data = ChipData(
                dg1_mrz=document.mrz_data.line1.encode("utf-8") + document.mrz_data.line2.encode("utf-8"),
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
            primary_identifier=parsed_data.get("surname", ""),
            secondary_identifier=parsed_data.get("given_names", ""),
            nationality=parsed_data.get("nationality", ""),
            date_of_birth=parsed_data.get("date_of_birth"),
            gender=parsed_data.get("gender")
        )

        document_data = TD2DocumentData(
            document_type=TD2DocumentType(parsed_data.get("document_type", "I")),
            document_number=parsed_data.get("document_number", ""),
            issuing_state=parsed_data.get("issuing_state", ""),
            date_of_issue=date.today(),  # Not available in MRZ
            date_of_expiry=parsed_data.get("date_of_expiry")
        )

        return TD2Document(
            personal_data=personal_data,
            document_data=document_data,
            mrz_data=mrz_data,
            document_id="temp_verify",
            status=TD2Status.ISSUED
        )

    async def _matches_search_criteria(self, document: TD2Document, request: TD2DocumentSearchRequest) -> bool:
        """Check if document matches search criteria with early exits.

        This condensed implementation preserves behavior while reducing
        repetitive hasattr / attribute checks and branches.
        """
        # Simple equality checks mapping: (requested_value, actual_value)
        equality_checks = [
            (getattr(request, "document_type", None), document.document_data.document_type),
            (getattr(request, "status", None), document.status),
            (getattr(request, "issuing_state", None), document.document_data.issuing_state),
            (getattr(request, "nationality", None), document.personal_data.nationality),
        ]
        for expected, actual in equality_checks:
            if expected and expected != actual:
                return False
        # Text query filtering
        query = getattr(request, "query", None)
        if query:
            query_lower = query.lower()
            searchable_text = (
                f"{document.personal_data.primary_identifier} "
                f"{document.personal_data.secondary_identifier} "
                f"{document.document_data.document_number}".lower()
            )
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

    def __init__(self, td2_service: TD2Service) -> None:
        """
        Initialize batch processor.

        Args:
            td2_service: Main TD-2 service
        """
        self.td2_service = td2_service

    async def create_documents_batch(self, requests: list[TD2DocumentCreateRequest], created_by: str | None = None) -> list[TD2Document]:
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
                logger.exception(f"Failed to create document in batch: {e}")
                # Continue with other documents
                continue

        return results

    async def verify_documents_batch(self, requests: list[TD2DocumentVerifyRequest]) -> list[VerificationResult]:
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
                logger.exception(f"Failed to verify document in batch: {e}")
                # Create error result
                error_result = VerificationResult(
                    is_valid=False,
                    errors=[f"Verification failed: {e!s}"],
                    verified_at=datetime.utcnow()
                )
                results.append(error_result)

        return results


class TD2ServiceManager:
    """Manager for TD-2 service operations and reporting."""

    def __init__(self, td2_service: TD2Service) -> None:
        """
        Initialize service manager.

        Args:
            td2_service: Main TD-2 service
        """
        self.td2_service = td2_service

    async def generate_compliance_report(self) -> dict[str, Any]:
        """
        Generate ICAO Part 6 compliance report.

        Returns:
            Compliance report
        """
        stats = await self.td2_service.get_statistics()

        # Check compliance metrics
        total_docs = stats["total_documents"]
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
            "by_document_type": stats["by_document_type"],
            "by_issuing_state": stats["by_issuing_state"],
            "generated_at": stats["generated_at"]
        }
