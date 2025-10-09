"""
Visa service layer providing business logic for visa operations.

This module implements comprehensive visa management including:
- Visa creation and issuance for both MRV and e-visa
- Verification workflows with full protocol support
- Lifecycle management (status updates, revocation, renewal)
- Policy enforcement and validation
- Integration with external systems
"""

from __future__ import annotations

import asyncio
import logging
from datetime import date, datetime, timedelta
from typing import Any

from src.shared.models.visa import (
    SecurityModel,
    VerificationResult,
    Visa,
    VisaCreateRequest,
    VisaSearchRequest,
    VisaSearchResponse,
    VisaStatus,
    VisaType,
    VisaVerifyRequest,
)
from src.shared.services.visa_verification import VisaLookupService, VisaVerificationEngine
from src.shared.utils.vds_nc import VDSNCEncoder
from src.shared.utils.visa_mrz import MRZGenerator

logger = logging.getLogger(__name__)


class VisaServiceError(Exception):
    """Custom exception for visa service errors."""


class VisaIssueError(VisaServiceError):
    """Exception for visa issuance errors."""


class VisaVerificationError(VisaServiceError):
    """Exception for visa verification errors."""


class VisaService:
    """Main service for visa operations."""

    def __init__(
        self,
        verification_engine: VisaVerificationEngine | None = None,
        lookup_service: VisaLookupService | None = None,
        issuer_config: dict[str, Any] | None = None,
    ) -> None:
        """
        Initialize visa service.

        Args:
            verification_engine: Verification engine instance
            lookup_service: Lookup service instance
            issuer_config: Issuer configuration
        """
        self.verification_engine = verification_engine or VisaVerificationEngine()
        self.lookup_service = lookup_service or VisaLookupService()
        self.issuer_config = issuer_config or {}

        # In-memory storage (in production, this would be a database)
        self.visa_storage: dict[str, Visa] = {}

        logger.info("Visa service initialized")

    async def create_visa(self, request: VisaCreateRequest, created_by: str | None = None) -> Visa:
        """
        Create a new visa document.

        Args:
            request: Visa creation request
            created_by: Creator identifier

        Returns:
            Created visa object

        Raises:
            VisaIssueError: If visa creation fails
        """
        try:
            logger.info(
                f"Creating visa: type={request.document_data.visa_type}, category={request.document_data.visa_category}"
            )

            # Validate request
            await self._validate_create_request(request)

            # Create visa object
            visa = Visa(
                personal_data=request.personal_data,
                document_data=request.document_data,
                security_model=request.security_model,
                policy_constraints=request.policy_constraints,
                metadata=request.metadata,
                created_by=created_by,
                status=VisaStatus.DRAFT,
            )

            # Generate security data based on visa type
            if visa.document_data.visa_type in [VisaType.MRV_TYPE_A, VisaType.MRV_TYPE_B]:
                await self._generate_mrz_data(visa)

            if visa.document_data.visa_type in [VisaType.E_VISA, VisaType.DTA]:
                await self._generate_vds_nc_data(visa)

            # Store visa
            self.visa_storage[visa.visa_id] = visa

            logger.info(f"Visa created successfully: {visa.visa_id}")
        except Exception as e:
            logger.exception(f"Visa creation failed: {e!s}")
            msg = f"Failed to create visa: {e!s}"
            raise VisaIssueError(msg) from e
        else:
            return visa

    async def issue_visa(self, visa_id: str, issued_by: str | None = None) -> Visa:
        """
        Issue a visa (mark as issued and generate final security features).

        Args:
            visa_id: Visa identifier
            issued_by: Issuer identifier

        Returns:
            Updated visa object

        Raises:
            VisaIssueError: If visa issuance fails
        """
        try:
            visa = await self.get_visa(visa_id)

            if visa.status != VisaStatus.DRAFT:
                msg = f"Visa {visa_id} is not in draft status (current: {visa.status})"
                raise VisaIssueError(msg)

            # Perform final validation
            await self._validate_for_issuance(visa)

            # Update status and metadata
            visa.status = VisaStatus.ISSUED
            visa.metadata["issued_by"] = issued_by
            visa.metadata["issued_at"] = datetime.utcnow().isoformat()
            visa.update_timestamp()

            # Generate final security features if needed
            if visa.security_model == SecurityModel.VDS_NC and not visa.vds_nc_data:
                await self._generate_vds_nc_data(visa)

            logger.info(f"Visa issued successfully: {visa_id}")
        except Exception as e:
            logger.exception(f"Visa issuance failed: {e!s}")
            msg = f"Failed to issue visa: {e!s}"
            raise VisaIssueError(msg) from e
        else:
            return visa

    async def verify_visa(self, request: VisaVerifyRequest) -> VerificationResult:
        """
        Verify a visa document.

        Args:
            request: Verification request

        Returns:
            Verification result

        Raises:
            VisaVerificationError: If verification fails
        """
        try:
            logger.info("Starting visa verification")

            # Look up reference visa if ID provided
            reference_visa = None
            if request.visa_id:
                reference_visa = await self.get_visa(request.visa_id)

            # Perform verification
            result = await self.verification_engine.verify_visa(request, reference_visa)

            logger.info(f"Visa verification completed: valid={result.is_valid}")
        except Exception as e:
            logger.exception(f"Visa verification failed: {e!s}")
            msg = f"Verification failed: {e!s}"
            raise VisaVerificationError(msg) from e
        else:
            return result

    async def get_visa(self, visa_id: str) -> Visa:
        """
        Get visa by ID.

        Args:
            visa_id: Visa identifier

        Returns:
            Visa object

        Raises:
            VisaServiceError: If visa not found
        """
        visa = self.visa_storage.get(visa_id)
        if not visa:
            msg = f"Visa not found: {visa_id}"
            raise VisaServiceError(msg)

        return visa

    async def search_visas(self, request: VisaSearchRequest) -> VisaSearchResponse:
        """
        Search for visas based on criteria.

        Args:
            request: Search request

        Returns:
            Search response with matching visas
        """
        try:
            logger.info(f"Searching visas with criteria: {request.dict(exclude_unset=True)}")

            # Filter visas based on search criteria
            matching_visas = []

            for visa in self.visa_storage.values():
                if await self._matches_search_criteria(visa, request):
                    matching_visas.append(visa)

            # Apply pagination
            total_count = len(matching_visas)
            start_idx = request.offset
            end_idx = start_idx + request.limit
            paginated_visas = matching_visas[start_idx:end_idx]

            response = VisaSearchResponse(
                visas=paginated_visas,
                total_count=total_count,
                limit=request.limit,
                offset=request.offset,
                has_more=end_idx < total_count,
            )

            logger.info(f"Search completed: {len(paginated_visas)} visas returned")
        except Exception as e:
            logger.exception(f"Visa search failed: {e!s}")
            msg = f"Search failed: {e!s}"
            raise VisaServiceError(msg) from e
        else:
            return response

    async def update_visa_status(
        self,
        visa_id: str,
        new_status: VisaStatus,
        reason: str | None = None,
        updated_by: str | None = None,
    ) -> Visa:
        """
        Update visa status.

        Args:
            visa_id: Visa identifier
            new_status: New status
            reason: Reason for status change
            updated_by: User making the change

        Returns:
            Updated visa object
        """
        try:
            visa = await self.get_visa(visa_id)

            # Validate status transition
            await self._validate_status_transition(visa.status, new_status)

            # Update status and metadata
            old_status = visa.status
            visa.status = new_status
            visa.metadata["status_history"] = visa.metadata.get("status_history", [])
            visa.metadata["status_history"].append(
                {
                    "from_status": old_status.value,
                    "to_status": new_status.value,
                    "timestamp": datetime.utcnow().isoformat(),
                    "reason": reason,
                    "updated_by": updated_by,
                }
            )
            visa.update_timestamp()

            logger.info(f"Visa status updated: {visa_id} from {old_status} to {new_status}")
        except Exception as e:
            logger.exception(f"Status update failed: {e!s}")
            msg = f"Failed to update status: {e!s}"
            raise VisaServiceError(msg) from e
        else:
            return visa

    async def revoke_visa(self, visa_id: str, reason: str, revoked_by: str | None = None) -> Visa:
        """
        Revoke a visa.

        Args:
            visa_id: Visa identifier
            reason: Revocation reason
            revoked_by: User performing revocation

        Returns:
            Updated visa object
        """
        return await self.update_visa_status(visa_id, VisaStatus.REVOKED, reason, revoked_by)

    async def renew_visa(self, visa_id: str, new_expiry: date) -> Visa:
        """
        Renew a visa with new expiry date.

        Args:
            visa_id: Visa identifier
            new_expiry: New expiry date

        Returns:
            Updated visa object
        """
        try:
            visa = await self.get_visa(visa_id)

            if visa.status not in [VisaStatus.ISSUED, VisaStatus.ACTIVE]:
                msg = f"Cannot renew visa in status: {visa.status}"
                raise VisaServiceError(msg)

            # Update expiry date
            visa.document_data.date_of_expiry = new_expiry

            # Regenerate security data if needed
            if visa.mrz_data:
                await self._generate_mrz_data(visa)

            if visa.vds_nc_data:
                await self._generate_vds_nc_data(visa)

            # Update metadata
            visa.metadata["renewed"] = True
            visa.metadata["renewal_date"] = datetime.utcnow().isoformat()
            visa.update_timestamp()

            logger.info(f"Visa renewed: {visa_id} with new expiry {new_expiry}")
        except Exception as e:
            logger.exception(f"Visa renewal failed: {e!s}")
            msg = f"Failed to renew visa: {e!s}"
            raise VisaServiceError(msg) from e
        else:
            return visa

    async def _validate_create_request(self, request: VisaCreateRequest) -> None:
        """Validate visa creation request."""
        # Validate dates
        if request.document_data.date_of_issue >= request.document_data.date_of_expiry:
            msg = "Expiry date must be after issue date"
            raise VisaIssueError(msg)

        # Validate security model compatibility
        if request.document_data.visa_type in [VisaType.E_VISA, VisaType.DTA]:
            if request.security_model not in [SecurityModel.VDS_NC, SecurityModel.HYBRID]:
                msg = "E-visa requires VDS-NC security model"
                raise VisaIssueError(msg)

        # Validate age
        today = date.today()
        age = today.year - request.personal_data.date_of_birth.year
        if age < 0 or age > 150:
            msg = "Invalid date of birth"
            raise VisaIssueError(msg)

        # Additional validation rules would go here

    async def _validate_for_issuance(self, visa: Visa) -> None:
        """Validate visa is ready for issuance."""
        # Check required security data is present
        if visa.document_data.visa_type in [VisaType.MRV_TYPE_A, VisaType.MRV_TYPE_B]:
            if not visa.mrz_data:
                msg = "MRZ data required for MRV visa"
                raise VisaIssueError(msg)

        if visa.document_data.visa_type in [VisaType.E_VISA, VisaType.DTA]:
            if visa.security_model == SecurityModel.VDS_NC and not visa.vds_nc_data:
                msg = "VDS-NC data required for e-visa"
                raise VisaIssueError(msg)

        # Additional issuance validation

    async def _generate_mrz_data(self, visa: Visa) -> None:
        """Generate MRZ data for visa."""
        try:
            mrz_data = MRZGenerator.generate_mrz_for_visa(visa)
            visa.mrz_data = mrz_data
            logger.debug(f"MRZ data generated for visa {visa.visa_id}")

        except Exception as e:
            msg = f"Failed to generate MRZ: {e!s}"
            raise VisaIssueError(msg) from e

    async def _generate_vds_nc_data(self, visa: Visa) -> None:
        """Generate VDS-NC data for visa."""
        try:
            # Get issuer config
            issuer = self.issuer_config.get("issuer_id", "DEFAULT")
            private_key = self.issuer_config.get("private_key")
            certificate = self.issuer_config.get("certificate")

            if not private_key:
                msg = "Private key required for VDS-NC generation"
                raise VisaIssueError(msg)

            # Generate VDS-NC data
            vds_nc_data = VDSNCEncoder.encode_vds_nc(
                visa, issuer, private_key, certificate_pem=certificate
            )

            visa.vds_nc_data = vds_nc_data
            logger.debug(f"VDS-NC data generated for visa {visa.visa_id}")

        except Exception as e:
            msg = f"Failed to generate VDS-NC: {e!s}"
            raise VisaIssueError(msg) from e

    async def _matches_search_criteria(self, visa: Visa, request: VisaSearchRequest) -> bool:
        """Check if visa matches search criteria."""
        # Document number match
        if request.document_number:
            if visa.document_data.document_number != request.document_number:
                return False

        # Surname match (partial)
        if request.surname:
            if request.surname.upper() not in visa.personal_data.surname.upper():
                return False

        # Nationality match
        if request.nationality and visa.personal_data.nationality != request.nationality:
            return False

        # Issuing state match
        if request.issuing_state:
            if visa.document_data.issuing_state != request.issuing_state:
                return False

        # Category match
        if request.visa_category:
            if visa.document_data.visa_category != request.visa_category:
                return False

        # Status match
        if request.status and visa.status != request.status:
            return False

        # Date range match
        if request.date_from and visa.document_data.date_of_issue < request.date_from:
            return False

        return not (request.date_to and visa.document_data.date_of_issue > request.date_to)

    async def _validate_status_transition(
        self, from_status: VisaStatus, to_status: VisaStatus
    ) -> None:
        """Validate status transition is allowed."""
        # Define allowed transitions
        allowed_transitions = {
            VisaStatus.DRAFT: [VisaStatus.ISSUED, VisaStatus.REVOKED],
            VisaStatus.ISSUED: [VisaStatus.ACTIVE, VisaStatus.SUSPENDED, VisaStatus.REVOKED],
            VisaStatus.ACTIVE: [VisaStatus.EXPIRED, VisaStatus.SUSPENDED, VisaStatus.REVOKED],
            VisaStatus.SUSPENDED: [VisaStatus.ACTIVE, VisaStatus.REVOKED],
            VisaStatus.EXPIRED: [VisaStatus.REVOKED],
            VisaStatus.REVOKED: [],  # Terminal state
        }

        if to_status not in allowed_transitions.get(from_status, []):
            msg = f"Invalid status transition from {from_status} to {to_status}"
            raise VisaServiceError(msg)


class VisaBatchService:
    """Service for batch visa operations."""

    def __init__(self, visa_service: VisaService) -> None:
        """
        Initialize batch service.

        Args:
            visa_service: Main visa service
        """
        self.visa_service = visa_service

    async def create_visas_batch(
        self, requests: list[VisaCreateRequest], created_by: str | None = None
    ) -> list[Visa | Exception]:
        """
        Create multiple visas in batch.

        Args:
            requests: List of creation requests
            created_by: Creator identifier

        Returns:
            List of created visas or exceptions
        """
        logger.info(f"Starting batch visa creation: {len(requests)} visas")

        results = []

        # Process in parallel
        tasks = [self.visa_service.create_visa(request, created_by) for request in requests]

        # Gather results with exception handling
        for i, task in enumerate(asyncio.as_completed(tasks)):
            try:
                visa = await task
                results.append(visa)
                logger.debug(f"Batch item {i+1} completed successfully")
            except Exception as e:
                results.append(e)
                logger.exception(f"Batch item {i+1} failed: {e!s}")

        logger.info(
            f"Batch creation completed: {len([r for r in results if isinstance(r, Visa)])} succeeded"
        )
        return results

    async def verify_visas_batch(
        self, requests: list[VisaVerifyRequest]
    ) -> list[VerificationResult | Exception]:
        """
        Verify multiple visas in batch.

        Args:
            requests: List of verification requests

        Returns:
            List of verification results or exceptions
        """
        logger.info(f"Starting batch visa verification: {len(requests)} visas")

        results = []

        # Process in parallel
        tasks = [self.visa_service.verify_visa(request) for request in requests]

        # Gather results with exception handling
        for i, task in enumerate(asyncio.as_completed(tasks)):
            try:
                result = await task
                results.append(result)
                logger.debug(f"Batch verification {i+1} completed")
            except Exception as e:
                results.append(e)
                logger.exception(f"Batch verification {i+1} failed: {e!s}")

        logger.info(
            f"Batch verification completed: {len([r for r in results if isinstance(r, VerificationResult)])} succeeded"
        )
        return results


class VisaReportingService:
    """Service for visa reporting and analytics."""

    def __init__(self, visa_service: VisaService) -> None:
        """
        Initialize reporting service.

        Args:
            visa_service: Main visa service
        """
        self.visa_service = visa_service

    async def get_visa_statistics(self) -> dict[str, Any]:
        """
        Get visa statistics.

        Returns:
            Statistics dictionary
        """
        stats = {
            "total_visas": len(self.visa_service.visa_storage),
            "by_status": {},
            "by_type": {},
            "by_category": {},
            "by_nationality": {},
            "expiring_soon": 0,
        }

        today = date.today()
        expiry_threshold = today + timedelta(days=30)

        for visa in self.visa_service.visa_storage.values():
            # Status breakdown
            status = visa.status.value
            stats["by_status"][status] = stats["by_status"].get(status, 0) + 1

            # Type breakdown
            visa_type = visa.document_data.visa_type.value
            stats["by_type"][visa_type] = stats["by_type"].get(visa_type, 0) + 1

            # Category breakdown
            category = visa.document_data.visa_category.value
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1

            # Nationality breakdown
            nationality = visa.personal_data.nationality
            stats["by_nationality"][nationality] = stats["by_nationality"].get(nationality, 0) + 1

            # Expiring soon
            if visa.document_data.date_of_expiry <= expiry_threshold:
                stats["expiring_soon"] += 1

        return stats

    async def get_expiring_visas(self, days_ahead: int = 30) -> list[Visa]:
        """
        Get visas expiring within specified days.

        Args:
            days_ahead: Number of days to look ahead

        Returns:
            List of expiring visas
        """
        threshold = date.today() + timedelta(days=days_ahead)

        expiring_visas = [
            visa
            for visa in self.visa_service.visa_storage.values()
            if visa.document_data.date_of_expiry <= threshold
            and visa.status in [VisaStatus.ISSUED, VisaStatus.ACTIVE]
        ]

        return sorted(expiring_visas, key=lambda v: v.document_data.date_of_expiry)
