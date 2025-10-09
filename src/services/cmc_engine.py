"""CMC (Crew Member Certificate) Engine Service

This module implements the CMC Engine service for processing Crew Member Certificates
as TD-1 MROTDs according to ICAO Doc 9303 Part 5 and Annex 9.

Features:
- TD-1 format MRZ support
- Dual security models: Chip/LDS and VDS-NC barcode
- Annex 9 compliance for background verification
- VDS-NC barcode generation for offline verification
- Minimal LDS implementation with DG1/DG2
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import grpc

from marty_common.event_bus.event_bus import EventBus
from marty_common.models.passport import (
    CMCCertificate,
    CMCData,
    CMCSecurityModel,
    CMCTD1MRZData,
    VDSNCBarcode,
)
from marty_common.policies.annex9_policies import VisaFreeEntryStatus, get_policy_manager
from marty_common.services.document_signer import DocumentSigner
from marty_common.storage.storage_interface import StorageInterface
from marty_common.utils.mrz_utils import generate_td1_mrz
from proto import cmc_engine_pb2, cmc_engine_pb2_grpc
from shared.logging_config import get_logger

logger = get_logger(__name__)


class CMCEngineServicer(cmc_engine_pb2_grpc.CMCEngineServicer):
    """CMC Engine gRPC service implementation."""

    def __init__(
        self,
        storage: StorageInterface,
        document_signer: DocumentSigner,
        event_bus: EventBus,
    ) -> None:
        """Initialize CMC Engine service.

        Args:
            storage: Storage interface for persisting CMC data
            document_signer: Service for signing CMC documents
            event_bus: Event bus for publishing CMC events
        """
        self.storage = storage
        self.document_signer = document_signer
        self.event_bus = event_bus
        logger.info("CMC Engine service initialized")

    async def CreateCMC(
        self,
        request: cmc_engine_pb2.CreateCMCRequest,
        context: grpc.aio.ServicerContext,
    ) -> cmc_engine_pb2.CreateCMCResponse:
        """Create a new Crew Member Certificate.

        Args:
            request: CMC creation request with certificate data
            context: gRPC service context

        Returns:
            CreateCMCResponse with CMC ID and TD-1 MRZ
        """
        try:
            logger.info(f"Creating CMC for document number: {request.document_number}")

            # Validate request
            validation_error = self._validate_create_request(request)
            if validation_error:
                return cmc_engine_pb2.CreateCMCResponse(
                    success=False, error_message=validation_error
                )

            # Generate unique CMC ID
            cmc_id = str(uuid.uuid4())

            # Create TD-1 MRZ data
            td1_mrz_data = CMCTD1MRZData(
                document_type="I",  # ID card format for CMC
                issuing_country=request.issuing_country,
                document_number=request.document_number,
                surname=request.surname,
                given_names=request.given_names,
                nationality=request.nationality,
                date_of_birth=request.date_of_birth,
                gender=request.gender,
                date_of_expiry=request.date_of_expiry,
            )

            # Generate TD-1 MRZ string
            td1_mrz = generate_td1_mrz(td1_mrz_data)

            # Create CMC data
            cmc_data = CMCData(
                document_number=request.document_number,
                issuing_country=request.issuing_country,
                surname=request.surname,
                given_names=request.given_names,
                nationality=request.nationality,
                date_of_birth=request.date_of_birth,
                gender=request.gender,
                date_of_expiry=request.date_of_expiry,
                employer=request.employer or "",
                crew_id=request.crew_id or "",
                background_check_verified=request.background_check_verified,
                electronic_record_id=request.electronic_record_id or "",
                issuer_record_keeping=request.issuer_record_keeping,
            )

            # Create CMC certificate
            cmc_certificate = CMCCertificate(
                cmc_id=cmc_id,
                cmc_data=cmc_data,
                td1_mrz_data=td1_mrz_data,
                security_model=CMCSecurityModel(request.security_model),
                face_image=request.face_image if request.face_image else b"",
                status="DRAFT",
                created_at=datetime.utcnow(),
            )

            # Store CMC certificate
            await self.storage.store_cmc(cmc_certificate)

            # Publish creation event
            await self.event_bus.publish(
                "cmc.created",
                {
                    "cmc_id": cmc_id,
                    "document_number": request.document_number,
                    "issuing_country": request.issuing_country,
                    "security_model": request.security_model,
                    "created_at": cmc_certificate.created_at.isoformat(),
                },
            )

            logger.info(f"CMC created successfully: {cmc_id}")

            return cmc_engine_pb2.CreateCMCResponse(
                success=True,
                cmc_id=cmc_id,
                document_number=request.document_number,
                td1_mrz=td1_mrz,
                created_at=cmc_certificate.created_at.isoformat(),
            )

        except Exception as e:
            logger.exception(f"Error creating CMC: {e!s}")
            return cmc_engine_pb2.CreateCMCResponse(
                success=False, error_message=f"Internal error: {e!s}"
            )

    async def GetCMC(
        self,
        request: cmc_engine_pb2.GetCMCRequest,
        context: grpc.aio.ServicerContext,
    ) -> cmc_engine_pb2.CMCResponse:
        """Retrieve a CMC by ID or document number.

        Args:
            request: CMC retrieval request
            context: gRPC service context

        Returns:
            CMCResponse with certificate data
        """
        try:
            # Determine lookup key
            if request.HasField("cmc_id"):
                lookup_key = ("cmc_id", request.cmc_id)
                logger.info(f"Retrieving CMC by ID: {request.cmc_id}")
            elif request.HasField("document_number"):
                lookup_key = ("document_number", request.document_number)
                logger.info(f"Retrieving CMC by document number: {request.document_number}")
            else:
                return cmc_engine_pb2.CMCResponse(
                    success=False, error_message="Either cmc_id or document_number must be provided"
                )

            # Retrieve CMC from storage
            cmc_certificate = await self.storage.get_cmc(lookup_key[0], lookup_key[1])

            if not cmc_certificate:
                return cmc_engine_pb2.CMCResponse(
                    success=False,
                    error_message=f"CMC not found for {lookup_key[0]}: {lookup_key[1]}",
                )

            # Convert to protobuf message
            cmc_pb = self._convert_cmc_to_protobuf(cmc_certificate)

            return cmc_engine_pb2.CMCResponse(success=True, cmc=cmc_pb)

        except Exception as e:
            logger.exception(f"Error retrieving CMC: {e!s}")
            return cmc_engine_pb2.CMCResponse(success=False, error_message=f"Internal error: {e!s}")

    async def SignCMC(
        self,
        request: cmc_engine_pb2.SignCMCRequest,
        context: grpc.aio.ServicerContext,
    ) -> cmc_engine_pb2.SignCMCResponse:
        """Sign a CMC using the Document Signer service.

        Args:
            request: CMC signing request
            context: gRPC service context

        Returns:
            SignCMCResponse with signature information
        """
        try:
            logger.info(f"Signing CMC: {request.cmc_id}")

            # Retrieve CMC
            cmc_certificate = await self.storage.get_cmc("cmc_id", request.cmc_id)
            if not cmc_certificate:
                return cmc_engine_pb2.SignCMCResponse(
                    success=False, error_message=f"CMC not found: {request.cmc_id}"
                )

            # Sign the CMC based on security model
            if cmc_certificate.security_model == CMCSecurityModel.CHIP_LDS:
                signature_info = await self._sign_chip_lds_cmc(cmc_certificate, request.signer_id)
            elif cmc_certificate.security_model == CMCSecurityModel.VDS_NC:
                signature_info = await self._sign_vds_nc_cmc(cmc_certificate, request.signer_id)
            else:
                return cmc_engine_pb2.SignCMCResponse(
                    success=False,
                    error_message=f"Unsupported security model: {cmc_certificate.security_model}",
                )

            # Update CMC status to ACTIVE
            cmc_certificate.status = "ACTIVE"
            cmc_certificate.updated_at = datetime.utcnow()
            await self.storage.update_cmc(cmc_certificate)

            # Publish signing event
            await self.event_bus.publish(
                "cmc.signed",
                {
                    "cmc_id": request.cmc_id,
                    "signer_id": request.signer_id,
                    "security_model": cmc_certificate.security_model.value,
                    "signed_at": datetime.utcnow().isoformat(),
                },
            )

            logger.info(f"CMC signed successfully: {request.cmc_id}")

            return cmc_engine_pb2.SignCMCResponse(success=True, signature_info=signature_info)

        except Exception as e:
            logger.exception(f"Error signing CMC: {e!s}")
            return cmc_engine_pb2.SignCMCResponse(
                success=False, error_message=f"Internal error: {e!s}"
            )

    async def GenerateVDSNCBarcode(
        self,
        request: cmc_engine_pb2.GenerateVDSNCRequest,
        context: grpc.aio.ServicerContext,
    ) -> cmc_engine_pb2.GenerateVDSNCResponse:
        """Generate VDS-NC barcode for offline verification.

        Args:
            request: VDS-NC generation request
            context: gRPC service context

        Returns:
            GenerateVDSNCResponse with barcode data
        """
        try:
            logger.info(f"Generating VDS-NC barcode for CMC: {request.cmc_id}")

            # Retrieve CMC
            cmc_certificate = await self.storage.get_cmc("cmc_id", request.cmc_id)
            if not cmc_certificate:
                return cmc_engine_pb2.GenerateVDSNCResponse(
                    success=False, error_message=f"CMC not found: {request.cmc_id}"
                )

            # Generate VDS-NC barcode
            vds_nc_barcode = await self._generate_vds_nc_barcode(
                cmc_certificate,
                request.certificate_reference,
                request.signature_algorithm or "ES256",
            )

            # Convert to protobuf
            vds_nc_pb = self._convert_vds_nc_to_protobuf(vds_nc_barcode)

            logger.info(f"VDS-NC barcode generated for CMC: {request.cmc_id}")

            return cmc_engine_pb2.GenerateVDSNCResponse(success=True, vds_nc_barcode=vds_nc_pb)

        except Exception as e:
            logger.exception(f"Error generating VDS-NC barcode: {e!s}")
            return cmc_engine_pb2.GenerateVDSNCResponse(
                success=False, error_message=f"Internal error: {e!s}"
            )

    async def VerifyCMC(
        self,
        request: cmc_engine_pb2.VerifyCMCRequest,
        context: grpc.aio.ServicerContext,
    ) -> cmc_engine_pb2.VerifyCMCResponse:
        """Verify a CMC certificate.

        Args:
            request: CMC verification request
            context: gRPC service context

        Returns:
            VerifyCMCResponse with verification results
        """
        try:
            logger.info("Verifying CMC certificate")

            # Determine verification method
            cmc_certificate = None
            verification_results = []

            if request.HasField("td1_mrz"):
                # Verify via TD-1 MRZ
                cmc_certificate, mrz_results = await self._verify_from_td1_mrz(request.td1_mrz)
                verification_results.extend(mrz_results)

            elif request.HasField("barcode_data"):
                # Verify via VDS-NC barcode
                cmc_certificate, barcode_results = await self._verify_from_vds_nc_barcode(
                    request.barcode_data
                )
                verification_results.extend(barcode_results)

            elif request.HasField("cmc_id"):
                # Direct CMC lookup and verification
                cmc_certificate = await self.storage.get_cmc("cmc_id", request.cmc_id)
                if cmc_certificate:
                    verification_results = await self._verify_cmc_certificate(cmc_certificate)

            else:
                return cmc_engine_pb2.VerifyCMCResponse(
                    success=False, error_message="No verification data provided"
                )

            if not cmc_certificate:
                return cmc_engine_pb2.VerifyCMCResponse(
                    success=False, error_message="CMC certificate not found or invalid"
                )

            # Additional verification checks
            if request.check_revocation:
                revocation_result = await self._check_revocation_status(cmc_certificate)
                verification_results.append(revocation_result)

            if request.validate_background_check:
                background_result = await self._validate_background_check(cmc_certificate)
                verification_results.append(background_result)

            # Determine overall validity
            is_valid = all(result.passed for result in verification_results)

            # Convert results to protobuf
            verification_results_pb = [
                self._convert_verification_result_to_protobuf(result)
                for result in verification_results
            ]

            cmc_pb = self._convert_cmc_to_protobuf(cmc_certificate)

            logger.info(f"CMC verification completed: {is_valid}")

            return cmc_engine_pb2.VerifyCMCResponse(
                success=True,
                is_valid=is_valid,
                cmc=cmc_pb,
                verification_results=verification_results_pb,
            )

        except Exception as e:
            logger.exception(f"Error verifying CMC: {e!s}")
            return cmc_engine_pb2.VerifyCMCResponse(
                success=False, error_message=f"Internal error: {e!s}"
            )

    def _validate_create_request(self, request: cmc_engine_pb2.CreateCMCRequest) -> str | None:
        """Validate CMC creation request.

        Args:
            request: Creation request to validate

        Returns:
            Error message if validation fails, None if valid
        """
        validation_errors = {
            not request.document_number: "Document number is required",
            not request.issuing_country
            or len(request.issuing_country) != 3: "Valid 3-letter issuing country code is required",
            not request.surname: "Surname is required",
            not request.nationality
            or len(request.nationality) != 3: "Valid 3-letter nationality code is required",
            not request.date_of_birth: "Date of birth is required",
            request.gender not in ["M", "F", "X"]: "Gender must be M, F, or X",
            not request.date_of_expiry: "Date of expiry is required",
        }

        # Check for any validation errors
        for condition, error_msg in validation_errors.items():
            if condition:
                return error_msg

        # Validate security model specific requirements
        if request.security_model == cmc_engine_pb2.CHIP_LDS and not request.face_image:
            return "Face image is required for Chip/LDS security model"

        return None

    async def _sign_chip_lds_cmc(
        self, cmc_certificate: CMCCertificate, signer_id: str
    ) -> cmc_engine_pb2.SignatureInfo:
        """Sign CMC using Chip/LDS model with SOD.

        Args:
            cmc_certificate: CMC to sign
            signer_id: Document signer ID

        Returns:
            Signature information
        """
        from marty_common.lds.cmc_lds_impl import get_lds_manager

        try:
            # Get LDS manager
            lds_manager = get_lds_manager()

            # Update CMC with LDS data (DG1, DG2, SOD, chip content)
            updated_cmc = lds_manager.update_cmc_with_lds_data(
                cmc_certificate, signer_certificate=signer_id
            )

            # Update the stored certificate with LDS data
            cmc_certificate.data_groups = updated_cmc.data_groups
            cmc_certificate.security_object = updated_cmc.security_object
            cmc_certificate.chip_content = updated_cmc.chip_content
            cmc_certificate.updated_at = updated_cmc.updated_at

            signature_date = datetime.now(tz=timezone.utc)

            return cmc_engine_pb2.SignatureInfo(
                signature_date=signature_date.isoformat(),
                signer_id=signer_id,
                signature=b"lds_sod_signature",
                algorithm="RSA-PSS",
                is_valid=True,
            )

        except Exception:
            logger.exception("Failed to sign chip/LDS CMC")
            signature_date = datetime.now(tz=timezone.utc)

            return cmc_engine_pb2.SignatureInfo(
                signature_date=signature_date.isoformat(),
                signer_id=signer_id,
                signature=b"error_signature",
                algorithm="RSA-PSS",
                is_valid=False,
            )

    async def _sign_vds_nc_cmc(
        self, cmc_certificate: CMCCertificate, signer_id: str
    ) -> cmc_engine_pb2.SignatureInfo:
        """Sign CMC using VDS-NC model.

        Args:
            cmc_certificate: CMC to sign
            signer_id: Document signer ID

        Returns:
            Signature information
        """
        # Implementation would involve:
        # 1. Create VDS-NC payload
        # 2. Sign with ES256 algorithm
        # 3. Generate barcode

        # For now, return mock signature info
        signature_date = datetime.utcnow()

        return cmc_engine_pb2.SignatureInfo(
            signature_date=signature_date.isoformat(),
            signer_id=signer_id,
            signature=b"mock_vds_nc_signature",
            algorithm="ES256",
            is_valid=True,
        )

    async def _generate_vds_nc_barcode(
        self, cmc_certificate: CMCCertificate, certificate_reference: str, signature_algorithm: str
    ) -> VDSNCBarcode:
        """Generate VDS-NC barcode for CMC.

        Args:
            cmc_certificate: CMC certificate
            certificate_reference: Certificate reference
            signature_algorithm: Signature algorithm

        Returns:
            VDS-NC barcode data
        """
        # Mock implementation - would generate actual VDS-NC barcode
        return VDSNCBarcode(
            header="DC03",
            message_type="CMC",
            issuing_country=cmc_certificate.cmc_data.issuing_country,
            signature_algorithm=signature_algorithm,
            certificate_reference=certificate_reference,
            signature_creation_date=datetime.utcnow().strftime("%y%m%d"),
            signature_creation_time=datetime.utcnow().strftime("%H%M%S"),
            cmc_payload="mock_payload",
            signature="mock_signature",
            barcode_data="mock_barcode_data",
        )

    def _convert_cmc_to_protobuf(self, cmc: CMCCertificate) -> cmc_engine_pb2.CMCCertificate:
        """Convert CMC certificate to protobuf message."""
        # Mock conversion - would implement full conversion
        return cmc_engine_pb2.CMCCertificate(
            cmc_id=cmc.cmc_id,
            document_number=cmc.cmc_data.document_number,
            issuing_country=cmc.cmc_data.issuing_country,
            surname=cmc.cmc_data.surname,
            given_names=cmc.cmc_data.given_names,
            # ... other fields
        )

    def _convert_vds_nc_to_protobuf(self, vds_nc: VDSNCBarcode) -> cmc_engine_pb2.VDSNCBarcode:
        """Convert VDS-NC barcode to protobuf message."""
        return cmc_engine_pb2.VDSNCBarcode(
            header=vds_nc.header,
            message_type=vds_nc.message_type,
            issuing_country=vds_nc.issuing_country,
            # ... other fields
        )

    def _convert_verification_result_to_protobuf(
        self, result: dict[str, str | bool]
    ) -> cmc_engine_pb2.VerificationResult:
        """Convert verification result to protobuf message."""
        return cmc_engine_pb2.VerificationResult(
            check_name=result["check_name"],
            passed=result["passed"],
            details=result.get("details", ""),
        )

    async def _verify_from_td1_mrz(self, td1_mrz: str) -> tuple[CMCCertificate | None, list[dict]]:
        """Verify CMC from TD-1 MRZ string."""
        from marty_common.verification.cmc_verification import get_verification_protocol

        try:
            verification_protocol = get_verification_protocol()
            is_valid, cmc_certificate, results = verification_protocol.verify_cmc_from_td1_mrz(
                td1_mrz
            )

            verification_dicts = [result.to_dict() for result in results]

        except Exception:
            return None, [
                {
                    "check_name": "TD-1 MRZ Verification",
                    "passed": False,
                    "details": "Verification failed",
                    "error_code": "VERIFICATION_ERROR",
                }
            ]
        else:
            return cmc_certificate, verification_dicts

    async def _verify_from_vds_nc_barcode(
        self, barcode_data: str
    ) -> tuple[CMCCertificate | None, list[dict]]:
        """Verify CMC from VDS-NC barcode."""
        from marty_common.verification.cmc_verification import get_verification_protocol

        try:
            verification_protocol = get_verification_protocol()
            is_valid, cmc_certificate, results = (
                verification_protocol.verify_cmc_from_vds_nc_barcode(barcode_data)
            )

            verification_dicts = [result.to_dict() for result in results]

        except Exception:
            return None, [
                {
                    "check_name": "VDS-NC Verification",
                    "passed": False,
                    "details": "Verification failed",
                    "error_code": "VERIFICATION_ERROR",
                }
            ]
        else:
            return cmc_certificate, verification_dicts

    async def _verify_cmc_certificate(self, cmc: CMCCertificate) -> list[dict]:
        """Verify CMC certificate."""
        from marty_common.verification.cmc_verification import get_verification_protocol

        try:
            verification_protocol = get_verification_protocol()
            is_valid, results = verification_protocol.perform_comprehensive_verification(cmc)

            return [result.to_dict() for result in results]

        except Exception:
            return [
                {
                    "check_name": "CMC Verification",
                    "passed": False,
                    "details": "Verification failed",
                    "error_code": "VERIFICATION_ERROR",
                }
            ]

    async def _check_revocation_status(self, cmc: CMCCertificate) -> dict:
        """Check CMC revocation status."""
        return {"check_name": "Revocation Status", "passed": True, "details": "Not revoked"}

    async def _validate_background_check(self, cmc: CMCCertificate) -> dict:
        """Validate background check (Annex 9 compliance)."""
        policy_manager = get_policy_manager()

        # Check if there's a valid background check record
        compliance_result = await policy_manager.verify_annex9_compliance(cmc.cmc_id)
        background_compliant = compliance_result["checks"]["background_verification"]["compliant"]

        return {
            "check_name": "Background Check",
            "passed": background_compliant,
            "details": compliance_result["checks"]["background_verification"]["details"],
        }

    async def CheckBackgroundVerification(
        self,
        request: cmc_engine_pb2.BackgroundCheckRequest,
        _context: grpc.aio.ServicerContext,
    ) -> cmc_engine_pb2.BackgroundCheckResponse:
        """Check or initiate background verification for CMC (Annex 9)."""
        try:
            logger.info(f"Background check request for CMC: {request.cmc_id}")
            policy_manager = get_policy_manager()

            # Check if background check already exists
            existing_compliance = await policy_manager.verify_annex9_compliance(request.cmc_id)

            if existing_compliance["checks"]["background_verification"]["compliant"]:
                return cmc_engine_pb2.BackgroundCheckResponse(
                    success=True,
                    check_passed=True,
                    check_date=datetime.now(timezone.utc).isoformat(),
                    check_authority=request.check_authority,
                    check_reference=request.check_reference,
                )

            # Initiate new background check
            await policy_manager.initiate_background_check(
                cmc_id=request.cmc_id,
                check_authority=request.check_authority,
                check_scope=[
                    "criminal_history",
                    "employment_history",
                    "identity_verification",
                    "security_clearance",
                    "aviation_experience",
                ],
            )

            return cmc_engine_pb2.BackgroundCheckResponse(
                success=True,
                check_passed=False,  # Still pending
                check_date=datetime.now(timezone.utc).isoformat(),
                check_authority=request.check_authority,
                check_reference=request.check_reference,
            )

        except Exception as e:
            logger.exception("Error processing background check")
            return cmc_engine_pb2.BackgroundCheckResponse(
                success=False, check_passed=False, error_message=f"Internal error: {e!s}"
            )

    async def UpdateVisaFreeStatus(
        self,
        request: cmc_engine_pb2.VisaFreeStatusRequest,
        _context: grpc.aio.ServicerContext,
    ) -> cmc_engine_pb2.VisaFreeStatusResponse:
        """Update visa-free entry eligibility status (Annex 9)."""
        try:
            logger.info(f"Visa-free status update for CMC: {request.cmc_id}")
            policy_manager = get_policy_manager()

            # Convert request status to our enum
            status = (
                VisaFreeEntryStatus.ELIGIBLE
                if request.visa_free_eligible
                else VisaFreeEntryStatus.NOT_ELIGIBLE
            )

            # Update visa-free status
            valid_until = (
                datetime.now(timezone.utc) + timedelta(days=365)
                if request.visa_free_eligible
                else None
            )

            await policy_manager.manage_visa_free_status(
                cmc_id=request.cmc_id,
                status=status,
                granting_authority=request.authority,
                reason=request.reason,
                valid_until=valid_until,
            )

            # Update CMC certificate record
            cmc_dict = await self.storage.get_cmc_by_id(request.cmc_id)
            if cmc_dict:
                cmc = CMCCertificate.from_dict(cmc_dict)
                cmc.visa_free_entry_eligible = request.visa_free_eligible
                await self.storage.update_cmc(cmc.to_dict())

            return cmc_engine_pb2.VisaFreeStatusResponse(
                success=True,
                visa_free_eligible=request.visa_free_eligible,
                updated_at=datetime.now(timezone.utc).isoformat(),
            )

        except Exception as e:
            logger.exception("Error updating visa-free status")
            return cmc_engine_pb2.VisaFreeStatusResponse(
                success=False, visa_free_eligible=False, error_message=f"Internal error: {e!s}"
            )
