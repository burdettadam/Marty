"""
Trust Anchor gRPC Service implementation
"""

import concurrent.futures
import logging

import grpc

import src.trust_anchor_pb2_grpc as trust_anchor_grpc
from src.trust_anchor_pb2 import (
    CertificateInfo,
    ExpiringCertificate,
    ExpiryCheckResponse,
    MasterListResponse,
    ServiceStats,
    ServiceStatusResponse,
    SyncResponse,
    TrustResponse,
    UploadMasterListResponse,
    VerificationResponse,
)

from .services.openxpki_service import OpenXPKIService

logger = logging.getLogger(__name__)


class TrustAnchorServicer(trust_anchor_grpc.TrustAnchorServicer):
    """
    Implementation of the Trust Anchor gRPC service
    """

    def __init__(self) -> None:
        """Initialize the servicer with required components"""
        self.openxpki_service = OpenXPKIService()
        logger.info("Trust Anchor Service initialized with OpenXPKI integration")

    def VerifyTrust(self, request, context):
        """
        Check if an entity is trusted
        """
        logger.info(f"Verifying trust for entity: {request.entity}")

        # Basic trust verification (should be expanded based on requirements)
        # For now, assume all properly registered entities are trusted
        return TrustResponse(is_trusted=True)

    def GetMasterList(self, request, context):
        """
        Get the current master list from OpenXPKI
        """
        logger.info(f"Getting master list in format: {request.format}")

        result = self.openxpki_service.get_master_list(request.format)

        # Prepare response
        response = MasterListResponse(
            format=result.get("format", "DER"),
            certificate_count=result.get("certificate_count", 0),
            is_valid=result.get("is_valid", False),
            last_updated=result.get("last_updated", ""),
        )

        # Handle master list data based on format
        master_list_data = result.get("master_list_data", b"")
        if isinstance(master_list_data, str):
            response.master_list_data = master_list_data.encode("utf-8")
        else:
            response.master_list_data = master_list_data

        return response

    def UploadMasterList(self, request, context):
        """
        Upload a master list to OpenXPKI
        """
        logger.info(f"Uploading master list in format: {request.format}")

        result = self.openxpki_service.import_master_list(request.master_list_data, request.format)

        # Prepare response
        response = UploadMasterListResponse(
            success=result.get("success", False),
            certificates_imported=result.get("certificates_imported", 0),
        )

        # Add any errors
        if "error" in result:
            response.errors.append(result["error"])

        # Add certificate info
        for cert_info in result.get("certificates", []):
            cert = CertificateInfo(
                subject=cert_info.get("subject", ""),
                issuer=cert_info.get("issuer", ""),
                serial_number=cert_info.get("serial_number", ""),
                not_before=cert_info.get("not_before", ""),
                not_after=cert_info.get("not_after", ""),
                country_code=cert_info.get("country_code", ""),
                fingerprint=cert_info.get("fingerprint", ""),
            )
            response.certificates.append(cert)

        return response

    def VerifyCertificate(self, request, context):
        """
        Verify a certificate against trusted certificates
        """
        logger.info(f"Verifying certificate in format: {request.format}")

        result = self.openxpki_service.verify_certificate(
            request.certificate, request.format, request.check_revocation
        )

        # Prepare response
        response = VerificationResponse(
            is_valid=result.get("is_valid", False),
            is_trusted=result.get("is_trusted", False),
            is_revoked=result.get("is_revoked", False),
            subject=result.get("subject", ""),
            issuer=result.get("issuer", ""),
        )

        # Add validation errors
        for error in result.get("validation_errors", []):
            response.validation_errors.append(error)

        # Add revocation reason if applicable
        if result.get("is_revoked", False) and "revocation_reason" in result:
            response.revocation_reason = result["revocation_reason"]

        return response

    def SyncCertificateStore(self, request, context):
        """
        Synchronize certificates from OpenXPKI to the local store
        """
        logger.info(f"Syncing certificate store with force={request.force}")

        result = self.openxpki_service.sync_to_local_store(request.force)

        # Prepare response
        response = SyncResponse(
            success=result.get("success", False),
            certificates_synced=result.get("certificates_synced", 0),
            sync_timestamp=result.get("sync_timestamp", ""),
        )

        # Add any errors
        for error in result.get("errors", []):
            response.errors.append(error)

        return response

    def CheckExpiringCertificates(self, request, context):
        """
        Check for certificates expiring within the specified time
        """
        logger.info(f"Checking certificates expiring within {request.days} days")

        result = self.openxpki_service.check_expiring_certificates(request.days)

        # Prepare response
        response = ExpiryCheckResponse()

        # Add expiring certificates
        for cert_info in result.get("expiring_certificates", []):
            cert = ExpiringCertificate(
                subject=cert_info.get("subject", ""),
                issuer=cert_info.get("issuer", ""),
                serial_number=cert_info.get("serial_number", ""),
                not_after=cert_info.get("not_after", ""),
                days_remaining=cert_info.get("days_remaining", 0),
                country_code=cert_info.get("country_code", ""),
            )
            response.expiring_certificates.append(cert)

        return response

    def GetServiceStatus(self, request, context):
        """
        Get the service status and statistics
        """
        logger.info("Getting service status")

        # Get OpenXPKI status
        openxpki_status = self.openxpki_service.get_server_status()

        # Prepare stats
        stats = ServiceStats(
            total_certificates=openxpki_status.get("total_certificates", 0),
            trusted_countries=0,  # This would need to be calculated separately
            last_sync_time="",  # This would come from a separate tracking mechanism
            expiring_soon=0,  # This would need a separate query
        )

        # Check for expiring certificates (30 days)
        expiring_result = self.openxpki_service.check_expiring_certificates(30)
        stats.expiring_soon = len(expiring_result.get("expiring_certificates", []))

        # Prepare response
        response = ServiceStatusResponse(
            is_healthy=openxpki_status.get("healthy", False),
            version="1.0.0",  # Version of the Trust Anchor service
            openxpki_status=f"{openxpki_status.get('status', 'unknown')}"
            f" v{openxpki_status.get('version', 'unknown')}",
        )

        response.stats.CopyFrom(stats)

        return response


def serve(host="0.0.0.0", port=50055) -> None:
    """Start the gRPC server"""
    server = grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=10))
    trust_anchor_grpc.add_TrustAnchorServicer_to_server(TrustAnchorServicer(), server)
    server.add_insecure_port(f"{host}:{port}")
    server.start()
    logger.info(f"Trust Anchor Service running on {host}:{port}")
    server.wait_for_termination()
