#!/usr/bin/env python3
"""
Standalone test script for the CSCA certificate lifecycle management.

This script directly tests the CSCA service implementation without relying on proto imports.
"""

import logging
import os
import sys
import uuid
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parents[1]
sys.path.append(str(project_root))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from src.services.csca import CscaService


class MockContext:
    """Mock gRPC context."""


def test_certificate_lifecycle():
    """Test the complete certificate lifecycle management."""
    # Create test data directory
    test_data_dir = os.path.join(os.path.dirname(__file__), "test_data_csca_standalone")
    os.makedirs(test_data_dir, exist_ok=True)

    # Set environment variables for test
    os.environ["DATA_DIR"] = test_data_dir

    # Initialize the service
    service = CscaService()
    context = MockContext()

    # Generate a unique test ID
    test_id = uuid.uuid4().hex[:8]
    logger.info(f"Starting certificate lifecycle test with ID: {test_id}")

    # Step 1: Create a new certificate
    logger.info("Step 1: Creating a new certificate")

    class MockCreateRequest:
        subject_name = f"CN=Test CSCA {test_id}, O=Standalone Test"
        validity_days = 365
        key_algorithm = "RSA"
        key_size = 2048
        extensions = {}

    create_request = MockCreateRequest()
    create_response = service.CreateCertificate(create_request, context)

    assert create_response.certificate_id, "Certificate ID should not be empty"
    assert create_response.certificate_data, "Certificate data should not be empty"
    assert (
        create_response.status == "ISSUED"
    ), f"Expected status ISSUED, got {create_response.status}"

    certificate_id = create_response.certificate_id
    logger.info(f"Created certificate with ID: {certificate_id}")

    # Step 2: Check certificate status
    logger.info("Step 2: Checking certificate status")

    class MockStatusRequest:
        def __init__(self, certificate_id):
            self.certificate_id = certificate_id

    status_request = MockStatusRequest(certificate_id)
    status_response = service.GetCertificateStatus(status_request, context)

    assert status_response.certificate_id == certificate_id, "Certificate ID mismatch"
    assert status_response.status == "VALID", f"Expected status VALID, got {status_response.status}"
    logger.info(f"Certificate status: {status_response.status}")

    # Step 3: List certificates
    logger.info("Step 3: Listing certificates")

    class MockListRequest:
        status_filter = "VALID"
        subject_filter = ""

    list_request = MockListRequest()
    list_response = service.ListCertificates(list_request, context)

    found = False
    for cert in list_response.certificates:
        if cert.certificate_id == certificate_id:
            found = True
            assert cert.status == "VALID", f"Expected status VALID, got {cert.status}"
            break

    assert found, "Certificate not found in the list"
    logger.info(
        f"Found certificate in the list with total count: {len(list_response.certificates)}"
    )

    # Step 4: Renew certificate
    logger.info("Step 4: Renewing certificate")

    class MockRenewRequest:
        certificate_id = certificate_id
        validity_days = 730  # 2 years
        reuse_key = True

    renew_request = MockRenewRequest()
    renew_response = service.RenewCertificate(renew_request, context)

    assert renew_response.certificate_id, "Renewed certificate ID should not be empty"
    assert (
        renew_response.certificate_id != certificate_id
    ), "Renewed certificate should have a new ID"
    assert (
        renew_response.status == "RENEWED"
    ), f"Expected status RENEWED, got {renew_response.status}"

    renewed_certificate_id = renew_response.certificate_id
    logger.info(f"Renewed certificate with new ID: {renewed_certificate_id}")

    # Step 5: Check original certificate status (should be superseded)
    logger.info("Step 5: Checking status of original certificate")

    status_request.certificate_id = certificate_id
    original_status_response = service.GetCertificateStatus(status_request, context)

    # Acceptable statuses are SUPERSEDED or VALID depending on implementation
    assert original_status_response.status in [
        "SUPERSEDED",
        "VALID",
    ], f"Expected status SUPERSEDED or VALID, got {original_status_response.status}"
    logger.info(f"Original certificate status: {original_status_response.status}")

    # Step 6: Revoke the renewed certificate
    logger.info("Step 6: Revoking the renewed certificate")

    class MockRevokeRequest:
        certificate_id = renewed_certificate_id
        reason = "KEY_COMPROMISE"

    revoke_request = MockRevokeRequest()
    revoke_response = service.RevokeCertificate(revoke_request, context)

    assert revoke_response.certificate_id == renewed_certificate_id, "Certificate ID mismatch"
    assert revoke_response.success, "Revocation should be successful"
    assert (
        revoke_response.status == "REVOKED"
    ), f"Expected status REVOKED, got {revoke_response.status}"
    logger.info(f"Revoked certificate: {revoke_response.certificate_id}")

    # Step 7: Check the status of the revoked certificate
    logger.info("Step 7: Checking status of revoked certificate")

    status_request.certificate_id = renewed_certificate_id
    revoked_status_response = service.GetCertificateStatus(status_request, context)

    assert (
        revoked_status_response.status == "REVOKED"
    ), f"Expected status REVOKED, got {revoked_status_response.status}"
    assert (
        revoked_status_response.revocation_reason == "KEY_COMPROMISE"
    ), f"Expected reason KEY_COMPROMISE, got {revoked_status_response.revocation_reason}"
    logger.info(f"Revoked certificate status: {revoked_status_response.status}")

    # Step 8: List revoked certificates
    logger.info("Step 8: Listing revoked certificates")

    list_request.status_filter = "REVOKED"
    revoked_list_response = service.ListCertificates(list_request, context)

    found = False
    for cert in revoked_list_response.certificates:
        if cert.certificate_id == renewed_certificate_id:
            found = True
            assert cert.status == "REVOKED", f"Expected status REVOKED, got {cert.status}"
            break

    assert found, "Revoked certificate not found in the list"
    logger.info(
        f"Found revoked certificate in the list with total count: {len(revoked_list_response.certificates)}"
    )

    # Step 9: Create a certificate that will expire soon and check expiring certificates
    logger.info("Step 9: Testing expiring certificates")

    class MockExpiringCreateRequest:
        subject_name = f"CN=Expiring CSCA {test_id}, O=Standalone Test"
        validity_days = 10  # Short validity to test expiring soon
        key_algorithm = "RSA"
        key_size = 2048
        extensions = {}

    expiring_create_request = MockExpiringCreateRequest()
    expiring_create_response = service.CreateCertificate(expiring_create_request, context)

    expiring_certificate_id = expiring_create_response.certificate_id
    logger.info(f"Created expiring certificate with ID: {expiring_certificate_id}")

    class MockExpiryRequest:
        days_threshold = 30

    expiry_request = MockExpiryRequest()
    expiry_response = service.CheckExpiringCertificates(expiry_request, context)

    found = False
    for cert in expiry_response.certificates:
        if cert.certificate_id == expiring_certificate_id:
            found = True
            break

    assert found, "Expiring certificate not found in the expiring list"
    logger.info(
        f"Found expiring certificate in the list with total count: {len(expiry_response.certificates)}"
    )

    logger.info("All tests passed! Certificate lifecycle management is working correctly.")


if __name__ == "__main__":
    test_certificate_lifecycle()
