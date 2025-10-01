"""
Refactored mDoc Engine service using shared gRPC utilities.

This demonstrates how to use the new shared infrastructure to reduce code duplication.
"""

import json
import logging
import uuid
from typing import Any

import grpc

from marty_common.config_manager import get_service_config
from marty_common.grpc_server import run_grpc_service
from src.proto import mdoc_engine_pb2, mdoc_engine_pb2_grpc

logger = logging.getLogger(__name__)


class MDocEngineServicer(mdoc_engine_pb2_grpc.MDocEngineServicer):
    """Refactored mDoc Engine servicer using shared patterns."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize the mDoc Engine servicer.
        
        Args:
            config: Optional configuration dictionary (for backward compatibility)
        """
        self.config = get_service_config("mdoc_engine")
        self.logger = logging.getLogger(self.__class__.__name__)
        self._initialize_default_templates()

    def _initialize_default_templates(self) -> None:
        """Initialize default mDoc templates."""
        self.logger.info("Initializing default mDoc templates...")
        self.default_templates = {
            "eu_pid_v1": {
                "doc_type": "eu.europa.ec.eudi.pid.1",
                "name": "EU Digital Identity Wallet PID",
                "claims": {
                    "given_name": None,
                    "family_name": None,
                    "birth_date": None,
                },
            },
        }
        self.logger.info(f"Default mDoc templates loaded: {list(self.default_templates.keys())}")

    def CreateMDoc(self, request, context):
        """Create a new mDoc."""
        self.logger.info(f"CreateMDoc request received for doc_type: {request.doc_type}")
        
        try:
            if not request.doc_type:
                return self._create_error_response(
                    context, 
                    grpc.StatusCode.INVALID_ARGUMENT,
                    "doc_type cannot be empty"
                )

            mdoc_id = str(uuid.uuid4())
            
            # Validate data elements
            if not self._validate_data_elements(request.data_elements):
                return self._create_error_response(
                    context,
                    grpc.StatusCode.INVALID_ARGUMENT,
                    "Invalid data_elements format"
                )

            self.logger.info(f"mDoc created with ID: {mdoc_id} for type: {request.doc_type}")
            return mdoc_engine_pb2.CreateMDocResponse(
                mdoc_id=mdoc_id, 
                status_message="mDoc created successfully"
            )
            
        except Exception as e:
            self.logger.exception("Error creating mDoc")
            return self._create_error_response(
                context,
                grpc.StatusCode.INTERNAL,
                f"Internal server error: {e}"
            )

    def PresentMDoc(self, request, context):
        """Present an mDoc with requested elements."""
        self.logger.info(
            f"PresentMDoc request received for mdoc_id: {request.mdoc_id}, "
            f"elements: {request.requested_elements}"
        )
        
        try:
            if not request.mdoc_id:
                return self._create_error_response(
                    context,
                    grpc.StatusCode.INVALID_ARGUMENT,
                    "mdoc_id cannot be empty"
                )

            # Create presentation data
            presentation_data = self._create_presentation_data(
                request.mdoc_id,
                request.requested_elements
            )

            self.logger.info(f"mDoc presentation prepared for mdoc_id: {request.mdoc_id}")
            return mdoc_engine_pb2.PresentMDocResponse(
                presentation_data=presentation_data,
                status_message="mDoc presentation prepared"
            )
            
        except Exception as e:
            self.logger.exception("Error presenting mDoc")
            return self._create_error_response(
                context,
                grpc.StatusCode.INTERNAL,
                f"Internal server error: {e}"
            )

    def GetMDoc(self, request, context):
        """Retrieve an mDoc by document ID."""
        self.logger.info(f"GetMDoc request received for mdoc_id: {request.mdoc_id}")
        
        try:
            if not request.mdoc_id:
                return mdoc_engine_pb2.MDocResponse(
                    error_message="mdoc_id cannot be empty"
                )

            # Create mock response (in real implementation, retrieve from database)
            mock_response = self._create_mock_mdoc_response(request.mdoc_id)
            
            self.logger.info(f"Retrieved mDoc with ID: {request.mdoc_id}")
            return mock_response
            
        except Exception as e:
            self.logger.exception("Error retrieving mDoc")
            return mdoc_engine_pb2.MDocResponse(
                error_message=f"Internal server error: {e}"
            )

    def SignMDoc(self, request, context):
        """Sign an mDoc using Document Signer."""
        self.logger.info(f"SignMDoc request received for mdoc_id: {request.mdoc_id}")
        
        try:
            if not request.mdoc_id:
                return mdoc_engine_pb2.SignMDocResponse(
                    success=False,
                    error_message="mdoc_id cannot be empty"
                )

            # Create mock signature (in real implementation, call Document Signer service)
            signature_info = self._create_mock_signature(request.mdoc_id)
            
            self.logger.info(f"Successfully signed mDoc: {request.mdoc_id}")
            return mdoc_engine_pb2.SignMDocResponse(
                success=True,
                signature_info=signature_info
            )
            
        except Exception as e:
            self.logger.exception("Error signing mDoc")
            return mdoc_engine_pb2.SignMDocResponse(
                success=False,
                error_message=f"Internal server error: {e}"
            )

    def VerifyMDoc(self, request, context):
        """Verify an mDoc."""
        self.logger.info("VerifyMDoc request received")
        
        try:
            # Determine mDoc source
            mdoc_source = self._determine_mdoc_source(request)
            if not mdoc_source:
                return mdoc_engine_pb2.VerifyMDocResponse(
                    is_valid=False,
                    error_message="No mDoc data provided"
                )

            # Perform verification (mock implementation)
            verification_results = self._create_mock_verification_results()
            mdoc_data = self._create_mock_mdoc_response("verified_mdoc_id")
            
            self.logger.info(f"Successfully verified mDoc from {mdoc_source}")
            return mdoc_engine_pb2.VerifyMDocResponse(
                is_valid=True,
                verification_results=verification_results,
                mdoc_data=mdoc_data
            )
            
        except Exception as e:
            self.logger.exception("Error verifying mDoc")
            return mdoc_engine_pb2.VerifyMDocResponse(
                is_valid=False,
                error_message=f"Internal server error: {e}"
            )

    # Helper methods to reduce duplication

    def _create_error_response(self, context, status_code, message):
        """Create a standardized error response."""
        self.logger.warning(f"Request failed: {message}")
        context.set_code(status_code)
        context.set_details(message)
        return mdoc_engine_pb2.CreateMDocResponse(status_message=f"Error: {message}")

    def _validate_data_elements(self, data_elements) -> bool:
        """Validate data elements format."""
        try:
            if hasattr(data_elements, "items"):
                data_dict = dict(data_elements.items())
                json.dumps(data_dict)  # Test serialization
            elif isinstance(data_elements, str):
                json.loads(data_elements)  # Test deserialization
            return True
        except Exception as e:
            self.logger.error(f"Data elements validation failed: {e}")
            return False

    def _create_presentation_data(self, mdoc_id: str, requested_elements: list[str]) -> bytes:
        """Create presentation data for an mDoc."""
        presentation = {
            "mdoc_id": mdoc_id,
            "doc_type": "retrieved_doc_type_placeholder",
            "requested_elements_data": {
                elem: f"dummy_value_for_{elem}" for elem in requested_elements
            },
            "signature": "dummy_signature_over_presentation",
        }
        return json.dumps(presentation).encode("utf-8")

    def _create_mock_mdoc_response(self, mdoc_id: str) -> mdoc_engine_pb2.MDocResponse:
        """Create a mock mDoc response."""
        person_info = mdoc_engine_pb2.PersonInfo(
            first_name="John",
            last_name="Doe",
            date_of_birth="1990-01-01",
            place_of_birth="City, Country",
            nationality="US",
            gender="M",
        )

        signature_info = mdoc_engine_pb2.SignatureInfo(
            signature_date="2024-01-01T12:00:00Z",
            signer_id="issuer-123",
            signature=b"mock_signature_data",
            is_valid=True,
        )

        return mdoc_engine_pb2.MDocResponse(
            mdoc_id=mdoc_id,
            document_type="ID_CARD",
            document_number="123456789",
            issuing_authority="Mock Authority",
            issue_date="2024-01-01",
            expiry_date="2034-01-01",
            person_info=person_info,
            signature_info=signature_info,
            status="ACTIVE",
            created_at="2024-01-01T12:00:00Z",
        )

    def _create_mock_signature(self, mdoc_id: str) -> mdoc_engine_pb2.SignatureInfo:
        """Create a mock signature info."""
        return mdoc_engine_pb2.SignatureInfo(
            signature_date="2024-01-01T12:00:00Z",
            signer_id="document-signer-001",
            signature=b"mock_signature_bytes_for_" + mdoc_id.encode(),
            is_valid=True,
        )

    def _determine_mdoc_source(self, request) -> str | None:
        """Determine the source of mDoc data in the request."""
        if request.HasField("mdoc_id"):
            return f"mdoc_id: {request.mdoc_id}"
        elif request.HasField("qr_code_data"):
            return f"qr_code_data: {len(request.qr_code_data)} bytes"
        elif request.HasField("device_data"):
            return f"device_data: {len(request.device_data)} bytes"
        return None

    def _create_mock_verification_results(self) -> list[mdoc_engine_pb2.VerificationResult]:
        """Create mock verification results."""
        return [
            mdoc_engine_pb2.VerificationResult(
                check_name="signature_verification",
                passed=True,
                details="Digital signature is valid",
            ),
            mdoc_engine_pb2.VerificationResult(
                check_name="certificate_chain_validation",
                passed=True,
                details="Certificate chain is trusted",
            ),
            mdoc_engine_pb2.VerificationResult(
                check_name="expiration_check", 
                passed=True, 
                details="Document has not expired"
            ),
        ]


def main() -> None:
    """Run the mDoc Engine service using shared infrastructure."""
    run_grpc_service(
        service_name="mdoc_engine",
        servicer_class=MDocEngineServicer,
        add_servicer_func=mdoc_engine_pb2_grpc.add_MDocEngineServicer_to_server
    )


if __name__ == "__main__":
    main()