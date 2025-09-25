import base64
import hashlib
import logging
import os
import time

# Import the generated gRPC modules
from proto import (
    csca_service_pb2,
    csca_service_pb2_grpc,
    document_signer_pb2,
    document_signer_pb2_grpc,
)


class DocumentSigner(document_signer_pb2_grpc.DocumentSignerServicer):
    """
    Implementation of the Document Signer service.

    This service is responsible for:
    - Maintaining DSCs signed by the CSCA
    - Signing SOD (Document Security Object) files
    - Handling key rotation and certificate expiry
    """

    def __init__(self, channels=None) -> None:
        """
        Initialize the Document Signer service.

        Args:
            channels (dict): Dictionary of gRPC channels to other services
        """
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self.data_dir = os.environ.get("DATA_DIR", "/app/data")
        self.logger.info("Document Signer service initialized")

    def SignDocument(self, request, context):
        """
        Sign a document with the Document Signer's private key.

        Args:
            request: The gRPC request containing the document to sign
            context: The gRPC context

        Returns:
            SignResponse: The gRPC response containing the signature
        """
        self.logger.info(f"SignDocument called with document of length {len(request.document)}")

        # Get the CSCA certificate if needed (demonstrating inter-service communication)
        csca_cert = self._get_csca_certificate()
        self.logger.info(f"Using CSCA certificate: {csca_cert}")

        # In a real implementation, this would use HSM or secure cryptographic operations
        # For demonstration, we'll create a mock signature
        document_hash = hashlib.sha256(request.document.encode()).digest()
        signature = base64.b64encode(document_hash).decode()

        # Add a timestamp to make the signature unique
        signature = f"{signature}.{int(time.time())}"

        self.logger.info(f"Document signed, signature length: {len(signature)}")

        # Return the response
        return document_signer_pb2.SignResponse(signature=signature)

    def _get_csca_certificate(self):
        """
        Get the CSCA certificate from the CSCA service.
        This demonstrates inter-service communication.

        Returns:
            str: The CSCA certificate
        """
        try:
            # Get the channel to the CSCA service
            csca_channel = self.channels.get("csca_service")
            if not csca_channel:
                self.logger.warning("CSCA service channel not available, using mock certificate")
                return "MOCK_CSCA_CERTIFICATE"

            # Create a stub for the CSCA service
            csca_stub = csca_service_pb2_grpc.CscaServiceStub(csca_channel)

            # Call the GetCscaData method
            response = csca_stub.GetCscaData(csca_service_pb2.CscaRequest(id="document-signer"))

            return response.data
        except Exception as e:
            self.logger.exception(f"Error getting CSCA certificate: {e}")
            return "ERROR_GETTING_CSCA_CERTIFICATE"
