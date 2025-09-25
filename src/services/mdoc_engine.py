# --- BEGIN Standard Library Imports ---
import json
import logging
import os
import sys
import uuid
from concurrent import futures

import grpc  # Ensure grpc is imported and grouped with third-party if considered so, or here if standard-like

# --- END Standard Library Imports ---

# --- BEGIN Third-Party Imports ---
# (No third-party imports were previously listed here for mdoc_engine)
# --- END Third-Party Imports ---

# --- BEGIN Project-Specific Imports ---
# Modify sys.path to include the project root.
# This MUST be done before attempting to import from 'src'.
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.marty_common.error_handling import (
    GrpcErrorHandler,
)
from src.marty_common.grpc_logging import LoggingStreamerServicer
from src.marty_common.logging_config import setup_logging

# For LoggingStreamerServicer and its addition to server
from src.proto import common_services_pb2_grpc, mdoc_engine_pb2, mdoc_engine_pb2_grpc

# --- END Project-Specific Imports ---

# Module-level logger, will be initialized in serve() after setup_logging
logger = None


class MDocEngineServicer(mdoc_engine_pb2_grpc.MDocEngineServicer):
    def __init__(self, channels=None) -> None:
        self.logger = logging.getLogger(__name__)
        self.logger.info("MDocEngineServicer initialized.")
        self.channels = channels if channels else {}
        self.error_handler = GrpcErrorHandler("mdoc-engine", self.logger)
        self._initialize_default_templates()

    def _initialize_default_templates(self) -> None:
        current_logger = self.logger or logging.getLogger(__name__)
        current_logger.info("Initializing default mDoc templates...")
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
        current_logger.info(f"Default mDoc templates loaded: {list(self.default_templates.keys())}")

    def CreateMDoc(self, request, context):
        self.logger.info(f"CreateMDoc request received for doc_type: {request.doc_type}")
        try:
            if not request.doc_type:
                self.logger.warning("CreateMDoc called with empty doc_type.")
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("doc_type cannot be empty.")
                return mdoc_engine_pb2.CreateMDocResponse(
                    status_message="Invalid request: doc_type missing."
                )

            mdoc_id = str(uuid.uuid4())

            try:
                if hasattr(request, "data_elements") and hasattr(request.data_elements, "items"):
                    # Convert Struct to Python dict
                    data_elements_dict = dict(request.data_elements.items())
                    _ = json.dumps(data_elements_dict)  # Test serialization
                elif isinstance(request.data_elements, str):
                    _ = json.loads(request.data_elements)
                else:
                    self.logger.warning(
                        f"request.data_elements is of type {type(request.data_elements)}. "
                        "Attempting to process as is, but may require specific handling."
                    )

            except Exception as ser_ex:
                self.logger.error(
                    f"Error processing data_elements: {ser_ex}. "
                    "Ensure it's a valid format (e.g., JSON string or compatible dict).",
                    exc_info=True,
                )
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("Invalid format for data_elements.")
                return mdoc_engine_pb2.CreateMDocResponse(
                    status_message="Invalid data_elements format."
                )

            self.logger.info(f"mDoc created with ID: {mdoc_id} for type: {request.doc_type}")
            return mdoc_engine_pb2.CreateMDocResponse(
                mdoc_id=mdoc_id, status_message="mDoc created successfully (simulated)."
            )
        except Exception as e:
            self.logger.error(f"Error creating mDoc: {e}", exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal server error: {e}")
            return mdoc_engine_pb2.CreateMDocResponse(status_message=f"Error: {e}")

    def PresentMDoc(self, request, context):
        self.logger.info(
            f"PresentMDoc request received for mdoc_id: {request.mdoc_id}, "
            f"elements: {request.requested_elements}"
        )
        try:
            if not request.mdoc_id:
                self.logger.warning("PresentMDoc called with empty mdoc_id.")
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("mdoc_id cannot be empty.")
                return mdoc_engine_pb2.PresentMDocResponse(
                    status_message="Invalid request: mdoc_id missing."
                )

            dummy_presentation = {
                "mdoc_id": request.mdoc_id,
                "doc_type": "retrieved_doc_type_placeholder",
                "requested_elements_data": {
                    elem: f"dummy_value_for_{elem}" for elem in request.requested_elements
                },
                "signature": "dummy_signature_over_presentation",
            }
            presentation_data_bytes = json.dumps(dummy_presentation).encode("utf-8")

            self.logger.info(f"mDoc presentation prepared for mdoc_id: {request.mdoc_id}")
            return mdoc_engine_pb2.PresentMDocResponse(
                presentation_data=presentation_data_bytes,
                status_message="mDoc presentation prepared (simulated).",
            )
        except Exception as e:
            self.logger.error(f"Error presenting mDoc: {e}", exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal server error: {e}")
            return mdoc_engine_pb2.PresentMDocResponse(status_message=f"Error: {e}")

    def GetMDoc(self, request, context):
        """Retrieve an mDoc by document ID"""
        self.logger.info(f"GetMDoc request received for mdoc_id: {request.mdoc_id}")
        try:
            if not request.mdoc_id:
                self.logger.warning("GetMDoc called with empty mdoc_id.")
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("mdoc_id cannot be empty.")
                return mdoc_engine_pb2.MDocResponse(
                    error_message="Invalid request: mdoc_id missing."
                )

            # NOTE: mDoc storage/retrieval should be implemented with persistent backend
            # For now, return a mock response
            mock_person_info = mdoc_engine_pb2.PersonInfo(
                first_name="John",
                last_name="Doe",
                date_of_birth="1990-01-01",
                place_of_birth="City, Country",
                nationality="US",
                gender="M",
            )

            mock_signature_info = mdoc_engine_pb2.SignatureInfo(
                signature_date="2024-01-01T12:00:00Z",
                signer_id="issuer-123",
                signature=b"mock_signature_data",
                is_valid=True,
            )

            self.logger.info(f"Retrieved mDoc with ID: {request.mdoc_id}")
            return mdoc_engine_pb2.MDocResponse(
                mdoc_id=request.mdoc_id,
                document_type="ID_CARD",
                document_number="123456789",
                issuing_authority="Mock Authority",
                issue_date="2024-01-01",
                expiry_date="2034-01-01",
                person_info=mock_person_info,
                signature_info=mock_signature_info,
                status="ACTIVE",
                created_at="2024-01-01T12:00:00Z",
            )
        except Exception as e:
            self.logger.error(f"Error retrieving mDoc: {e}", exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal server error: {e}")
            return mdoc_engine_pb2.MDocResponse(error_message=f"Error: {e}")

    def SignMDoc(self, request, context):
        """Sign an mDoc using Document Signer"""
        self.logger.info(f"SignMDoc request received for mdoc_id: {request.mdoc_id}")
        try:
            if not request.mdoc_id:
                self.logger.warning("SignMDoc called with empty mdoc_id.")
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("mdoc_id cannot be empty.")
                return mdoc_engine_pb2.SignMDocResponse(
                    success=False, error_message="Invalid request: mdoc_id missing."
                )

            # NOTE: Actual signing logic should integrate with Document Signer service
            # For now, return a mock successful signature
            mock_signature_info = mdoc_engine_pb2.SignatureInfo(
                signature_date="2024-01-01T12:00:00Z",
                signer_id="document-signer-001",
                signature=b"mock_signature_bytes_for_" + request.mdoc_id.encode(),
                is_valid=True,
            )

            self.logger.info(f"Successfully signed mDoc: {request.mdoc_id}")
            return mdoc_engine_pb2.SignMDocResponse(
                success=True, signature_info=mock_signature_info
            )
        except Exception as e:
            self.logger.error(f"Error signing mDoc: {e}", exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal server error: {e}")
            return mdoc_engine_pb2.SignMDocResponse(success=False, error_message=f"Error: {e}")

    def GenerateMDocQRCode(self, request, context):
        """Generate QR code for offline verification"""
        self.logger.info(f"GenerateMDocQRCode request received for mdoc_id: {request.mdoc_id}")
        try:
            if not request.mdoc_id:
                self.logger.warning("GenerateMDocQRCode called with empty mdoc_id.")
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("mdoc_id cannot be empty.")
                return mdoc_engine_pb2.GenerateQRCodeResponse(
                    error_message="Invalid request: mdoc_id missing."
                )

            # NOTE: QR code generation should use proper ISO 18013-5 encoding
            # For now, return mock QR code data
            import hashlib

            qr_content = {
                "mdoc_id": request.mdoc_id,
                "namespaces": (
                    list(request.namespaces_to_include)
                    if request.namespaces_to_include
                    else ["org.iso.18013.5.1"]
                ),
                "fields": list(request.fields_to_include) if request.fields_to_include else ["all"],
                "timestamp": "2024-01-01T12:00:00Z",
            }

            qr_data_str = json.dumps(qr_content, sort_keys=True)
            mock_qr_bytes = hashlib.sha256(qr_data_str.encode()).digest()

            self.logger.info(f"Generated QR code for mDoc: {request.mdoc_id}")
            return mdoc_engine_pb2.GenerateQRCodeResponse(qr_code=mock_qr_bytes)
        except Exception as e:
            self.logger.error(f"Error generating QR code: {e}", exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal server error: {e}")
            return mdoc_engine_pb2.GenerateQRCodeResponse(error_message=f"Error: {e}")

    def TransferMDocToDevice(self, request, context):
        """Transfer mDoc to device"""
        self.logger.info(
            f"TransferMDocToDevice request received for mdoc_id: {request.mdoc_id}, device_id: {request.device_id}"
        )
        try:
            if not request.mdoc_id:
                self.logger.warning("TransferMDocToDevice called with empty mdoc_id.")
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("mdoc_id cannot be empty.")
                return mdoc_engine_pb2.TransferMDocResponse(
                    success=False, error_message="Invalid request: mdoc_id missing."
                )

            if not request.device_id:
                self.logger.warning("TransferMDocToDevice called with empty device_id.")
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("device_id cannot be empty.")
                return mdoc_engine_pb2.TransferMDocResponse(
                    success=False, error_message="Invalid request: device_id missing."
                )

            # NOTE: Device transfer logic should support BLE, NFC, and ONLINE methods
            # For now, simulate a successful transfer
            transfer_id = f"transfer_{request.mdoc_id}_{request.device_id}_{uuid.uuid4().hex[:8]}"

            self.logger.info(
                f"Successfully transferred mDoc {request.mdoc_id} to device {request.device_id} via {request.transfer_method}"
            )
            return mdoc_engine_pb2.TransferMDocResponse(success=True, transfer_id=transfer_id)
        except Exception as e:
            self.logger.error(f"Error transferring mDoc to device: {e}", exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal server error: {e}")
            return mdoc_engine_pb2.TransferMDocResponse(success=False, error_message=f"Error: {e}")

    def VerifyMDoc(self, request, context):
        """Verify an mDoc"""
        self.logger.info("VerifyMDoc request received")
        try:
            # Determine which type of mDoc data was provided
            mdoc_source = None
            if request.HasField("mdoc_id"):
                mdoc_source = f"mdoc_id: {request.mdoc_id}"
            elif request.HasField("qr_code_data"):
                mdoc_source = f"qr_code_data: {len(request.qr_code_data)} bytes"
            elif request.HasField("device_data"):
                mdoc_source = f"device_data: {len(request.device_data)} bytes"
            else:
                self.logger.warning("VerifyMDoc called with no mDoc data.")
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("No mDoc data provided.")
                return mdoc_engine_pb2.VerifyMDocResponse(
                    is_valid=False, error_message="Invalid request: No mDoc data provided."
                )

            # NOTE: Verification logic should validate against ISO 18013-5 standards
            # For now, return mock verification results
            verification_results = [
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
                    check_name="expiration_check", passed=True, details="Document has not expired"
                ),
            ]

            # Mock mDoc data that verifier is authorized to see
            mock_person_info = mdoc_engine_pb2.PersonInfo(
                first_name="John", last_name="Doe", date_of_birth="1990-01-01"
            )

            mock_mdoc_data = mdoc_engine_pb2.MDocResponse(
                mdoc_id="verified_mdoc_id",
                document_type="ID_CARD",
                document_number="123456789",
                issuing_authority="Mock Authority",
                issue_date="2024-01-01",
                expiry_date="2034-01-01",
                person_info=mock_person_info,
                status="ACTIVE",
            )

            self.logger.info(f"Successfully verified mDoc from {mdoc_source}")
            return mdoc_engine_pb2.VerifyMDocResponse(
                is_valid=True, verification_results=verification_results, mdoc_data=mock_mdoc_data
            )
        except Exception as e:
            self.logger.error(f"Error verifying mDoc: {e}", exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal server error: {e}")
            return mdoc_engine_pb2.VerifyMDocResponse(is_valid=False, error_message=f"Error: {e}")

    def CreateDocumentTypeTemplate(self, request, context):
        """Create document type template"""
        self.logger.info(
            f"CreateDocumentTypeTemplate request received for template: {request.template_name}"
        )
        try:
            if not request.template_name:
                self.logger.warning("CreateDocumentTypeTemplate called with empty template_name.")
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("template_name cannot be empty.")
                return mdoc_engine_pb2.CreateTemplateResponse(
                    success=False, error_message="Invalid request: template_name missing."
                )

            if not request.document_type:
                self.logger.warning("CreateDocumentTypeTemplate called with empty document_type.")
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("document_type cannot be empty.")
                return mdoc_engine_pb2.CreateTemplateResponse(
                    success=False, error_message="Invalid request: document_type missing."
                )

            # NOTE: Template storage should be implemented with persistent backend
            # For now, generate a template ID and simulate storage
            template_id = f"template_{uuid.uuid4().hex[:12]}"

            self.logger.info(f"Created template {request.template_name} with ID: {template_id}")
            return mdoc_engine_pb2.CreateTemplateResponse(template_id=template_id, success=True)
        except Exception as e:
            self.logger.error(f"Error creating document template: {e}", exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal server error: {e}")
            return mdoc_engine_pb2.CreateTemplateResponse(
                success=False, error_message=f"Error: {e}"
            )

    def GetDocumentTemplates(self, request, context):
        """Get available document type templates"""
        self.logger.info(
            f"GetDocumentTemplates request received with document_type filter: {request.document_type}"
        )
        try:
            # NOTE: Template retrieval should be implemented with persistent backend
            # For now, return mock templates
            mock_templates = [
                mdoc_engine_pb2.DocumentTemplate(
                    template_id="template_id_card",
                    template_name="Standard ID Card",
                    document_type="ID_CARD",
                    required_fields=[
                        mdoc_engine_pb2.DocumentField(
                            field_name="first_name",
                            field_value="",
                            is_mandatory=True,
                            namespace="org.iso.18013.5.1",
                        ),
                        mdoc_engine_pb2.DocumentField(
                            field_name="last_name",
                            field_value="",
                            is_mandatory=True,
                            namespace="org.iso.18013.5.1",
                        ),
                    ],
                    required_images=["PORTRAIT"],
                ),
                mdoc_engine_pb2.DocumentTemplate(
                    template_id="template_residence_permit",
                    template_name="Residence Permit",
                    document_type="RESIDENCE_PERMIT",
                    required_fields=[
                        mdoc_engine_pb2.DocumentField(
                            field_name="permit_number",
                            field_value="",
                            is_mandatory=True,
                            namespace="org.iso.residence",
                        )
                    ],
                    required_images=["PORTRAIT", "SIGNATURE"],
                ),
            ]

            # Filter templates if document_type is specified
            if request.document_type:
                filtered_templates = [
                    template
                    for template in mock_templates
                    if template.document_type == request.document_type
                ]
            else:
                filtered_templates = mock_templates

            self.logger.info(f"Retrieved {len(filtered_templates)} templates")
            return mdoc_engine_pb2.GetTemplatesResponse(templates=filtered_templates)
        except Exception as e:
            self.logger.error(f"Error retrieving document templates: {e}", exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal server error: {e}")
            return mdoc_engine_pb2.GetTemplatesResponse(templates=[])


def serve() -> None:
    global logger

    service_name = os.environ.get("MDOC_ENGINE_SERVICE_NAME", "mdoc-engine")
    setup_logging(service_name=service_name)
    logger = logging.getLogger(__name__)

    logger.info(f"Starting {service_name} gRPC server...")

    grpc_port = os.environ.get("GRPC_PORT", "50054")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

    channels = {}

    servicer_instance = MDocEngineServicer(channels=channels)
    mdoc_engine_pb2_grpc.add_MDocEngineServicer_to_server(servicer_instance, server)
    logger.info("MDocEngineServicer added to gRPC server.")

    try:
        logging_streamer_servicer = LoggingStreamerServicer()
        common_services_pb2_grpc.add_LoggingStreamerServicer_to_server(
            logging_streamer_servicer, server
        )
        logger.info("Successfully added LoggingStreamerServicer to gRPC server.")
    except AttributeError as ae:
        logger.error(
            f"Failed to add LoggingStreamerServicer due to AttributeError: {ae}. "
            "Ensure 'common_services.proto' is compiled and "
            "'common_services_pb2_grpc.py' is correctly generated.",
            exc_info=True,
        )
    except Exception as e:
        logger.error(f"Failed to add LoggingStreamerServicer: {e}", exc_info=True)

    server.add_insecure_port(f"[::]:{grpc_port}")
    server.start()
    logger.info(f"{service_name} server started successfully on port {grpc_port}.")

    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down server due to KeyboardInterrupt...")
    except Exception as e:
        logger.error(f"Server termination error: {e}", exc_info=True)
    finally:
        logger.info("Stopping gRPC server...")
        server.stop(0)
        logger.info(f"{service_name} server shut down.")


if __name__ == "__main__":
    # Corrected f-string formatting for the debug print statement.
    service_name_env = os.environ.get("MDOC_ENGINE_SERVICE_NAME", "mdoc-engine-default")
    grpc_port_env = os.environ.get("GRPC_PORT", "50054")
    print(
        f"DEBUG: mdoc_engine.py execution started. "
        f"SERVICE_NAME='{service_name_env}', "
        f"GRPC_PORT='{grpc_port_env}'",
        file=sys.stdout,
    )
    sys.stdout.flush()
    serve()
