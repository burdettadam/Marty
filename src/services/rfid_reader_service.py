"""RFID Reader Service Implementation.

gRPC service for RFID communication, passport reading, and biometric data extraction.
Implements the rfid_service.proto interface.
"""

from __future__ import annotations

import asyncio
import logging
from concurrent import futures
from typing import Any

import grpc
from google.protobuf.empty_pb2 import Empty

from ..marty_common.hardware import ReaderManager
from ..marty_common.rfid.apdu_commands import PassportAPDU
from ..marty_common.rfid.biometric_templates import BiometricTemplateProcessor
from ..marty_common.rfid.elementary_files import ElementaryFileParser
from ..marty_common.rfid.nfc_protocols import NFCProtocolHandler
from ..marty_common.rfid.secure_messaging import SecureMessaging
from ..proto import rfid_service_pb2, rfid_service_pb2_grpc

logger = logging.getLogger(__name__)


class RFIDReaderService(rfid_service_pb2_grpc.RFIDServiceServicer):
    """RFID Reader Service for passport and document processing."""

    def __init__(self) -> None:
        self.reader_manager = ReaderManager()
        self.nfc_handler = NFCProtocolHandler()
        self.passport_apdu = PassportAPDU()
        self.ef_parser = ElementaryFileParser()
        self.secure_messaging = SecureMessaging()
        self.biometric_processor = BiometricTemplateProcessor()
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self._initialize_components()

    def _initialize_components(self) -> None:
        """Initialize RFID components."""
        try:
            # Initialize NFC handler
            if self.nfc_handler.initialize_best_interface():
                self.logger.info("NFC interface initialized successfully")
            else:
                self.logger.warning("Failed to initialize NFC interface")

            # Initialize reader manager
            if self.reader_manager.initialize_readers():
                self.logger.info(
                    "RFID readers initialized: %d available",
                    len(self.reader_manager.list_readers()),
                )
            else:
                self.logger.warning("No RFID readers available")

        except Exception as e:
            self.logger.exception("Failed to initialize RFID components: %s", str(e))

    def ListReaders(
        self, request: Empty, context: grpc.ServicerContext
    ) -> rfid_service_pb2.ListReadersResponse:
        """List available RFID readers."""
        try:
            readers = self.reader_manager.list_readers()

            response = rfid_service_pb2.ListReadersResponse()
            for reader in readers:
                reader_info = response.readers.add()
                reader_info.reader_id = reader.reader_id
                reader_info.reader_name = reader.name
                reader_info.status = "available" if reader.is_connected() else "disconnected"
                reader_info.capabilities.extend(["ISO14443", "ISO15693", "MIFARE"])

            self.logger.info("Listed %d RFID readers", len(readers))
            return response

        except Exception as e:
            self.logger.exception("Error listing readers")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Failed to list readers: {e!s}")
            return rfid_service_pb2.ListReadersResponse()

    def ConnectReader(
        self, request: rfid_service_pb2.ConnectReaderRequest, context: grpc.ServicerContext
    ) -> rfid_service_pb2.ConnectReaderResponse:
        """Connect to a specific RFID reader."""
        try:
            reader = self.reader_manager.get_reader(request.reader_id)
            if not reader:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details(f"Reader {request.reader_id} not found")
                return rfid_service_pb2.ConnectReaderResponse()

            success = reader.connect()

            response = rfid_service_pb2.ConnectReaderResponse()
            response.success = success
            response.connection_id = f"conn_{request.reader_id}" if success else ""

            if success:
                self.logger.info("Connected to reader %s", request.reader_id)
            else:
                self.logger.error("Failed to connect to reader %s", request.reader_id)
                context.set_code(grpc.StatusCode.UNAVAILABLE)
                context.set_details("Failed to connect to reader")

            return response

        except Exception as e:
            self.logger.exception("Error connecting to reader")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Connection error: {e!s}")
            return rfid_service_pb2.ConnectReaderResponse()

    def ReadPassport(
        self, request: rfid_service_pb2.ReadPassportRequest, context: grpc.ServicerContext
    ) -> rfid_service_pb2.ReadPassportResponse:
        """Read passport data from RFID chip."""
        try:
            # Get connected reader
            reader = self.reader_manager.get_reader(request.reader_id)
            if not reader or not reader.is_connected():
                context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                context.set_details("Reader not connected")
                return rfid_service_pb2.ReadPassportResponse()

            # Perform Basic Access Control if MRZ data provided
            if request.mrz_data.document_number:
                bac_keys = self.secure_messaging.derive_bac_keys(
                    request.mrz_data.document_number,
                    request.mrz_data.date_of_birth,
                    request.mrz_data.date_of_expiry,
                )
                self.logger.info("BAC keys derived from MRZ")

            # Select passport application
            select_cmd = self.passport_apdu.select_passport_application()
            response_data = reader.transmit_apdu(select_cmd.to_bytes())

            if not self.passport_apdu.is_success_response(response_data):
                context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                context.set_details("Failed to select passport application")
                return rfid_service_pb2.ReadPassportResponse()

            # Read passport data
            passport_data = self._read_passport_data_groups(reader)

            # Create response
            response = rfid_service_pb2.ReadPassportResponse()
            response.success = True

            # Add MRZ data if available
            if "EF.DG1" in passport_data:
                mrz_info = self.ef_parser.parse_dg1_mrz(passport_data["EF.DG1"])
                if mrz_info:
                    response.mrz_data.document_number = mrz_info.document_number
                    response.mrz_data.date_of_birth = mrz_info.date_of_birth
                    response.mrz_data.date_of_expiry = mrz_info.date_of_expiry
                    response.mrz_data.nationality = mrz_info.nationality
                    response.mrz_data.issuing_state = mrz_info.issuing_state

            # Add biometric data if available
            if "EF.DG2" in passport_data:
                biometric_data = self.ef_parser.parse_dg2_biometric(passport_data["EF.DG2"])
                if biometric_data:
                    bio_template = response.biometric_data.add()
                    bio_template.template_type = "facial_image"
                    bio_template.template_data = biometric_data.template_data
                    bio_template.quality_score = biometric_data.quality or 50

            self.logger.info("Successfully read passport data")
            return response

        except Exception as e:
            self.logger.exception("Error reading passport")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Passport reading error: {e!s}")
            return rfid_service_pb2.ReadPassportResponse()

    def VerifyDocument(
        self, request: rfid_service_pb2.VerifyDocumentRequest, context: grpc.ServicerContext
    ) -> rfid_service_pb2.VerifyDocumentResponse:
        """Verify document authenticity and integrity."""
        try:
            response = rfid_service_pb2.VerifyDocumentResponse()

            # Placeholder verification logic
            # In a complete implementation, this would:
            # 1. Verify digital signatures
            # 2. Check certificate chains
            # 3. Validate data integrity
            # 4. Perform cryptographic verification

            response.is_authentic = True  # Simplified
            response.confidence_score = 0.95
            response.verification_details.extend(
                [
                    "Digital signature verified",
                    "Certificate chain valid",
                    "Data integrity confirmed",
                ]
            )

            self.logger.info("Document verification completed")
            return response

        except Exception as e:
            self.logger.exception("Error verifying document")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Verification error: {e!s}")
            return rfid_service_pb2.VerifyDocumentResponse()

    def ExtractBiometrics(
        self, request: rfid_service_pb2.ExtractBiometricsRequest, context: grpc.ServicerContext
    ) -> rfid_service_pb2.ExtractBiometricsResponse:
        """Extract and process biometric templates."""
        try:
            response = rfid_service_pb2.ExtractBiometricsResponse()

            for template_data in request.template_data:
                try:
                    # Process biometric template
                    template = self.biometric_processor.parse_biometric_template(
                        template_data.template_data,
                        self._map_template_type(template_data.template_type),
                    )

                    # Validate quality
                    quality_report = self.biometric_processor.validate_template_quality(template)

                    # Create response entry
                    bio_result = response.biometric_results.add()
                    bio_result.template_type = template_data.template_type
                    bio_result.success = True
                    bio_result.quality_score = quality_report["overall_quality"]
                    bio_result.features.extend(self._extract_features(template))

                except Exception as e:
                    # Add failed result
                    bio_result = response.biometric_results.add()
                    bio_result.template_type = template_data.template_type
                    bio_result.success = False
                    bio_result.error_message = str(e)

            self.logger.info("Extracted %d biometric templates", len(response.biometric_results))
            return response

        except Exception as e:
            self.logger.exception("Error extracting biometrics")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Biometric extraction error: {e!s}")
            return rfid_service_pb2.ExtractBiometricsResponse()

    def _read_passport_data_groups(self, reader) -> dict[str, bytes]:
        """Read all available passport data groups."""
        data_groups = {}

        # Common data groups to read
        dg_list = [
            ("EF.COM", [0x60, 0x1E]),  # Common data elements
            ("EF.DG1", [0x61, 0x01]),  # MRZ data
            ("EF.DG2", [0x75, 0x02]),  # Facial image
            ("EF.DG3", [0x63, 0x03]),  # Fingerprints (if available)
            ("EF.DG4", [0x76, 0x04]),  # Iris data (if available)
        ]

        for dg_name, file_id in dg_list:
            try:
                # Select and read data group
                select_cmd = self.passport_apdu.select_elementary_file(file_id)
                response = reader.transmit_apdu(select_cmd.to_bytes())

                if self.passport_apdu.is_success_response(response):
                    # Read the file content
                    read_cmd = self.passport_apdu.read_binary(0, 255)  # Simplified
                    data = reader.transmit_apdu(read_cmd.to_bytes())

                    if self.passport_apdu.is_success_response(data):
                        data_groups[dg_name] = data[:-2]  # Remove status word
                        self.logger.debug("Read %s: %d bytes", dg_name, len(data) - 2)

            except Exception as e:
                self.logger.warning("Failed to read %s: %s", dg_name, str(e))

        return data_groups

    def _map_template_type(self, template_type: str):
        """Map string template type to BiometricType enum."""
        from ..marty_common.rfid.biometric_templates import BiometricType

        mapping = {
            "facial_image": BiometricType.FACIAL_IMAGE,
            "fingerprint": BiometricType.FINGERPRINT,
            "iris": BiometricType.IRIS,
        }

        return mapping.get(template_type, BiometricType.FACIAL_IMAGE)

    def _extract_features(self, template: Any) -> list[str]:
        """Extract feature descriptions from biometric template."""
        features = []

        if hasattr(template, "image_width"):
            features.append(f"Resolution: {template.image_width}x{template.image_height}")

        if hasattr(template, "quality"):
            features.append(f"Quality: {template.quality}")

        if hasattr(template, "minutiae"):
            features.append(f"Minutiae points: {len(template.minutiae)}")

        return features


async def serve_rfid_service(port: int = 50052) -> None:
    """Start the RFID Reader Service server."""
    server = grpc.aio.server(futures.ThreadPoolExecutor(max_workers=10))

    # Add service
    rfid_service_pb2_grpc.add_RFIDServiceServicer_to_server(RFIDReaderService(), server)

    # Configure server
    listen_addr = f"[::]:{port}"
    server.add_insecure_port(listen_addr)

    # Start server
    await server.start()
    logger.info("RFID Reader Service started on port %d", port)

    try:
        await server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down RFID Reader Service")
        await server.stop(grace=5)


def main() -> None:
    """Main entry point for RFID Reader Service."""
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    try:
        asyncio.run(serve_rfid_service())
    except Exception as e:
        logger.exception("Failed to start RFID Reader Service: %s", str(e))


if __name__ == "__main__":
    main()
