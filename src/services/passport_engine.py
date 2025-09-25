import json
import logging
import os
import uuid
from datetime import datetime
from typing import Optional

# Import the new models
from marty_common.models.passport import (
    DataGroupType,
    ICaoPassport,
)

# Import the generated gRPC modules
from proto import (
    document_signer_pb2,
    document_signer_pb2_grpc,
    passport_engine_pb2,
    passport_engine_pb2_grpc,
)


class PassportEngine(passport_engine_pb2_grpc.PassportEngineServicer):
    """
    Implementation of the Passport Engine service.

    This service is responsible for:
    - Generating the Logical Data Structure (LDS) for ePassports
    - Creating required Data Groups: DG1 (MRZ), DG2 (photo), etc.
    - Producing the complete eMRTD chip content using the DS service
    - Following ICAO Doc 9303 standards for passport structure
    """

    def __init__(self, channels=None) -> None:
        """
        Initialize the Passport Engine service.

        Args:
            channels (dict): Dictionary of gRPC channels to other services
        """
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self.data_dir = os.environ.get("DATA_DIR", "/app/data")
        self.logger.info("Passport Engine service initialized")

        # Passport status tracking
        self.passport_status = {}

        # Ensure data directory exists
        os.makedirs(self.data_dir, exist_ok=True)

    def _generate_passport_data(self, passport_number: str) -> ICaoPassport:
        """
        Generate ICAO-compliant passport data structure for the given passport number.

        Args:
            passport_number: The passport number

        Returns:
            ICaoPassport: The ICAO-compliant passport data structure
        """
        # In a real system, this would retrieve or generate detailed passport data
        # from a passport application database
        issue_date = datetime.now().strftime("%Y-%m-%d")
        expiry_date = datetime.now().replace(year=datetime.now().year + 10).strftime("%Y-%m-%d")

        # Create data groups as per ICAO Doc 9303 standards
        data_groups = {
            DataGroupType.DG1.value: f"MRZ-DATA-{passport_number}",
            DataGroupType.DG2.value: f"PHOTO-DATA-{passport_number}",
            DataGroupType.DG3.value: f"FINGERPRINT-DATA-{passport_number}",
            DataGroupType.DG4.value: f"IRIS-DATA-{passport_number}",
        }

        # Create ICAO passport structure
        return ICaoPassport(
            passport_number=passport_number,
            issue_date=issue_date,
            expiry_date=expiry_date,
            data_groups=data_groups,
            sod=None,  # To be signed by Document Signer service
        )

    def _sign_passport_data(self, passport_data: ICaoPassport) -> Optional[str]:
        """
        Sign passport data with the Document Signer service.

        Args:
            passport_data: The passport data to sign

        Returns:
            str: The signature string in format "signature.timestamp" or None if signing failed
        """
        # Make a copy without the SOD before signing
        passport_dict = passport_data.to_dict()
        passport_dict.pop("sod", None)

        # Serialize passport data for signing
        passport_json = json.dumps(passport_dict)

        # Get the channel to the Document Signer service
        ds_channel = self.channels.get("document_signer")
        if not ds_channel:
            self.logger.warning("Document Signer service channel not available")
            return None

        try:
            # Create a stub for the Document Signer service
            ds_stub = document_signer_pb2_grpc.DocumentSignerStub(ds_channel)

            # Call the SignDocument method
            response = ds_stub.SignDocument(document_signer_pb2.SignRequest(document=passport_json))

            # Create the SOD format: signature.timestamp
            timestamp = int(datetime.now().timestamp())
            signature_string = f"{response.signature}.{timestamp}"

            self.logger.info(
                f"Passport data signed, signature: {response.signature[:20]}... with timestamp {timestamp}"
            )
            return signature_string
        except Exception as e:
            self.logger.exception(f"Error signing passport data: {e}")
            return None

    def _save_passport_data(self, passport_number: str, passport_data: ICaoPassport) -> bool:
        """
        Save passport data to disk.

        Args:
            passport_number: The passport number
            passport_data: The passport data

        Returns:
            bool: True if save was successful, False otherwise
        """
        try:
            file_path = os.path.join(self.data_dir, f"{passport_number}.json")

            # Convert to dict for JSON serialization
            passport_dict = passport_data.to_dict()

            with open(file_path, "w") as f:
                json.dump(passport_dict, f, indent=2)

            self.logger.info(f"Passport data saved to {file_path}")
            return True
        except Exception as e:
            self.logger.exception(f"Error saving passport data: {e}")
            return False

    def ProcessPassport(self, request, context):
        """
        Process a passport - generate and sign passport data according to ICAO standards.

        Args:
            request: The gRPC request containing the passport number
            context: The gRPC context

        Returns:
            PassportResponse: The gRPC response containing the status
        """
        passport_number = request.passport_number
        self.logger.info(f"ProcessPassport called for passport number: {passport_number}")

        # Check if passport number is valid
        if not passport_number:
            passport_number = f"P{uuid.uuid4().hex[:8].upper()}"
            self.logger.info(f"Generated new passport number: {passport_number}")

        # Generate ICAO-compliant passport data
        passport_data = self._generate_passport_data(passport_number)

        # Sign passport data
        signature = self._sign_passport_data(passport_data)

        if signature:
            # Add signature to passport data
            passport_data.sod = signature

            # Save passport data
            if self._save_passport_data(passport_number, passport_data):
                status = "SUCCESS"
                self.passport_status[passport_number] = "PROCESSED"
            else:
                status = "ERROR_SAVING"
                self.passport_status[passport_number] = "ERROR"
        else:
            status = "ERROR_SIGNING"
            self.passport_status[passport_number] = "ERROR"

        self.logger.info(f"Passport {passport_number} processed with status: {status}")

        # Return the response
        return passport_engine_pb2.PassportResponse(status=status)
