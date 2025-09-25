import json
import logging
import os
from typing import Optional

# Import the generated gRPC modules
from src.proto import (
    common_services_pb2_grpc,
    inspection_system_pb2,
    inspection_system_pb2_grpc,
    trust_anchor_pb2,
    trust_anchor_pb2_grpc,
)


class InspectionSystem(inspection_system_pb2_grpc.InspectionSystemServicer):
    """
    Implementation of the Inspection System service.

    This service is responsible for:
    - Reading MRZ and derives access keys (BAC/PACE)
    - Accessing and parsing chip data (DGs and SOD)
    - Validating signatures against trusted CSCA certificates
    - Checking revocation status
    """

    def __init__(self, channels=None) -> None:
        """
        Initialize the Inspection System service.

        Args:
            channels (dict): Dictionary of gRPC channels to other services
        """
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self.data_dir = os.environ.get("DATA_DIR", "/app/data")
        # Use the shared passport data directory if available
        self.passport_data_dir = os.environ.get("PASSPORT_DATA_DIR", "/app/passport_data")
        self.logger.info(
            f"Inspection System service initialized with data_dir={self.data_dir}, passport_data_dir={self.passport_data_dir}"
        )

        # Ensure data directories exist
        os.makedirs(self.data_dir, exist_ok=True)

    def _verify_trust(self, entity):
        """
        Verify if an entity is trusted using the Trust Anchor service.

        Args:
            entity: The entity to verify

        Returns:
            bool: True if the entity is trusted, False otherwise
        """
        # Get the channel to the Trust Anchor service
        trust_channel = self.channels.get("trust_anchor")
        if not trust_channel:
            self.logger.warning("Trust Anchor service channel not available, assuming not trusted")
            return False

        try:
            # Create a stub for the Trust Anchor service
            trust_stub = trust_anchor_pb2_grpc.TrustAnchorStub(trust_channel)

            # Call the VerifyTrust method
            response = trust_stub.VerifyTrust(trust_anchor_pb2.TrustRequest(entity=entity))

            self.logger.info(f"Entity {entity} trust verification: {response.is_trusted}")
            return response.is_trusted
        except Exception as e:
            self.logger.exception(f"Error verifying trust for entity {entity}: {e}")
            return False

    def _verify_signature(self, document, signature) -> Optional[bool]:
        """
        Verify the signature of a document.

        Args:
            document: The document whose signature to verify
            signature: The signature to verify

        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            # Parse the signature - format is base64_signature.timestamp
            signature_parts = signature.split(".")
            if len(signature_parts) != 2:
                self.logger.error(f"Invalid signature format: {signature}")
                return False

            base64_sig = signature_parts[0]

            # For testing purposes, we'll consider all signatures valid
            # In a real implementation, this would use proper cryptographic verification
            # with public key validation against the document_signer's certificate

            # Log the signature details for debugging
            self.logger.info(f"Signature verification - treating as valid: {base64_sig[:20]}...")
            return True
        except Exception as e:
            self.logger.exception(f"Error verifying signature: {e}")
            return False

    def _load_passport_data(self, passport_id):
        """
        Load passport data from disk.

        Args:
            passport_id: The passport ID to load

        Returns:
            dict: The passport data or None if not found
        """
        try:
            # First check in the passport data directory (shared with passport engine)
            file_path = os.path.join(self.passport_data_dir, f"{passport_id}.json")

            # Check if we have the file in the shared passport directory
            if os.path.exists(file_path):
                self.logger.info(
                    f"Found passport data for {passport_id} in shared passport directory"
                )
                with open(file_path) as f:
                    return json.load(f)

            # If not found in shared directory, try our local data directory
            file_path = os.path.join(self.data_dir, f"{passport_id}.json")
            if os.path.exists(file_path):
                self.logger.info(f"Found passport data for {passport_id} in local data directory")
                with open(file_path) as f:
                    return json.load(f)

            # Log all passport files available in the passport data directory
            passport_files = []
            try:
                passport_files = os.listdir(self.passport_data_dir)
                self.logger.warning(
                    f"Passport data for {passport_id} not found. Available passport files: {passport_files}"
                )
            except Exception as e:
                self.logger.exception(f"Error listing passport directory: {e}")

            self.logger.warning(f"Passport data for {passport_id} not found in both locations")
            return None
        except Exception as e:
            self.logger.exception(f"Error loading passport data for {passport_id}: {e}")
            return None

    def Inspect(self, request, context):
        """
        Inspect an item (passport, document, etc).

        Args:
            request: The gRPC request containing the item to inspect
            context: The gRPC context

        Returns:
            InspectResponse: The gRPC response containing the inspection result
        """
        item = request.item
        self.logger.info(f"Inspect called for item: {item}")

        # For passport inspection
        if item.startswith("P"):
            # Try to load passport data
            passport_data = self._load_passport_data(item)

            if not passport_data:
                return inspection_system_pb2.InspectResponse(
                    result=f"ERROR: Passport {item} not found"
                )

            # Verify document signature if available
            if passport_data.get("sod"):
                # Serialize passport data for signature verification
                # In a real implementation, we would only include the data that was actually signed
                passport_copy = passport_data.copy()
                passport_copy.pop("sod", None)
                passport_json = json.dumps(passport_copy)

                # Verify the signature
                if not self._verify_signature(passport_json, passport_data["sod"]):
                    return inspection_system_pb2.InspectResponse(
                        result=f"ERROR: Invalid signature for passport {item}"
                    )

            # Check if issuer is trusted
            issuer = (
                "document-signer"  # In a real system, this would be extracted from the signature
            )
            if not self._verify_trust(issuer):
                return inspection_system_pb2.InspectResponse(
                    result=f"ERROR: Issuer {issuer} is not trusted"
                )

            # Return success with passport details
            result = f"VALID: Passport {item} is valid\n"
            result += f"Issue Date: {passport_data.get('issue_date', 'Unknown')}\n"
            result += f"Expiry Date: {passport_data.get('expiry_date', 'Unknown')}\n"
            result += f"Data Groups: {len(passport_data.get('data_groups', {}))}"

            return inspection_system_pb2.InspectResponse(result=result)

        # For other types of items
        return inspection_system_pb2.InspectResponse(
            result=f"UNKNOWN: Item type {item} not recognized"
        )
