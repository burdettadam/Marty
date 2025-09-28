import asyncio
import base64
import json
import logging
import os
from typing import Optional

import grpc
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from marty_common.infrastructure import (
    CertificateRepository,
    KeyVaultClient,
    ObjectStorageClient,
)
from src.marty_common.security.passport_crypto_validator import PassportCryptoValidator
from src.proto import (
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

    def __init__(self, channels=None, dependencies=None) -> None:
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
        if dependencies is None:
            msg = "InspectionSystem requires service dependencies"
            raise ValueError(msg)
        self._object_storage: ObjectStorageClient = dependencies.object_storage
        self._key_vault: KeyVaultClient = dependencies.key_vault
        self._database = dependencies.database
        self._signing_key_id = "document-signer-default"
        self.logger.info(
            f"Inspection System service initialized with data_dir={self.data_dir}, passport_data_dir={self.passport_data_dir}"
        )

        # Ensure data directories exist
        os.makedirs(self.data_dir, exist_ok=True)

    async def _verify_trust(self, entity):
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
            response = await trust_stub.VerifyTrust(trust_anchor_pb2.TrustRequest(entity=entity))

            self.logger.info(f"Entity {entity} trust verification: {response.is_trusted}")
            return response.is_trusted
        except Exception as e:
            self.logger.exception(f"Error verifying trust for entity {entity}: {e}")
            return False

    async def _verify_signature(self, document, signature) -> Optional[bool]:
        """
        Verify the signature of a document.

        Args:
            document: The document whose signature to verify
            signature: The signature to verify

        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            signature_bytes = bytes.fromhex(signature)
            public_pem = await self._key_vault.public_material(self._signing_key_id)
            public_key = serialization.load_pem_public_key(public_pem)
            public_key.verify(signature_bytes, document.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
            self.logger.info("Signature verified for document")
            return True
        except Exception as e:
            self.logger.exception("Error verifying signature: %s", e)
            return False

    async def _load_passport_data(self, passport_id):
        """
        Load passport data from disk.

        Args:
            passport_id: The passport ID to load

        Returns:
            dict: The passport data or None if not found
        """
        storage_key = f"passports/{passport_id}.json"
        try:
            payload = await self._object_storage.get_object(storage_key)
            return json.loads(payload.decode("utf-8"))
        except Exception as storage_error:  # pylint: disable=broad-except
            self.logger.warning("Object storage lookup failed for %s: %s", passport_id, storage_error)

        try:
            file_path = os.path.join(self.data_dir, f"{passport_id}.json")
            if os.path.exists(file_path):
                with open(file_path) as f:
                    return json.load(f)
        except Exception as e:
            self.logger.exception("Error reading fallback passport file for %s: %s", passport_id, e)

        self.logger.warning("Passport data for %s not found", passport_id)
        return None

    async def _load_trust_anchors(self) -> list[x509.Certificate]:
        """Load CSCA trust anchors from the certificate repository."""

        async def handler(session):
            repo = CertificateRepository(session)
            records = await repo.list_by_type("CSCA")
            anchors: list[x509.Certificate] = []
            for record in records:
                if not record.pem:
                    continue
                try:
                    anchors.append(x509.load_pem_x509_certificate(record.pem.encode("utf-8")))
                except ValueError:
                    self.logger.warning("Failed to parse CSCA certificate %s", record.certificate_id)
            return anchors

        try:
            return await self._database.run_within_transaction(handler)
        except Exception:  # pylint: disable=broad-except
            self.logger.exception("Unable to load CSCA trust anchors from repository")
            return []

    async def Inspect(self, request, context):
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
            passport_data = await self._load_passport_data(item)

            if not passport_data:
                return inspection_system_pb2.InspectResponse(
                    result=f"ERROR: Passport {item} not found"
                )

            sod_encoded = passport_data.get("sod")
            data_groups = passport_data.get("data_groups", {})
            if not sod_encoded or not data_groups:
                return inspection_system_pb2.InspectResponse(
                    result=f"ERROR: Passport {item} missing SOD or data groups"
                )

            try:
                sod_bytes = base64.b64decode(sod_encoded)
            except (TypeError, ValueError):
                try:
                    sod_bytes = bytes.fromhex(sod_encoded)
                except ValueError:
                    return inspection_system_pb2.InspectResponse(
                        result=f"ERROR: SOD for passport {item} is not valid base64/hex"
                    )

            validator = PassportCryptoValidator()
            trust_anchors = await self._load_trust_anchors()
            if trust_anchors:
                validator.load_trust_anchors(trust_anchors)

            sod_result = validator.verify_sod(sod_bytes, data_groups)

            mrz_source = data_groups.get("DG1")
            if not mrz_source:
                return inspection_system_pb2.InspectResponse(
                    result=f"ERROR: Passport {item} missing DG1/MRZ data"
                )

            mrz_bytes = PassportCryptoValidator.decode_maybe_base64(mrz_source)
            try:
                mrz_lines = mrz_bytes.decode("ascii")
            except UnicodeDecodeError:
                mrz_lines = mrz_bytes.decode("latin1")

            mrz_result = validator.validate_mrz(mrz_lines)
            cert_result = validator.validate_sod_certificate(sod_bytes, trust_anchors)

            issuer_trusted = True
            if cert_result.sod_certificate_subject:
                issuer_trusted = await self._verify_trust(cert_result.sod_certificate_subject)

            validation_success = (
                mrz_result.is_valid
                and sod_result.is_valid
                and cert_result.result.is_valid
                and issuer_trusted
            )

            status_prefix = "VALID" if validation_success else "ERROR"
            lines = [f"{status_prefix}: Passport {item}"]
            lines.append(f"Issue Date: {passport_data.get('issue_date', 'Unknown')}")
            lines.append(f"Expiry Date: {passport_data.get('expiry_date', 'Unknown')}")

            mrz_detail = ", ".join(mrz_result.errors) if mrz_result.errors else "MRZ check digits verified"
            lines.append(f"MRZ: {'PASS' if mrz_result.is_valid else 'FAIL'} ({mrz_detail})")

            sod_detail = (
                ", ".join(sod_result.errors)
                if sod_result.errors
                else f"hashes={len(sod_result.expected_hashes)}"
            )
            lines.append(f"SOD Integrity: {'PASS' if sod_result.is_valid else 'FAIL'} ({sod_detail})")

            chain_summary = (
                cert_result.result.error_summary
                if cert_result.result.errors
                else cert_result.sod_certificate_subject or "certificate ok"
            )
            lines.append(
                "Certificate Chain: "
                f"{'PASS' if cert_result.result.is_valid else 'FAIL'} ({chain_summary})"
            )

            if cert_result.sod_certificate_subject:
                lines.append(
                    "Issuer Trust: "
                    f"{'PASS' if issuer_trusted else 'FAIL'} ({cert_result.sod_certificate_subject})"
                )

            if not trust_anchors:
                lines.append("Trust Anchors: none loaded")
            else:
                lines.append(f"Trust Anchors: {len(trust_anchors)} loaded")

            return inspection_system_pb2.InspectResponse(result="\n".join(lines))

        # For other types of items
        return inspection_system_pb2.InspectResponse(
            result=f"UNKNOWN: Item type {item} not recognized"
        )
