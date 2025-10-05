from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from marty_common.infrastructure import CertificateRepository, KeyVaultClient, ObjectStorageClient
from src.marty_common.security.passport_crypto_validator import PassportCryptoValidator
from src.marty_common.vc.sd_jwt_verifier import SdJwtVerifier
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

    def __init__(self, channels: dict[str, Any] | None, dependencies: ServiceDependencies) -> None:
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
        except Exception as e:
            self.logger.exception(f"Error verifying trust for entity {entity}: {e}")
            return False
        else:
            return response.is_trusted

    async def _verify_signature(self, document, signature) -> bool | None:
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
            public_key.verify(
                signature_bytes, document.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
            )
            self.logger.info("Signature verified for document")
        except Exception as e:
            self.logger.exception("Error verifying signature: %s", e)
            return False
        else:
            return True

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
            self.logger.warning(
                "Object storage lookup failed for %s: %s", passport_id, storage_error
            )

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
                    self.logger.warning(
                        "Failed to parse CSCA certificate %s", record.certificate_id
                    )
            return anchors

        try:
            return await self._database.run_within_transaction(handler)
        except Exception:  # pylint: disable=broad-except
            self.logger.exception("Unable to load CSCA trust anchors from repository")
            return []

    async def _load_wallet_attestation_certificates(self) -> list[x509.Certificate]:
        """Load wallet provider certificates when available."""

        async def handler(session):
            repo = CertificateRepository(session)
            records = await repo.list_by_type("WALLET_ATTESTATION")
            anchors: list[x509.Certificate] = []
            for record in records:
                if not record.pem:
                    continue
                try:
                    anchors.append(x509.load_pem_x509_certificate(record.pem.encode("utf-8")))
                except ValueError:
                    self.logger.warning(
                        "Failed to parse wallet attestation certificate %s",
                        record.certificate_id,
                    )
            return anchors

        try:
            return await self._database.run_within_transaction(handler)
        except Exception:  # pylint: disable=broad-except
            self.logger.exception("Unable to load wallet attestation certificates")
            return []

    def Inspect(
        self,
        request: ProtoMessage,
        context: GrpcServicerContext,
    ) -> ProtoMessage:
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

        parsed_payload: dict[str, Any] | None
        try:
            parsed_payload = json.loads(item)
        except json.JSONDecodeError:
            parsed_payload = None

        if isinstance(parsed_payload, dict) and parsed_payload.get("format") == "vc+sd-jwt":
            result_text = await self._inspect_sd_jwt(parsed_payload)
            return inspection_system_pb2.InspectResponse(result=result_text)

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

            mrz_detail = (
                ", ".join(mrz_result.errors) if mrz_result.errors else "MRZ check digits verified"
            )
            lines.append(f"MRZ: {'PASS' if mrz_result.is_valid else 'FAIL'} ({mrz_detail})")

            sod_detail = (
                ", ".join(sod_result.errors)
                if sod_result.errors
                else f"hashes={len(sod_result.expected_hashes)}"
            )
            lines.append(
                f"SOD Integrity: {'PASS' if sod_result.is_valid else 'FAIL'} ({sod_detail})"
            )

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

    async def _inspect_sd_jwt(self, payload: dict[str, Any]) -> str:
        credential = payload.get("credential") or payload.get("sd_jwt")
        disclosures = payload.get("disclosures") or []
        wallet_attestation = payload.get("wallet_attestation")

        if not credential:
            return "ERROR: SD-JWT credential missing"

        if not isinstance(disclosures, (list, tuple)):
            return "ERROR: disclosures must be a list"

        trust_anchors = await self._load_trust_anchors()
        wallet_anchors = await self._load_wallet_attestation_certificates()
        verifier = SdJwtVerifier(trust_anchors, wallet_anchors)

        if isinstance(wallet_attestation, dict):
            attestation_payload = json.dumps(wallet_attestation)
        else:
            attestation_payload = (
                wallet_attestation if isinstance(wallet_attestation, str) else None
            )

        result = verifier.verify(
            credential,
            disclosures,
            wallet_attestation=attestation_payload,
        )

        lines: list[str] = []
        lines.append("SD-JWT VERIFICATION: PASS" if result.valid else "SD-JWT VERIFICATION: FAIL")
        issuer = result.payload.get("iss", "unknown")
        subject = result.payload.get("sub", "unknown")
        lines.append(f"Issuer: {issuer}")
        lines.append(f"Subject: {subject}")
        if result.certificate_subject:
            lines.append(f"Signer Certificate: {result.certificate_subject}")

        if result.disclosures:
            lines.append("Disclosed Claims:")
            for key, value in result.disclosures.items():
                value_repr = json.dumps(value) if isinstance(value, (dict, list)) else value
                lines.append(f"  - {key}: {value_repr}")

        if result.errors:
            lines.append("Errors:")
            lines.extend(f"  - {err}" for err in result.errors)

        if result.warnings:
            lines.append("Warnings:")
            lines.extend(f"  - {warn}" for warn in result.warnings)

        return "\n".join(lines)

    async def VerifyPresentation(
        self, 
        request: ProtoMessage,  # inspection_system_pb2.VerifyPresentationRequest
        context: GrpcServicerContext,  # grpc.ServicerContext
    ) -> ProtoMessage:  # inspection_system_pb2.VerifyPresentationResponse
        """Verify an OID4VP presentation against a presentation definition."""
        try:
            # Parse the VP token (can be SD-JWT or other format)
            vp_token = request.vp_token
            presentation_definition = request.presentation_definition
            nonce = request.nonce
            
            # Load presentation definition from DB if ID provided
            if request.presentation_definition_id:
                pd_data = await self._load_presentation_definition(request.presentation_definition_id)
                if pd_data:
                    presentation_definition = json.dumps(pd_data)
            
            if not presentation_definition:
                return inspection_system_pb2.VerifyPresentationResponse(
                    valid=False,
                    errors=["Missing presentation definition"]
                )
            
            pd_obj = json.loads(presentation_definition)
            verification_result = await self._verify_vp_token_against_pd(vp_token, pd_obj, nonce)
            
            return inspection_system_pb2.VerifyPresentationResponse(
                valid=verification_result.valid,
                errors=verification_result.errors,
                warnings=verification_result.warnings,
                disclosed_claims=json.dumps(verification_result.disclosed_claims),
                issuer=verification_result.issuer,
                subject=verification_result.subject
            )
            
        except Exception as e:
            self.logger.exception("Failed to verify presentation")
            return inspection_system_pb2.VerifyPresentationResponse(
                valid=False,
                errors=[f"Verification failed: {str(e)}"]
            )

    async def _load_presentation_definition(self, pd_id: str) -> dict[str, Any] | None:
        """Load presentation definition from database or config."""
        try:
            # Try to load from object storage first
            storage_key = f"presentation-definitions/{pd_id}.json"
            payload = await self._object_storage.get_object(storage_key)
            return json.loads(payload.decode("utf-8"))
        except Exception:
            self.logger.warning(f"Could not load presentation definition {pd_id} from storage")
            
        # Fallback to loading from config directory
        try:
            config_path = f"/app/config/pd/{pd_id}.json"
            if os.path.exists(config_path):
                with open(config_path) as f:
                    return json.load(f)
        except Exception as e:
            self.logger.warning(f"Could not load presentation definition {pd_id} from config: {e}")
            
        return None

    async def _verify_vp_token_against_pd(self, vp_token: str, pd: dict[str, Any], nonce: str | None) -> 'VerificationResult':
        """Verify a VP token against a presentation definition."""
        class VerificationResult:
            def __init__(self):
                self.valid = False
                self.errors: list[str] = []
                self.warnings: list[str] = []
                self.disclosed_claims: dict[str, Any] = {}
                self.issuer = ""
                self.subject = ""
        
        result = VerificationResult()
        
        try:
            # Check if it's an SD-JWT format
            if "~" in vp_token or vp_token.count(".") >= 2:
                # Parse SD-JWT presentation
                sd_jwt_result = await self._verify_sd_jwt_presentation(vp_token, pd, nonce)
                result.valid = sd_jwt_result.valid
                result.errors = sd_jwt_result.errors
                result.warnings = sd_jwt_result.warnings
                result.disclosed_claims = sd_jwt_result.disclosed_claims
                result.issuer = sd_jwt_result.issuer
                result.subject = sd_jwt_result.subject
            else:
                result.errors.append("Unsupported VP token format")
                
        except Exception as e:
            result.errors.append(f"Token verification error: {str(e)}")
            
        return result

    async def _verify_sd_jwt_presentation(self, sd_jwt_token: str, pd: dict[str, Any], nonce: str | None) -> 'SdJwtVerificationResult':
        """Verify an SD-JWT presentation token against presentation definition."""
        class SdJwtVerificationResult:
            def __init__(self):
                self.valid = False
                self.errors: list[str] = []
                self.warnings: list[str] = []
                self.disclosed_claims: dict[str, Any] = {}
                self.issuer = ""
                self.subject = ""
        
        result = SdJwtVerificationResult()
        
        try:
            # Split SD-JWT token into parts (JWT~disclosure1~disclosure2~...~)
            parts = sd_jwt_token.split("~")
            jwt_part = parts[0]
            disclosures = [part for part in parts[1:] if part]
            
            # Load trust anchors for verification
            trust_anchors = await self._load_trust_anchors()
            wallet_anchors = await self._load_wallet_attestation_certificates()
            verifier = SdJwtVerifier(trust_anchors, wallet_anchors)
            
            # Verify the SD-JWT
            verification = verifier.verify(jwt_part, disclosures)
            
            if not verification.valid:
                result.errors.extend(verification.errors)
                return result
            
            # Extract issuer and subject
            result.issuer = verification.payload.get("iss", "")
            result.subject = verification.payload.get("sub", "")
            result.disclosed_claims = verification.disclosures
            
            # Verify against presentation definition
            pd_result = self._check_presentation_definition_compliance(
                verification.payload, 
                verification.disclosures, 
                pd
            )
            
            result.valid = pd_result.valid
            result.errors.extend(pd_result.errors)
            result.warnings.extend(pd_result.warnings)
            
            # Verify nonce if provided
            if nonce:
                token_nonce = verification.payload.get("nonce")
                if token_nonce != nonce:
                    result.valid = False
                    result.errors.append("Nonce mismatch")
            
        except Exception as e:
            result.errors.append(f"SD-JWT verification error: {str(e)}")
            
        return result

    def _check_presentation_definition_compliance(
        self, 
        payload: dict[str, Any], 
        disclosures: dict[str, Any], 
        pd: dict[str, Any]
    ) -> 'ComplianceResult':
        """Check if the disclosed claims comply with presentation definition requirements."""
        class ComplianceResult:
            def __init__(self):
                self.valid = True
                self.errors: list[str] = []
                self.warnings: list[str] = []
        
        result = ComplianceResult()
        
        try:
            # Get input descriptors from presentation definition
            input_descriptors = pd.get("input_descriptors", [])
            
            for descriptor in input_descriptors:
                descriptor_id = descriptor.get("id", "unknown")
                constraints = descriptor.get("constraints", {})
                fields = constraints.get("fields", [])
                
                for field in fields:
                    path = field.get("path", [])
                    optional = field.get("optional", False)
                    
                    # Check if required fields are present
                    field_found = False
                    for json_path in path:
                        # Simple path checking (could be enhanced with JSONPath library)
                        field_name = json_path.replace("$.", "").replace("$.vc.credentialSubject.", "")
                        
                        if field_name in payload or field_name in disclosures:
                            field_found = True
                            break
                    
                    if not field_found and not optional:
                        result.valid = False
                        result.errors.append(f"Required field missing: {field.get('path')} in descriptor {descriptor_id}")
                        
                    # Check field filters if present
                    if field_found and "filter" in field:
                        filter_result = self._apply_field_filter(
                            payload.get(field_name) or disclosures.get(field_name),
                            field["filter"]
                        )
                        if not filter_result.valid:
                            result.valid = False
                            result.errors.extend(filter_result.errors)
                            
        except Exception as e:
            result.valid = False
            result.errors.append(f"Presentation definition compliance check error: {str(e)}")
            
        return result

    def _apply_field_filter(self, value: Any, filter_spec: dict[str, Any]) -> 'FilterResult':
        """Apply field filter to a disclosed value."""
        class FilterResult:
            def __init__(self):
                self.valid = True
                self.errors: list[str] = []
        
        result = FilterResult()
        
        try:
            # Handle type constraints
            if "type" in filter_spec:
                expected_type = filter_spec["type"]
                if expected_type == "string" and not isinstance(value, str):
                    result.valid = False
                    result.errors.append(f"Expected string, got {type(value).__name__}")
                elif expected_type == "number" and not isinstance(value, (int, float)):
                    result.valid = False
                    result.errors.append(f"Expected number, got {type(value).__name__}")
                elif expected_type == "boolean" and not isinstance(value, bool):
                    result.valid = False
                    result.errors.append(f"Expected boolean, got {type(value).__name__}")
            
            # Handle const constraints
            if "const" in filter_spec:
                if value != filter_spec["const"]:
                    result.valid = False
                    result.errors.append(f"Expected constant value {filter_spec['const']}, got {value}")
            
            # Handle enum constraints
            if "enum" in filter_spec:
                if value not in filter_spec["enum"]:
                    result.valid = False
                    result.errors.append(f"Value {value} not in allowed values {filter_spec['enum']}")
                    
            # Handle pattern constraints (for strings)
            if "pattern" in filter_spec and isinstance(value, str):
                import re
                pattern = filter_spec["pattern"]
                if not re.match(pattern, value):
                    result.valid = False
                    result.errors.append(f"Value '{value}' does not match pattern '{pattern}'")
                    
        except Exception as e:
            result.valid = False
            result.errors.append(f"Filter application error: {str(e)}")
            
        return result
