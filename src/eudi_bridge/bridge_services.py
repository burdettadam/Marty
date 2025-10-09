"""
EUDI Bridge Services

Core bridge services for translating between ICAO/mDL formats and EUDI-compatible
Verifiable Credentials. This module provides the translation layer that enables
Marty's existing PKI and mDL systems to work seamlessly with the EUDI ecosystem.

Note: This is for standards exploration and roadmap development.
Production security separation maintained.
"""

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union

# Conditional imports for external dependencies
try:
    import jwt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    x509 = None
    jwt = None


class CredentialFormat(Enum):
    """Supported credential formats."""

    ICAO_MRTD = "icao_mrtd"
    MDL = "mdl"
    EUDI_VC = "eudi_vc"
    SD_JWT_VC = "sd_jwt_vc"
    MDOC = "mdoc"


class VerificationStatus(Enum):
    """Verification status for credential translation."""

    VALID = "valid"
    INVALID = "invalid"
    PENDING = "pending"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class CredentialMetadata:
    """Metadata for credential translation."""

    source_format: CredentialFormat
    target_format: CredentialFormat
    issuer_id: str
    subject_id: str
    issuance_date: datetime
    expiration_date: datetime | None
    verification_status: VerificationStatus
    trust_anchor: str | None
    policy_constraints: list[str]


@dataclass
class TranslationResult:
    """Result of credential translation."""

    success: bool
    target_credential: dict[str, Any] | None
    metadata: CredentialMetadata
    errors: list[str]
    warnings: list[str]
    eudi_compliance_score: float


class EUDIBridgeService:
    """
    Core EUDI Bridge Service for translating between credential formats.

    This service provides the main translation functionality for converting
    ICAO MRTD and mDL credentials into EUDI-compatible formats while
    preserving cryptographic integrity and trust relationships.
    """

    def __init__(self, trust_store_path: str, eudi_config: dict[str, Any]):
        """Initialize the EUDI Bridge Service."""
        self.trust_store_path = trust_store_path
        self.eudi_config = eudi_config
        self.logger = logging.getLogger(__name__)

        # Load trust store for ICAO verification
        self.trust_store = self._load_trust_store()

        # EUDI ARF compliance settings
        self.eudi_arf_version = "2.4.0"
        self.supported_algorithms = ["ES256", "ES384", "ES512", "RS256"]
        self.max_credential_age_days = 90

    def _load_trust_store(self) -> dict[str, Any]:
        """Load ICAO trust store for verification."""
        try:
            with open(self.trust_store_path, encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            self.logger.warning(f"Could not load trust store: {e}")
            return {}

    def translate_icao_to_eudi(
        self,
        icao_credential: dict[str, Any],
        target_format: CredentialFormat = CredentialFormat.SD_JWT_VC,
    ) -> TranslationResult:
        """
        Translate ICAO MRTD credential to EUDI format.

        Args:
            icao_credential: The ICAO credential data
            target_format: Target EUDI credential format

        Returns:
            TranslationResult with translated credential
        """
        errors = []
        warnings = []

        try:
            # Extract ICAO data
            icao_data = self._extract_icao_data(icao_credential)
            if not icao_data:
                errors.append("Failed to extract ICAO data")

            # Verify ICAO trust chain
            verification_result = self._verify_icao_trust_chain(icao_credential)
            if not verification_result.get("valid", False):
                warnings.append("ICAO trust chain verification failed")

            # Create EUDI-compatible credential
            if target_format == CredentialFormat.SD_JWT_VC:
                eudi_credential = self._create_sd_jwt_vc(icao_data)
            elif target_format == CredentialFormat.EUDI_VC:
                eudi_credential = self._create_eudi_vc(icao_data)
            else:
                errors.append(f"Unsupported target format: {target_format}")
                eudi_credential = None

            # Calculate compliance score
            compliance_score = self._calculate_eudi_compliance_score(icao_data, eudi_credential)

            # Create metadata
            metadata = CredentialMetadata(
                source_format=CredentialFormat.ICAO_MRTD,
                target_format=target_format,
                issuer_id=icao_data.get("issuer", "unknown"),
                subject_id=icao_data.get("subject_id", "unknown"),
                issuance_date=datetime.now(),
                expiration_date=icao_data.get("expiration_date"),
                verification_status=(
                    VerificationStatus.VALID if not errors else VerificationStatus.INVALID
                ),
                trust_anchor=verification_result.get("trust_anchor"),
                policy_constraints=[],
            )

            return TranslationResult(
                success=len(errors) == 0,
                target_credential=eudi_credential,
                metadata=metadata,
                errors=errors,
                warnings=warnings,
                eudi_compliance_score=compliance_score,
            )

        except Exception as e:
            self.logger.error(f"Translation failed: {e}")
            errors.append(f"Translation error: {str(e)}")

            metadata = CredentialMetadata(
                source_format=CredentialFormat.ICAO_MRTD,
                target_format=target_format,
                issuer_id="unknown",
                subject_id="unknown",
                issuance_date=datetime.now(),
                expiration_date=None,
                verification_status=VerificationStatus.INVALID,
                trust_anchor=None,
                policy_constraints=[],
            )

            return TranslationResult(
                success=False,
                target_credential=None,
                metadata=metadata,
                errors=errors,
                warnings=warnings,
                eudi_compliance_score=0.0,
            )

    def translate_mdl_to_eudi(
        self,
        mdl_credential: dict[str, Any],
        target_format: CredentialFormat = CredentialFormat.MDOC,
    ) -> TranslationResult:
        """
        Translate mDL credential to EUDI format.

        Args:
            mdl_credential: The mDL credential data
            target_format: Target EUDI credential format

        Returns:
            TranslationResult with translated credential
        """
        errors = []
        warnings = []

        try:
            # Extract mDL data
            mdl_data = self._extract_mdl_data(mdl_credential)
            if not mdl_data:
                errors.append("Failed to extract mDL data")

            # Verify mDL integrity
            verification_result = self._verify_mdl_integrity(mdl_credential)
            if not verification_result.get("valid", False):
                warnings.append("mDL integrity verification failed")

            # Create EUDI-compatible credential
            if target_format == CredentialFormat.MDOC:
                eudi_credential = self._create_mdoc(mdl_data)
            elif target_format == CredentialFormat.SD_JWT_VC:
                eudi_credential = self._create_sd_jwt_from_mdl(mdl_data)
            else:
                errors.append(f"Unsupported target format: {target_format}")
                eudi_credential = None

            # Calculate compliance score
            compliance_score = self._calculate_eudi_compliance_score(mdl_data, eudi_credential)

            # Create metadata
            metadata = CredentialMetadata(
                source_format=CredentialFormat.MDL,
                target_format=target_format,
                issuer_id=mdl_data.get("issuer", "unknown"),
                subject_id=mdl_data.get("subject_id", "unknown"),
                issuance_date=datetime.now(),
                expiration_date=mdl_data.get("expiration_date"),
                verification_status=(
                    VerificationStatus.VALID if not errors else VerificationStatus.INVALID
                ),
                trust_anchor=verification_result.get("trust_anchor"),
                policy_constraints=[],
            )

            return TranslationResult(
                success=len(errors) == 0,
                target_credential=eudi_credential,
                metadata=metadata,
                errors=errors,
                warnings=warnings,
                eudi_compliance_score=compliance_score,
            )

        except Exception as e:
            self.logger.error(f"mDL translation failed: {e}")
            errors.append(f"Translation error: {str(e)}")

            metadata = CredentialMetadata(
                source_format=CredentialFormat.MDL,
                target_format=target_format,
                issuer_id="unknown",
                subject_id="unknown",
                issuance_date=datetime.now(),
                expiration_date=None,
                verification_status=VerificationStatus.INVALID,
                trust_anchor=None,
                policy_constraints=[],
            )

            return TranslationResult(
                success=False,
                target_credential=None,
                metadata=metadata,
                errors=errors,
                warnings=warnings,
                eudi_compliance_score=0.0,
            )

    def _extract_icao_data(self, icao_credential: dict[str, Any]) -> dict[str, Any]:
        """Extract structured data from ICAO credential."""
        try:
            # Extract key ICAO fields for EUDI translation
            return {
                "document_type": icao_credential.get("document_type", "P"),
                "issuing_state": icao_credential.get("issuing_state"),
                "document_number": icao_credential.get("document_number"),
                "given_names": icao_credential.get("given_names"),
                "surname": icao_credential.get("surname"),
                "nationality": icao_credential.get("nationality"),
                "date_of_birth": icao_credential.get("date_of_birth"),
                "sex": icao_credential.get("sex"),
                "date_of_expiry": icao_credential.get("date_of_expiry"),
                "personal_number": icao_credential.get("personal_number"),
                "issuer": icao_credential.get("issuing_state", "unknown"),
                "subject_id": icao_credential.get("document_number", "unknown"),
                "expiration_date": self._parse_date(icao_credential.get("date_of_expiry")),
            }
        except Exception as e:
            self.logger.error(f"Failed to extract ICAO data: {e}")
            return {}

    def _extract_mdl_data(self, mdl_credential: dict[str, Any]) -> dict[str, Any]:
        """Extract structured data from mDL credential."""
        try:
            # Extract key mDL fields for EUDI translation
            return {
                "family_name": mdl_credential.get("family_name"),
                "given_name": mdl_credential.get("given_name"),
                "birth_date": mdl_credential.get("birth_date"),
                "issue_date": mdl_credential.get("issue_date"),
                "expiry_date": mdl_credential.get("expiry_date"),
                "issuing_country": mdl_credential.get("issuing_country"),
                "issuing_authority": mdl_credential.get("issuing_authority"),
                "document_number": mdl_credential.get("document_number"),
                "driving_privileges": mdl_credential.get("driving_privileges", []),
                "portrait": mdl_credential.get("portrait"),
                "issuer": mdl_credential.get("issuing_authority", "unknown"),
                "subject_id": mdl_credential.get("document_number", "unknown"),
                "expiration_date": self._parse_date(mdl_credential.get("expiry_date")),
            }
        except Exception as e:
            self.logger.error(f"Failed to extract mDL data: {e}")
            return {}

    def _parse_date(self, date_str: str | None) -> datetime | None:
        """Parse date string to datetime object."""
        if not date_str:
            return None
        try:
            # Try common date formats
            for fmt in ["%Y-%m-%d", "%Y%m%d", "%d/%m/%Y", "%m/%d/%Y"]:
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
            return None
        except Exception:
            return None

    def _verify_icao_trust_chain(self, icao_credential: dict[str, Any]) -> dict[str, Any]:
        """Verify ICAO trust chain using loaded trust store."""
        # For standards exploration, return mock verification
        # Production would implement full ICAO PKI verification
        return {
            "valid": True,
            "trust_anchor": "ICAO_ROOT_CA",
            "verification_time": datetime.now().isoformat(),
            "note": "Standards exploration - production verification required",
        }

    def _verify_mdl_integrity(self, mdl_credential: dict[str, Any]) -> dict[str, Any]:
        """Verify mDL integrity and authenticity."""
        # For standards exploration, return mock verification
        # Production would implement full mDL verification
        return {
            "valid": True,
            "trust_anchor": "MDL_ISSUING_AUTHORITY",
            "verification_time": datetime.now().isoformat(),
            "note": "Standards exploration - production verification required",
        }

    def _create_sd_jwt_vc(self, icao_data: dict[str, Any]) -> dict[str, Any]:
        """Create SD-JWT VC from ICAO data."""
        # Create EUDI-compliant SD-JWT VC
        now = datetime.now()

        vc_claims = {
            "iss": f"https://marty.eudi.bridge/icao/{icao_data.get('issuer', 'unknown')}",
            "sub": icao_data.get("subject_id", "unknown"),
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(days=self.max_credential_age_days)).timestamp()),
            "vct": "https://eudi.europa.eu/vc/icao_identity",
            "vc": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://eudi.europa.eu/contexts/icao/v1",
                ],
                "type": ["VerifiableCredential", "ICAOIdentityCredential"],
                "credentialSubject": {
                    "id": f"did:eudi:{icao_data.get('subject_id', 'unknown')}",
                    "document_type": icao_data.get("document_type"),
                    "issuing_state": icao_data.get("issuing_state"),
                    "given_names": icao_data.get("given_names"),
                    "surname": icao_data.get("surname"),
                    "nationality": icao_data.get("nationality"),
                    "date_of_birth": icao_data.get("date_of_birth"),
                    "sex": icao_data.get("sex"),
                },
            },
        }

        return vc_claims

    def _create_eudi_vc(self, icao_data: dict[str, Any]) -> dict[str, Any]:
        """Create standard EUDI VC from ICAO data."""
        now = datetime.now()

        return {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://eudi.europa.eu/contexts/icao/v1",
            ],
            "type": ["VerifiableCredential", "ICAOIdentityCredential"],
            "issuer": f"https://marty.eudi.bridge/icao/{icao_data.get('issuer', 'unknown')}",
            "issuanceDate": now.isoformat(),
            "expirationDate": (now + timedelta(days=self.max_credential_age_days)).isoformat(),
            "credentialSubject": {
                "id": f"did:eudi:{icao_data.get('subject_id', 'unknown')}",
                "document_type": icao_data.get("document_type"),
                "issuing_state": icao_data.get("issuing_state"),
                "given_names": icao_data.get("given_names"),
                "surname": icao_data.get("surname"),
                "nationality": icao_data.get("nationality"),
                "date_of_birth": icao_data.get("date_of_birth"),
                "sex": icao_data.get("sex"),
            },
        }

    def _create_mdoc(self, mdl_data: dict[str, Any]) -> dict[str, Any]:
        """Create EUDI mDoc from mDL data."""
        now = datetime.now()

        return {
            "version": "1.0",
            "documents": [
                {
                    "docType": "org.iso.18013.5.1.mDL",
                    "issuer": f"https://marty.eudi.bridge/mdl/{mdl_data.get('issuer', 'unknown')}",
                    "issuanceDate": now.isoformat(),
                    "expirationDate": (
                        now + timedelta(days=self.max_credential_age_days)
                    ).isoformat(),
                    "nameSpaces": {
                        "org.iso.18013.5.1": {
                            "family_name": mdl_data.get("family_name"),
                            "given_name": mdl_data.get("given_name"),
                            "birth_date": mdl_data.get("birth_date"),
                            "issue_date": mdl_data.get("issue_date"),
                            "expiry_date": mdl_data.get("expiry_date"),
                            "issuing_country": mdl_data.get("issuing_country"),
                            "issuing_authority": mdl_data.get("issuing_authority"),
                            "document_number": mdl_data.get("document_number"),
                            "driving_privileges": mdl_data.get("driving_privileges", []),
                        }
                    },
                }
            ],
        }

    def _create_sd_jwt_from_mdl(self, mdl_data: dict[str, Any]) -> dict[str, Any]:
        """Create SD-JWT VC from mDL data."""
        now = datetime.now()

        vc_claims = {
            "iss": f"https://marty.eudi.bridge/mdl/{mdl_data.get('issuer', 'unknown')}",
            "sub": mdl_data.get("subject_id", "unknown"),
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(days=self.max_credential_age_days)).timestamp()),
            "vct": "https://eudi.europa.eu/vc/mdl_identity",
            "vc": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://eudi.europa.eu/contexts/mdl/v1",
                ],
                "type": ["VerifiableCredential", "DrivingLicenseCredential"],
                "credentialSubject": {
                    "id": f"did:eudi:{mdl_data.get('subject_id', 'unknown')}",
                    "family_name": mdl_data.get("family_name"),
                    "given_name": mdl_data.get("given_name"),
                    "birth_date": mdl_data.get("birth_date"),
                    "issuing_country": mdl_data.get("issuing_country"),
                    "issuing_authority": mdl_data.get("issuing_authority"),
                    "driving_privileges": mdl_data.get("driving_privileges", []),
                },
            },
        }

        return vc_claims

    def _calculate_eudi_compliance_score(
        self, source_data: dict[str, Any], target_credential: dict[str, Any] | None
    ) -> float:
        """Calculate EUDI compliance score for translated credential."""
        if not target_credential:
            return 0.0

        score = 0.0
        max_score = 100.0

        # Check required fields (40 points)
        required_fields = ["iss", "sub", "iat", "exp"]
        field_score = 0
        for field in required_fields:
            if field in target_credential:
                field_score += 10
        score += field_score

        # Check EUDI context (20 points)
        if "@context" in target_credential:
            contexts = target_credential.get("@context", [])
            if any("eudi.europa.eu" in str(ctx) for ctx in contexts):
                score += 20

        # Check credential structure (20 points)
        if "credentialSubject" in target_credential:
            score += 10
            if "id" in target_credential.get("credentialSubject", {}):
                score += 10

        # Check expiration handling (10 points)
        if "exp" in target_credential or "expirationDate" in target_credential:
            score += 10

        # Check issuer format (10 points)
        issuer = target_credential.get("iss") or target_credential.get("issuer")
        if issuer and "https://" in str(issuer):
            score += 10

        return min(score, max_score) / max_score


class EUDITrustService:
    """
    EUDI Trust Service for managing trust relationships and validation.

    This service handles trust establishment between ICAO/mDL trust anchors
    and EUDI wallet ecosystems, providing the necessary trust translation
    and validation services.
    """

    def __init__(self, trust_config: dict[str, Any]):
        """Initialize the EUDI Trust Service."""
        self.trust_config = trust_config
        self.logger = logging.getLogger(__name__)

        # Trust anchor mappings
        self.icao_trust_anchors = {}
        self.mdl_trust_anchors = {}
        self.eudi_trust_lists = {}

    def establish_trust_mapping(
        self, source_anchor: str, source_type: str, eudi_trust_list: str
    ) -> bool:
        """Establish trust mapping between source anchor and EUDI trust list."""
        try:
            mapping = {
                "source_anchor": source_anchor,
                "source_type": source_type,
                "eudi_trust_list": eudi_trust_list,
                "established_at": datetime.now().isoformat(),
                "status": "active",
            }

            if source_type == "icao":
                self.icao_trust_anchors[source_anchor] = mapping
            elif source_type == "mdl":
                self.mdl_trust_anchors[source_anchor] = mapping

            self.logger.info(f"Trust mapping established: {source_anchor} -> {eudi_trust_list}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to establish trust mapping: {e}")
            return False

    def validate_trust_chain(self, credential_issuer: str, credential_type: str) -> dict[str, Any]:
        """Validate trust chain for credential issuer."""
        try:
            trust_anchors = (
                self.icao_trust_anchors if credential_type == "icao" else self.mdl_trust_anchors
            )

            # Find matching trust anchor
            matching_anchor = None
            for anchor_id, mapping in trust_anchors.items():
                if credential_issuer.startswith(anchor_id):
                    matching_anchor = mapping
                    break

            if not matching_anchor:
                return {
                    "valid": False,
                    "error": "No matching trust anchor found",
                    "trust_level": "none",
                }

            return {
                "valid": True,
                "trust_anchor": matching_anchor["source_anchor"],
                "eudi_trust_list": matching_anchor["eudi_trust_list"],
                "trust_level": "verified",
                "validation_time": datetime.now().isoformat(),
            }

        except Exception as e:
            self.logger.error(f"Trust validation failed: {e}")
            return {"valid": False, "error": str(e), "trust_level": "error"}


# Factory function for creating bridge services
def create_eudi_bridge_service(
    trust_store_path: str = "/Users/adamburdett/Github/work/Marty/data/trust_store.json",
    eudi_config: dict[str, Any] | None = None,
) -> EUDIBridgeService:
    """
    Factory function to create configured EUDI Bridge Service.

    Args:
        trust_store_path: Path to ICAO trust store
        eudi_config: EUDI configuration settings

    Returns:
        Configured EUDIBridgeService instance
    """
    if eudi_config is None:
        eudi_config = {
            "arf_version": "2.4.0",
            "supported_formats": ["sd_jwt_vc", "eudi_vc", "mdoc"],
            "max_credential_age_days": 90,
            "compliance_mode": "strict",
        }

    return EUDIBridgeService(trust_store_path, eudi_config)


def create_eudi_trust_service(trust_config: dict[str, Any] | None = None) -> EUDITrustService:
    """
    Factory function to create configured EUDI Trust Service.

    Args:
        trust_config: Trust configuration settings

    Returns:
        Configured EUDITrustService instance
    """
    if trust_config is None:
        trust_config = {"trust_lists": [], "validation_mode": "strict", "cache_duration_hours": 24}

    return EUDITrustService(trust_config)
