"""
OIDC4VCI Issuer Facade for EUDI Compliance

This service provides an OpenID for Verifiable Credential Issuance (OIDC4VCI) facade
that enables minting of EUDI-compatible Verifiable Credentials derived from existing
ICAO PKI and mDL data sources.

Compliance:
- EUDI Architecture and Reference Framework v2.4.0
- OpenID4VCI specification
- ISO/IEC 18013-5 source compatibility
- ICAO Doc 9303 bridge support

Security Notice:
This implementation is for standards exploration. Production environments
must implement additional security controls per EUDI ARF requirements.
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, asdict
from urllib.parse import urljoin

# Conditional imports for external dependencies
try:
    import jwt
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from jwcrypto import jwk, jws
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    jwt = None
    jwk = None
    jws = None

# Internal imports with fallback for testing
try:
    from src.marty_common.types.verification_types import DocumentClass
    from src.marty_common.utils.logger import get_logger
    logger = get_logger(__name__)
except ImportError:
    # Fallback for testing without full Marty environment
    import logging
    logger = logging.getLogger(__name__)
    DocumentClass = None


@dataclass
class EUDICredentialMetadata:
    """EUDI-compliant credential metadata structure."""
    credential_issuer: str
    credential_endpoint: str
    token_endpoint: str
    supported_credential_formats: List[str]
    credential_configurations_supported: Dict[str, Any]
    issuer_display: Dict[str, Any]
    grant_types_supported: List[str]


@dataclass
class OIDC4VCICredentialOffer:
    """OIDC4VCI credential offer structure."""
    credential_issuer: str
    credential_configuration_ids: List[str]
    grants: Dict[str, Any]
    credential_offer_uri: Optional[str] = None


@dataclass
class VerifiableCredential:
    """EUDI-compatible Verifiable Credential structure."""
    context: List[str]
    id: str
    type: List[str]
    issuer: Union[str, Dict[str, Any]]
    issuance_date: str
    expiration_date: Optional[str]
    credential_subject: Dict[str, Any]
    proof: Optional[Dict[str, Any]] = None
    evidence: Optional[List[Dict[str, Any]]] = None


class OIDC4VCIIssuerFacade:
    """
    OIDC4VCI Issuer Facade for EUDI Compliance
    
    Provides an OIDC4VCI-compliant interface that can mint Verifiable Credentials
    from existing ICAO PKI and mDL data sources, enabling interoperability with
    the EU Digital Identity Wallet ecosystem.
    """
    
    def __init__(
        self,
        issuer_identifier: str,
        base_url: str,
        signing_key: Optional[Any] = None,  # jwk.JWK when available
        icao_bridge_enabled: bool = True,
        mdl_bridge_enabled: bool = True
    ):
        """
        Initialize the OIDC4VCI Issuer Facade.
        
        Args:
            issuer_identifier: Unique identifier for this issuer
            base_url: Base URL for OIDC4VCI endpoints
            signing_key: JWK for signing credentials (generates if None)
            icao_bridge_enabled: Enable ICAO PKI source bridging
            mdl_bridge_enabled: Enable mDL source bridging
        """
        if not JWT_AVAILABLE:
            raise ImportError(
                "JWT dependencies not available. Install with: pip install pyjwt[crypto] jwcrypto"
            )
            
        self.issuer_identifier = issuer_identifier
        self.base_url = base_url.rstrip('/')
        self.icao_bridge_enabled = icao_bridge_enabled
        self.mdl_bridge_enabled = mdl_bridge_enabled
        
        # Generate signing key if not provided (for standards exploration)
        self.signing_key = signing_key or self._generate_issuer_key()
        
        # EUDI ARF compliance endpoints
        self.credential_endpoint = f"{base_url}/oidc4vci/credential"
        self.token_endpoint = f"{base_url}/oidc4vci/token"
        self.metadata_endpoint = f"{base_url}/oidc4vci/.well-known/openid-credential-issuer"
        
        logger.info(f"EUDI OIDC4VCI Issuer initialized: {issuer_identifier}")

    def _generate_issuer_key(self) -> Any:  # Returns jwk.JWK when available
        """Generate P-256 signing key for EUDI compliance."""
        if not JWT_AVAILABLE or jwk is None:
            raise ImportError("JWK library not available")
        return jwk.JWK.generate(kty="EC", crv="P-256")

    def get_issuer_metadata(self) -> EUDICredentialMetadata:
        """
        Generate EUDI-compliant issuer metadata.
        
        Returns:
            EUDICredentialMetadata following EUDI ARF specifications
        """
        credential_configurations = {}
        
        if self.icao_bridge_enabled:
            credential_configurations.update({
                "passport_credential": {
                    "format": "vc+sd-jwt",
                    "scope": "passport_credential", 
                    "cryptographic_binding_methods_supported": ["jwk"],
                    "credential_signing_alg_values_supported": ["ES256"],
                    "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}},
                    "credential_definition": {
                        "type": ["VerifiableCredential", "PassportCredential"],
                        "credentialSubject": {
                            "given_name": {"mandatory": True},
                            "family_name": {"mandatory": True},
                            "birth_date": {"mandatory": True},
                            "nationality": {"mandatory": True},
                            "document_number": {"mandatory": True}
                        }
                    },
                    "display": [
                        {
                            "name": "ICAO Passport Credential",
                            "locale": "en-US",
                            "logo": {"url": f"{self.base_url}/assets/passport-logo.png"},
                            "background_color": "#1E3A8A",
                            "text_color": "#FFFFFF"
                        }
                    ]
                },
                "dtc_credential": {
                    "format": "vc+sd-jwt",
                    "scope": "dtc_credential",
                    "cryptographic_binding_methods_supported": ["jwk"],
                    "credential_signing_alg_values_supported": ["ES256"],
                    "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}},
                    "credential_definition": {
                        "type": ["VerifiableCredential", "DigitalTravelCredential"],
                        "credentialSubject": {
                            "given_name": {"mandatory": True},
                            "family_name": {"mandatory": True},
                            "travel_document_number": {"mandatory": True},
                            "travel_purpose": {"mandatory": False}
                        }
                    },
                    "display": [
                        {
                            "name": "Digital Travel Credential",
                            "locale": "en-US", 
                            "logo": {"url": f"{self.base_url}/assets/dtc-logo.png"},
                            "background_color": "#059669",
                            "text_color": "#FFFFFF"
                        }
                    ]
                }
            })
        
        if self.mdl_bridge_enabled:
            credential_configurations.update({
                "mdl_credential": {
                    "format": "mso_mdoc",
                    "scope": "mdl_credential",
                    "cryptographic_binding_methods_supported": ["cose_key"],
                    "credential_signing_alg_values_supported": ["ES256"],
                    "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}},
                    "doctype": "org.iso.18013.5.1.mDL",
                    "credential_definition": {
                        "type": ["VerifiableCredential", "MobileDrivingLicence"], 
                        "credentialSubject": {
                            "given_name": {"mandatory": True},
                            "family_name": {"mandatory": True},
                            "birth_date": {"mandatory": True},
                            "driving_privileges": {"mandatory": True}
                        }
                    },
                    "display": [
                        {
                            "name": "Mobile Driving Licence",
                            "locale": "en-US",
                            "logo": {"url": f"{self.base_url}/assets/mdl-logo.png"},
                            "background_color": "#DC2626",
                            "text_color": "#FFFFFF"
                        }
                    ]
                }
            })

        return EUDICredentialMetadata(
            credential_issuer=self.issuer_identifier,
            credential_endpoint=self.credential_endpoint,
            token_endpoint=self.token_endpoint,
            supported_credential_formats=["vc+sd-jwt", "mso_mdoc"],
            credential_configurations_supported=credential_configurations,
            issuer_display={
                "name": "Marty EUDI Bridge Issuer",
                "locale": "en-US",
                "logo": {"url": f"{self.base_url}/assets/marty-logo.png"},
                "description": "ICAO PKI to EUDI ARF Bridge Service"
            },
            grant_types_supported=[
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "authorization_code"
            ]
        )

    def create_credential_offer(
        self,
        subject_id: str,
        credential_types: List[str],
        pre_authorized: bool = True,
        user_pin_required: bool = False
    ) -> OIDC4VCICredentialOffer:
        """
        Create EUDI-compliant credential offer.
        
        Args:
            subject_id: Subject identifier for the credential
            credential_types: List of credential type IDs to offer
            pre_authorized: Use pre-authorized code flow
            user_pin_required: Require user PIN for pre-authorized flow
            
        Returns:
            OIDC4VCICredentialOffer object
        """
        grants = {}
        
        if pre_authorized:
            pre_auth_code = str(uuid.uuid4())
            grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"] = {
                "pre-authorized_code": pre_auth_code,
                "user_pin_required": user_pin_required
            }
        else:
            grants["authorization_code"] = {
                "issuer_state": str(uuid.uuid4())
            }

        offer = OIDC4VCICredentialOffer(
            credential_issuer=self.issuer_identifier,
            credential_configuration_ids=credential_types,
            grants=grants
        )
        
        logger.info(f"Created credential offer for subject {subject_id}: {credential_types}")
        return offer

    def mint_credential_from_icao_source(
        self,
        icao_document_data: Dict[str, Any],
        credential_type: str = "passport_credential",
        selective_disclosure: bool = True
    ) -> VerifiableCredential:
        """
        Mint EUDI-compatible VC from ICAO PKI source data.
        
        Args:
            icao_document_data: ICAO document data (MRZ, etc.)
            credential_type: Type of credential to mint
            selective_disclosure: Enable selective disclosure
            
        Returns:
            VerifiableCredential in EUDI format
        """
        if not self.icao_bridge_enabled:
            raise ValueError("ICAO bridge is disabled")
            
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(days=365)  # 1 year validity
        
        # Extract relevant fields from ICAO source
        subject_data = self._extract_icao_subject_data(icao_document_data, credential_type)
        
        # Build credential with EUDI compliance
        credential = VerifiableCredential(
            context=[
                "https://www.w3.org/2018/credentials/v1",
                "https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/contexts/v1"
            ],
            id=f"urn:uuid:{uuid.uuid4()}",
            type=["VerifiableCredential", self._get_credential_type_name(credential_type)],
            issuer={
                "id": self.issuer_identifier,
                "name": "Marty EUDI Bridge Issuer"
            },
            issuance_date=now.isoformat(),
            expiration_date=expiry.isoformat(),
            credential_subject=subject_data,
            evidence=[
                {
                    "type": ["DocumentVerification"],
                    "source": "ICAO_PKI",
                    "verification_method": "cryptographic_signature",
                    "verification_date": now.isoformat()
                }
            ]
        )
        
        # Add cryptographic proof
        if selective_disclosure:
            credential.proof = self._create_sd_jwt_proof(credential)
        else:
            credential.proof = self._create_jwt_proof(credential)
            
        logger.info(f"Minted {credential_type} from ICAO source: {credential.id}")
        return credential

    def mint_credential_from_mdl_source(
        self,
        mdl_document_data: Dict[str, Any],
        credential_format: str = "mso_mdoc"
    ) -> Union[VerifiableCredential, Dict[str, Any]]:
        """
        Mint EUDI-compatible credential from mDL source data.
        
        Args:
            mdl_document_data: mDL document data
            credential_format: Output format (mso_mdoc or vc+sd-jwt)
            
        Returns:
            Credential in requested format
        """
        if not self.mdl_bridge_enabled:
            raise ValueError("mDL bridge is disabled")
            
        if credential_format == "mso_mdoc":
            return self._create_mso_mdoc_credential(mdl_document_data)
        else:
            return self._create_vc_from_mdl(mdl_document_data)

    def _extract_icao_subject_data(self, icao_data: Dict[str, Any], credential_type: str) -> Dict[str, Any]:
        """Extract subject data from ICAO document for VC creation."""
        base_subject = {
            "id": f"urn:uuid:{uuid.uuid4()}",
            "given_name": icao_data.get("given_names", ""),
            "family_name": icao_data.get("surname", ""),
            "birth_date": icao_data.get("date_of_birth", ""),
            "nationality": icao_data.get("nationality", "")
        }
        
        if credential_type == "passport_credential":
            base_subject.update({
                "document_number": icao_data.get("document_number", ""),
                "document_type": "P",
                "issuing_country": icao_data.get("issuing_state", ""),
                "issuing_authority": icao_data.get("issuing_authority", "")
            })
        elif credential_type == "dtc_credential":
            base_subject.update({
                "travel_document_number": icao_data.get("document_number", ""),
                "travel_document_type": "DTC",
                "travel_purpose": icao_data.get("travel_purpose", "tourism")
            })
            
        return base_subject

    def _get_credential_type_name(self, credential_type: str) -> str:
        """Map credential type ID to formal type name."""
        type_mapping = {
            "passport_credential": "PassportCredential",
            "dtc_credential": "DigitalTravelCredential", 
            "mdl_credential": "MobileDrivingLicence"
        }
        return type_mapping.get(credential_type, "GenericCredential")

    def _create_sd_jwt_proof(self, credential: VerifiableCredential) -> Dict[str, Any]:
        """Create selective disclosure JWT proof for EUDI compliance."""
        # Simplified SD-JWT proof for standards exploration
        header = {
            "alg": "ES256",
            "typ": "vc+sd-jwt",
            "kid": self.signing_key.thumbprint()
        }
        
        payload = {
            "iss": self.issuer_identifier,
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "vc": asdict(credential)
        }
        
        # Sign with issuer key
        if not JWT_AVAILABLE or jwt is None:
            raise ImportError("JWT library not available for signing")
        token = jwt.encode(payload, self.signing_key.export_to_pem(private_key=True, password=None), algorithm="ES256", headers=header)
        
        return {
            "type": "JsonWebSignature2020",
            "created": datetime.now(timezone.utc).isoformat(),
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"{self.issuer_identifier}#key-1",
            "jws": token
        }

    def _create_jwt_proof(self, credential: VerifiableCredential) -> Dict[str, Any]:
        """Create standard JWT proof."""
        return self._create_sd_jwt_proof(credential)

    def _create_mso_mdoc_credential(self, mdl_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create mso_mdoc format credential from mDL data."""
        # Simplified mso_mdoc structure for standards exploration
        return {
            "format": "mso_mdoc",
            "doctype": "org.iso.18013.5.1.mDL",
            "issuerSigned": {
                "nameSpaces": {
                    "org.iso.18013.5.1": self._map_mdl_to_iso_namespace(mdl_data)
                }
            },
            "deviceSigned": {
                "nameSpaces": {},
                "deviceAuth": {
                    "deviceMac": "placeholder_mac"  # Would be actual device MAC in production
                }
            }
        }

    def _create_vc_from_mdl(self, mdl_data: Dict[str, Any]) -> VerifiableCredential:
        """Create VC+SD-JWT format credential from mDL data."""
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(days=365)
        
        subject_data = {
            "id": f"urn:uuid:{uuid.uuid4()}",
            "given_name": mdl_data.get("given_name", ""),
            "family_name": mdl_data.get("family_name", ""),
            "birth_date": mdl_data.get("birth_date", ""),
            "driving_privileges": mdl_data.get("driving_privileges", [])
        }
        
        credential = VerifiableCredential(
            context=[
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/mobility/v1"
            ],
            id=f"urn:uuid:{uuid.uuid4()}",
            type=["VerifiableCredential", "MobileDrivingLicence"],
            issuer={
                "id": self.issuer_identifier,
                "name": "Marty EUDI Bridge Issuer"
            },
            issuance_date=now.isoformat(),
            expiration_date=expiry.isoformat(),
            credential_subject=subject_data
        )
        
        credential.proof = self._create_sd_jwt_proof(credential)
        return credential

    def _map_mdl_to_iso_namespace(self, mdl_data: Dict[str, Any]) -> Dict[str, Any]:
        """Map mDL data to ISO 18013-5 namespace."""
        return {
            "given_name": mdl_data.get("given_name", ""),
            "family_name": mdl_data.get("family_name", ""),
            "birth_date": mdl_data.get("birth_date", ""),
            "driving_privileges": mdl_data.get("driving_privileges", []),
            "document_number": mdl_data.get("document_number", ""),
            "issuing_country": mdl_data.get("issuing_country", ""),
            "issue_date": mdl_data.get("issue_date", ""),
            "expiry_date": mdl_data.get("expiry_date", "")
        }

    def validate_credential_request(self, request: Dict[str, Any]) -> bool:
        """
        Validate OIDC4VCI credential request for EUDI compliance.
        
        Args:
            request: OIDC4VCI credential request
            
        Returns:
            True if valid, False otherwise
        """
        required_fields = ["format", "credential_definition"]
        
        if not all(field in request for field in required_fields):
            logger.warning("Missing required fields in credential request")
            return False
            
        if request["format"] not in ["vc+sd-jwt", "mso_mdoc"]:
            logger.warning(f"Unsupported credential format: {request['format']}")
            return False
            
        return True

    def get_public_key_jwks(self) -> Dict[str, Any]:
        """Get public key in JWKS format for verification."""
        public_key = self.signing_key.export_public()
        return {
            "keys": [json.loads(public_key)]
        }


# Factory function for easy instantiation
def create_eudi_oidc4vci_issuer(
    issuer_id: str = "https://marty.example.com/eudi",
    base_url: str = "https://marty.example.com",
    **kwargs
) -> OIDC4VCIIssuerFacade:
    """
    Factory function to create EUDI-compliant OIDC4VCI issuer.
    
    Args:
        issuer_id: Issuer identifier URL
        base_url: Base URL for endpoints
        **kwargs: Additional configuration options
        
    Returns:
        Configured OIDC4VCIIssuerFacade instance
    """
    return OIDC4VCIIssuerFacade(
        issuer_identifier=issuer_id,
        base_url=base_url,
        **kwargs
    )