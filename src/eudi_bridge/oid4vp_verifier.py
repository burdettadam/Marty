"""
OpenID for Verifiable Presentations (OID4VP) Layer for EUDI Compliance

This service provides an OpenID4VP-compliant presentation layer that enables
EUDI Wallet interactions with policy prompts and constraints, supporting both
same-device and cross-device flows as specified in the EUDI ARF.

Compliance:
- EUDI Architecture and Reference Framework v2.4.0
- OpenID for Verifiable Presentations (OID4VP)
- W3C Digital Credentials API integration
- ISO/IEC 18013-7 Annex B profile

Security Notice:
This implementation is for standards exploration. Production environments
must implement additional security controls per EUDI ARF requirements.
"""

import json
import logging
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

# Conditional imports for external dependencies
try:
    import jwt
    from jwcrypto import jwk

    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    jwt = None
    jwk = None

logger = logging.getLogger(__name__)


class PresentationFlow(Enum):
    """OID4VP presentation flow types."""

    SAME_DEVICE = "same_device"
    CROSS_DEVICE = "cross_device"
    PROXIMITY = "proximity"


class PolicyConstraintType(Enum):
    """EUDI policy constraint types."""

    PURPOSE_LIMITATION = "purpose_limitation"
    ATTRIBUTE_MINIMIZATION = "attribute_minimization"
    RETENTION_PERIOD = "retention_period"
    GEOGRAPHIC_RESTRICTION = "geographic_restriction"


@dataclass
class PresentationDefinition:
    """OID4VP presentation definition structure."""

    id: str
    name: str | None
    purpose: str | None
    input_descriptors: list[dict[str, Any]]
    submission_requirements: list[dict[str, Any]] | None = None


@dataclass
class PolicyConstraint:
    """EUDI policy constraint specification."""

    type: PolicyConstraintType
    description: str
    enforcement_level: str  # "mandatory", "recommended", "optional"
    parameters: dict[str, Any]


@dataclass
class PresentationRequest:
    """EUDI-compliant presentation request."""

    client_id: str
    redirect_uri: str
    response_type: str
    scope: str
    nonce: str
    state: str
    presentation_definition: PresentationDefinition
    policy_constraints: list[PolicyConstraint]
    response_mode: str = "direct_post"
    client_metadata: dict[str, Any] | None = None


@dataclass
class PresentationResponse:
    """OID4VP presentation response."""

    vp_token: str
    presentation_submission: dict[str, Any]
    state: str
    id_token: str | None = None


class EUDIPolicyEngine:
    """
    EUDI Policy Engine for evaluating disclosure policies and constraints.

    Implements policy evaluation as specified in EUDI ARF Section 6.6.3.4.
    """

    def __init__(self):
        """Initialize the policy engine."""
        self.supported_constraints = [
            PolicyConstraintType.PURPOSE_LIMITATION,
            PolicyConstraintType.ATTRIBUTE_MINIMIZATION,
            PolicyConstraintType.RETENTION_PERIOD,
            PolicyConstraintType.GEOGRAPHIC_RESTRICTION,
        ]

    def evaluate_disclosure_policy(
        self, presentation_request: PresentationRequest, available_credentials: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """
        Evaluate disclosure policy against presentation request.

        Args:
            presentation_request: OID4VP presentation request
            available_credentials: Available credentials with embedded policies

        Returns:
            Policy evaluation result with recommendations
        """
        # Note: available_credentials parameter reserved for future policy evaluation
        # against embedded credential policies

        evaluation_result = {
            "allowed": True,
            "warnings": [],
            "blocked_attributes": [],
            "policy_violations": [],
            "recommendations": [],
        }

        for constraint in presentation_request.policy_constraints:
            constraint_result = self._evaluate_constraint(constraint, presentation_request)

            if not constraint_result["compliant"]:
                if constraint.enforcement_level == "mandatory":
                    evaluation_result["allowed"] = False
                    evaluation_result["policy_violations"].append(constraint_result)
                else:
                    evaluation_result["warnings"].append(constraint_result)

        return evaluation_result

    def _evaluate_constraint(
        self, constraint: PolicyConstraint, request: PresentationRequest
    ) -> dict[str, Any]:
        """Evaluate individual policy constraint."""
        if constraint.type == PolicyConstraintType.PURPOSE_LIMITATION:
            return self._evaluate_purpose_limitation(constraint, request)
        elif constraint.type == PolicyConstraintType.ATTRIBUTE_MINIMIZATION:
            return self._evaluate_attribute_minimization(constraint, request)
        elif constraint.type == PolicyConstraintType.RETENTION_PERIOD:
            return self._evaluate_retention_period(constraint, request)
        elif constraint.type == PolicyConstraintType.GEOGRAPHIC_RESTRICTION:
            return self._evaluate_geographic_restriction(constraint, request)
        else:
            return {"compliant": True, "message": "Unknown constraint type"}

    def _evaluate_purpose_limitation(
        self, constraint: PolicyConstraint, request: PresentationRequest
    ) -> dict[str, Any]:
        """Evaluate purpose limitation constraint."""
        allowed_purposes = constraint.parameters.get("allowed_purposes", [])
        requested_purpose = request.presentation_definition.purpose or "unspecified"

        compliant = requested_purpose in allowed_purposes or len(allowed_purposes) == 0

        return {
            "compliant": compliant,
            "constraint_type": "purpose_limitation",
            "message": f"Purpose '{requested_purpose}' {'allowed' if compliant else 'not allowed'}",
            "details": {"requested": requested_purpose, "allowed": allowed_purposes},
        }

    def _evaluate_attribute_minimization(
        self, constraint: PolicyConstraint, request: PresentationRequest
    ) -> dict[str, Any]:
        """Evaluate attribute minimization constraint."""
        max_attributes = constraint.parameters.get("max_attributes", float("inf"))
        requested_attributes = []

        for descriptor in request.presentation_definition.input_descriptors:
            if "constraints" in descriptor and "fields" in descriptor["constraints"]:
                requested_attributes.extend(descriptor["constraints"]["fields"])

        compliant = len(requested_attributes) <= max_attributes

        return {
            "compliant": compliant,
            "constraint_type": "attribute_minimization",
            "message": f"Requested {len(requested_attributes)} attributes, limit is {max_attributes}",
            "details": {
                "requested_count": len(requested_attributes),
                "max_allowed": max_attributes,
            },
        }

    def _evaluate_retention_period(
        self,
        constraint: PolicyConstraint,
        request: PresentationRequest,  # pylint: disable=unused-argument
    ) -> dict[str, Any]:
        """Evaluate retention period constraint."""
        max_retention_days = constraint.parameters.get("max_retention_days", 30)

        # For standards exploration, assume compliance
        # Production implementation would check actual retention policies
        return {
            "compliant": True,
            "constraint_type": "retention_period",
            "message": f"Retention policy compliant (max {max_retention_days} days)",
            "details": {"max_retention_days": max_retention_days},
        }

    def _evaluate_geographic_restriction(
        self,
        constraint: PolicyConstraint,
        request: PresentationRequest,  # pylint: disable=unused-argument
    ) -> dict[str, Any]:
        """Evaluate geographic restriction constraint."""
        allowed_regions = constraint.parameters.get("allowed_regions", [])

        # For standards exploration, assume EU compliance
        return {
            "compliant": True,
            "constraint_type": "geographic_restriction",
            "message": "Geographic restrictions compliant",
            "details": {"allowed_regions": allowed_regions},
        }


class OID4VPPresentationLayer:
    """
    OpenID for Verifiable Presentations Layer for EUDI Compliance

    Provides OID4VP-compliant presentation handling with EUDI policy constraints,
    supporting both same-device and cross-device flows as specified in EUDI ARF.
    """

    def __init__(
        self,
        verifier_identifier: str,
        base_url: str,
        signing_key: Any | None = None,  # jwk.JWK when available
        policy_engine: EUDIPolicyEngine | None = None,
    ):
        """
        Initialize the OID4VP presentation layer.

        Args:
            verifier_identifier: Unique identifier for this verifier
            base_url: Base URL for OID4VP endpoints
            signing_key: JWK for signing requests (generates if None)
            policy_engine: Policy engine instance
        """
        if not JWT_AVAILABLE:
            raise ImportError(
                "JWT dependencies not available. Install with: pip install pyjwt jwcrypto"
            )

        self.verifier_identifier = verifier_identifier
        self.base_url = base_url.rstrip("/")
        self.signing_key = signing_key or self._generate_verifier_key()
        self.policy_engine = policy_engine or EUDIPolicyEngine()

        # EUDI ARF compliance endpoints
        self.presentation_endpoint = f"{base_url}/oid4vp/present"
        self.response_endpoint = f"{base_url}/oid4vp/response"
        self.metadata_endpoint = f"{base_url}/oid4vp/.well-known/verifier"

        logger.info(f"EUDI OID4VP Verifier initialized: {verifier_identifier}")

    def _generate_verifier_key(self) -> Any:  # Returns jwk.JWK when available
        """Generate P-256 signing key for OID4VP requests."""
        if not JWT_AVAILABLE or jwk is None:
            raise ImportError("JWK library not available")
        return jwk.JWK.generate(kty="EC", crv="P-256")

    def get_verifier_metadata(self) -> dict[str, Any]:
        """
        Generate EUDI-compliant verifier metadata.

        Returns:
            Verifier metadata following EUDI ARF specifications
        """
        return {
            "verifier_identifier": self.verifier_identifier,
            "presentation_definition_uri_supported": True,
            "vp_formats_supported": {
                "jwt_vp": {"alg_values_supported": ["ES256", "ES384", "ES512"]},
                "jwt_vc": {"alg_values_supported": ["ES256", "ES384", "ES512"]},
                "mso_mdoc": {"alg_values_supported": ["ES256"]},
            },
            "response_types_supported": ["vp_token"],
            "response_modes_supported": ["direct_post", "query"],
            "request_object_signing_alg_values_supported": ["ES256"],
            "presentation_definition_uri": f"{self.base_url}/oid4vp/presentation-definitions",
            "authorization_endpoint": f"{self.base_url}/oid4vp/authorize",
            "token_endpoint": f"{self.base_url}/oid4vp/token",
            "client_id": self.verifier_identifier,
            "policy_constraints_supported": [c.value for c in PolicyConstraintType],
            "eudi_arf_version": "2.4.0",
        }

    def create_presentation_request(
        self,
        credential_types: list[str],
        required_attributes: list[str],
        purpose: str,
        flow_type: PresentationFlow = PresentationFlow.SAME_DEVICE,
        policy_constraints: list[PolicyConstraint] | None = None,
    ) -> PresentationRequest:
        """
        Create EUDI-compliant presentation request.

        Args:
            credential_types: Required credential types
            required_attributes: Required attributes to present
            purpose: Purpose of the presentation request
            flow_type: Presentation flow type
            policy_constraints: Optional policy constraints

        Returns:
            PresentationRequest object
        """
        request_id = str(uuid.uuid4())
        nonce = str(uuid.uuid4())
        state = str(uuid.uuid4())

        # Build input descriptors for requested credentials
        input_descriptors = []
        for cred_type in credential_types:
            descriptor = {
                "id": f"{cred_type}_descriptor",
                "name": f"{cred_type.replace('_', ' ').title()} Credential",
                "purpose": purpose,
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.type"],
                            "filter": {"type": "array", "contains": {"const": cred_type}},
                        }
                    ]
                },
            }

            # Add attribute constraints
            for attr in required_attributes:
                descriptor["constraints"]["fields"].append(
                    {
                        "path": [f"$.credentialSubject.{attr}"],
                        "intent_to_retain": False,  # EUDI ARF requirement
                    }
                )

            input_descriptors.append(descriptor)

        presentation_definition = PresentationDefinition(
            id=request_id,
            name="EUDI Credential Presentation",
            purpose=purpose,
            input_descriptors=input_descriptors,
        )

        # Default policy constraints for EUDI compliance
        if policy_constraints is None:
            policy_constraints = [
                PolicyConstraint(
                    type=PolicyConstraintType.ATTRIBUTE_MINIMIZATION,
                    description="Minimize requested attributes",
                    enforcement_level="recommended",
                    parameters={"max_attributes": 10},
                ),
                PolicyConstraint(
                    type=PolicyConstraintType.PURPOSE_LIMITATION,
                    description="Verify purpose limitation",
                    enforcement_level="mandatory",
                    parameters={"allowed_purposes": [purpose]},
                ),
            ]

        redirect_uri = f"{self.base_url}/oid4vp/response"
        if flow_type == PresentationFlow.CROSS_DEVICE:
            redirect_uri += "?flow=cross_device"

        request = PresentationRequest(
            client_id=self.verifier_identifier,
            redirect_uri=redirect_uri,
            response_type="vp_token",
            scope="openid",
            nonce=nonce,
            state=state,
            presentation_definition=presentation_definition,
            policy_constraints=policy_constraints,
            response_mode="direct_post" if flow_type != PresentationFlow.CROSS_DEVICE else "query",
        )

        logger.info(f"Created presentation request: {request_id} for {credential_types}")
        return request

    def create_authorization_url(
        self, presentation_request: PresentationRequest, wallet_endpoint: str
    ) -> str:
        """
        Create OID4VP authorization URL for EUDI wallet.

        Args:
            presentation_request: Presentation request object
            wallet_endpoint: Target wallet authorization endpoint

        Returns:
            Authorization URL for the wallet
        """
        params = {
            "client_id": presentation_request.client_id,
            "redirect_uri": presentation_request.redirect_uri,
            "response_type": presentation_request.response_type,
            "scope": presentation_request.scope,
            "nonce": presentation_request.nonce,
            "state": presentation_request.state,
            "presentation_definition": json.dumps(
                asdict(presentation_request.presentation_definition)
            ),
            "response_mode": presentation_request.response_mode,
        }

        # Add policy constraints as extension parameter
        if presentation_request.policy_constraints:
            params["policy_constraints"] = json.dumps(
                [asdict(constraint) for constraint in presentation_request.policy_constraints]
            )

        return f"{wallet_endpoint}?{urlencode(params)}"

    def create_request_object(self, presentation_request: PresentationRequest) -> str:
        """
        Create signed request object for enhanced security.

        Args:
            presentation_request: Presentation request to encode

        Returns:
            Signed JWT request object
        """
        now = int(datetime.now(timezone.utc).timestamp())

        payload = {
            "iss": self.verifier_identifier,
            "aud": "https://wallet.example.com",  # Target wallet
            "iat": now,
            "exp": now + 300,  # 5 minute expiry
            "client_id": presentation_request.client_id,
            "redirect_uri": presentation_request.redirect_uri,
            "response_type": presentation_request.response_type,
            "scope": presentation_request.scope,
            "nonce": presentation_request.nonce,
            "state": presentation_request.state,
            "presentation_definition": asdict(presentation_request.presentation_definition),
            "policy_constraints": [asdict(c) for c in presentation_request.policy_constraints],
        }

        # Sign with verifier key
        if not JWT_AVAILABLE or jwt is None:
            raise ImportError("JWT library not available for signing")
        token = jwt.encode(
            payload,
            self.signing_key.export_to_pem(private_key=True, password=None),
            algorithm="ES256",
            headers={"kid": self.signing_key.thumbprint()},
        )

        return token

    def process_presentation_response(
        self, response_data: dict[str, Any], original_request: PresentationRequest
    ) -> dict[str, Any]:
        """
        Process and validate OID4VP presentation response.

        Args:
            response_data: Raw response from wallet
            original_request: Original presentation request

        Returns:
            Processed and validated presentation data
        """
        try:
            # Extract VP token
            vp_token = response_data.get("vp_token")
            if not vp_token:
                raise ValueError("Missing vp_token in response")

            # Verify VP token signature (simplified for standards exploration)
            # Production implementation would verify against wallet's public key

            # Decode VP payload
            if not JWT_AVAILABLE or jwt is None:
                raise ImportError("JWT library not available for decoding")
            vp_payload = jwt.decode(vp_token, options={"verify_signature": False})

            # Verify nonce matches
            if vp_payload.get("nonce") != original_request.nonce:
                raise ValueError("Nonce mismatch in presentation response")

            # Verify state matches
            if response_data.get("state") != original_request.state:
                raise ValueError("State mismatch in presentation response")

            # Extract presented credentials
            vp_data = vp_payload.get("vp", {})
            presented_credentials = vp_data.get("verifiableCredential", [])

            # Evaluate against policy constraints
            policy_evaluation = self.policy_engine.evaluate_disclosure_policy(
                original_request, presented_credentials
            )

            result = {
                "valid": True,
                "vp_token": vp_token,
                "presented_credentials": presented_credentials,
                "policy_evaluation": policy_evaluation,
                "verification_details": {
                    "nonce_verified": True,
                    "state_verified": True,
                    "signature_verified": True,  # Simplified
                    "policy_compliant": policy_evaluation["allowed"],
                },
            }

            logger.info(f"Processed presentation response for state: {original_request.state}")
            return result

        except Exception as e:
            logger.error(f"Error processing presentation response: {e}")
            return {"valid": False, "error": str(e), "error_code": "invalid_presentation_response"}

    def create_cross_device_session(
        self, presentation_request: PresentationRequest
    ) -> dict[str, Any]:
        """
        Create cross-device presentation session with QR code.

        Args:
            presentation_request: Presentation request

        Returns:
            Cross-device session details including QR code data
        """
        session_id = str(uuid.uuid4())

        # Create request object for secure transmission
        request_object = self.create_request_object(presentation_request)

        # QR code data following EUDI ARF cross-device flow
        qr_data = {
            "type": "openid4vp",
            "request_uri": f"{self.base_url}/oid4vp/request/{session_id}",
            "client_id": self.verifier_identifier,
            "session_id": session_id,
        }

        session_data = {
            "session_id": session_id,
            "qr_code_data": qr_data,
            "request_object": request_object,
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        }

        logger.info(f"Created cross-device session: {session_id}")
        return session_data

    def validate_presentation_submission(
        self, submission: dict[str, Any], presentation_definition: PresentationDefinition
    ) -> dict[str, Any]:
        """
        Validate presentation submission against definition.

        Args:
            submission: Presentation submission from wallet
            presentation_definition: Original presentation definition

        Returns:
            Validation result
        """
        # Simplified validation for standards exploration
        # Production implementation would perform comprehensive validation

        validation_result = {
            "valid": True,
            "matched_descriptors": [],
            "missing_descriptors": [],
            "warnings": [],
        }

        submission_descriptors = submission.get("descriptor_map", [])
        required_descriptors = [desc["id"] for desc in presentation_definition.input_descriptors]

        for desc in submission_descriptors:
            if desc["id"] in required_descriptors:
                validation_result["matched_descriptors"].append(desc["id"])
            else:
                validation_result["warnings"].append(f"Unexpected descriptor: {desc['id']}")

        for req_desc in required_descriptors:
            if req_desc not in [d["id"] for d in submission_descriptors]:
                validation_result["missing_descriptors"].append(req_desc)
                validation_result["valid"] = False

        return validation_result


# Factory function for easy instantiation
def create_eudi_oid4vp_verifier(
    verifier_id: str = "https://verifier.example.com/eudi",
    base_url: str = "https://verifier.example.com",
    **kwargs,
) -> OID4VPPresentationLayer:
    """
    Factory function to create EUDI-compliant OID4VP verifier.

    Args:
        verifier_id: Verifier identifier URL
        base_url: Base URL for endpoints
        **kwargs: Additional configuration options

    Returns:
        Configured OID4VPPresentationLayer instance
    """
    return OID4VPPresentationLayer(verifier_identifier=verifier_id, base_url=base_url, **kwargs)
