"""
EUDI Bridge Components for ICAO/mDL to EUDI ARF Interoperability

This module provides bridge services that enable Marty's ICAO PKI and mDL systems
to interoperate with the EU Digital Identity Wallet (EUDI) ecosystem through
OIDC4VCI/VP protocols while maintaining strict separation between standards
exploration and production security.

Key Components:
- OIDC4VCI Issuer Facade: Mints EUDI-compatible VCs from ICAO/mDoc sources
- OID4VP Presentation Layer: Handles verifiable presentations with policy constraints
- Bridge Services: Format translation between ICAO/mDL and EUDI standards
- Configuration & Orchestration: Unified service management

Standards Compliance:
- EUDI Architecture and Reference Framework v2.4.0
- OpenID for Verifiable Credential Issuance (OIDC4VCI)
- OpenID for Verifiable Presentations (OID4VP)
- ISO/IEC 18013-5 (mDL) bridging
- ICAO Doc 9303 compatibility

Security Note:
This is a standards exploration implementation. Production deployments should
implement additional security measures as specified in the EUDI ARF.
"""

__version__ = "1.0.0"
__author__ = "Marty EUDI Bridge Team"

# EUDI ARF Compliance Markers
EUDI_ARF_VERSION = "2.4.0"
OIDC4VCI_PROFILE = "eudi-compliant"
SUPPORTED_CREDENTIAL_FORMATS = ["vc+sd-jwt", "mso_mdoc"]

# Bridge Service Types
BRIDGE_SERVICES = [
    "oidc4vci_issuer",
    "oid4vp_verifier", 
    "icao_mdl_translator",
    "eudi_policy_engine"
]

# Import main components
from .oidc4vci_issuer import OIDC4VCIIssuerFacade
from .oid4vp_verifier import OID4VPPresentationLayer, EUDIPolicyEngine
from .bridge_services import (
    EUDIBridgeService, 
    EUDITrustService,
    CredentialFormat,
    VerificationStatus,
    TranslationResult,
    create_eudi_bridge_service,
    create_eudi_trust_service
)
from .config import (
    EUDIBridgeConfig,
    EUDIBridgeConfigLoader,
    EUDIBridgeOrchestrator,
    EUDIBridgeHealthCheck,
    create_eudi_bridge_orchestrator,
    quick_health_check
)

__all__ = [
    # Core classes
    "OIDC4VCIIssuerFacade",
    "OID4VPPresentationLayer", 
    "EUDIPolicyEngine",
    "EUDIBridgeService",
    "EUDITrustService",
    "EUDIBridgeOrchestrator",
    "EUDIBridgeHealthCheck",
    
    # Configuration
    "EUDIBridgeConfig",
    "EUDIBridgeConfigLoader",
    
    # Data types
    "CredentialFormat",
    "VerificationStatus", 
    "TranslationResult",
    
    # Factory functions
    "create_eudi_bridge_service",
    "create_eudi_trust_service",
    "create_eudi_bridge_orchestrator",
    "quick_health_check",
    
    # Constants
    "SUPPORTED_CREDENTIAL_FORMATS",
    "BRIDGE_SERVICES",
    "EUDI_ARF_VERSION",
    "OIDC4VCI_PROFILE"
]