"""
EUDI Bridge Configuration and Integration

Configuration management and integration utilities for the EUDI bridge services.
This module provides configuration loading, service integration, and deployment
support for the EUDI bridge components.

Note: This is for standards exploration and roadmap development.
Production security separation maintained.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from pathlib import Path

# Conditional import for YAML
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None

from .bridge_services import EUDIBridgeService, EUDITrustService
from .oidc4vci_issuer import OIDC4VCIIssuerFacade
from .oid4vp_verifier import OID4VPPresentationLayer


@dataclass
class EUDIBridgeConfig:
    """Configuration for EUDI Bridge services."""
    
    # Service configuration
    bridge_service_enabled: bool = True
    trust_service_enabled: bool = True
    oidc4vci_issuer_enabled: bool = True
    oid4vp_verifier_enabled: bool = True
    
    # EUDI ARF compliance
    arf_version: str = "2.4.0"
    compliance_mode: str = "strict"  # strict, permissive, development
    
    # Trust store configuration
    trust_store_path: str = "/Users/adamburdett/Github/work/Marty/data/trust_store.json"
    icao_trust_anchors: Optional[List[str]] = None
    mdl_trust_anchors: Optional[List[str]] = None
    
    # Credential settings
    max_credential_age_days: int = 90
    supported_formats: Optional[List[str]] = None
    default_key_algorithm: str = "ES256"
    
    # Network configuration
    base_url: str = "https://marty.eudi.bridge"
    issuer_endpoint: str = "/oidc4vci"
    verifier_endpoint: str = "/oid4vp"
    
    # Security settings
    require_https: bool = True
    enable_cors: bool = True
    allowed_origins: Optional[List[str]] = None
    
    # Logging configuration
    log_level: str = "INFO"
    enable_audit_logging: bool = True
    
    def __post_init__(self):
        """Initialize default values."""
        if self.icao_trust_anchors is None:
            self.icao_trust_anchors = []
        if self.mdl_trust_anchors is None:
            self.mdl_trust_anchors = []
        if self.supported_formats is None:
            self.supported_formats = ["sd_jwt_vc", "eudi_vc", "mdoc"]
        if self.allowed_origins is None:
            self.allowed_origins = ["https://localhost:3000"]


class EUDIBridgeConfigLoader:
    """Configuration loader for EUDI Bridge services."""
    
    def __init__(self, config_dir: str = "/Users/adamburdett/Github/work/Marty/config"):
        """Initialize configuration loader."""
        self.config_dir = Path(config_dir)
        self.logger = logging.getLogger(__name__)
        
    def load_config(
        self,
        environment: str = "development",
        config_file: Optional[str] = None
    ) -> EUDIBridgeConfig:
        """
        Load EUDI Bridge configuration.
        
        Args:
            environment: Environment name (development, testing, production)
            config_file: Optional specific config file path
            
        Returns:
            EUDIBridgeConfig instance
        """
        try:
            # Load base configuration
            base_config = self._load_base_config()
            
            # Load environment-specific configuration
            env_config = self._load_environment_config(environment)
            
            # Load custom config file if provided
            custom_config = {}
            if config_file:
                custom_config = self._load_custom_config(config_file)
            
            # Merge configurations (custom > env > base)
            merged_config = {**base_config, **env_config, **custom_config}
            
            # Create configuration object
            return EUDIBridgeConfig(**merged_config)
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            # Return default configuration
            return EUDIBridgeConfig()
    
    def _load_base_config(self) -> Dict[str, Any]:
        """Load base configuration."""
        base_file = self.config_dir / "base.yaml"
        if base_file.exists():
            return self._load_yaml_file(base_file)
        return {}
    
    def _load_environment_config(self, environment: str) -> Dict[str, Any]:
        """Load environment-specific configuration."""
        env_file = self.config_dir / f"{environment}.yaml"
        if env_file.exists():
            return self._load_yaml_file(env_file)
        return {}
    
    def _load_custom_config(self, config_file: str) -> Dict[str, Any]:
        """Load custom configuration file."""
        config_path = Path(config_file)
        if config_path.exists():
            if config_path.suffix.lower() in ['.yaml', '.yml']:
                return self._load_yaml_file(config_path)
            elif config_path.suffix.lower() == '.json':
                return self._load_json_file(config_path)
        return {}
    
    def _load_yaml_file(self, file_path: Path) -> Dict[str, Any]:
        """Load YAML configuration file."""
        try:
            if not YAML_AVAILABLE or yaml is None:
                self.logger.warning(f"YAML library not available, skipping {file_path}")
                return {}
            with open(file_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            self.logger.warning(f"Failed to load YAML file {file_path}: {e}")
            return {}
    
    def _load_json_file(self, file_path: Path) -> Dict[str, Any]:
        """Load JSON configuration file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.logger.warning(f"Failed to load JSON file {file_path}: {e}")
            return {}


class EUDIBridgeOrchestrator:
    """
    Orchestrator for EUDI Bridge services.
    
    This class coordinates all EUDI bridge components and provides a unified
    interface for credential translation, issuance, and verification workflows.
    """
    
    def __init__(self, config: EUDIBridgeConfig):
        """Initialize the EUDI Bridge Orchestrator."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize services
        self.bridge_service = None
        self.trust_service = None
        self.oidc4vci_issuer = None
        self.oid4vp_verifier = None
        
        self._initialize_services()
    
    def _initialize_services(self):
        """Initialize all EUDI bridge services based on configuration."""
        try:
            # Initialize bridge service
            if self.config.bridge_service_enabled:
                eudi_config = {
                    "arf_version": self.config.arf_version,
                    "supported_formats": self.config.supported_formats,
                    "max_credential_age_days": self.config.max_credential_age_days,
                    "compliance_mode": self.config.compliance_mode
                }
                self.bridge_service = EUDIBridgeService(
                    self.config.trust_store_path,
                    eudi_config
                )
                self.logger.info("EUDI Bridge Service initialized")
            
            # Initialize trust service
            if self.config.trust_service_enabled:
                trust_config = {
                    "icao_trust_anchors": self.config.icao_trust_anchors,
                    "mdl_trust_anchors": self.config.mdl_trust_anchors,
                    "validation_mode": self.config.compliance_mode
                }
                self.trust_service = EUDITrustService(trust_config)
                self.logger.info("EUDI Trust Service initialized")
            
            # Initialize OIDC4VCI issuer
            if self.config.oidc4vci_issuer_enabled:
                issuer_identifier = f"{self.config.base_url}{self.config.issuer_endpoint}"
                self.oidc4vci_issuer = OIDC4VCIIssuerFacade(
                    issuer_identifier=issuer_identifier,
                    base_url=self.config.base_url
                )
                self.logger.info("OIDC4VCI Issuer initialized")
            
            # Initialize OID4VP verifier
            if self.config.oid4vp_verifier_enabled:
                verifier_identifier = f"{self.config.base_url}{self.config.verifier_endpoint}"
                self.oid4vp_verifier = OID4VPPresentationLayer(
                    verifier_identifier=verifier_identifier,
                    base_url=self.config.base_url
                )
                self.logger.info("OID4VP Verifier initialized")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize services: {e}")
            raise
    
    def translate_and_issue(
        self,
        source_credential: Dict[str, Any],
        source_format: str,
        target_format: str = "sd_jwt_vc",
        issuance_options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Translate credential and issue EUDI-compatible format.
        
        Note: This is a placeholder implementation for standards exploration.
        Full implementation requires external dependencies.
        """
        try:
            if not self.bridge_service:
                raise ValueError("Bridge service not initialized")
            
            # TODO: Implement full translation and issuance workflow
            # This requires all external dependencies to be available
            
            return {
                "success": False,
                "error": "Translation and issuance not yet implemented",
                "note": "Requires external dependencies (PyJWT, cryptography, etc.)"
            }
                
        except Exception as e:
            self.logger.error(f"Translation and issuance failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def verify_presentation(
        self,
        presentation_request: Dict[str, Any],
        presentation_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Verify EUDI presentation using OID4VP.
        
        Note: This is a placeholder implementation for standards exploration.
        Full implementation requires external dependencies.
        """
        try:
            if not self.oid4vp_verifier:
                raise ValueError("OID4VP verifier not initialized")
            
            # TODO: Implement full presentation verification
            # This requires all external dependencies to be available
            
            return {
                "success": False,
                "error": "Presentation verification not yet implemented",
                "note": "Requires external dependencies (PyJWT, jwcrypto, etc.)"
            }
            
        except Exception as e:
            self.logger.error(f"Presentation verification failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get status of all EUDI bridge services."""
        return {
            "bridge_service": {
                "enabled": self.config.bridge_service_enabled,
                "initialized": self.bridge_service is not None,
                "status": "active" if self.bridge_service else "disabled"
            },
            "trust_service": {
                "enabled": self.config.trust_service_enabled,
                "initialized": self.trust_service is not None,
                "status": "active" if self.trust_service else "disabled"
            },
            "oidc4vci_issuer": {
                "enabled": self.config.oidc4vci_issuer_enabled,
                "initialized": self.oidc4vci_issuer is not None,
                "status": "active" if self.oidc4vci_issuer else "disabled"
            },
            "oid4vp_verifier": {
                "enabled": self.config.oid4vp_verifier_enabled,
                "initialized": self.oid4vp_verifier is not None,
                "status": "active" if self.oid4vp_verifier else "disabled"
            },
            "configuration": {
                "arf_version": self.config.arf_version,
                "compliance_mode": self.config.compliance_mode,
                "supported_formats": self.config.supported_formats
            }
        }


class EUDIBridgeHealthCheck:
    """Health check utilities for EUDI Bridge services."""
    
    def __init__(self, orchestrator: EUDIBridgeOrchestrator):
        """Initialize health check."""
        self.orchestrator = orchestrator
        self.logger = logging.getLogger(__name__)
    
    def check_health(self) -> Dict[str, Any]:
        """Perform comprehensive health check."""
        health_status = {
            "overall_status": "healthy",
            "timestamp": None,
            "services": {},
            "configuration": {},
            "dependencies": {}
        }
        
        try:
            from datetime import datetime
            health_status["timestamp"] = datetime.now().isoformat()
            
            # Check service status
            service_status = self.orchestrator.get_service_status()
            health_status["services"] = service_status
            
            # Check configuration
            config_health = self._check_configuration()
            health_status["configuration"] = config_health
            
            # Check dependencies
            deps_health = self._check_dependencies()
            health_status["dependencies"] = deps_health
            
            # Determine overall status
            if not config_health.get("valid", False):
                health_status["overall_status"] = "unhealthy"
            elif any(not svc.get("initialized", False) 
                    for svc in service_status.values() 
                    if isinstance(svc, dict) and svc.get("enabled", False)):
                health_status["overall_status"] = "degraded"
            
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            health_status["overall_status"] = "error"
            health_status["error"] = str(e)
        
        return health_status
    
    def _check_configuration(self) -> Dict[str, Any]:
        """Check configuration validity."""
        try:
            config = self.orchestrator.config
            issues = []
            
            # Check required paths
            trust_store_path = Path(config.trust_store_path)
            if not trust_store_path.exists():
                issues.append(f"Trust store not found: {config.trust_store_path}")
            
            # Check URL format
            if not config.base_url.startswith(("http://", "https://")):
                issues.append("Invalid base URL format")
            
            # Check supported formats
            valid_formats = ["sd_jwt_vc", "eudi_vc", "mdoc"]
            for fmt in config.supported_formats or []:
                if fmt not in valid_formats:
                    issues.append(f"Unsupported format: {fmt}")
            
            return {
                "valid": len(issues) == 0,
                "issues": issues,
                "arf_version": config.arf_version,
                "compliance_mode": config.compliance_mode
            }
            
        except Exception as e:
            return {
                "valid": False,
                "error": str(e)
            }
    
    def _check_dependencies(self) -> Dict[str, Any]:
        """Check external dependencies."""
        dependencies = {
            "cryptography": self._check_cryptography(),
            "jwt": self._check_jwt(),
            "yaml": self._check_yaml()
        }
        
        all_healthy = all(dep.get("available", False) for dep in dependencies.values())
        
        return {
            "all_available": all_healthy,
            "details": dependencies
        }
    
    def _check_cryptography(self) -> Dict[str, Any]:
        """Check cryptography library."""
        try:
            import cryptography
            return {
                "available": True,
                "version": cryptography.__version__
            }
        except ImportError as e:
            return {
                "available": False,
                "error": str(e)
            }
    
    def _check_jwt(self) -> Dict[str, Any]:
        """Check JWT library."""
        try:
            import jwt
            return {
                "available": True,
                "version": getattr(jwt, "__version__", "unknown")
            }
        except ImportError as e:
            return {
                "available": False,
                "error": str(e)
            }
    
    def _check_yaml(self) -> Dict[str, Any]:
        """Check YAML library."""
        try:
            import yaml
            return {
                "available": True,
                "version": getattr(yaml, "__version__", "unknown")
            }
        except ImportError as e:
            return {
                "available": False,
                "error": str(e)
            }


# Factory functions for easy initialization
def create_eudi_bridge_orchestrator(
    environment: str = "development",
    config_file: Optional[str] = None,
    config_dir: str = "/Users/adamburdett/Github/work/Marty/config"
) -> EUDIBridgeOrchestrator:
    """
    Factory function to create EUDI Bridge Orchestrator.
    
    Args:
        environment: Environment name
        config_file: Optional config file path
        config_dir: Configuration directory
        
    Returns:
        Configured EUDIBridgeOrchestrator instance
    """
    config_loader = EUDIBridgeConfigLoader(config_dir)
    config = config_loader.load_config(environment, config_file)
    return EUDIBridgeOrchestrator(config)


def quick_health_check(
    environment: str = "development",
    config_dir: str = "/Users/adamburdett/Github/work/Marty/config"
) -> Dict[str, Any]:
    """
    Perform quick health check of EUDI Bridge services.
    
    Args:
        environment: Environment name
        config_dir: Configuration directory
        
    Returns:
        Health check results
    """
    try:
        orchestrator = create_eudi_bridge_orchestrator(environment, None, config_dir)
        health_checker = EUDIBridgeHealthCheck(orchestrator)
        return health_checker.check_health()
    except Exception as e:
        return {
            "overall_status": "error",
            "error": str(e),
            "timestamp": None
        }