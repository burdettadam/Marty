"""
Production security configuration loader for Trust Service.

This module loads and validates security configuration from multiple sources
including YAML files, environment variables, and Vault.
"""

import os
import yaml
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """Security levels for different environments."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass
class VaultConfig:
    """Vault configuration."""
    url: str
    auth_method: str = "approle"
    token: Optional[str] = None
    role_id: Optional[str] = None
    secret_id: Optional[str] = None
    namespace: Optional[str] = None
    ca_cert: Optional[str] = None
    verify_ssl: bool = True
    mount_point_kv: str = "kv"
    mount_point_pki: str = "pki"
    mount_point_database: str = "database"
    timeout: int = 30
    max_retries: int = 3
    retry_delay: int = 1


@dataclass
class MTLSConfig:
    """Mutual TLS configuration."""
    enabled: bool = True
    require_client_cert: bool = True
    verify_client_cert: bool = True
    server_cert_path: Optional[str] = None
    server_key_path: Optional[str] = None
    client_ca_path: Optional[str] = None
    allowed_clients: List[str] = None
    min_tls_version: str = "TLSv1.2"
    cipher_suites: Optional[str] = None


@dataclass
class JWTConfig:
    """JWT configuration."""
    enabled: bool = True
    algorithm: str = "RS256"
    expiry_minutes: int = 60
    issuer: str = "trust-service"
    audience: str = "trust-service-api"
    key_rotation_days: int = 30


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    enabled: bool = True
    requests_per_minute: int = 1000
    burst_size: int = 100
    by_ip: bool = True
    by_api_key: bool = True
    by_user: bool = True


@dataclass
class DatabaseSecurityConfig:
    """Database security configuration."""
    ssl_enabled: bool = True
    ssl_mode: str = "require"
    ssl_ca_cert: Optional[str] = None
    ssl_client_cert: Optional[str] = None
    ssl_client_key: Optional[str] = None
    require_ssl: bool = True
    min_tls_version: str = "TLSv1.2"
    credential_rotation_enabled: bool = True
    rotation_check_interval: int = 300
    credential_ttl_hours: int = 8
    max_connections: int = 20
    connection_timeout: int = 30
    idle_timeout: int = 3600
    max_lifetime: int = 7200
    audit_enabled: bool = True
    log_connections: bool = True
    log_queries: bool = False


@dataclass
class AuditLoggingConfig:
    """Audit logging configuration."""
    enabled: bool = True
    log_to_file: bool = True
    log_to_database: bool = True
    log_to_siem: bool = False
    encryption_enabled: bool = True
    retention_days: int = 365
    log_file_path: str = "/var/log/trust-service/audit.log"
    log_file_max_size: str = "100MB"
    log_file_backup_count: int = 10
    log_authentication: bool = True
    log_authorization: bool = True
    log_certificate_operations: bool = True
    log_data_access: bool = True
    log_security_events: bool = True
    log_system_events: bool = True
    sensitive_fields: List[str] = None


@dataclass
class ProductionSecurityConfig:
    """Complete production security configuration."""
    security_level: SecurityLevel
    vault: VaultConfig
    mtls: MTLSConfig
    jwt: JWTConfig
    rate_limiting: RateLimitConfig
    database_security: DatabaseSecurityConfig
    audit_logging: AuditLoggingConfig
    
    # Additional security settings
    security_headers_enabled: bool = True
    request_validation_enabled: bool = True
    encryption_enabled: bool = True
    monitoring_enabled: bool = True
    compliance_enabled: bool = True


class SecurityConfigLoader:
    """Loads and validates security configuration."""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.environment = os.getenv("ENVIRONMENT", "development")
        self.security_level = SecurityLevel(self.environment)
    
    def load_config(self) -> ProductionSecurityConfig:
        """Load complete security configuration."""
        try:
            # Load base security configuration
            security_config = self._load_security_yaml()
            
            # Override with environment-specific settings
            env_overrides = self._load_environment_overrides()
            security_config = self._merge_configs(security_config, env_overrides)
            
            # Apply environment variables
            security_config = self._apply_env_vars(security_config)
            
            # Validate configuration
            self._validate_config(security_config)
            
            # Create configuration objects
            config = self._create_config_objects(security_config)
            
            logger.info(f"Security configuration loaded for {self.security_level.value}")
            return config
            
        except Exception as e:
            logger.error(f"Failed to load security configuration: {e}")
            raise
    
    def _load_security_yaml(self) -> Dict[str, Any]:
        """Load security configuration from YAML file."""
        security_file = self.config_dir / "security.yaml"
        
        if not security_file.exists():
            raise FileNotFoundError(f"Security configuration file not found: {security_file}")
        
        with open(security_file, 'r') as f:
            return yaml.safe_load(f)
    
    def _load_environment_overrides(self) -> Dict[str, Any]:
        """Load environment-specific configuration overrides."""
        env_file = self.config_dir / f"security-{self.environment}.yaml"
        
        if env_file.exists():
            with open(env_file, 'r') as f:
                return yaml.safe_load(f)
        
        return {}
    
    def _merge_configs(self, base: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
        """Merge configuration dictionaries."""
        result = base.copy()
        
        for key, value in overrides.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _apply_env_vars(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply environment variable overrides."""
        # This would implement environment variable substitution
        # For now, just return the config as-is
        return config
    
    def _validate_config(self, config: Dict[str, Any]) -> None:
        """Validate security configuration."""
        required_sections = ['vault', 'mtls', 'jwt', 'database_security', 'audit_logging']
        
        for section in required_sections:
            if section not in config:
                raise ValueError(f"Required security configuration section missing: {section}")
        
        # Additional validation logic here
        
        # Production-specific validations
        if self.security_level == SecurityLevel.PRODUCTION:
            self._validate_production_config(config)
    
    def _validate_production_config(self, config: Dict[str, Any]) -> None:
        """Additional validation for production environments."""
        # Ensure strong security settings for production
        vault_config = config.get('vault', {})
        
        if vault_config.get('auth_method') == 'token':
            logger.warning("Using token authentication in production is not recommended")
        
        if not config.get('mtls', {}).get('enabled'):
            raise ValueError("mTLS must be enabled in production")
        
        if not config.get('audit_logging', {}).get('enabled'):
            raise ValueError("Audit logging must be enabled in production")
    
    def _create_config_objects(self, config: Dict[str, Any]) -> ProductionSecurityConfig:
        """Create configuration objects from dictionary."""
        
        # Vault configuration
        vault_data = config.get('vault', {})
        vault_config = VaultConfig(
            url=vault_data.get('url', 'https://vault.internal:8200'),
            auth_method=vault_data.get('auth_method', 'approle'),
            token=vault_data.get('token'),
            role_id=vault_data.get('role_id'),
            secret_id=vault_data.get('secret_id'),
            namespace=vault_data.get('namespace'),
            ca_cert=vault_data.get('ca_cert'),
            verify_ssl=vault_data.get('verify_ssl', True),
            mount_point_kv=vault_data.get('mount_point_kv', 'kv'),
            mount_point_pki=vault_data.get('mount_point_pki', 'pki'),
            mount_point_database=vault_data.get('mount_point_database', 'database'),
            timeout=vault_data.get('timeout', 30),
            max_retries=vault_data.get('max_retries', 3),
            retry_delay=vault_data.get('retry_delay', 1)
        )
        
        # mTLS configuration
        mtls_data = config.get('mtls', {})
        mtls_config = MTLSConfig(
            enabled=mtls_data.get('enabled', True),
            require_client_cert=mtls_data.get('require_client_cert', True),
            verify_client_cert=mtls_data.get('verify_client_cert', True),
            server_cert_path=mtls_data.get('server_cert_path'),
            server_key_path=mtls_data.get('server_key_path'),
            client_ca_path=mtls_data.get('client_ca_path'),
            allowed_clients=mtls_data.get('allowed_clients', []),
            min_tls_version=mtls_data.get('min_tls_version', 'TLSv1.2'),
            cipher_suites=mtls_data.get('cipher_suites')
        )
        
        # JWT configuration
        jwt_data = config.get('jwt', {})
        jwt_config = JWTConfig(
            enabled=jwt_data.get('enabled', True),
            algorithm=jwt_data.get('algorithm', 'RS256'),
            expiry_minutes=jwt_data.get('expiry_minutes', 60),
            issuer=jwt_data.get('issuer', 'trust-service'),
            audience=jwt_data.get('audience', 'trust-service-api'),
            key_rotation_days=jwt_data.get('key_rotation_days', 30)
        )
        
        # Rate limiting configuration
        rate_limit_data = config.get('rate_limiting', {})
        rate_limit_config = RateLimitConfig(
            enabled=rate_limit_data.get('enabled', True),
            requests_per_minute=rate_limit_data.get('requests_per_minute', 1000),
            burst_size=rate_limit_data.get('burst_size', 100),
            by_ip=rate_limit_data.get('by_ip', True),
            by_api_key=rate_limit_data.get('by_api_key', True),
            by_user=rate_limit_data.get('by_user', True)
        )
        
        # Database security configuration
        db_security_data = config.get('database_security', {})
        db_security_config = DatabaseSecurityConfig(
            ssl_enabled=db_security_data.get('ssl_enabled', True),
            ssl_mode=db_security_data.get('ssl_mode', 'require'),
            ssl_ca_cert=db_security_data.get('ssl_ca_cert'),
            ssl_client_cert=db_security_data.get('ssl_client_cert'),
            ssl_client_key=db_security_data.get('ssl_client_key'),
            require_ssl=db_security_data.get('require_ssl', True),
            min_tls_version=db_security_data.get('min_tls_version', 'TLSv1.2'),
            credential_rotation_enabled=db_security_data.get('credential_rotation_enabled', True),
            rotation_check_interval=db_security_data.get('rotation_check_interval', 300),
            credential_ttl_hours=db_security_data.get('credential_ttl_hours', 8),
            max_connections=db_security_data.get('max_connections', 20),
            connection_timeout=db_security_data.get('connection_timeout', 30),
            idle_timeout=db_security_data.get('idle_timeout', 3600),
            max_lifetime=db_security_data.get('max_lifetime', 7200),
            audit_enabled=db_security_data.get('audit_enabled', True),
            log_connections=db_security_data.get('log_connections', True),
            log_queries=db_security_data.get('log_queries', False)
        )
        
        # Audit logging configuration
        audit_data = config.get('audit_logging', {})
        audit_config = AuditLoggingConfig(
            enabled=audit_data.get('enabled', True),
            log_to_file=audit_data.get('log_to_file', True),
            log_to_database=audit_data.get('log_to_database', True),
            log_to_siem=audit_data.get('log_to_siem', False),
            encryption_enabled=audit_data.get('encryption_enabled', True),
            retention_days=audit_data.get('retention_days', 365),
            log_file_path=audit_data.get('log_file_path', '/var/log/trust-service/audit.log'),
            log_file_max_size=audit_data.get('log_file_max_size', '100MB'),
            log_file_backup_count=audit_data.get('log_file_backup_count', 10),
            log_authentication=audit_data.get('log_authentication', True),
            log_authorization=audit_data.get('log_authorization', True),
            log_certificate_operations=audit_data.get('log_certificate_operations', True),
            log_data_access=audit_data.get('log_data_access', True),
            log_security_events=audit_data.get('log_security_events', True),
            log_system_events=audit_data.get('log_system_events', True),
            sensitive_fields=audit_data.get('sensitive_fields', ['password', 'token', 'key', 'secret'])
        )
        
        return ProductionSecurityConfig(
            security_level=self.security_level,
            vault=vault_config,
            mtls=mtls_config,
            jwt=jwt_config,
            rate_limiting=rate_limit_config,
            database_security=db_security_config,
            audit_logging=audit_config,
            security_headers_enabled=config.get('security_headers', {}).get('enabled', True),
            request_validation_enabled=config.get('request_validation', {}).get('enabled', True),
            encryption_enabled=config.get('encryption', {}).get('encrypt_at_rest', True),
            monitoring_enabled=config.get('security_monitoring', {}).get('enabled', True),
            compliance_enabled=config.get('compliance', {}).get('gdpr_enabled', True)
        )


# Global security configuration instance
_security_config: Optional[ProductionSecurityConfig] = None


def get_security_config() -> ProductionSecurityConfig:
    """Get or load global security configuration."""
    global _security_config
    
    if _security_config is None:
        loader = SecurityConfigLoader()
        _security_config = loader.load_config()
    
    return _security_config


def reload_security_config() -> ProductionSecurityConfig:
    """Reload security configuration."""
    global _security_config
    
    loader = SecurityConfigLoader()
    _security_config = loader.load_config()
    
    return _security_config


# Environment-specific configuration helpers

def is_production() -> bool:
    """Check if running in production environment."""
    return get_security_config().security_level == SecurityLevel.PRODUCTION


def is_development() -> bool:
    """Check if running in development environment."""
    return get_security_config().security_level == SecurityLevel.DEVELOPMENT


def get_vault_config() -> VaultConfig:
    """Get Vault configuration."""
    return get_security_config().vault


def get_mtls_config() -> MTLSConfig:
    """Get mTLS configuration."""
    return get_security_config().mtls


def get_jwt_config() -> JWTConfig:
    """Get JWT configuration."""
    return get_security_config().jwt


def get_audit_config() -> AuditLoggingConfig:
    """Get audit logging configuration."""
    return get_security_config().audit_logging