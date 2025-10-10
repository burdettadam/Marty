"""
Modern Document Signer Service with Unified Configuration and Observability.

This service demonstrates how to use the modern unified configuration system
and observability framework for a Marty microservice.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

# Add framework path
framework_path = Path(__file__).parent.parent.parent.parent / "marty-microservices-framework" / "src"
sys.path.append(str(framework_path))

from framework.config import BaseServiceConfig, Environment
from framework.config_factory import create_service_config
from framework.observability.unified_observability import (
    MartyMetrics,
    trace_method,
    trace_async_method,
    ObservabilityManager
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from marty_common.grpc_types import (
        DatabaseManager,
        GrpcServicerContext, 
        ProtoMessage,
        ServiceDependencies,
    )

import grpc
from src.proto.v1 import document_signer_pb2_grpc


class ModernDocumentSigner(document_signer_pb2_grpc.DocumentSignerServicer):
    """
    Modern Document Signer using unified MMF configuration.
    
    This service demonstrates best practices for using the unified configuration
    system in a Marty microservice.
    """
    
    def __init__(
        self,
        service_name: str = "document_signer",
        environment: Optional[str] = None,
        config_path: Optional[Path] = None,
        dependencies: Optional[ServiceDependencies] = None,
    ):
        self.logger = logging.getLogger(__name__)
        
        # Load modern unified configuration
        self.config = create_service_config(
            service_name=service_name,
            environment=environment or "development",
            config_path=config_path or Path("config")
        )
        
        # Set up dependencies
        if dependencies is None:
            raise ValueError("ModernDocumentSigner requires service dependencies")
        
        self.dependencies = dependencies
        self._database: DatabaseManager = dependencies.database
        # self._key_vault = dependencies.key_vault  # Commented out until interface exists
        self._object_storage = dependencies.object_storage
        
        # Initialize observability
        self.observability = None
        self.signer_metrics = {}
        
        # Initialize service with configuration
        self._initialize_service()
    
    def _initialize_service(self) -> None:
        """Initialize the service using unified configuration."""
        self.logger.info("Initializing Modern Document Signer with unified configuration")
        
        # Initialize observability first
        self._initialize_observability()
        
        # Configure database
        self._configure_database()
        
        # Configure cryptographic operations
        self._configure_cryptography()
        
        # Configure service discovery
        self._configure_service_discovery()
        
        # Configure monitoring
        self._configure_monitoring()
        
        # Configure resilience patterns
        self._configure_resilience()
        
        self.logger.info("Modern Document Signer initialization complete")
    
    def _initialize_observability(self) -> None:
        """Initialize unified observability for document signing operations."""
        try:
            # Check if observability config exists
            monitoring_config = getattr(self.config, 'monitoring', None)
            if monitoring_config:
                self.observability = ObservabilityManager(
                    config=monitoring_config,
                    service_name=self.config.service_name
                )
                
                # Setup document signer specific metrics
                self.signer_metrics = MartyMetrics.document_signing_metrics(self.observability)
                
                self.logger.info("Document Signer observability initialized")
            else:
                self.logger.warning("No monitoring configuration found")
                
        except Exception as e:
            self.logger.error("Failed to initialize observability: %s", e)
    
    def _configure_database(self) -> None:
        """Configure database connection using unified config."""
        db_config = self.config.database
        
        self.logger.info(
            f"Database configured: {db_config.host}:{db_config.port}/{db_config.database}"
        )
        
        # Store database configuration for use by managers
        self._db_config = {
            "connection_url": db_config.connection_url,
            "pool_size": db_config.pool_size,
            "max_overflow": db_config.max_overflow,
            "pool_timeout": db_config.pool_timeout,
        }
    
    def _configure_cryptography(self) -> None:
        """Configure cryptographic operations using unified config."""
        crypto_config = self.config.cryptographic
        
        # Signing configuration
        self._signing_algorithm = crypto_config.signing.algorithm
        self._signing_key_id = crypto_config.signing.key_id
        self._key_directory = crypto_config.signing.key_directory
        
        self.logger.info(
            f"Signing configured: algorithm={self._signing_algorithm}, "
            f"key_id={self._signing_key_id}"
        )
        
        # SD-JWT configuration
        self._sd_jwt_enabled = bool(crypto_config.sd_jwt.issuer)
        if self._sd_jwt_enabled:
            self._sd_jwt_config = {
                "issuer": crypto_config.sd_jwt.issuer,
                "signing_key_id": crypto_config.sd_jwt.signing_key_id,
                "signing_algorithm": crypto_config.sd_jwt.signing_algorithm,
                "vault_signing_algorithm": crypto_config.sd_jwt.vault_signing_algorithm,
                "certificate_id": crypto_config.sd_jwt.certificate_id,
                "offer_ttl_seconds": crypto_config.sd_jwt.offer_ttl_seconds,
                "token_ttl_seconds": crypto_config.sd_jwt.token_ttl_seconds,
            }
            
            self.logger.info(
                f"SD-JWT enabled: issuer={crypto_config.sd_jwt.issuer}"
            )
        else:
            self.logger.warning("SD-JWT disabled: no issuer configured")
        
        # Vault configuration
        if crypto_config.vault.url:
            self._vault_config = {
                "url": crypto_config.vault.url,
                "auth_method": crypto_config.vault.auth_method,
                "mount_path": crypto_config.vault.mount_path,
            }
            
            self.logger.info(
                f"Vault configured: {crypto_config.vault.url}"
            )
    
    def _configure_service_discovery(self) -> None:
        """Configure service discovery using unified config."""
        discovery_config = self.config.service_discovery
        
        self._service_urls = {}
        for service_name, host in discovery_config.hosts.items():
            port = discovery_config.ports.get(service_name, 8080)
            # Use TLS if security is enabled
            use_tls = self.config.security.tls.enabled
            protocol = "https" if use_tls else "http"
            self._service_urls[service_name] = f"{protocol}://{host}:{port}"
        
        self.logger.info(
            f"Service discovery configured: {len(self._service_urls)} services"
        )
        
        # Configure service mesh if enabled
        if discovery_config.enable_service_mesh:
            self.logger.info(
                f"Service mesh enabled in namespace: {discovery_config.service_mesh_namespace}"
            )
    
    def _configure_monitoring(self) -> None:
        """Configure monitoring using unified config."""
        monitoring_config = self.config.monitoring
        
        if monitoring_config.enabled:
            self._metrics_config = {
                "metrics_port": monitoring_config.metrics_port,
                "health_check_port": monitoring_config.health_check_port,
                "prometheus_enabled": monitoring_config.prometheus_enabled,
                "tracing_enabled": monitoring_config.tracing_enabled,
                "jaeger_endpoint": monitoring_config.jaeger_endpoint,
                "service_name": monitoring_config.service_name,
            }
            
            self.logger.info(
                f"Monitoring configured: metrics_port={monitoring_config.metrics_port}, "
                f"tracing={monitoring_config.tracing_enabled}"
            )
    
    def _configure_resilience(self) -> None:
        """Configure resilience patterns using unified config."""
        resilience_config = self.config.resilience
        
        self._circuit_breaker_config = {
            "failure_threshold": resilience_config.circuit_breaker.failure_threshold,
            "recovery_timeout": resilience_config.circuit_breaker.recovery_timeout,
            "half_open_max_calls": resilience_config.circuit_breaker.half_open_max_calls,
        }
        
        self._retry_config = {
            "max_attempts": resilience_config.retry_policy.max_attempts,
            "backoff_multiplier": resilience_config.retry_policy.backoff_multiplier,
            "max_delay_seconds": resilience_config.retry_policy.max_delay_seconds,
        }
        
        self.logger.info(
            f"Resilience configured: circuit_breaker_threshold="
            f"{resilience_config.circuit_breaker.failure_threshold}, "
            f"retry_attempts={resilience_config.retry_policy.max_attempts}"
        )
    
    def get_service_config_summary(self) -> dict[str, Any]:
        """Get a summary of the service configuration for debugging."""
        return {
            "service_name": self.config.service_name,
            "environment": self.config.environment.value,
            "database": {
                "host": self.config.database.host,
                "port": self.config.database.port,
                "database": self.config.database.database,
            },
            "security": {
                "tls_enabled": self.config.security.tls.enabled,
                "mtls_enabled": self.config.security.tls.mtls,
                "auth_required": self.config.security.auth.required,
            },
            "cryptographic": {
                "signing_algorithm": self._signing_algorithm,
                "sd_jwt_enabled": self._sd_jwt_enabled,
                "vault_configured": bool(getattr(self, '_vault_config', None)),
            },
            "monitoring": {
                "enabled": self.config.monitoring.enabled,
                "metrics_port": self.config.monitoring.metrics_port,
                "tracing_enabled": self.config.monitoring.tracing_enabled,
            },
            "service_discovery": {
                "service_count": len(self._service_urls),
                "service_mesh_enabled": self.config.service_discovery.enable_service_mesh,
            }
        }
    
    def print_configuration_summary(self) -> None:
        """Print a detailed configuration summary."""
        summary = self.get_service_config_summary()
        
        print("\\n" + "="*60)
        print("MODERN DOCUMENT SIGNER CONFIGURATION SUMMARY")
        print("="*60)
        
        print(f"Service Name: {summary['service_name']}")
        print(f"Environment: {summary['environment']}")
        
        print("\\nDatabase Configuration:")
        db = summary['database']
        print(f"  Host: {db['host']}:{db['port']}")
        print(f"  Database: {db['database']}")
        
        print("\\nSecurity Configuration:")
        sec = summary['security']
        print(f"  TLS Enabled: {sec['tls_enabled']}")
        print(f"  mTLS Enabled: {sec['mtls_enabled']}")
        print(f"  Auth Required: {sec['auth_required']}")
        
        print("\\nCryptographic Configuration:")
        crypto = summary['cryptographic']
        print(f"  Signing Algorithm: {crypto['signing_algorithm']}")
        print(f"  SD-JWT Enabled: {crypto['sd_jwt_enabled']}")
        print(f"  Vault Configured: {crypto['vault_configured']}")
        
        print("\\nMonitoring Configuration:")
        mon = summary['monitoring']
        print(f"  Enabled: {mon['enabled']}")
        print(f"  Metrics Port: {mon['metrics_port']}")
        print(f"  Tracing Enabled: {mon['tracing_enabled']}")
        
        print("\\nService Discovery:")
        sd = summary['service_discovery']
        print(f"  Services Configured: {sd['service_count']}")
        print(f"  Service Mesh: {sd['service_mesh_enabled']}")
        
        print("="*60)
    
    # Service methods with observability integration
    
    @trace_async_method
    async def SignDocument(self, request, context):
        """Sign a document using the configured signing algorithm with observability."""
        self.logger.info(f"Signing document with algorithm: {self._signing_algorithm}")
        
        try:
            # Extract document type for metrics
            document_type = getattr(request, 'document_type', 'unknown')
            
            # Record signing operation start
            if self.signer_metrics and 'document_operations' in self.signer_metrics:
                self.signer_metrics['document_operations'].labels(
                    operation="sign",
                    document_type=document_type,
                    algorithm=self._signing_algorithm
                ).inc()
            
            # Simulate document signing operation
            import time
            start_time = time.time()
            
            # In real implementation, this would perform actual signing
            # For now, simulate processing time
            await asyncio.sleep(0.1)
            
            # Record metrics for successful signing
            duration = time.time() - start_time
            
            if self.signer_metrics and 'signing_duration' in self.signer_metrics:
                self.signer_metrics['signing_duration'].labels(
                    algorithm=self._signing_algorithm,
                    document_type=document_type
                ).observe(duration)
            
            if self.signer_metrics and 'signature_operations' in self.signer_metrics:
                self.signer_metrics['signature_operations'].labels(
                    result="success",
                    algorithm=self._signing_algorithm,
                    key_type="rsa"  # Would get from actual key
                ).inc()
            
            self.logger.info(f"Document signed successfully in {duration:.3f}s")
            
            # Return success response (would include actual signature)
            from src.proto.v1.document_signer_pb2 import SignDocumentResponse
            return SignDocumentResponse(
                signature="placeholder_signature",
                success=True
            )
            
        except Exception as e:
            self.logger.error(f"Document signing failed: {e}")
            
            # Record error metrics
            if self.signer_metrics and 'signature_operations' in self.signer_metrics:
                self.signer_metrics['signature_operations'].labels(
                    result="error",
                    algorithm=self._signing_algorithm,
                    key_type="unknown"
                ).inc()
            
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            raise
    
    @trace_async_method
    async def CreateCredentialOffer(self, request, context):
        """Create an SD-JWT credential offer with observability."""
        if not self._sd_jwt_enabled:
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details("SD-JWT is not enabled")
            return
        
        self.logger.info(f"Creating credential offer for issuer: {self._sd_jwt_config['issuer']}")
        
        try:
            # Record SD-JWT operation start
            if self.signer_metrics and 'sdjwt_operations' in self.signer_metrics:
                self.signer_metrics['sdjwt_operations'].labels(
                    operation="create_offer",
                    issuer=self._sd_jwt_config.get('issuer', 'unknown'),
                    credential_type="unknown"  # Would extract from request
                ).inc()
            
            # Simulate credential offer creation
            import time
            start_time = time.time()
            await asyncio.sleep(0.05)
            
            # Record metrics
            duration = time.time() - start_time
            if self.signer_metrics and 'sdjwt_processing_time' in self.signer_metrics:
                self.signer_metrics['sdjwt_processing_time'].labels(
                    operation="create_offer",
                    issuer=self._sd_jwt_config.get('issuer', 'unknown')
                ).observe(duration)
            
            self.logger.info(f"Credential offer created successfully in {duration:.3f}s")
            
            # Return success response
            from src.proto.v1.document_signer_pb2 import CreateCredentialOfferResponse
            return CreateCredentialOfferResponse(
                offer="placeholder_offer",
                success=True
            )
            
        except Exception as e:
            self.logger.error(f"Credential offer creation failed: {e}")
            
            # Record error metrics
            if self.signer_metrics and 'sdjwt_operations' in self.signer_metrics:
                self.signer_metrics['sdjwt_operations'].labels(
                    operation="create_offer_error",
                    issuer=self._sd_jwt_config.get('issuer', 'unknown'),
                    credential_type="unknown"
                ).inc()
            
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            raise


def create_modern_document_signer(
    environment: Optional[str] = None,
    config_path: Optional[Path] = None,
    dependencies: Optional[ServiceDependencies] = None,
) -> ModernDocumentSigner:
    """
    Factory function to create a modern document signer service.
    
    Args:
        environment: Environment name (development, testing, production)
        config_path: Path to configuration directory  
        dependencies: Service dependencies
        
    Returns:
        ModernDocumentSigner instance
    """
    return ModernDocumentSigner(
        service_name="document_signer",
        environment=environment,
        config_path=config_path,
        dependencies=dependencies,
    )


if __name__ == "__main__":
    # Example usage - create and configure the service
    print("Modern Document Signer Configuration Example")
    
    # This would normally be provided by the service framework
    from unittest.mock import Mock
    mock_dependencies = Mock()
    mock_dependencies.database = Mock()
    mock_dependencies.key_vault = Mock()
    mock_dependencies.object_storage = Mock()
    
    try:
        # Test different environments
        for env in ["development", "testing", "production"]:
            print(f"\\n--- Testing {env.upper()} Environment ---")
            
            signer = ModernDocumentSigner(
                service_name="document_signer",
                environment=env,
                config_path=Path("config"),
                dependencies=mock_dependencies,
            )
            
            signer.print_configuration_summary()
            
    except Exception as e:
        print(f"Configuration test failed: {e}")
        print("Ensure config files exist and framework is properly set up")