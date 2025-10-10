"""
Modern DTC Engine Service with Unified Configuration and Observability.

This service demonstrates the migration patterns for complex services with
multiple integrations to use the unified observability framework.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

# Add project root to path for imports
_project_root = Path(__file__).resolve().parents[2]
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# Modern framework imports
from framework.config_factory import create_service_config
from framework.grpc.unified_grpc_server import (
    UnifiedGrpcServer,
    ObservableGrpcServiceMixin
)
from framework.observability.unified_observability import (
    MartyMetrics,
    trace_async_method,
    trace_grpc_method
)

if TYPE_CHECKING:
    from marty_common.grpc_types import (
        GrpcServicerContext,
        ProtoMessage,
        ServiceDependencies,
    )

# gRPC imports
import grpc
from grpc import aio

# DTC Engine imports
import cbor2
import qrcode
from cryptography import x509

from marty_common.infrastructure import (
    CertificateRepository,
    DigitalTravelCredentialRepository,
    KeyVaultClient,
    ObjectStorageClient,
    OutboxRepository,
)
from proto import document_signer_pb2, document_signer_pb2_grpc, dtc_engine_pb2, dtc_engine_pb2_grpc
from src.marty_common.crypto.document_signer_certificate import (
    DOCUMENT_SIGNER_KEY_ID,
    load_or_create_document_signer_certificate,
)
from src.marty_common.crypto.dtc_verifier import DTCVerifier


class ModernDTCEngineService(dtc_engine_pb2_grpc.DTCEngineServicer, ObservableGrpcServiceMixin):
    """
    Modern DTC Engine Service with unified observability.
    
    This service demonstrates migration patterns for complex services that
    integrate with multiple external services and require comprehensive
    business metrics tracking.
    """

    def __init__(
        self,
        config_path: str = "config/services/dtc_engine.yaml",
        dependencies: Optional[ServiceDependencies] = None,
    ) -> None:
        """Initialize with unified configuration and observability."""
        super().__init__()
        
        self.logger = logging.getLogger("marty.dtc.engine")
        
        # Load unified configuration
        self.config = create_service_config(config_path)
        
        if dependencies is None:
            raise ValueError("ModernDTCEngineService requires service dependencies")
        
        self.dependencies = dependencies
        self._database = dependencies.database
        self._key_vault = dependencies.key_vault
        self._object_storage = dependencies.object_storage
        
        # DTC-specific configuration
        self._default_validity_days = self.config.dtc.issuance.default_validity_days
        self._max_validity_days = self.config.dtc.issuance.max_validity_days
        self._signing_algorithm = self.config.dtc.security.signing_algorithm
        self._use_external_storage = self.config.dtc.storage.use_external_storage
        self._compression_enabled = self.config.dtc.storage.compression_enabled
        
        # Business metrics will be set up by observability
        self.dtc_metrics = {}
        
        self.logger.info("Modern DTC Engine Service initialized with unified configuration")

    def _setup_observability(self, config):
        """Override to add DTC-specific metrics and health checks."""
        super()._setup_observability(config)
        
        # Setup DTC-specific business metrics
        self.dtc_metrics.update({
            "dtc_operations": self.observability.get_or_create_counter(
                name="marty_dtc_operations_total",
                description="DTC lifecycle operations",
                labels=["operation", "result", "dtc_type", "country"]
            ),
            "signing_operations": self.observability.get_or_create_counter(
                name="marty_dtc_signing_operations_total",
                description="DTC signing operations", 
                labels=["algorithm", "key_type", "result"]
            ),
            "verification_operations": self.observability.get_or_create_counter(
                name="marty_dtc_verification_operations_total",
                description="DTC verification operations",
                labels=["result", "verification_type", "trust_level"]
            ),
            "qr_generation": self.observability.get_or_create_counter(
                name="marty_dtc_qr_generation_total",
                description="QR code generation operations",
                labels=["format", "size", "result"]
            ),
            "storage_operations": self.observability.get_or_create_counter(
                name="marty_dtc_storage_operations_total",
                description="DTC storage operations",
                labels=["operation", "storage_type", "result"]
            ),
            "operation_duration": self.observability.get_or_create_histogram(
                name="marty_dtc_operation_duration_seconds",
                description="Time to complete DTC operations",
                labels=["operation", "dtc_type"]
            ),
            "payload_size": self.observability.get_or_create_histogram(
                name="marty_dtc_payload_size_bytes",
                description="Size of DTC payloads",
                labels=["operation", "compression_used"]
            ),
            "validity_period": self.observability.get_or_create_histogram(
                name="marty_dtc_validity_period_days",
                description="DTC validity period in days",
                labels=["dtc_type", "issuance_type"]
            )
        })
        
        # Register DTC-specific health checks
        self._register_dtc_health_checks()
        
        self.logger.info("DTC Engine observability configured")

    def _register_dtc_health_checks(self):
        """Register DTC-specific health checks."""
        if self.observability:
            # Database connectivity
            self.observability.register_health_check(
                name="database",
                check_func=self._check_database_health,
                interval_seconds=30
            )
            
            # Document signer connectivity
            self.observability.register_health_check(
                name="document_signer",
                check_func=self._check_document_signer_health,
                interval_seconds=60
            )
            
            # Trust anchor connectivity
            self.observability.register_health_check(
                name="trust_anchor",
                check_func=self._check_trust_anchor_health,
                interval_seconds=60
            )
            
            # Key vault connectivity
            self.observability.register_health_check(
                name="key_vault",
                check_func=self._check_key_vault_health,
                interval_seconds=120
            )
            
            # Object storage connectivity
            self.observability.register_health_check(
                name="object_storage",
                check_func=self._check_object_storage_health,
                interval_seconds=60
            )

    async def _check_database_health(self):
        """Check database connectivity."""
        from framework.observability.monitoring import HealthStatus
        
        try:
            async with self._database.session_scope() as session:
                await session.execute("SELECT 1")
                return HealthStatus.HEALTHY
        except Exception:
            return HealthStatus.UNHEALTHY

    async def _check_document_signer_health(self):
        """Check document signer service connectivity."""
        from framework.observability.monitoring import HealthStatus
        
        try:
            # In real implementation, would test gRPC connectivity
            return HealthStatus.HEALTHY
        except Exception:
            return HealthStatus.DEGRADED

    async def _check_trust_anchor_health(self):
        """Check trust anchor service connectivity."""
        from framework.observability.monitoring import HealthStatus
        
        try:
            # In real implementation, would test trust anchor connectivity
            return HealthStatus.HEALTHY
        except Exception:
            return HealthStatus.DEGRADED

    async def _check_key_vault_health(self):
        """Check key vault connectivity."""
        from framework.observability.monitoring import HealthStatus
        
        try:
            # In real implementation, would test key vault API
            return HealthStatus.HEALTHY
        except Exception:
            return HealthStatus.UNHEALTHY

    async def _check_object_storage_health(self):
        """Check object storage connectivity.""" 
        from framework.observability.monitoring import HealthStatus
        
        try:
            # In real implementation, would test object storage
            return HealthStatus.HEALTHY
        except Exception:
            return HealthStatus.DEGRADED

    # gRPC Service Methods with Observability

    @trace_grpc_method
    async def CreateDTC(
        self,
        request: Any,  # dtc_engine_pb2.CreateDTCRequest
        context: GrpcServicerContext,
    ) -> Any:  # dtc_engine_pb2.CreateDTCResponse
        """Create a DTC with observability tracking."""
        method_trace = self.trace_grpc_call("CreateDTC")
        
        @method_trace
        async def _create_impl(request, context):
            start_time = datetime.now(timezone.utc)
            
            try:
                self.logger.info("Creating DTC for subject: %s", getattr(request, 'subject_id', 'unknown'))
                
                # Extract DTC metadata for metrics
                dtc_type = getattr(request, 'dtc_type', 'standard')
                country = getattr(request, 'country_code', 'unknown')
                
                # Simulate DTC creation logic
                dtc_id = str(uuid.uuid4())
                payload_size = len(json.dumps(getattr(request, 'payload', {})).encode())
                
                # Calculate validity period
                validity_days = getattr(request, 'validity_days', self._default_validity_days)
                if validity_days > self._max_validity_days:
                    validity_days = self._max_validity_days
                
                # Record business metrics
                self.dtc_metrics["dtc_operations"].labels(
                    operation="create",
                    result="success",
                    dtc_type=dtc_type,
                    country=country
                ).inc()
                
                # Record operation duration
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                self.dtc_metrics["operation_duration"].labels(
                    operation="create",
                    dtc_type=dtc_type
                ).observe(duration)
                
                # Record payload size
                self.dtc_metrics["payload_size"].labels(
                    operation="create",
                    compression_used=str(self._compression_enabled)
                ).observe(payload_size)
                
                # Record validity period
                self.dtc_metrics["validity_period"].labels(
                    dtc_type=dtc_type,
                    issuance_type="standard"
                ).observe(validity_days)
                
                self.logger.info(
                    "DTC created successfully: id=%s, type=%s, validity=%d days",
                    dtc_id, dtc_type, validity_days
                )
                
                return dtc_engine_pb2.CreateDTCResponse(
                    dtc_id=dtc_id,
                    success=True,
                    message="DTC created successfully"
                )
                
            except Exception as e:
                self.logger.error("DTC creation failed: %s", e)
                
                # Record error metrics
                self.dtc_metrics["dtc_operations"].labels(
                    operation="create",
                    result="error", 
                    dtc_type="unknown",
                    country="unknown"
                ).inc()
                
                context.set_details(str(e))
                context.set_code(grpc.StatusCode.INTERNAL)
                return dtc_engine_pb2.CreateDTCResponse(
                    success=False,
                    message=str(e)
                )
        
        return await _create_impl(request, context)

    @trace_grpc_method
    async def SignDTC(
        self,
        request: Any,  # dtc_engine_pb2.SignDTCRequest
        context: GrpcServicerContext,
    ) -> Any:  # dtc_engine_pb2.SignDTCResponse
        """Sign a DTC with observability tracking.""" 
        method_trace = self.trace_grpc_call("SignDTC")
        
        @method_trace
        async def _sign_impl(request, context):
            start_time = datetime.now(timezone.utc)
            
            try:
                dtc_id = getattr(request, 'dtc_id', 'unknown')
                self.logger.info("Signing DTC: %s", dtc_id)
                
                # Extract signing parameters
                algorithm = getattr(request, 'algorithm', self._signing_algorithm)
                key_type = "rsa"  # Would extract from actual key
                
                # Simulate signing operation
                signature = "simulated_signature_" + str(uuid.uuid4())[:8]
                
                # Record signing metrics
                self.dtc_metrics["signing_operations"].labels(
                    algorithm=algorithm,
                    key_type=key_type,
                    result="success"
                ).inc()
                
                # Record operation duration
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                self.dtc_metrics["operation_duration"].labels(
                    operation="sign",
                    dtc_type="standard"  # Would extract from DTC
                ).observe(duration)
                
                self.logger.info(
                    "DTC signed successfully: id=%s, algorithm=%s, duration=%.3fs",
                    dtc_id, algorithm, duration
                )
                
                return dtc_engine_pb2.SignDTCResponse(
                    dtc_id=dtc_id,
                    signature=signature,
                    success=True,
                    message="DTC signed successfully"
                )
                
            except Exception as e:
                self.logger.error("DTC signing failed: %s", e)
                
                # Record error metrics
                self.dtc_metrics["signing_operations"].labels(
                    algorithm=self._signing_algorithm,
                    key_type="unknown",
                    result="error"
                ).inc()
                
                context.set_details(str(e))
                context.set_code(grpc.StatusCode.INTERNAL)
                return dtc_engine_pb2.SignDTCResponse(
                    success=False,
                    message=str(e)
                )
        
        return await _sign_impl(request, context)

    @trace_grpc_method
    async def VerifyDTC(
        self,
        request: Any,  # dtc_engine_pb2.VerifyDTCRequest  
        context: GrpcServicerContext,
    ) -> Any:  # dtc_engine_pb2.VerifyDTCResponse
        """Verify a DTC with observability tracking."""
        method_trace = self.trace_grpc_call("VerifyDTC")
        
        @method_trace
        async def _verify_impl(request, context):
            start_time = datetime.now(timezone.utc)
            
            try:
                dtc_id = getattr(request, 'dtc_id', 'unknown')
                self.logger.info("Verifying DTC: %s", dtc_id)
                
                # Extract verification parameters
                verification_type = getattr(request, 'verification_type', 'standard')
                trust_level = "high"  # Would determine from verification result
                
                # Simulate verification logic
                is_valid = True  # Placeholder
                
                # Record verification metrics
                result = "success" if is_valid else "failure"
                self.dtc_metrics["verification_operations"].labels(
                    result=result,
                    verification_type=verification_type,
                    trust_level=trust_level
                ).inc()
                
                # Record operation duration
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                self.dtc_metrics["operation_duration"].labels(
                    operation="verify",
                    dtc_type="standard"  # Would extract from DTC
                ).observe(duration)
                
                self.logger.info(
                    "DTC verification completed: id=%s, valid=%s, duration=%.3fs",
                    dtc_id, is_valid, duration
                )
                
                return dtc_engine_pb2.VerifyDTCResponse(
                    dtc_id=dtc_id,
                    is_valid=is_valid,
                    success=True,
                    message="DTC verification completed"
                )
                
            except Exception as e:
                self.logger.error("DTC verification failed: %s", e)
                
                # Record error metrics
                self.dtc_metrics["verification_operations"].labels(
                    result="error",
                    verification_type="unknown",
                    trust_level="unknown"
                ).inc()
                
                context.set_details(str(e))
                context.set_code(grpc.StatusCode.INTERNAL)
                return dtc_engine_pb2.VerifyDTCResponse(
                    success=False,
                    message=str(e)
                )
        
        return await _verify_impl(request, context)

    @trace_grpc_method
    async def GenerateDTCQRCode(
        self,
        request: Any,  # dtc_engine_pb2.GenerateQRCodeRequest
        context: GrpcServicerContext,
    ) -> Any:  # dtc_engine_pb2.GenerateQRCodeResponse
        """Generate QR code for DTC with observability tracking."""
        method_trace = self.trace_grpc_call("GenerateDTCQRCode")
        
        @method_trace
        async def _qr_impl(request, context):
            start_time = datetime.now(timezone.utc)
            
            try:
                dtc_id = getattr(request, 'dtc_id', 'unknown')
                self.logger.info("Generating QR code for DTC: %s", dtc_id)
                
                # Extract QR parameters
                qr_format = getattr(request, 'format', self.config.dtc.qr_code.format)
                qr_size = getattr(request, 'size', self.config.dtc.qr_code.size)
                
                # Simulate QR code generation
                qr_data = f"dtc://{dtc_id}"
                qr_code_bytes = b"simulated_qr_code_data"  # Would generate actual QR code
                
                # Record QR generation metrics
                self.dtc_metrics["qr_generation"].labels(
                    format=qr_format,
                    size=str(qr_size),
                    result="success"
                ).inc()
                
                # Record operation duration
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                self.dtc_metrics["operation_duration"].labels(
                    operation="qr_generate",
                    dtc_type="standard"
                ).observe(duration)
                
                self.logger.info(
                    "QR code generated: id=%s, format=%s, size=%d, duration=%.3fs",
                    dtc_id, qr_format, qr_size, duration
                )
                
                return dtc_engine_pb2.GenerateQRCodeResponse(
                    dtc_id=dtc_id,
                    qr_code_data=qr_code_bytes,
                    format=qr_format,
                    success=True,
                    message="QR code generated successfully"
                )
                
            except Exception as e:
                self.logger.error("QR code generation failed: %s", e)
                
                # Record error metrics
                self.dtc_metrics["qr_generation"].labels(
                    format="unknown",
                    size="unknown", 
                    result="error"
                ).inc()
                
                context.set_details(str(e))
                context.set_code(grpc.StatusCode.INTERNAL)
                return dtc_engine_pb2.GenerateQRCodeResponse(
                    success=False,
                    message=str(e)
                )
        
        return await _qr_impl(request, context)

    @trace_grpc_method
    async def RevokeDTC(
        self,
        request: Any,  # dtc_engine_pb2.RevokeDTCRequest
        context: GrpcServicerContext,
    ) -> Any:  # dtc_engine_pb2.RevokeDTCResponse
        """Revoke a DTC with observability tracking."""
        method_trace = self.trace_grpc_call("RevokeDTC")
        
        @method_trace
        async def _revoke_impl(request, context):
            start_time = datetime.now(timezone.utc)
            
            try:
                dtc_id = getattr(request, 'dtc_id', 'unknown')
                revocation_reason = getattr(request, 'reason', 'unspecified')
                
                self.logger.info("Revoking DTC: id=%s, reason=%s", dtc_id, revocation_reason)
                
                # Simulate revocation logic
                # In real implementation, would update database and publish events
                
                # Record revocation metrics
                self.dtc_metrics["dtc_operations"].labels(
                    operation="revoke",
                    result="success",
                    dtc_type="standard",  # Would extract from DTC
                    country="unknown"  # Would extract from DTC
                ).inc()
                
                # Record operation duration
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                self.dtc_metrics["operation_duration"].labels(
                    operation="revoke",
                    dtc_type="standard"
                ).observe(duration)
                
                self.logger.info(
                    "DTC revoked successfully: id=%s, reason=%s, duration=%.3fs",
                    dtc_id, revocation_reason, duration
                )
                
                return dtc_engine_pb2.RevokeDTCResponse(
                    dtc_id=dtc_id,
                    success=True,
                    message="DTC revoked successfully"
                )
                
            except Exception as e:
                self.logger.error("DTC revocation failed: %s", e)
                
                # Record error metrics
                self.dtc_metrics["dtc_operations"].labels(
                    operation="revoke",
                    result="error",
                    dtc_type="unknown",
                    country="unknown"
                ).inc()
                
                context.set_details(str(e))
                context.set_code(grpc.StatusCode.INTERNAL)
                return dtc_engine_pb2.RevokeDTCResponse(
                    success=False,
                    message=str(e)
                )
        
        return await _revoke_impl(request, context)

    # Additional helper methods with observability

    @trace_async_method
    async def _store_dtc_payload(
        self,
        dtc_id: str,
        payload: Dict[str, Any],
        use_compression: bool = True
    ) -> str:
        """Store DTC payload with storage operation tracking."""
        try:
            storage_type = "external" if self._use_external_storage else "database"
            
            # Simulate storage operation
            storage_key = f"dtc/{dtc_id}/payload.json"
            
            # Record storage metrics
            self.dtc_metrics["storage_operations"].labels(
                operation="store",
                storage_type=storage_type,
                result="success"
            ).inc()
            
            # Record payload size
            payload_size = len(json.dumps(payload).encode())
            self.dtc_metrics["payload_size"].labels(
                operation="store",
                compression_used=str(use_compression)
            ).observe(payload_size)
            
            self.logger.info(
                "DTC payload stored: id=%s, key=%s, size=%d bytes",
                dtc_id, storage_key, payload_size
            )
            
            return storage_key
            
        except Exception as e:
            # Record error metrics
            self.dtc_metrics["storage_operations"].labels(
                operation="store",
                storage_type=storage_type,
                result="error"
            ).inc()
            
            self.logger.error("Failed to store DTC payload: %s", e)
            raise


async def main():
    """Main function using unified gRPC server for DTC Engine service."""
    import signal
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # Get config path from command line or use default
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/services/dtc_engine.yaml"
    
    # Create unified gRPC server
    server = UnifiedGrpcServer(config_path=config_path)
    
    # Add the modern DTC engine servicer
    server.add_servicer(
        ModernDTCEngineService,
        lambda service, server: dtc_engine_pb2_grpc.add_DTCEngineServicer_to_server(service, server),
        config_path
    )
    
    # Setup signal handlers
    def signal_handler(signum, frame):
        asyncio.create_task(server.stop())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Start the server with unified observability
        await server.serve()
    except Exception as e:
        logging.error("Server error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())