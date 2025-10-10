"""
Modern MDL Engine Service with Unified Observability.

Handles Mobile Driving License creation, signing, verification, and device engagement
with comprehensive business metrics and distributed tracing.
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Optional

# Add project root to path for imports
_project_root = Path(__file__).resolve().parents[2]
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# REQUIRED: Modern framework imports
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

# Service-specific imports
if TYPE_CHECKING:
    from marty_common.grpc_types import (
        GrpcServicerContext,
        ServiceDependencies,
    )

import grpc
from grpc import aio

from marty_common.infrastructure import (
    MobileDrivingLicenseRepository,
    ObjectStorageClient,
    OutboxRepository,
)
from src.proto import (
    document_signer_pb2,
    document_signer_pb2_grpc,
    mdl_engine_pb2,
    mdl_engine_pb2_grpc,
)

# Default disclosure policies for MDL data
DEFAULT_DISCLOSURE_POLICIES = {
    "BASIC": ["first_name", "last_name", "license_number"],
    "STANDARD": ["first_name", "last_name", "license_number", "date_of_birth", "issuing_authority"],
    "ENHANCED": [
        "first_name",
        "last_name", 
        "license_number",
        "date_of_birth",
        "issuing_authority",
        "issue_date",
        "expiry_date",
        "license_categories",
        "additional_fields",
    ],
}


class ModernMDLEngineService(mdl_engine_pb2_grpc.MDLEngineServicer, ObservableGrpcServiceMixin):
    """
    Modern MDL Engine Service with unified observability.
    
    Manages Mobile Driving License lifecycle including creation, signing,
    verification, QR code generation, and device engagement.
    """

    def __init__(
        self,
        config_path: str = "config/services/mdl_engine.yaml",
        dependencies: Optional[ServiceDependencies] = None,
    ) -> None:
        """Initialize with unified configuration and observability."""
        super().__init__()
        
        self.logger = logging.getLogger("marty.mdl.engine")
        
        # REQUIRED: Load unified configuration
        self.config = create_service_config(config_path)
        
        if dependencies is None:
            raise ValueError("ModernMDLEngineService requires service dependencies")
        
        self.dependencies = dependencies
        self._database = dependencies.database
        
        # Extract service-specific configuration
        self._mdl_config = self.config.mdl_engine
        self._storage_config = self.config.object_storage
        
        # Initialize object storage client
        self._storage_client = ObjectStorageClient(
            endpoint=self._storage_config.endpoint,
            access_key=self._storage_config.access_key,
            secret_key=self._storage_config.secret_key,
            bucket_name=self._storage_config.bucket_name,
            secure=self._storage_config.secure,
            region=self._storage_config.region,
        )
        
        # Business metrics will be set up by observability
        self.mdl_metrics = {}
        
        self.logger.info("Modern MDL Engine Service initialized")

    def _setup_observability(self, config):
        """REQUIRED: Override to add service-specific metrics and health checks."""
        super()._setup_observability(config)
        
        # Setup MDL-specific business metrics
        self.mdl_metrics.update({
            "mdl_operations": self.observability.get_or_create_counter(
                name="marty_mdl_operations_total",
                description="MDL operation metrics by type and result",
                labels=["operation", "result", "license_type", "user_type"]
            ),
            "mdl_processing_duration": self.observability.get_or_create_histogram(
                name="marty_mdl_processing_duration_seconds",
                description="MDL processing time by operation complexity",
                labels=["operation", "complexity", "portrait_size"],
                buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
            ),
            "storage_operations": self.observability.get_or_create_counter(
                name="marty_mdl_storage_operations_total",
                description="Storage operation metrics for MDL data",
                labels=["operation", "storage_type", "file_type", "size_category"]
            ),
            "qr_generation": self.observability.get_or_create_histogram(
                name="marty_mdl_qr_generation_duration_seconds",
                description="QR code generation performance metrics",
                labels=["size", "error_correction", "content_type"],
                buckets=[0.01, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0]
            ),
            "device_engagement": self.observability.get_or_create_counter(
                name="marty_mdl_device_engagement_total",
                description="Device engagement operation metrics",
                labels=["method", "engagement_type", "session_status"]
            ),
            "signing_operations": self.observability.get_or_create_counter(
                name="marty_mdl_signing_operations_total",
                description="Document signing integration metrics",
                labels=["algorithm", "key_type", "operation", "result"]
            ),
            "verification_operations": self.observability.get_or_create_counter(
                name="marty_mdl_verification_operations_total",
                description="MDL verification operation metrics",
                labels=["verification_type", "trust_level", "result"]
            ),
            "portrait_processing": self.observability.get_or_create_histogram(
                name="marty_mdl_portrait_processing_duration_seconds",
                description="Portrait image processing time",
                labels=["format", "size_category", "operation"],
                buckets=[0.1, 0.2, 0.5, 1.0, 2.0, 5.0]
            ),
            "license_validation": self.observability.get_or_create_counter(
                name="marty_mdl_license_validation_total",
                description="License number validation attempts",
                labels=["validation_type", "result", "pattern_match"]
            )
        })
        
        # REQUIRED: Register service-specific health checks
        self._register_mdl_health_checks()
        
        self.logger.info("MDL Engine observability configured")

    def _register_mdl_health_checks(self):
        """REQUIRED: Register MDL Engine-specific health checks."""
        if self.observability:
            # Database connectivity
            self.observability.register_health_check(
                name="database",
                check_func=self._check_database_health,
                interval_seconds=30
            )
            
            # Object storage connectivity
            self.observability.register_health_check(
                name="object_storage",
                check_func=self._check_storage_health,
                interval_seconds=60
            )
            
            # Document signer service availability
            self.observability.register_health_check(
                name="document_signer",
                check_func=self._check_document_signer_health,
                interval_seconds=45
            )
            
            # Trust anchor service availability
            self.observability.register_health_check(
                name="trust_anchor",
                check_func=self._check_trust_anchor_health,
                interval_seconds=45
            )

    async def _check_database_health(self):
        """Check database connectivity for MDL storage."""
        from framework.observability.monitoring import HealthStatus
        
        try:
            async with self._database.session_scope() as session:
                await session.execute("SELECT 1")
                return HealthStatus.HEALTHY
        except Exception:
            return HealthStatus.UNHEALTHY

    async def _check_storage_health(self):
        """Check object storage connectivity for portrait storage."""
        from framework.observability.monitoring import HealthStatus
        
        try:
            await self._storage_client.health_check()
            return HealthStatus.HEALTHY
        except Exception:
            return HealthStatus.UNHEALTHY

    async def _check_document_signer_health(self):
        """Check document signer service availability."""
        from framework.observability.monitoring import HealthStatus
        
        try:
            # Simple health check call to document signer
            # Implementation would depend on actual service discovery
            return HealthStatus.HEALTHY
        except Exception:
            return HealthStatus.UNHEALTHY

    async def _check_trust_anchor_health(self):
        """Check trust anchor service availability."""
        from framework.observability.monitoring import HealthStatus
        
        try:
            # Simple health check call to trust anchor
            # Implementation would depend on actual service discovery
            return HealthStatus.HEALTHY
        except Exception:
            return HealthStatus.UNHEALTHY

    # REQUIRED: Add observability decorators to gRPC methods
    @trace_grpc_method
    async def CreateMDL(
        self,
        request: mdl_engine_pb2.CreateMDLRequest,
        context: GrpcServicerContext,
    ) -> mdl_engine_pb2.CreateMDLResponse:
        """Create a new Mobile Driving License with observability tracking."""
        method_trace = self.trace_grpc_call("CreateMDL")
        
        @method_trace
        async def _create_mdl_impl(request, context):
            start_time = datetime.now(timezone.utc)
            
            try:
                # Input validation with metrics
                if not request.license_number:
                    self.mdl_metrics["mdl_operations"].labels(
                        operation="create_mdl",
                        result="validation_error",
                        license_type="unknown",
                        user_type="unknown"
                    ).inc()
                    
                    await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "license_number is required")
                    return mdl_engine_pb2.CreateMDLResponse(
                        status="ERROR", error_message="license_number is required"
                    )
                
                if not request.user_id:
                    self.mdl_metrics["mdl_operations"].labels(
                        operation="create_mdl",
                        result="validation_error",
                        license_type="unknown",
                        user_type="unknown"
                    ).inc()
                    
                    await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "user_id is required")
                    return mdl_engine_pb2.CreateMDLResponse(
                        status="ERROR", error_message="user_id is required"
                    )

                # License validation with metrics
                license_valid = await self._validate_license_number(request.license_number)
                if not license_valid:
                    self.mdl_metrics["license_validation"].labels(
                        validation_type="format",
                        result="failed",
                        pattern_match="false"
                    ).inc()
                    
                    await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid license number format")
                    return mdl_engine_pb2.CreateMDLResponse(
                        status="ERROR", error_message="Invalid license number format"
                    )
                
                self.mdl_metrics["license_validation"].labels(
                    validation_type="format",
                    result="success",
                    pattern_match="true"
                ).inc()

                # Check for existing MDL
                existing = await self._load_record_by_license(request.license_number)
                if existing is not None:
                    self.mdl_metrics["mdl_operations"].labels(
                        operation="create_mdl",
                        result="already_exists",
                        license_type="duplicate",
                        user_type="existing"
                    ).inc()
                    
                    await context.abort(
                        grpc.StatusCode.ALREADY_EXISTS, "MDL already exists for license number"
                    )
                    return mdl_engine_pb2.CreateMDLResponse(
                        status="ERROR", error_message="MDL already exists"
                    )

                # Generate MDL ID and process portrait
                mdl_id = f"MDL{uuid.uuid4().hex[:12].upper()}"
                
                # Process portrait with metrics
                portrait_size_category = self._categorize_portrait_size(len(request.portrait))
                portrait_reference = await self._store_portrait_with_metrics(
                    mdl_id, request.portrait, portrait_size_category
                )
                
                # Prepare license data
                license_categories = self._prepare_license_categories(request)
                additional_fields = self._prepare_additional_fields(request)
                
                # Create MDL details
                details = {
                    "mdl_id": mdl_id,
                    "license_number": request.license_number,
                    "user_id": request.user_id,
                    "first_name": request.first_name,
                    "last_name": request.last_name,
                    "date_of_birth": request.date_of_birth,
                    "issuing_authority": request.issuing_authority,
                    "issue_date": request.issue_date,
                    "expiry_date": request.expiry_date,
                    "license_categories": license_categories,
                    "additional_fields": additional_fields,
                    "portrait_reference": portrait_reference,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
                
                disclosure_policies = {
                    key: list(values) for key, values in DEFAULT_DISCLOSURE_POLICIES.items()
                }
                
                # Store payload with metrics
                payload_key = f"mdl/{mdl_id}.json"
                await self._persist_payload_with_metrics(payload_key, details)
                
                # Persist to database
                async def handler(session) -> None:
                    repo = MobileDrivingLicenseRepository(session)
                    await repo.create(
                        mdl_id=mdl_id,
                        license_number=request.license_number,
                        user_id=request.user_id,
                        status="PENDING_SIGNATURE",
                        details=details,
                        payload_location=payload_key,
                        disclosure_policies=disclosure_policies,
                    )
                    
                    # Publish event
                    await self._publish_event(
                        "mdl.created",
                        {
                            "mdl_id": mdl_id,
                            "license_number": request.license_number,
                            "user_id": request.user_id,
                            "payload_location": payload_key,
                        },
                        session=session,
                        key=mdl_id,
                    )
                
                await self._database.run_within_transaction(handler)
                
                # Record success metrics
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                license_type = self._determine_license_type(license_categories)
                user_type = "standard"  # Could be enhanced based on user classification
                
                self.mdl_metrics["mdl_operations"].labels(
                    operation="create_mdl",
                    result="success",
                    license_type=license_type,
                    user_type=user_type
                ).inc()
                
                complexity = "complex" if len(license_categories) > 1 else "simple"
                self.mdl_metrics["mdl_processing_duration"].labels(
                    operation="create_mdl",
                    complexity=complexity,
                    portrait_size=portrait_size_category
                ).observe(duration)
                
                self.logger.info("MDL created successfully", extra={
                    "mdl_id": mdl_id,
                    "license_number": request.license_number,
                    "user_id": request.user_id,
                    "duration_seconds": duration
                })
                
                return mdl_engine_pb2.CreateMDLResponse(
                    mdl_id=mdl_id, 
                    status="PENDING_SIGNATURE", 
                    error_message=""
                )
                
            except Exception as e:
                self.logger.error("MDL creation failed: %s", e, extra={
                    "license_number": getattr(request, 'license_number', 'unknown'),
                    "user_id": getattr(request, 'user_id', 'unknown')
                })
                
                # Record error metrics
                self.mdl_metrics["mdl_operations"].labels(
                    operation="create_mdl",
                    result="error",
                    license_type="unknown",
                    user_type="unknown"
                ).inc()
                
                context.set_details(str(e))
                context.set_code(grpc.StatusCode.INTERNAL)
                raise
        
        return await _create_mdl_impl(request, context)

    @trace_grpc_method
    async def GetMDL(
        self,
        request: mdl_engine_pb2.GetMDLRequest,
        context: GrpcServicerContext,
    ) -> mdl_engine_pb2.MDLResponse:
        """Retrieve an MDL by license number with observability tracking."""
        method_trace = self.trace_grpc_call("GetMDL")
        
        @method_trace
        async def _get_mdl_impl(request, context):
            start_time = datetime.now(timezone.utc)
            
            try:
                if not request.license_number:
                    self.mdl_metrics["mdl_operations"].labels(
                        operation="get_mdl",
                        result="validation_error",
                        license_type="unknown",
                        user_type="unknown"
                    ).inc()
                    
                    await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "license_number is required")
                    return mdl_engine_pb2.MDLResponse(
                        status="FAILED", error_message="license_number is required"
                    )

                record = await self._load_record_by_license(request.license_number)
                if record is None:
                    self.mdl_metrics["mdl_operations"].labels(
                        operation="get_mdl",
                        result="not_found",
                        license_type="unknown",
                        user_type="unknown"
                    ).inc()
                    
                    await context.abort(grpc.StatusCode.NOT_FOUND, "MDL not found")
                    return mdl_engine_pb2.MDLResponse(
                        status="NOT_FOUND", error_message="MDL not found"
                    )

                details = record.details or {}
                
                # Record success metrics
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                license_categories = details.get("license_categories", [])
                license_type = self._determine_license_type(license_categories)
                
                self.mdl_metrics["mdl_operations"].labels(
                    operation="get_mdl",
                    result="success",
                    license_type=license_type,
                    user_type="standard"
                ).inc()
                
                self.mdl_metrics["mdl_processing_duration"].labels(
                    operation="get_mdl",
                    complexity="simple",
                    portrait_size="n/a"
                ).observe(duration)
                
                self.logger.info("MDL retrieved successfully", extra={
                    "mdl_id": record.mdl_id,
                    "license_number": request.license_number,
                    "duration_seconds": duration
                })
                
                return self._build_mdl_response(record, details)
                
            except Exception as e:
                self.logger.error("MDL retrieval failed: %s", e, extra={
                    "license_number": getattr(request, 'license_number', 'unknown')
                })
                
                self.mdl_metrics["mdl_operations"].labels(
                    operation="get_mdl",
                    result="error",
                    license_type="unknown",
                    user_type="unknown"
                ).inc()
                
                context.set_details(str(e))
                context.set_code(grpc.StatusCode.INTERNAL)
                raise
        
        return await _get_mdl_impl(request, context)

    @trace_grpc_method
    async def SignMDL(
        self,
        request: mdl_engine_pb2.SignMDLRequest,
        context: GrpcServicerContext,
    ) -> mdl_engine_pb2.SignMDLResponse:
        """Sign an MDL using Document Signer with observability tracking."""
        method_trace = self.trace_grpc_call("SignMDL")
        
        @method_trace
        async def _sign_mdl_impl(request, context):
            start_time = datetime.now(timezone.utc)
            
            try:
                if not request.mdl_id:
                    self.mdl_metrics["signing_operations"].labels(
                        algorithm="unknown",
                        key_type="unknown",
                        operation="sign_mdl",
                        result="validation_error"
                    ).inc()
                    
                    await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "mdl_id is required")
                    return mdl_engine_pb2.SignMDLResponse(
                        success=False, error_message="mdl_id is required"
                    )

                record = await self._load_record(request.mdl_id)
                if record is None:
                    self.mdl_metrics["signing_operations"].labels(
                        algorithm="unknown",
                        key_type="unknown",
                        operation="sign_mdl",
                        result="not_found"
                    ).inc()
                    
                    await context.abort(grpc.StatusCode.NOT_FOUND, "MDL not found")
                    return mdl_engine_pb2.SignMDLResponse(
                        success=False, error_message="MDL not found"
                    )

                details = record.details or {}
                
                # Prepare signing request
                algorithm = self._mdl_config.signing.get("default_algorithm", "ES256")
                signing_request = document_signer_pb2.SignDocumentRequest(
                    document_id=request.mdl_id,
                    content_type="application/cbor",
                    payload=json.dumps(details).encode(),
                    algorithm=algorithm,
                )
                
                # Call document signer service
                signature_data = await self._call_document_signer(signing_request)
                
                # Update MDL status
                await self._update_status(request.mdl_id, "SIGNED")
                
                # Record success metrics
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                key_type = "ec" if algorithm.startswith("ES") else "rsa"
                
                self.mdl_metrics["signing_operations"].labels(
                    algorithm=algorithm,
                    key_type=key_type,
                    operation="sign_mdl",
                    result="success"
                ).inc()
                
                self.mdl_metrics["mdl_processing_duration"].labels(
                    operation="sign_mdl",
                    complexity="standard",
                    portrait_size="n/a"
                ).observe(duration)
                
                self.logger.info("MDL signed successfully", extra={
                    "mdl_id": request.mdl_id,
                    "algorithm": algorithm,
                    "duration_seconds": duration
                })
                
                return mdl_engine_pb2.SignMDLResponse(
                    success=True,
                    signature=signature_data.signature,
                    certificate=signature_data.certificate,
                    algorithm=algorithm,
                    error_message=""
                )
                
            except Exception as e:
                self.logger.error("MDL signing failed: %s", e, extra={
                    "mdl_id": getattr(request, 'mdl_id', 'unknown')
                })
                
                self.mdl_metrics["signing_operations"].labels(
                    algorithm="unknown",
                    key_type="unknown",
                    operation="sign_mdl",
                    result="error"
                ).inc()
                
                context.set_details(str(e))
                context.set_code(grpc.StatusCode.INTERNAL)
                raise
        
        return await _sign_mdl_impl(request, context)

    @trace_grpc_method
    async def GenerateMDLQRCode(
        self,
        request: mdl_engine_pb2.GenerateQRCodeRequest,
        context: GrpcServicerContext,
    ) -> mdl_engine_pb2.GenerateQRCodeResponse:
        """Generate QR code for MDL with observability tracking."""
        method_trace = self.trace_grpc_call("GenerateMDLQRCode")
        
        @method_trace
        async def _generate_qr_impl(request, context):
            start_time = datetime.now(timezone.utc)
            
            try:
                if not request.mdl_id:
                    await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "mdl_id is required")
                    return mdl_engine_pb2.GenerateQRCodeResponse(
                        success=False, error_message="mdl_id is required"
                    )

                record = await self._load_record(request.mdl_id)
                if record is None:
                    await context.abort(grpc.StatusCode.NOT_FOUND, "MDL not found")
                    return mdl_engine_pb2.GenerateQRCodeResponse(
                        success=False, error_message="MDL not found"
                    )

                # Generate QR code with metrics
                qr_size = str(self._mdl_config.qr_code_size)
                error_correction = self._mdl_config.qr_code_error_correction
                
                qr_data = await self._generate_qr_code_data(record, request)
                qr_image = await self._create_qr_image(qr_data, qr_size, error_correction)
                
                # Record metrics
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                content_type = "mdl_verification" if request.verification_mode else "mdl_transfer"
                
                self.mdl_metrics["qr_generation"].labels(
                    size=qr_size,
                    error_correction=error_correction,
                    content_type=content_type
                ).observe(duration)
                
                self.logger.info("QR code generated successfully", extra={
                    "mdl_id": request.mdl_id,
                    "size": qr_size,
                    "error_correction": error_correction,
                    "duration_seconds": duration
                })
                
                return mdl_engine_pb2.GenerateQRCodeResponse(
                    success=True,
                    qr_code_data=qr_image,
                    format="PNG",
                    error_message=""
                )
                
            except Exception as e:
                self.logger.error("QR code generation failed: %s", e, extra={
                    "mdl_id": getattr(request, 'mdl_id', 'unknown')
                })
                
                context.set_details(str(e))
                context.set_code(grpc.StatusCode.INTERNAL)
                raise
        
        return await _generate_qr_impl(request, context)

    @trace_grpc_method
    async def VerifyMDL(
        self,
        request: mdl_engine_pb2.VerifyMDLRequest,
        context: GrpcServicerContext,
    ) -> mdl_engine_pb2.VerifyMDLResponse:
        """Verify an MDL for inspection system with observability tracking."""
        method_trace = self.trace_grpc_call("VerifyMDL")
        
        @method_trace
        async def _verify_mdl_impl(request, context):
            start_time = datetime.now(timezone.utc)
            
            try:
                verification_type = "signature" if request.verify_signature else "basic"
                
                # Perform verification logic
                verification_result = await self._perform_mdl_verification(request)
                
                # Record metrics
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                trust_level = verification_result.get("trust_level", "unknown")
                result = "success" if verification_result.get("valid", False) else "failed"
                
                self.mdl_metrics["verification_operations"].labels(
                    verification_type=verification_type,
                    trust_level=trust_level,
                    result=result
                ).inc()
                
                self.mdl_metrics["mdl_processing_duration"].labels(
                    operation="verify_mdl",
                    complexity=verification_type,
                    portrait_size="n/a"
                ).observe(duration)
                
                self.logger.info("MDL verification completed", extra={
                    "verification_type": verification_type,
                    "result": result,
                    "trust_level": trust_level,
                    "duration_seconds": duration
                })
                
                return mdl_engine_pb2.VerifyMDLResponse(
                    valid=verification_result.get("valid", False),
                    trust_level=trust_level,
                    verification_details=json.dumps(verification_result),
                    error_message=verification_result.get("error", "")
                )
                
            except Exception as e:
                self.logger.error("MDL verification failed: %s", e)
                
                self.mdl_metrics["verification_operations"].labels(
                    verification_type="unknown",
                    trust_level="unknown",
                    result="error"
                ).inc()
                
                context.set_details(str(e))
                context.set_code(grpc.StatusCode.INTERNAL)
                raise
        
        return await _verify_mdl_impl(request, context)

    # Helper methods with observability integration
    @trace_async_method
    async def _store_portrait_with_metrics(
        self, mdl_id: str, portrait_data: bytes, size_category: str
    ) -> str:
        """Store portrait image with performance metrics."""
        start_time = datetime.now(timezone.utc)
        
        try:
            # Determine format
            format_type = self._detect_image_format(portrait_data)
            
            # Store in object storage
            portrait_key = f"portraits/{mdl_id}.{format_type.lower()}"
            await self._storage_client.put_object(portrait_key, portrait_data)
            
            # Record metrics
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            self.mdl_metrics["storage_operations"].labels(
                operation="store",
                storage_type="object_storage",
                file_type="portrait",
                size_category=size_category
            ).inc()
            
            self.mdl_metrics["portrait_processing"].labels(
                format=format_type,
                size_category=size_category,
                operation="store"
            ).observe(duration)
            
            return portrait_key
            
        except Exception as e:
            self.logger.error("Portrait storage failed: %s", e, extra={"mdl_id": mdl_id})
            
            self.mdl_metrics["storage_operations"].labels(
                operation="store",
                storage_type="object_storage",
                file_type="portrait",
                size_category="error"
            ).inc()
            raise

    @trace_async_method
    async def _persist_payload_with_metrics(self, payload_key: str, details: dict) -> None:
        """Persist MDL payload with storage metrics."""
        try:
            payload_data = json.dumps(details).encode()
            size_category = self._categorize_data_size(len(payload_data))
            
            await self._storage_client.put_object(payload_key, payload_data)
            
            self.mdl_metrics["storage_operations"].labels(
                operation="store",
                storage_type="object_storage",
                file_type="payload",
                size_category=size_category
            ).inc()
            
        except Exception as e:
            self.logger.error("Payload persistence failed: %s", e, extra={"payload_key": payload_key})
            
            self.mdl_metrics["storage_operations"].labels(
                operation="store",
                storage_type="object_storage",
                file_type="payload",
                size_category="error"
            ).inc()
            raise

    @trace_async_method
    async def _validate_license_number(self, license_number: str) -> bool:
        """Validate license number format with metrics."""
        import re
        
        pattern = self._mdl_config.get("license_number_pattern", r"^[A-Z0-9]{8,12}$")
        is_valid = bool(re.match(pattern, license_number))
        
        return is_valid

    def _categorize_portrait_size(self, size_bytes: int) -> str:
        """Categorize portrait size for metrics."""
        if size_bytes < 100_000:  # < 100KB
            return "small"
        elif size_bytes < 1_000_000:  # < 1MB
            return "medium" 
        elif size_bytes < 5_000_000:  # < 5MB
            return "large"
        else:
            return "xlarge"

    def _categorize_data_size(self, size_bytes: int) -> str:
        """Categorize data size for metrics."""
        if size_bytes < 10_000:  # < 10KB
            return "small"
        elif size_bytes < 100_000:  # < 100KB
            return "medium"
        else:
            return "large"

    def _determine_license_type(self, license_categories: list) -> str:
        """Determine license type for metrics."""
        if not license_categories:
            return "basic"
        elif len(license_categories) == 1:
            return "standard"
        else:
            return "commercial"

    def _detect_image_format(self, image_data: bytes) -> str:
        """Detect image format from binary data."""
        if image_data.startswith(b'\xff\xd8\xff'):
            return "JPEG"
        elif image_data.startswith(b'\x89PNG'):
            return "PNG"
        elif image_data.startswith(b'RIFF') and b'WEBP' in image_data[:12]:
            return "WEBP"
        else:
            return "UNKNOWN"

    # Additional helper methods (implementation details)
    async def _load_record(self, mdl_id: str) -> Any:
        """Load MDL record from database."""
        async def handler(session):
            repo = MobileDrivingLicenseRepository(session)
            return await repo.get(mdl_id)
        return await self._database.run_within_transaction(handler)

    async def _load_record_by_license(self, license_number: str) -> Any:
        """Load MDL record by license number."""
        async def handler(session):
            repo = MobileDrivingLicenseRepository(session)
            return await repo.get_by_license(license_number)
        return await self._database.run_within_transaction(handler)

    async def _update_status(self, mdl_id: str, status: str) -> None:
        """Update MDL status."""
        async def handler(session) -> None:
            repo = MobileDrivingLicenseRepository(session)
            await repo.update_status(mdl_id, status)
        await self._database.run_within_transaction(handler)

    async def _publish_event(self, event_type: str, data: dict, session=None, key=None) -> None:
        """Publish event to event bus."""
        # Implementation would depend on actual event bus configuration
        pass

    def _prepare_license_categories(self, request) -> list:
        """Prepare license categories from request."""
        return [
            {
                "category_code": cat.category_code,
                "issue_date": cat.issue_date,
                "expiry_date": cat.expiry_date,
                "restrictions": list(cat.restrictions)
            }
            for cat in request.license_categories
        ]

    def _prepare_additional_fields(self, request) -> list:
        """Prepare additional fields from request."""
        return [
            {
                "field_name": field.field_name,
                "field_value": field.field_value
            }
            for field in request.additional_fields
        ]

    def _build_mdl_response(self, record, details: dict):
        """Build MDL response from record and details."""
        # Implementation would build complete MDL response
        return mdl_engine_pb2.MDLResponse(
            mdl_id=record.mdl_id,
            status=record.status,
            # ... other fields
        )

    async def _call_document_signer(self, signing_request):
        """Call document signer service."""
        # Implementation would call actual document signer service
        pass

    async def _generate_qr_code_data(self, record, request) -> dict:
        """Generate QR code data for MDL."""
        # Implementation would generate appropriate QR code data
        return {"mdl_id": record.mdl_id, "verification_url": "..."}

    async def _create_qr_image(self, qr_data: dict, size: str, error_correction: str) -> bytes:
        """Create QR code image."""
        # Implementation would generate actual QR code image
        return b"qr_image_data"

    async def _perform_mdl_verification(self, request) -> dict:
        """Perform MDL verification logic."""
        # Implementation would perform actual verification
        return {"valid": True, "trust_level": "high"}


async def main():
    """REQUIRED: Main function using unified gRPC server."""
    import signal
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/services/mdl_engine.yaml"
    
    # Create unified gRPC server
    server = UnifiedGrpcServer(config_path=config_path)
    
    # Add the MDL Engine service
    server.add_servicer(
        ModernMDLEngineService,
        lambda service, server: mdl_engine_pb2_grpc.add_MDLEngineServicer_to_server(service, server),
        config_path
    )
    
    # Setup signal handlers
    def signal_handler(signum, frame):
        asyncio.create_task(server.stop())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await server.serve()
    except Exception as e:
        logging.error("Server error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())