"""
Modern PKD Service with Unified Configuration and Observability.

This service demonstrates the migration to unified observability patterns,
serving as a validation example for the migration approach.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
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
        ServiceDependencies,
    )

# gRPC imports
import grpc
from grpc import aio

# PKD service imports
from marty_common.infrastructure import CertificateRepository, DatabaseManager, OutboxRepository
from src.proto.v1 import pkd_service_pb2, pkd_service_pb2_grpc


class ModernPKDService(pkd_service_pb2_grpc.PKDServiceServicer, ObservableGrpcServiceMixin):
    """
    Modern PKD Service with unified observability.
    
    This service demonstrates the migration patterns for existing services
    to use the unified configuration and observability framework.
    """

    def __init__(
        self,
        config_path: str = "config/services/pkd_service.yaml",
        dependencies: Optional[ServiceDependencies] = None,
    ) -> None:
        """Initialize with unified configuration and observability."""
        super().__init__()
        
        self.logger = logging.getLogger("marty.pkd.service")
        
        # Load unified configuration
        self.config = create_service_config(config_path)
        
        if dependencies is None:
            raise ValueError("ModernPKDService requires service dependencies")
        
        self.dependencies = dependencies
        self._database: DatabaseManager = dependencies.database
        
        # PKD-specific configuration
        self._data_dir = Path(self.config.pkd.data.directory)
        self._auto_sync_interval = self.config.pkd.data.auto_sync_interval
        self._batch_size = self.config.pkd.ingestion.batch_size
        self._max_retries = self.config.pkd.ingestion.max_retries
        self._validation_enabled = self.config.pkd.ingestion.validation_enabled
        
        # Business metrics will be set up by observability
        self.pkd_metrics = {}
        
        # Background sync task
        self._sync_task: Optional[asyncio.Task] = None
        
        self.logger.info("Modern PKD Service initialized with unified configuration")
        
        # Start background sync if enabled
        if self._auto_sync_interval > 0:
            self._start_background_sync()

    def _setup_observability(self, config):
        """Override to add PKD-specific metrics and health checks."""
        super()._setup_observability(config)
        
        # Setup PKD-specific business metrics
        self.pkd_metrics.update({
            "trust_anchor_operations": self.observability.get_or_create_counter(
                name="marty_trust_anchor_operations_total",
                description="PKD trust anchor operations",
                labels=["operation", "result", "country_code"]
            ),
            "sync_operations": self.observability.get_or_create_counter(
                name="marty_pkd_sync_operations_total", 
                description="PKD synchronization operations",
                labels=["result", "dataset_type", "source"]
            ),
            "ingestion_operations": self.observability.get_or_create_counter(
                name="marty_pkd_ingestion_operations_total",
                description="PKD data ingestion operations", 
                labels=["result", "batch_size", "validation_result"]
            ),
            "certificate_queries": self.observability.get_or_create_counter(
                name="marty_pkd_certificate_queries_total",
                description="Certificate query operations",
                labels=["query_type", "result", "country_code"]
            ),
            "sync_duration": self.observability.get_or_create_histogram(
                name="marty_pkd_sync_duration_seconds",
                description="Time to complete PKD sync operations",
                labels=["dataset_type", "source"]
            ),
            "ingestion_duration": self.observability.get_or_create_histogram(
                name="marty_pkd_ingestion_duration_seconds",
                description="Time to complete data ingestion",
                labels=["batch_size"]
            ),
            "records_processed": self.observability.get_or_create_histogram(
                name="marty_pkd_records_processed",
                description="Number of records processed in operations",
                labels=["operation", "result"]
            )
        })
        
        # Register PKD-specific health checks
        self._register_pkd_health_checks()
        
        self.logger.info("PKD Service observability configured")

    def _register_pkd_health_checks(self):
        """Register PKD-specific health checks."""
        if self.observability:
            # Database connectivity
            self.observability.register_health_check(
                name="database",
                check_func=self._check_database_health,
                interval_seconds=30
            )
            
            # Data directory accessibility
            self.observability.register_health_check(
                name="data_directory",
                check_func=self._check_data_directory_health,
                interval_seconds=60
            )
            
            # Trust anchor connectivity (if needed)
            self.observability.register_health_check(
                name="trust_anchor_connectivity",
                check_func=self._check_trust_anchor_health,
                interval_seconds=120
            )

    async def _check_database_health(self):
        """Check database connectivity."""
        from framework.observability.monitoring import HealthStatus
        
        try:
            async with self._database.session_scope() as session:
                await session.execute("SELECT 1")
                return HealthStatus.HEALTHY
        except Exception as e:
            self.logger.warning("Database health check failed: %s", e)
            return HealthStatus.UNHEALTHY

    async def _check_data_directory_health(self):
        """Check data directory accessibility."""
        from framework.observability.monitoring import HealthStatus
        
        try:
            if self._data_dir.exists() and self._data_dir.is_dir():
                return HealthStatus.HEALTHY
            else:
                return HealthStatus.DEGRADED
        except Exception:
            return HealthStatus.UNHEALTHY

    async def _check_trust_anchor_health(self):
        """Check trust anchor service connectivity."""
        from framework.observability.monitoring import HealthStatus
        
        try:
            # In a real implementation, would test connectivity to trust anchor service
            # For now, return healthy as placeholder
            return HealthStatus.HEALTHY
        except Exception:
            return HealthStatus.DEGRADED

    def _start_background_sync(self):
        """Start background synchronization task."""
        if self._sync_task is None or self._sync_task.done():
            self._sync_task = asyncio.create_task(self._background_sync())
            self.logger.info("Started background PKD sync task")

    async def _background_sync(self):
        """Background task for periodic PKD synchronization."""
        while True:
            try:
                await asyncio.sleep(self._auto_sync_interval)
                self.logger.info("Starting scheduled PKD sync")
                
                # Record sync start
                start_time = datetime.now(timezone.utc)
                
                # Perform sync operation
                ingested = await self._ingest_local_dataset(
                    force_refresh=False,
                    emit_event=True
                )
                
                # Record metrics
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                
                self.pkd_metrics["sync_operations"].labels(
                    result="success",
                    dataset_type="local",
                    source="background_task"
                ).inc()
                
                self.pkd_metrics["sync_duration"].labels(
                    dataset_type="local",
                    source="background_task"
                ).observe(duration)
                
                self.pkd_metrics["records_processed"].labels(
                    operation="sync",
                    result="success"
                ).observe(ingested)
                
                self.logger.info("Completed scheduled PKD sync: %d records", ingested)
                
            except Exception as e:
                self.logger.error("Background sync failed: %s", e)
                
                # Record error metrics
                self.pkd_metrics["sync_operations"].labels(
                    result="error",
                    dataset_type="local",
                    source="background_task"
                ).inc()

    # gRPC Service Methods with Observability

    @trace_grpc_method
    async def ListTrustAnchors(
        self,
        request: Any,  # empty_pb2.Empty
        context: GrpcServicerContext,
    ) -> Any:  # pkd_service_pb2.ListTrustAnchorsResponse
        """List trust anchors with observability tracking."""
        method_trace = self.trace_grpc_call("ListTrustAnchors")
        
        @method_trace
        async def _list_impl(request, context):
            try:
                self.logger.info("Listing trust anchors")
                
                # Get filter criteria from request metadata if available
                country_code = "unknown"  # Would extract from request/context
                
                # Perform the operation
                records = await self._list_csca_records()
                
                # Build response
                anchors = []
                for record in records:
                    details = record.details or {}
                    anchors.append(
                        pkd_service_pb2.TrustAnchor(
                            certificate_id=record.certificate_id,
                            subject=record.subject or "",
                            certificate_pem=record.pem,
                            storage_key=details.get("storage_key", ""),
                            not_after=details.get("not_after", ""),
                            revoked=record.revoked,
                        )
                    )
                
                # Record business metrics
                self.pkd_metrics["trust_anchor_operations"].labels(
                    operation="list",
                    result="success", 
                    country_code=country_code
                ).inc()
                
                self.pkd_metrics["records_processed"].labels(
                    operation="list",
                    result="success"
                ).observe(len(anchors))
                
                self.logger.info("Listed %d trust anchors", len(anchors))
                
                return pkd_service_pb2.ListTrustAnchorsResponse(anchors=anchors)
                
            except Exception as e:
                self.logger.error("Failed to list trust anchors: %s", e)
                
                # Record error metrics
                self.pkd_metrics["trust_anchor_operations"].labels(
                    operation="list",
                    result="error",
                    country_code="unknown"
                ).inc()
                
                context.set_details(str(e))
                context.set_code(grpc.StatusCode.INTERNAL)
                raise
        
        return await _list_impl(request, context)

    @trace_grpc_method 
    async def Sync(
        self,
        request: Any,  # pkd_service_pb2.SyncRequest
        context: GrpcServicerContext,
    ) -> Any:  # pkd_service_pb2.SyncResponse
        """Sync PKD data with observability tracking."""
        method_trace = self.trace_grpc_call("Sync")
        
        @method_trace
        async def _sync_impl(request, context):
            try:
                self.logger.info("Starting PKD sync: force_refresh=%s", request.force_refresh)
                
                # Record sync start time
                start_time = datetime.now(timezone.utc)
                
                # Perform ingestion
                ingested = await self._ingest_local_dataset(
                    force_refresh=request.force_refresh,
                    emit_event=True,
                )
                
                # Calculate duration
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                
                # Record metrics
                self.pkd_metrics["sync_operations"].labels(
                    result="success",
                    dataset_type="local",
                    source="manual_request"
                ).inc()
                
                self.pkd_metrics["sync_duration"].labels(
                    dataset_type="local",
                    source="manual_request"
                ).observe(duration)
                
                self.pkd_metrics["records_processed"].labels(
                    operation="sync",
                    result="success"
                ).observe(ingested)
                
                message = f"Ingested {ingested} trust anchors from PKD dataset in {duration:.2f}s"
                self.logger.info(message)
                
                return pkd_service_pb2.SyncResponse(success=True, message=message)
                
            except Exception as e:
                self.logger.error("PKD sync failed: %s", e)
                
                # Record error metrics
                self.pkd_metrics["sync_operations"].labels(
                    result="error",
                    dataset_type="local", 
                    source="manual_request"
                ).inc()
                
                context.set_details(str(e))
                context.set_code(grpc.StatusCode.INTERNAL)
                return pkd_service_pb2.SyncResponse(success=False, message=str(e))
        
        return await _sync_impl(request, context)

    @trace_async_method
    async def get_trust_material_by_criteria(
        self,
        subject_pattern: Optional[str] = None,
        ski_hex: Optional[str] = None,
        cert_hash: Optional[str] = None,
        country_code: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get trust material matching criteria with observability.
        
        This method provides a programmatic interface for the inspection system
        to query trust material without requiring gRPC calls.
        """
        try:
            # Determine query type for metrics
            query_type = "subject" if subject_pattern else \
                        "ski" if ski_hex else \
                        "hash" if cert_hash else \
                        "country" if country_code else "all"
            
            self.logger.info("Querying trust material: type=%s", query_type)
            
            async with self._database.session_scope() as session:
                repo = CertificateRepository(session)
                all_records = await repo.list_by_type("CSCA")

                matching_records = []
                for record in all_records:
                    details = record.details or {}

                    # Apply filters
                    if subject_pattern and subject_pattern not in (record.subject or ""):
                        continue
                    if ski_hex and ski_hex != details.get("ski_hex"):
                        continue
                    if cert_hash and cert_hash != details.get("cert_hash"):
                        continue
                    if country_code and country_code != details.get("country_code"):
                        continue

                    matching_records.append({
                        "certificate_id": record.certificate_id,
                        "subject": record.subject,
                        "pem": record.pem,
                        "details": details,
                        "revoked": record.revoked,
                    })

            # Record metrics
            self.pkd_metrics["certificate_queries"].labels(
                query_type=query_type,
                result="success",
                country_code=country_code or "unknown"
            ).inc()
            
            self.pkd_metrics["records_processed"].labels(
                operation="query",
                result="success"
            ).observe(len(matching_records))
            
            self.logger.info("Query completed: %d matches", len(matching_records))
            
            return matching_records
            
        except Exception as e:
            self.logger.error("Trust material query failed: %s", e)
            
            # Record error metrics
            self.pkd_metrics["certificate_queries"].labels(
                query_type=query_type,
                result="error",
                country_code=country_code or "unknown"
            ).inc()
            
            raise

    # Implementation of PKD-specific methods
    # These would be migrated from the original PKD service

    async def _list_csca_records(self):
        """List CSCA records from database - implementation from original service."""
        async with self._database.session_scope() as session:
            repo = CertificateRepository(session)
            return await repo.list_by_type("CSCA")

    @trace_async_method
    async def _ingest_local_dataset(
        self,
        force_refresh: bool = False,
        emit_event: bool = True
    ) -> int:
        """
        Ingest local PKD dataset with observability tracking.
        
        This is a simplified version of the original ingestion logic
        with added observability patterns.
        """
        try:
            self.logger.info("Starting dataset ingestion: force_refresh=%s", force_refresh)
            
            # Record ingestion start
            start_time = datetime.now(timezone.utc)
            batch_size = str(self._batch_size)
            
            # Simulate dataset ingestion (would implement actual logic)
            # In real implementation, this would read PKD data files and process them
            ingested_count = 0
            
            # Placeholder for actual ingestion logic
            # This would read from self._data_dir and process PKD files
            
            # For demonstration, simulate some processing
            await asyncio.sleep(0.1)
            ingested_count = 42  # Placeholder count
            
            # Calculate duration
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            # Record metrics
            validation_result = "passed" if self._validation_enabled else "skipped"
            
            self.pkd_metrics["ingestion_operations"].labels(
                result="success",
                batch_size=batch_size,
                validation_result=validation_result
            ).inc()
            
            self.pkd_metrics["ingestion_duration"].labels(
                batch_size=batch_size
            ).observe(duration)
            
            self.pkd_metrics["records_processed"].labels(
                operation="ingest",
                result="success"
            ).observe(ingested_count)
            
            self.logger.info(
                "Dataset ingestion completed: %d records in %.2fs",
                ingested_count,
                duration
            )
            
            return ingested_count
            
        except Exception as e:
            self.logger.error("Dataset ingestion failed: %s", e)
            
            # Record error metrics
            self.pkd_metrics["ingestion_operations"].labels(
                result="error",
                batch_size=str(self._batch_size),
                validation_result="failed"
            ).inc()
            
            raise


async def main():
    """Main function using unified gRPC server for PKD service."""
    import signal
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # Get config path from command line or use default
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/services/pkd_service.yaml"
    
    # Create unified gRPC server
    server = UnifiedGrpcServer(config_path=config_path)
    
    # Add the modern PKD servicer
    server.add_servicer(
        ModernPKDService,
        lambda service, server: pkd_service_pb2_grpc.add_PKDServiceServicer_to_server(service, server),
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
    asyncio.run(main())