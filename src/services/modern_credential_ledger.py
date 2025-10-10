"""
Modern Credential Ledger Service with Unified Observability.

Event-driven service that maintains an audit ledger of all credential operations
with comprehensive business metrics and distributed tracing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from collections.abc import Iterable
from dataclasses import dataclass
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
from aiokafka import AIOKafkaConsumer

from marty_common.infrastructure import (
    CredentialLedgerRepository,
    DatabaseManager,
    EventBusConfig,
)

# Default topics to monitor for credential events
DEFAULT_LEDGER_TOPICS: tuple[str, ...] = (
    "certificate.issued",
    "certificate.renewed", 
    "certificate.revoked",
    "passport.issued",
    "dtc.issued",
    "dtc.signed",
    "dtc.revoked",
    "mdl.created",
    "mdl.signed",
    "mdl.transfer_requested",
    "credential.issued",
    "pkd.sync.completed",
    "trust.updated",
)


@dataclass(slots=True)
class MessageContext:
    """Message context for event processing."""
    topic: str
    partition: int | None
    offset: int | None


class ModernCredentialLedgerProcessor(ObservableGrpcServiceMixin):
    """
    Modern Credential Ledger Processor with unified observability.
    
    Processes credential events and maintains audit ledger with comprehensive
    business metrics and distributed tracing.
    """

    def __init__(
        self,
        config_path: str = "config/services/credential_ledger.yaml",
        dependencies: Optional[ServiceDependencies] = None,
    ) -> None:
        """Initialize with unified configuration and observability."""
        super().__init__()
        
        self.logger = logging.getLogger("marty.credential.ledger")
        
        # REQUIRED: Load unified configuration
        self.config = create_service_config(config_path)
        
        if dependencies is None:
            raise ValueError("ModernCredentialLedgerProcessor requires service dependencies")
        
        self.dependencies = dependencies
        self._database = dependencies.database
        
        # Extract service-specific configuration
        self._ledger_config = self.config.credential_ledger
        self._event_config = self.config.event_bus
        
        # Business metrics will be set up by observability
        self.ledger_metrics = {}
        
        # Event processing state
        self._consumer: Optional[AIOKafkaConsumer] = None
        self._processing_tasks: set[asyncio.Task] = set()
        self._shutdown_event = asyncio.Event()
        
        self.logger.info("Modern Credential Ledger Processor initialized")

    def _setup_observability(self, config):
        """REQUIRED: Override to add service-specific metrics and health checks."""
        super()._setup_observability(config)
        
        # Setup ledger-specific business metrics
        self.ledger_metrics.update({
            "event_processing": self.observability.get_or_create_counter(
                name="marty_ledger_event_processing_total",
                description="Event processing metrics by topic and result",
                labels=["topic", "event_type", "result", "source"]
            ),
            "ledger_operations": self.observability.get_or_create_counter(
                name="marty_ledger_operations_total",
                description="Credential ledger operation metrics",
                labels=["operation", "credential_type", "result", "status"]
            ),
            "event_processing_duration": self.observability.get_or_create_histogram(
                name="marty_ledger_event_processing_duration_seconds",
                description="Event processing time by topic",
                labels=["topic", "event_type", "complexity"],
                buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]
            ),
            "event_throughput": self.observability.get_or_create_counter(
                name="marty_ledger_event_throughput_total",
                description="Event processing throughput metrics",
                labels=["topic", "partition", "consumer_group"]
            ),
            "consistency_checks": self.observability.get_or_create_counter(
                name="marty_ledger_consistency_checks_total",
                description="Data consistency validation metrics",
                labels=["check_type", "result", "severity"]
            ),
            "audit_operations": self.observability.get_or_create_counter(
                name="marty_ledger_audit_operations_total",
                description="Audit trail operation metrics",
                labels=["operation", "credential_id", "user_context"]
            ),
            "deduplication": self.observability.get_or_create_counter(
                name="marty_ledger_deduplication_total",
                description="Event deduplication metrics",
                labels=["topic", "duplicate_type", "action"]
            ),
            "retention_operations": self.observability.get_or_create_counter(
                name="marty_ledger_retention_operations_total",
                description="Data retention policy execution metrics",
                labels=["policy_type", "operation", "records_affected"]
            ),
            "consumer_lag": self.observability.get_or_create_gauge(
                name="marty_ledger_consumer_lag_seconds",
                description="Consumer lag in seconds by topic and partition",
                labels=["topic", "partition", "consumer_group"]
            ),
            "event_queue_size": self.observability.get_or_create_gauge(
                name="marty_ledger_event_queue_size",
                description="Number of events in processing queue",
                labels=["queue_type", "priority"]
            )
        })
        
        # REQUIRED: Register service-specific health checks
        self._register_ledger_health_checks()
        
        self.logger.info("Credential Ledger observability configured")

    def _register_ledger_health_checks(self):
        """REQUIRED: Register Credential Ledger-specific health checks."""
        if self.observability:
            # Database connectivity
            self.observability.register_health_check(
                name="database",
                check_func=self._check_database_health,
                interval_seconds=30
            )
            
            # Kafka connectivity
            self.observability.register_health_check(
                name="kafka_connectivity",
                check_func=self._check_kafka_health,
                interval_seconds=45
            )
            
            # Event processing health
            self.observability.register_health_check(
                name="event_processing",
                check_func=self._check_event_processing_health,
                interval_seconds=60
            )

    async def _check_database_health(self):
        """Check database connectivity for ledger storage."""
        from framework.observability.monitoring import HealthStatus
        
        try:
            async with self._database.session_scope() as session:
                await session.execute("SELECT 1")
                return HealthStatus.HEALTHY
        except Exception:
            return HealthStatus.UNHEALTHY

    async def _check_kafka_health(self):
        """Check Kafka connectivity for event consumption."""
        from framework.observability.monitoring import HealthStatus
        
        try:
            if self._consumer and not self._consumer._closed:
                return HealthStatus.HEALTHY
            else:
                return HealthStatus.UNHEALTHY
        except Exception:
            return HealthStatus.UNHEALTHY

    async def _check_event_processing_health(self):
        """Check event processing pipeline health."""
        from framework.observability.monitoring import HealthStatus
        
        try:
            # Check if processing tasks are running
            active_tasks = [task for task in self._processing_tasks if not task.done()]
            if len(active_tasks) > 0 or not self._shutdown_event.is_set():
                return HealthStatus.HEALTHY
            else:
                return HealthStatus.UNHEALTHY
        except Exception:
            return HealthStatus.UNHEALTHY

    @trace_async_method
    async def start(self) -> None:
        """Start the credential ledger service with observability tracking."""
        try:
            self.logger.info("Starting Credential Ledger service")
            
            # Initialize Kafka consumer
            await self._initialize_consumer()
            
            # Start event processing
            await self._start_event_processing()
            
            self.logger.info("Credential Ledger service started successfully")
            
        except Exception as e:
            self.logger.error("Failed to start Credential Ledger service: %s", e)
            raise

    @trace_async_method
    async def stop(self) -> None:
        """Stop the credential ledger service gracefully."""
        try:
            self.logger.info("Stopping Credential Ledger service")
            
            # Signal shutdown
            self._shutdown_event.set()
            
            # Stop consumer
            if self._consumer:
                await self._consumer.stop()
            
            # Wait for processing tasks to complete
            if self._processing_tasks:
                await asyncio.gather(*self._processing_tasks, return_exceptions=True)
            
            self.logger.info("Credential Ledger service stopped")
            
        except Exception as e:
            self.logger.error("Error stopping Credential Ledger service: %s", e)

    @trace_async_method
    async def _initialize_consumer(self) -> None:
        """Initialize Kafka consumer with configuration."""
        bootstrap_servers = self._event_config.connection_string.split(',')
        consumer_group = self._event_config.consumer_group
        
        self._consumer = AIOKafkaConsumer(
            *DEFAULT_LEDGER_TOPICS,
            bootstrap_servers=bootstrap_servers,
            group_id=consumer_group,
            auto_offset_reset=self._event_config.consumer.get('auto_offset_reset', 'earliest'),
            enable_auto_commit=self._event_config.consumer.get('enable_auto_commit', True),
            max_poll_records=self._event_config.consumer.get('max_poll_records', 500),
            session_timeout_ms=self._event_config.consumer.get('session_timeout_ms', 30000),
            heartbeat_interval_ms=self._event_config.consumer.get('heartbeat_interval_ms', 3000),
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            key_deserializer=lambda m: m.decode('utf-8') if m else None,
        )
        
        await self._consumer.start()
        self.logger.info("Kafka consumer initialized for topics: %s", DEFAULT_LEDGER_TOPICS)

    @trace_async_method
    async def _start_event_processing(self) -> None:
        """Start event processing loop."""
        max_concurrent = self._ledger_config.max_concurrent_events
        
        for _ in range(max_concurrent):
            task = asyncio.create_task(self._event_processing_loop())
            self._processing_tasks.add(task)
        
        self.logger.info("Started %d event processing workers", max_concurrent)

    @trace_async_method
    async def _event_processing_loop(self) -> None:
        """Main event processing loop with observability."""
        while not self._shutdown_event.is_set():
            try:
                # Consume events with timeout
                timeout_ms = 1000  # 1 second timeout
                async for message in self._consumer:
                    if self._shutdown_event.is_set():
                        break
                    
                    await self._process_event_with_metrics(message)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Error in event processing loop: %s", e)
                await asyncio.sleep(1)  # Brief pause before retry

    @trace_async_method
    async def _process_event_with_metrics(self, message) -> None:
        """Process a single event with comprehensive metrics."""
        start_time = datetime.now(timezone.utc)
        topic = message.topic
        key = message.key
        payload = message.value
        
        context = MessageContext(
            topic=topic,
            partition=message.partition,
            offset=message.offset
        )
        
        try:
            # Determine event characteristics for metrics
            event_type = self._classify_event_type(topic, payload)
            complexity = self._determine_processing_complexity(payload)
            source = payload.get('source', 'unknown')
            
            # Update queue size metric
            self.ledger_metrics["event_queue_size"].labels(
                queue_type="processing",
                priority="normal"
            ).inc()
            
            # Check for duplicates
            if await self._is_duplicate_event(topic, key, payload, context):
                self.ledger_metrics["deduplication"].labels(
                    topic=topic,
                    duplicate_type="exact_match",
                    action="skipped"
                ).inc()
                
                self.logger.debug("Skipping duplicate event", extra={
                    "topic": topic,
                    "key": key,
                    "offset": context.offset
                })
                return
            
            # Process the event
            await self._process_ledger_event(topic, payload, key, context)
            
            # Record success metrics
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            self.ledger_metrics["event_processing"].labels(
                topic=topic,
                event_type=event_type,
                result="success",
                source=source
            ).inc()
            
            self.ledger_metrics["event_processing_duration"].labels(
                topic=topic,
                event_type=event_type,
                complexity=complexity
            ).observe(duration)
            
            self.ledger_metrics["event_throughput"].labels(
                topic=topic,
                partition=str(message.partition),
                consumer_group=self._event_config.consumer_group
            ).inc()
            
            # Update consumer lag
            lag_seconds = self._calculate_consumer_lag(message)
            self.ledger_metrics["consumer_lag"].labels(
                topic=topic,
                partition=str(message.partition),
                consumer_group=self._event_config.consumer_group
            ).set(lag_seconds)
            
            self.logger.debug("Event processed successfully", extra={
                "topic": topic,
                "event_type": event_type,
                "key": key,
                "duration_seconds": duration,
                "complexity": complexity
            })
            
        except Exception as e:
            # Record error metrics
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            self.ledger_metrics["event_processing"].labels(
                topic=topic,
                event_type="unknown",
                result="error",
                source="unknown"
            ).inc()
            
            self.logger.error("Event processing failed: %s", e, extra={
                "topic": topic,
                "key": key,
                "offset": context.offset,
                "duration_seconds": duration
            })
            
        finally:
            # Update queue size metric
            self.ledger_metrics["event_queue_size"].labels(
                queue_type="processing",
                priority="normal"
            ).dec()

    @trace_async_method
    async def _process_ledger_event(
        self,
        topic: str,
        payload: dict[str, Any],
        key: str | None,
        context: MessageContext,
    ) -> None:
        """Process ledger event using domain-specific handlers."""
        # Get handler method
        handler_name = f"_handle_{topic.replace('.', '_')}"
        handler = getattr(self, handler_name, None)
        
        if handler is None:
            self.logger.debug("No ledger handler for topic %s", topic)
            return
        
        try:
            await handler(payload, key, context)
            
        except Exception as e:
            self.logger.error("Ledger handler failed for topic %s: %s", topic, e)
            raise

    # Domain-specific event handlers with observability
    @trace_async_method
    async def _handle_certificate_issued(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        """Handle certificate issued events."""
        await self._upsert_ledger_entry(
            credential_id=payload.get("certificate_id"),
            credential_type="CERTIFICATE",
            status="ISSUED",
            metadata=payload,
            context=context,
        )

    @trace_async_method
    async def _handle_certificate_renewed(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        """Handle certificate renewal events."""
        await self._upsert_ledger_entry(
            credential_id=payload.get("certificate_id"),
            credential_type="CERTIFICATE",
            status="RENEWED",
            metadata=payload,
            context=context,
        )

    @trace_async_method
    async def _handle_certificate_revoked(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        """Handle certificate revocation events."""
        await self._upsert_ledger_entry(
            credential_id=payload.get("certificate_id"),
            credential_type="CERTIFICATE",
            status="REVOKED",
            metadata=payload,
            context=context,
        )

    @trace_async_method
    async def _handle_passport_issued(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        """Handle passport issued events."""
        await self._upsert_ledger_entry(
            credential_id=payload.get("passport_id"),
            credential_type="PASSPORT",
            status="ISSUED",
            metadata=payload,
            context=context,
        )

    @trace_async_method
    async def _handle_dtc_issued(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        """Handle DTC issued events."""
        await self._upsert_ledger_entry(
            credential_id=payload.get("dtc_id"),
            credential_type="DTC",
            status="ISSUED",
            metadata=payload,
            context=context,
        )

    @trace_async_method
    async def _handle_dtc_signed(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        """Handle DTC signed events."""
        await self._upsert_ledger_entry(
            credential_id=payload.get("dtc_id"),
            credential_type="DTC",
            status="SIGNED",
            metadata=payload,
            context=context,
        )

    @trace_async_method
    async def _handle_mdl_created(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        """Handle MDL created events."""
        await self._upsert_ledger_entry(
            credential_id=payload.get("mdl_id"),
            credential_type="MDL",
            status="CREATED",
            metadata=payload,
            context=context,
        )

    @trace_async_method
    async def _handle_mdl_signed(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        """Handle MDL signed events."""
        await self._upsert_ledger_entry(
            credential_id=payload.get("mdl_id"),
            credential_type="MDL",
            status="SIGNED",
            metadata=payload,
            context=context,
        )

    @trace_async_method
    async def _handle_credential_issued(
        self, payload: dict[str, Any], key: str | None, context: MessageContext
    ) -> None:
        """Handle generic credential issued events."""
        await self._upsert_ledger_entry(
            credential_id=payload.get("credential_id"),
            credential_type=payload.get("credential_type", "GENERIC"),
            status="ISSUED",
            metadata=payload,
            context=context,
        )

    @trace_async_method
    async def _upsert_ledger_entry(
        self,
        credential_id: str | None,
        credential_type: str,
        status: str,
        metadata: dict[str, Any] | None,
        context: MessageContext,
    ) -> None:
        """Upsert ledger entry with observability tracking."""
        if not credential_id:
            self.logger.warning(
                "Skipping ledger update for %s without credential_id", context.topic
            )
            
            self.ledger_metrics["ledger_operations"].labels(
                operation="upsert",
                credential_type=credential_type,
                result="skipped",
                status="missing_id"
            ).inc()
            return
        
        try:
            # Record event in database
            async def handler(session) -> None:
                repository = CredentialLedgerRepository(session)
                
                # Record the raw event
                await repository.record_event(
                    topic=context.topic,
                    payload=metadata or {},
                    key=credential_id,
                    partition=context.partition,
                    offset=context.offset,
                )
                
                # Upsert ledger entry
                await repository.upsert_entry(
                    credential_id=credential_id,
                    credential_type=credential_type,
                    status=status,
                    metadata=metadata,
                    topic=context.topic,
                    offset=context.offset,
                )
            
            await self._database.run_within_transaction(handler)
            
            # Record success metrics
            self.ledger_metrics["ledger_operations"].labels(
                operation="upsert",
                credential_type=credential_type,
                result="success",
                status=status
            ).inc()
            
            # Record audit operation
            self.ledger_metrics["audit_operations"].labels(
                operation="ledger_update",
                credential_id=credential_id[:8] + "..." if len(credential_id) > 8 else credential_id,
                user_context=metadata.get('user_context', 'system') if metadata else 'system'
            ).inc()
            
            self.logger.info("Ledger entry updated", extra={
                "credential_id": credential_id,
                "credential_type": credential_type,
                "status": status,
                "topic": context.topic
            })
            
        except Exception as e:
            # Record error metrics
            self.ledger_metrics["ledger_operations"].labels(
                operation="upsert",
                credential_type=credential_type,
                result="error",
                status="unknown"
            ).inc()
            
            self.logger.error("Failed to update ledger entry: %s", e, extra={
                "credential_id": credential_id,
                "credential_type": credential_type,
                "topic": context.topic
            })
            raise

    # Helper methods with observability
    def _classify_event_type(self, topic: str, payload: dict) -> str:
        """Classify event type for metrics."""
        if "certificate" in topic:
            return "certificate"
        elif "passport" in topic:
            return "passport"
        elif "dtc" in topic:
            return "dtc"
        elif "mdl" in topic:
            return "mdl"
        elif "credential" in topic:
            return "credential"
        elif "pkd" in topic:
            return "pkd"
        elif "trust" in topic:
            return "trust"
        else:
            return "unknown"

    def _determine_processing_complexity(self, payload: dict) -> str:
        """Determine processing complexity for metrics."""
        payload_size = len(json.dumps(payload))
        
        if payload_size < 1000:  # < 1KB
            return "simple"
        elif payload_size < 10000:  # < 10KB
            return "moderate"
        else:
            return "complex"

    async def _is_duplicate_event(
        self, topic: str, key: str | None, payload: dict, context: MessageContext
    ) -> bool:
        """Check if event is a duplicate."""
        if not self._ledger_config.deduplication.get('enabled', True):
            return False
        
        # Implementation would check for duplicates based on:
        # - Topic + key + offset combination
        # - Event timestamp within deduplication window
        # - Payload hash for exact content matching
        
        # For now, simple implementation
        return False

    def _calculate_consumer_lag(self, message) -> float:
        """Calculate consumer lag in seconds."""
        try:
            # Calculate lag based on message timestamp
            message_time = datetime.fromtimestamp(message.timestamp / 1000, tz=timezone.utc)
            current_time = datetime.now(timezone.utc)
            lag_seconds = (current_time - message_time).total_seconds()
            return max(0, lag_seconds)
        except Exception:
            return 0.0

    async def wait_until_stopped(self) -> None:
        """Wait until service is stopped."""
        await self._shutdown_event.wait()


class ModernCredentialLedgerService:
    """
    Main service class that orchestrates the credential ledger processor.
    """

    def __init__(
        self,
        config_path: str = "config/services/credential_ledger.yaml",
        dependencies: Optional[ServiceDependencies] = None,
    ) -> None:
        """Initialize the credential ledger service."""
        self.processor = ModernCredentialLedgerProcessor(config_path, dependencies)
        self.logger = logging.getLogger("marty.credential.ledger.service")

    async def start(self) -> None:
        """Start the credential ledger service."""
        await self.processor.start()

    async def stop(self) -> None:
        """Stop the credential ledger service."""
        await self.processor.stop()

    async def wait_until_stopped(self) -> None:
        """Wait until service is stopped."""
        await self.processor.wait_until_stopped()


async def main():
    """REQUIRED: Main function for credential ledger service."""
    import signal
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/services/credential_ledger.yaml"
    
    # For standalone operation, we would need to build dependencies
    # In practice, this would use the existing dependency injection system
    
    try:
        # This would normally use the existing dependency system
        # from apps.runtime import build_dependencies_async
        # dependencies = await build_dependencies_async(config)
        
        service = ModernCredentialLedgerService(config_path=config_path)
        
        # Setup signal handlers
        def signal_handler(signum, frame):
            asyncio.create_task(service.stop())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        await service.start()
        await service.wait_until_stopped()
        
    except Exception as e:
        logging.error("Credential Ledger service error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())