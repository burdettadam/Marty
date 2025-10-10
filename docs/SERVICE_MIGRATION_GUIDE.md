# Service Migration Guide: Unified Observability Framework

## Overview

This guide provides step-by-step instructions for migrating existing Marty microservices to use the unified observability framework. The migration approach has been validated with PKD Service and DTC Engine as reference implementations.

## Validated Migration Pattern

The migration follows a proven pattern that has been successfully applied to:
- ✅ **PKD Service**: Trust anchor data management with PKD sync operations
- ✅ **DTC Engine**: Digital Travel Credential lifecycle with complex integrations
- ✅ **Trust Anchor Service**: Certificate validation and trust store management  
- ✅ **Document Signer Service**: Document signing and SD-JWT operations

All migrations passed comprehensive validation with full observability integration.

## Migration Steps

### Phase 1: Configuration Migration

#### 1.1 Create Service Configuration File

Create a new YAML configuration file in `config/services/[service-name].yaml`:

```yaml
# Template: config/services/[service-name].yaml
service_name: "[service-name]"
environment: "${ENVIRONMENT:-development}"

# Database configuration
database:
  default:
    host: "${SERVICE_DB_HOST:-localhost}"
    port: ${SERVICE_DB_PORT:-5432}
    name: "${SERVICE_DB_NAME:-marty_service}"
    user: "${SERVICE_DB_USER:-marty_user}"
    password: "${SERVICE_DB_PASSWORD:-marty_password}"
    pool_size: ${SERVICE_DB_POOL_SIZE:-10}
    max_overflow: ${SERVICE_DB_MAX_OVERFLOW:-20}

# Service-specific configuration
[service_name]:
  # Add service-specific settings
  operation_timeout: ${SERVICE_TIMEOUT:-30}
  max_concurrent_operations: ${SERVICE_MAX_CONCURRENT:-10}

# gRPC server configuration
grpc:
  server:
    host: "${SERVICE_GRPC_HOST:-0.0.0.0}"
    port: ${SERVICE_GRPC_PORT:-50051}
    max_workers: ${SERVICE_GRPC_MAX_WORKERS:-10}
    reflection_enabled: ${SERVICE_GRPC_REFLECTION:-true}

# Service discovery configuration
service_discovery:
  hosts:
    [service_name]: "${SERVICE_HOST:-service-name}"
    # Add dependencies
    
  ports:
    [service_name]: ${SERVICE_PORT:-50051}
    # Add dependency ports

# CRITICAL: Unified observability configuration
monitoring:
  metrics:
    enabled: true
    port: 8080
    path: "/metrics"
    business_metrics:
      # Define service-specific business metrics
      service_operations:
        enabled: true
        labels: ["operation", "result", "category"]
        description: "Service operation metrics"
        
  tracing:
    enabled: true
    service_name: "[service-name]"
    jaeger_endpoint: "${JAEGER_ENDPOINT:-http://jaeger:14268/api/traces}"
    correlation_id:
      enabled: true
      header: "x-correlation-id"
      
  health_checks:
    enabled: true
    endpoint: "/health"
    checks:
      database:
        interval: 30
        timeout: 10
      # Add service-specific health checks
        
  logging:
    structured: true
    correlation_aware: true
    level: "${LOG_LEVEL:-INFO}"
    format: "json"

# Business metrics configuration
business_metrics:
  # Define domain-specific metrics tracking
  operations:
    duration_tracking: true
    error_categorization: true
    performance_monitoring: true

# Environment overrides
development:
  monitoring:
    logging:
      level: "DEBUG"
      
testing:
  database:
    default:
      name: "marty_service_test"
  monitoring:
    tracing:
      enabled: false
      
production:
  monitoring:
    tracing:
      jaeger_endpoint: "https://jaeger.marty.example.com/api/traces"
```

#### 1.2 Define Business Metrics

Identify and define service-specific business metrics based on service operations:

**Example Business Metrics by Service Type:**

- **Data Processing Services**: Records processed, validation results, processing time
- **Signing Services**: Signatures created, algorithms used, key operations
- **Validation Services**: Validations performed, success rates, trust levels
- **Sync Services**: Sync operations, records updated, sync duration
- **Storage Services**: Storage operations, data sizes, compression ratios

### Phase 2: Implementation Migration

#### 2.1 Update Service Implementation

Create or update the service implementation to use unified observability:

```python
"""
Modern [Service Name] Service with Unified Observability.
"""

from __future__ import annotations

import asyncio
import logging
import sys
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

# Import service-specific modules
from proto import [service]_pb2, [service]_pb2_grpc


class Modern[ServiceName]Service([service]_pb2_grpc.[ServiceName]Servicer, ObservableGrpcServiceMixin):
    """
    Modern [Service Name] Service with unified observability.
    """

    def __init__(
        self,
        config_path: str = "config/services/[service-name].yaml",
        dependencies: Optional[ServiceDependencies] = None,
    ) -> None:
        """Initialize with unified configuration and observability."""
        super().__init__()
        
        self.logger = logging.getLogger("marty.[service].service")
        
        # REQUIRED: Load unified configuration
        self.config = create_service_config(config_path)
        
        if dependencies is None:
            raise ValueError("Modern[ServiceName]Service requires service dependencies")
        
        self.dependencies = dependencies
        self._database = dependencies.database
        
        # Extract service-specific configuration
        self._service_config = self.config.[service_name]
        
        # Business metrics will be set up by observability
        self.service_metrics = {}
        
        self.logger.info("Modern [Service Name] Service initialized")

    def _setup_observability(self, config):
        """REQUIRED: Override to add service-specific metrics and health checks."""
        super()._setup_observability(config)
        
        # Setup service-specific business metrics
        self.service_metrics.update({
            "service_operations": self.observability.get_or_create_counter(
                name="marty_[service]_operations_total",
                description="Service operation metrics",
                labels=["operation", "result", "category"]
            ),
            "operation_duration": self.observability.get_or_create_histogram(
                name="marty_[service]_operation_duration_seconds",
                description="Time to complete service operations",
                labels=["operation", "category"]
            )
            # Add more service-specific metrics
        })
        
        # REQUIRED: Register service-specific health checks
        self._register_service_health_checks()
        
        self.logger.info("[Service Name] observability configured")

    def _register_service_health_checks(self):
        """REQUIRED: Register service-specific health checks."""
        if self.observability:
            # Database connectivity
            self.observability.register_health_check(
                name="database",
                check_func=self._check_database_health,
                interval_seconds=30
            )
            
            # Add service-specific health checks
            # Example: external service connectivity, resource availability

    async def _check_database_health(self):
        """Check database connectivity."""
        from framework.observability.monitoring import HealthStatus
        
        try:
            async with self._database.session_scope() as session:
                await session.execute("SELECT 1")
                return HealthStatus.HEALTHY
        except Exception:
            return HealthStatus.UNHEALTHY

    # REQUIRED: Add observability decorators to gRPC methods
    @trace_grpc_method
    async def ServiceMethod(
        self,
        request: Any,
        context: GrpcServicerContext,
    ) -> Any:
        """Service method with observability tracking."""
        method_trace = self.trace_grpc_call("ServiceMethod")
        
        @method_trace
        async def _method_impl(request, context):
            start_time = datetime.now(timezone.utc)
            
            try:
                # Extract relevant parameters for metrics
                operation_category = "standard"  # Extract from request
                
                # Perform business logic
                result = await self._perform_business_operation(request)
                
                # Record success metrics
                self.service_metrics["service_operations"].labels(
                    operation="service_method",
                    result="success",
                    category=operation_category
                ).inc()
                
                # Record duration
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                self.service_metrics["operation_duration"].labels(
                    operation="service_method",
                    category=operation_category
                ).observe(duration)
                
                self.logger.info("Service method completed successfully")
                
                return [service]_pb2.ServiceMethodResponse(
                    success=True,
                    result=result
                )
                
            except Exception as e:
                self.logger.error("Service method failed: %s", e)
                
                # Record error metrics
                self.service_metrics["service_operations"].labels(
                    operation="service_method",
                    result="error",
                    category="unknown"
                ).inc()
                
                context.set_details(str(e))
                context.set_code(grpc.StatusCode.INTERNAL)
                raise
        
        return await _method_impl(request, context)

    @trace_async_method
    async def _perform_business_operation(self, request) -> Any:
        """Business logic with observability tracking."""
        # Implement business logic with appropriate metrics
        pass


async def main():
    """REQUIRED: Main function using unified gRPC server."""
    import signal
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/services/[service-name].yaml"
    
    # Create unified gRPC server
    server = UnifiedGrpcServer(config_path=config_path)
    
    # Add the service
    server.add_servicer(
        Modern[ServiceName]Service,
        lambda service, server: [service]_pb2_grpc.add_[ServiceName]Servicer_to_server(service, server),
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
```

### Phase 3: Migration Validation

#### 3.1 Run Migration Validation

After implementing the migration, validate the observability integration:

```bash
# Run the validation script
python scripts/validate_observability_migration.py

# Expected output:
# 🎉 All services validated successfully!
#    Migration patterns are working correctly.
```

#### 3.2 Test Observability Features

**Test Metrics Collection:**
```bash
# Start service and check metrics endpoint
curl http://localhost:8080/metrics

# Look for service-specific metrics:
# marty_[service]_operations_total{operation="...",result="success"} 1
# marty_[service]_operation_duration_seconds{operation="..."} 0.123
```

**Test Health Checks:**
```bash
# Check health endpoint
curl http://localhost:8081/health

# Expected response:
# {"status": "healthy", "checks": {"database": "healthy", ...}}
```

**Test Distributed Tracing:**
- Verify traces appear in Jaeger UI
- Check correlation ID propagation
- Validate span metadata

### Phase 4: Environment Deployment

#### 4.1 Update Kubernetes Manifests

Update service deployment with observability ports:

```yaml
# k8s/services/[service-name]-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: [service-name]
  labels:
    app: [service-name]
    monitoring: "true"  # REQUIRED for Prometheus scraping
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
spec:
  ports:
  - name: grpc
    port: 50051
    targetPort: 50051
  - name: metrics     # REQUIRED
    port: 8080
    targetPort: 8080
  - name: health      # REQUIRED
    port: 8081
    targetPort: 8081
  selector:
    app: [service-name]
```

#### 4.2 Configure Monitoring

Ensure Prometheus ServiceMonitor includes the service:

```yaml
# monitoring/service-monitors.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: marty-services
  namespace: marty-monitoring
spec:
  selector:
    matchLabels:
      monitoring: "true"
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

## Service-Specific Migration Examples

### Recently Migrated Services - Comprehensive Examples

The following four services have been successfully migrated using the unified observability framework, demonstrating patterns for different service types:

#### 4.1 Mobile Document Processing - MDL Engine

**Service Type**: Data processing with external integrations
**Business Domain**: Mobile driving license generation and management

**Key Observability Features**:
- Portrait processing metrics with storage performance tracking
- QR code generation monitoring with success/failure rates
- Device engagement tracking (ISO 18013-5 compliance)
- Signing integration performance metrics

```yaml
# config/services/mdl_engine.yaml - Key sections
mdl_engine:
  max_concurrent_operations: 30
  portrait_processing:
    max_size_mb: 10
    supported_formats: ["JPEG", "PNG"]
    processing_timeout: 30

monitoring:
  metrics:
    business_metrics:
      mdl_operations:
        enabled: true
        labels: ["operation", "result", "license_type", "processing_mode"]
        description: "MDL generation and processing metrics"
      portrait_processing:
        enabled: true
        labels: ["operation", "format", "result", "size_category"]
        description: "Portrait image processing metrics"
      qr_generation:
        enabled: true
        labels: ["format", "result", "data_size_category"]
        description: "QR code generation performance"
      device_engagement:
        enabled: true
        labels: ["engagement_type", "result", "device_type"]
        description: "Device engagement (ISO 18013-5) metrics"
```

**Implementation Patterns**:
```python
@trace_function("mdl_engine.create_mdl")
async def CreateMDL(self, request, context):
    """Create mobile driving license with comprehensive tracking"""
    start_time = time.time()
    
    with correlation_context():
        try:
            # Track operation start
            self.metrics.increment_counter('mdl_operations_total', {
                'operation': 'create_mdl',
                'license_type': request.license_type,
                'processing_mode': request.processing_mode
            })
            
            # Process portrait with metrics
            if request.portrait_data:
                portrait_result = await self._process_portrait(request.portrait_data)
                self._track_portrait_processing(portrait_result)
            
            # Generate MDL with business metrics
            mdl_result = await self._generate_mdl_document(request)
            
            # Generate QR code with performance tracking
            qr_result = await self._generate_qr_code(mdl_result)
            self._track_qr_generation(qr_result)
            
            # Track success metrics
            processing_time = time.time() - start_time
            self.business_metrics.track_event('mdl_created', {
                'license_type': request.license_type,
                'has_portrait': bool(request.portrait_data),
                'has_qr_code': bool(qr_result),
                'processing_time': processing_time
            })
            
            return response
            
        except Exception as e:
            self._track_mdl_failure(request, e, time.time() - start_time)
            raise
```

#### 4.2 Event-Driven Audit Service - Credential Ledger

**Service Type**: Event-driven architecture with audit compliance
**Business Domain**: Credential lifecycle audit trail and compliance

**Key Observability Features**:
- Kafka event processing metrics with backlog monitoring
- Domain-specific event categorization (certificate, passport, DTC, MDL)
- Audit compliance tracking with retention policy monitoring
- Event deduplication and consistency checking metrics

```yaml
# config/services/credential_ledger.yaml - Key sections
credential_ledger:
  event_processing:
    max_concurrent_events: 50
    batch_size: 100
    processing_timeout: 30
    kafka:
      consumer_group: "credential_ledger_consumers"
      topics: ["credential.events", "audit.events"]

monitoring:
  metrics:
    business_metrics:
      event_processing:
        enabled: true
        labels: ["event_type", "domain", "result", "processing_mode"]
        description: "Event processing metrics by domain"
      audit_compliance:
        enabled: true
        labels: ["compliance_check", "result", "severity"]
        description: "Audit compliance validation metrics"
      kafka_integration:
        enabled: true
        labels: ["topic", "partition", "result", "lag_category"]
        description: "Kafka integration performance"
      retention_management:
        enabled: true
        labels: ["retention_policy", "action", "data_category"]
        description: "Data retention policy execution"
```

**Implementation Patterns**:
```python
@trace_function("credential_ledger.process_event")
async def process_credential_event(self, event_data: Dict[str, Any]):
    """Process credential event with domain-specific tracking"""
    start_time = time.time()
    
    event_type = event_data.get('event_type')
    event_domain = self._determine_event_domain(event_data)
    
    try:
        # Track event processing start
        self.metrics.increment_counter('event_processing_total', {
            'event_type': event_type,
            'domain': event_domain,
            'processing_mode': 'real_time'
        })
        
        # Route to domain-specific handler
        if event_domain == 'certificate':
            result = await self._handle_certificate_event(event_data)
        elif event_domain == 'passport':
            result = await self._handle_passport_event(event_data)
        elif event_domain == 'dtc':
            result = await self._handle_dtc_event(event_data)
        elif event_domain == 'mdl':
            result = await self._handle_mdl_event(event_data)
        
        # Store in audit ledger with compliance tracking
        audit_result = await self._store_audit_record(event_data, result)
        self._track_audit_compliance(audit_result)
        
        # Track successful processing
        processing_time = time.time() - start_time
        self.business_metrics.track_event('event_processed', {
            'domain': event_domain,
            'event_type': event_type,
            'processing_time': processing_time,
            'compliance_status': audit_result['compliance_status']
        })
        
    except Exception as e:
        self._track_event_processing_failure(event_data, e)
        raise
```

#### 4.3 Verification Service - Inspection System

**Service Type**: Complex verification and validation service  
**Business Domain**: Document verification with crypto validation

**Key Observability Features**:
- Passport crypto validation with component-level metrics
- SD-JWT verification workflow tracking
- OID4VP presentation verification with compliance monitoring
- Trust anchor integration performance metrics

```yaml
# config/services/inspection_system.yaml - Key sections
inspection_system:
  verification:
    passport_verification_enabled: true
    sd_jwt_verification_enabled: true
    oid4vp_verification_enabled: true
    crypto_validation:
      mrz_validation_enabled: true
      sod_validation_enabled: true
      certificate_chain_validation: true

monitoring:
  metrics:
    business_metrics:
      verification_workflow:
        enabled: true
        labels: ["workflow_type", "step", "result", "complexity"]
        description: "Verification workflow step metrics"
      passport_verification:
        enabled: true
        labels: ["verification_component", "result", "issuing_country", "document_type"]
        description: "Passport verification component metrics"
      sd_jwt_verification:
        enabled: true
        labels: ["verification_step", "result", "issuer_type", "disclosure_count"]
        description: "SD-JWT verification step metrics"
      trust_verification:
        enabled: true
        labels: ["trust_type", "entity_type", "result", "verification_source"]
        description: "Trust verification operation metrics"
```

**Implementation Patterns**:
```python
@trace_function("inspection_system.inspect_passport")
async def _inspect_passport(self, request, inspection_id: str, correlation_id: str):
    """Inspect passport with component-level verification tracking"""
    verification_details = {}
    
    try:
        # Track workflow start
        self.metrics.increment_counter('verification_workflow_total', {
            'workflow_type': 'passport',
            'step': 'start',
            'complexity': 'high'
        })
        
        # MRZ validation with metrics
        if self.verification_config.get('crypto_validation', {}).get('mrz_validation_enabled'):
            mrz_result = await self._validate_mrz(request.document_data)
            verification_details['mrz_validation'] = mrz_result
            
            self.metrics.increment_counter('passport_verification_total', {
                'verification_component': 'mrz',
                'result': 'valid' if mrz_result['is_valid'] else 'invalid',
                'document_type': 'passport'
            })
        
        # SOD validation with security metrics
        if self.verification_config.get('crypto_validation', {}).get('sod_validation_enabled'):
            sod_result = await self._validate_sod(request.document_data)
            verification_details['sod_validation'] = sod_result
            
            self.metrics.increment_counter('passport_verification_total', {
                'verification_component': 'sod',
                'result': 'valid' if sod_result['is_valid'] else 'invalid',
                'document_type': 'passport'
            })
        
        # Trust anchor verification
        trust_result = await self._verify_trust_anchor(request.document_data, 'passport')
        self.metrics.increment_counter('trust_verification_total', {
            'trust_type': 'issuer',
            'entity_type': 'passport_authority',
            'result': 'trusted' if trust_result['is_trusted'] else 'untrusted',
            'verification_source': trust_result.get('source', 'unknown')
        })
        
        # Calculate and track confidence score
        confidence_score = self._calculate_passport_confidence(verification_details)
        self.business_metrics.track_event('passport_verified', {
            'confidence_score': confidence_score,
            'components_verified': len(verification_details),
            'has_trust_anchor': trust_result['is_trusted']
        })
        
        return {
            'inspection_id': inspection_id,
            'confidence_score': confidence_score,
            'validation_details': verification_details
        }
        
    except Exception as e:
        self._track_verification_failure('passport', e, correlation_id)
        raise
```

#### 4.4 Data Consistency Service - Consistency Engine

**Service Type**: Cross-zone validation and data integrity
**Business Domain**: Document data consistency and quality assurance

**Key Observability Features**:
- Cross-zone consistency metrics with field-level granularity
- Rule execution performance tracking (exact match, fuzzy match, checksum, date validation)
- Data quality assessment with confidence scoring
- Audit trail management with retention compliance

```yaml
# config/services/consistency_engine.yaml - Key sections
consistency_engine:
  consistency_rules:
    default_fuzzy_threshold: 0.8
    enable_cross_validation: true
    enable_checksum_validation: true
    strict_exact_match: true
  performance:
    max_concurrent_checks: 100
    enable_parallel_rule_execution: true

monitoring:
  metrics:
    business_metrics:
      rule_execution:
        enabled: true
        labels: ["rule_type", "rule_id", "result", "execution_time_category"]
        description: "Consistency rule execution metrics"
      cross_zone_consistency:
        enabled: true
        labels: ["source_zone", "target_zone", "field_name", "consistency_result"]
        description: "Cross-zone data consistency metrics"
      data_quality:
        enabled: true
        labels: ["quality_metric", "zone", "severity", "confidence_level"]
        description: "Data quality assessment metrics"
      fuzzy_matching:
        enabled: true
        labels: ["match_type", "similarity_range", "field_type", "result"]
        description: "Fuzzy matching algorithm performance"
```

**Implementation Patterns**:
```python
@trace_function("consistency_engine.execute_single_rule")
async def _execute_single_rule(self, rule: ConsistencyRule, normalized_data: Dict[str, Dict[str, str]], fuzzy_threshold: float):
    """Execute consistency rule with detailed performance tracking"""
    start_time = time.time()
    
    try:
        # Track rule execution start
        self.metrics.increment_counter('rule_execution_total', {
            'rule_type': rule.rule_type,
            'rule_id': rule.rule_id,
            'result': 'started'
        })
        
        # Execute rule based on type with specific metrics
        if rule.rule_type == "exact_match":
            result = await self._execute_exact_match_rule(rule, normalized_data)
        elif rule.rule_type == "fuzzy_match":
            result = await self._execute_fuzzy_match_rule(rule, normalized_data, fuzzy_threshold)
            # Track fuzzy match specifics
            for mismatch in result.get('mismatches', []):
                similarity = mismatch.get('similarity', 0.0)
                self.metrics.increment_counter('fuzzy_matching_total', {
                    'match_type': 'field_comparison',
                    'similarity_range': self._categorize_similarity(similarity),
                    'field_type': mismatch.get('field', 'unknown'),
                    'result': 'mismatch'
                })
        
        # Track cross-zone consistency results
        for field in rule.applicable_fields:
            for source_zone in rule.source_zones:
                for target_zone in rule.target_zones:
                    if source_zone != target_zone:
                        consistency_result = self._check_zone_consistency(
                            normalized_data, source_zone, target_zone, field
                        )
                        self.metrics.increment_counter('cross_zone_consistency_total', {
                            'source_zone': source_zone,
                            'target_zone': target_zone,
                            'field_name': field,
                            'consistency_result': consistency_result
                        })
        
        # Track execution performance
        execution_time = time.time() - start_time
        execution_time_category = self._categorize_execution_time(execution_time)
        
        self.metrics.increment_counter('rule_execution_total', {
            'rule_type': rule.rule_type,
            'rule_id': rule.rule_id,
            'result': 'success',
            'execution_time_category': execution_time_category
        })
        
        # Track data quality metrics
        confidence_score = result.get('confidence_score', 0.0)
        self.business_metrics.track_event('rule_executed', {
            'rule_type': rule.rule_type,
            'execution_time': execution_time,
            'confidence_score': confidence_score,
            'zones_processed': len(normalized_data)
        })
        
        return result
        
    except Exception as e:
        self._track_rule_execution_failure(rule, e, time.time() - start_time)
        raise
```

### Legacy Service Examples

#### High-Volume Processing Services

**Example: PKD Service, DTC Engine**

```yaml
# Additional configuration for high-volume services

```yaml
# Additional configuration for high-volume services
monitoring:
  metrics:
    business_metrics:
      processing_operations:
        enabled: true
        labels: ["operation", "result", "batch_size", "format"]
      throughput_metrics:
        enabled: true
        labels: ["operation", "processing_mode"]
      queue_metrics:
        enabled: true
        labels: ["queue_name", "status"]

# Tracing optimization for high-volume
tracing:
  sampling:
    type: "probabilistic"
    rate: 0.1  # Sample 10% of traces
```

### Integration-Heavy Services

**Example: Inspection System, Consistency Engine**

```yaml
# Configuration for services with many integrations
monitoring:
  health_checks:
    checks:
      database:
        interval: 30
        timeout: 10
      external_service_1:
        interval: 60
        timeout: 15
      external_service_2:
        interval: 120
        timeout: 30

business_metrics:
  integration_health:
    connectivity_monitoring: true
    response_time_tracking: true
    error_rate_monitoring: true
```

### Storage Services

**Example: Object Storage, File Management**

```yaml
# Configuration for storage-focused services
monitoring:
  metrics:
    business_metrics:
      storage_operations:
        enabled: true
        labels: ["operation", "storage_type", "result", "size_category"]
      data_integrity:
        enabled: true
        labels: ["check_type", "result"]

business_metrics:
  storage:
    size_tracking: true
    compression_metrics: true
    access_pattern_analysis: true
```

## Migration Checklist

### Pre-Migration
- [ ] Identify service dependencies and integrations
- [ ] Define service-specific business metrics
- [ ] Review existing monitoring and alerting
- [ ] Plan migration timeline and rollback strategy

### During Migration
- [ ] Create service configuration file with observability settings
- [ ] Update service implementation with unified observability patterns
- [ ] Add observability decorators to all gRPC methods
- [ ] Implement service-specific health checks
- [ ] Define business metrics appropriate for service operations

### Post-Migration Validation
- [ ] Run migration validation script
- [ ] Verify metrics endpoint accessibility
- [ ] Test health check endpoints
- [ ] Validate trace collection in Jaeger
- [ ] Confirm business metrics are being recorded
- [ ] Test service under load to verify observability performance

### Production Deployment
- [ ] Update Kubernetes manifests with observability ports
- [ ] Configure Prometheus ServiceMonitor
- [ ] Update Grafana dashboards with new service metrics
- [ ] Configure alerting rules for new service
- [ ] Monitor service performance and observability overhead

## Troubleshooting Common Issues

### Configuration Issues

**Problem**: Service fails to start with configuration errors
**Solution**: Validate YAML syntax and required sections using validation script

**Problem**: Metrics not appearing in Prometheus
**Solution**: Check service annotations and ServiceMonitor configuration

### Implementation Issues

**Problem**: Import errors for framework modules
**Solution**: Ensure project root is in Python path and framework is installed

**Problem**: Health checks failing
**Solution**: Verify health check functions return correct HealthStatus values

### Runtime Issues

**Problem**: High observability overhead
**Solution**: Adjust tracing sampling rate and optimize metric cardinality

**Problem**: Traces not appearing in Jaeger
**Solution**: Verify Jaeger endpoint configuration and network connectivity

## Best Practices

1. **Start Small**: Begin with configuration and basic metrics before adding complex business metrics
2. **Test Thoroughly**: Use the validation script to ensure proper implementation
3. **Monitor Performance**: Watch for observability overhead in production
4. **Iterate**: Add more sophisticated metrics and health checks over time
5. **Document**: Update service documentation with observability features
6. **Collaborate**: Work with the platform team for monitoring infrastructure updates

## Getting Help

- **Validation Issues**: Run `python scripts/validate_observability_migration.py` for automated checks
- **Framework Questions**: Review reference implementations in PKD Service and DTC Engine
- **Monitoring Setup**: Consult the observability deployment guide
- **Performance Issues**: Review the monitoring dashboard for observability overhead metrics

The migration pattern has been proven effective across different service types and is ready for broader adoption across the Marty platform.