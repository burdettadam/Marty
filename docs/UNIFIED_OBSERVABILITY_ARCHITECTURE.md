# Unified Observability Architecture for Marty Platform

## Overview

This document outlines the unified observability architecture that leverages the newly consolidated configuration system to provide consistent monitoring, metrics, tracing, and logging across all Marty microservices.

## Architecture Principles

### 1. Configuration-Driven Observability
- **Unified Configuration**: All observability settings managed through the MMF configuration system
- **Environment-Specific**: Development, testing, and production configurations
- **Service-Specific Overrides**: Per-service customization while maintaining consistency

### 2. Three Pillars of Observability

#### Metrics Collection
- **Prometheus-based**: Standardized metric names and labels across services
- **Business Metrics**: Document verification rates, certificate validation success
- **Technical Metrics**: gRPC request rates, latency, error rates
- **Infrastructure Metrics**: Database connections, memory, CPU usage

#### Distributed Tracing
- **OpenTelemetry**: Industry-standard tracing instrumentation
- **Jaeger Backend**: Existing Jaeger infrastructure for trace storage and visualization
- **Correlation IDs**: Track requests across service boundaries
- **Sampling**: Intelligent sampling to reduce overhead

#### Centralized Logging
- **Structured Logging**: JSON format with consistent fields
- **Correlation**: Link logs to traces via correlation IDs
- **Service Context**: Automatic service name, version, environment tagging

### 3. Health Monitoring
- **Standardized Endpoints**: `/health`, `/readiness`, `/liveness`
- **Dependency Checks**: Database, external services, trust store validation
- **Circuit Breaker Integration**: Health status based on circuit breaker state

## Implementation Strategy

### Phase 1: Standardize Core Observability (Current)

#### 1.1 Unified Metrics Framework
```python
# Framework integration in services
from framework.observability import MetricsCollector, create_tracer
from framework.config_factory import create_service_config

config = create_service_config("config/services/trust_anchor.yaml")
metrics = MetricsCollector(config.monitoring.service_name)

# Business metrics for trust anchor
trust_validations = metrics.counter(
    "trust_validations_total",
    "Total trust validations performed", 
    ["result", "certificate_type"]
)

# Technical metrics automatically collected
# - gRPC request duration, errors, success rates
# - Database connection pool metrics
# - Health check results
```

#### 1.2 Service-Specific Configuration
```yaml
# config/services/trust_anchor.yaml
monitoring:
  enabled: true
  service_name: "trust-anchor"
  metrics_port: 9090
  health_check_port: 8080
  
  # Prometheus configuration
  prometheus:
    enabled: true
    path: "/metrics"
    
  # Tracing configuration  
  tracing:
    enabled: true
    jaeger_endpoint: "${JAEGER_ENDPOINT:-http://jaeger:14268/api/traces}"
    sampling_rate: ${TRACING_SAMPLING_RATE:-0.1}
    
  # Custom business metrics
  business_metrics:
    - name: "certificate_validations"
      type: "counter"
      description: "Certificate validation operations"
      labels: ["result", "issuer_country"]
      
    - name: "trust_store_sync_duration"
      type: "histogram" 
      description: "Trust store synchronization time"
      buckets: [0.1, 0.5, 1.0, 5.0, 10.0, 30.0]
```

#### 1.3 Tracing Integration
```python
# Automatic instrumentation for gRPC services
from opentelemetry import trace
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.instrumentation.grpc import GrpcInstrumentorServer

# Configured via unified config system
tracer = create_tracer(config.monitoring.service_name)

class TrustAnchorService:
    async def VerifyCertificate(self, request, context):
        with tracer.start_as_current_span("verify_certificate") as span:
            span.set_attribute("certificate.id", request.certificate_id)
            span.set_attribute("certificate.type", request.certificate_type)
            
            # Business logic with automatic tracing
            result = await self._validate_certificate(request)
            
            span.set_attribute("validation.result", result.is_valid)
            span.set_attribute("validation.trust_chain_length", len(result.trust_chain))
```

### Phase 2: Advanced Observability Patterns

#### 2.1 Correlation ID Propagation
- Automatic correlation ID generation and propagation
- gRPC metadata integration for service-to-service calls
- Log correlation linking traces and structured logs

#### 2.2 SLI/SLO Monitoring  
- Service Level Indicators based on business requirements
- Error budgets for certificate validation success rates
- Availability targets for critical services (99.9% uptime)

#### 2.3 Alerting Integration
- Configuration-driven alert rules
- Multi-channel notifications (Slack, PagerDuty, email)
- Business-specific alerts (trust store sync failures, certificate expiry)

## Service Integration Patterns

### Trust Anchor Service Example

```python
from framework.observability import ObservabilityManager

class ModernTrustAnchor:
    def __init__(self, config):
        self.observability = ObservabilityManager(config.monitoring)
        
        # Metrics automatically configured from config
        self.validation_metrics = self.observability.get_business_metrics()
        
        # Health checks automatically registered
        self.observability.register_health_check(
            name="trust_store",
            check_func=self._check_trust_store_health,
            interval_seconds=30
        )
        
        self.observability.register_health_check(
            name="pkd_service", 
            check_func=self._check_pkd_connectivity,
            interval_seconds=60
        )
    
    async def verify_certificate(self, certificate_data):
        # Automatic tracing and metrics collection
        with self.observability.trace_operation("certificate_verification"):
            try:
                result = await self._perform_validation(certificate_data)
                
                # Business metrics
                self.validation_metrics["certificate_validations"].inc(
                    labels={"result": "success", "issuer_country": result.issuer_country}
                )
                
                return result
                
            except ValidationError as e:
                self.validation_metrics["certificate_validations"].inc(
                    labels={"result": "error", "error_type": type(e).__name__}
                )
                raise
```

### Document Signer Service Example

```python  
class ModernDocumentSigner:
    def __init__(self, config):
        self.observability = ObservabilityManager(config.monitoring)
        
        # Cryptographic operation metrics
        self.signing_metrics = {
            "documents_signed": self.observability.counter(
                "documents_signed_total",
                "Total documents signed",
                ["algorithm", "document_type", "result"]
            ),
            "signing_duration": self.observability.histogram(
                "document_signing_duration_seconds", 
                "Time to sign documents",
                ["algorithm", "document_type"]
            )
        }
    
    async def sign_document(self, document, signing_request):
        with self.observability.trace_operation("document_signing") as span:
            span.set_attribute("document.type", document.type)
            span.set_attribute("signing.algorithm", signing_request.algorithm)
            
            start_time = time.time()
            
            try:
                signed_doc = await self._perform_signing(document, signing_request)
                
                # Record success metrics
                duration = time.time() - start_time
                self.signing_metrics["signing_duration"].observe(
                    duration, 
                    labels={"algorithm": signing_request.algorithm, "document_type": document.type}
                )
                
                self.signing_metrics["documents_signed"].inc(
                    labels={
                        "algorithm": signing_request.algorithm,
                        "document_type": document.type, 
                        "result": "success"
                    }
                )
                
                span.set_attribute("signing.success", True)
                return signed_doc
                
            except SigningError as e:
                self.signing_metrics["documents_signed"].inc(
                    labels={
                        "algorithm": signing_request.algorithm,
                        "document_type": document.type,
                        "result": "error"
                    }
                )
                span.set_attribute("signing.success", False)
                span.set_attribute("signing.error", str(e))
                raise
```

## Dashboard and Alerting Strategy

### Business Intelligence Dashboards
1. **Platform Overview**: Document processing rates, certificate validation success
2. **Trust Operations**: PKD sync status, trust store health, certificate expiry tracking
3. **Performance Monitoring**: Service latency percentiles, error rates, availability

### Alert Categories
1. **Critical**: Service down, very high error rates (>20%), certificate store unavailable
2. **Warning**: High error rates (>5%), elevated latency, approaching certificate expiry
3. **Info**: PKD sync completion, trust store updates, performance degradation

## Benefits of Unified Observability

### 1. Operational Excellence
- **Consistent Monitoring**: Same patterns across all services
- **Rapid Troubleshooting**: Correlated traces, logs, and metrics
- **Proactive Alerts**: Business and technical alerting

### 2. Business Intelligence  
- **Trust Operations**: Monitor certificate validation success rates
- **Document Processing**: Track signing operations and performance
- **Compliance**: SLA monitoring and reporting

### 3. Developer Experience
- **Configuration-Driven**: Easy setup via YAML configuration
- **Automatic Instrumentation**: Minimal code changes required  
- **Rich Context**: Traces linked to business operations

## Migration Plan

### Immediate (Week 1-2)
- Integrate observability framework into modern service templates
- Update trust-anchor and document-signer services
- Configure environment-specific monitoring settings

### Short Term (Week 3-4)  
- Migrate remaining core services
- Implement business-specific metrics and dashboards
- Configure alerting rules and notification channels

### Long Term (Month 2+)
- Advanced SLI/SLO monitoring
- Machine learning-based anomaly detection
- Cross-service transaction tracing

This unified observability architecture provides the foundation for operating Marty services at scale with full visibility into both business operations and technical performance.