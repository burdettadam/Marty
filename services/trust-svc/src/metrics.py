"""
Comprehensive Prometheus metrics for Trust Service monitoring.

This module provides detailed metrics collection for:
- Certificate operations and validation
- Security events and authentication
- Performance and resource utilization
- Business KPIs and compliance metrics
"""

import asyncio
import functools
import time
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Info,
    Summary,
    generate_latest,
    multiprocess,
    start_http_server,
    values,
)
from prometheus_client import Enum as PrometheusEnum

logger = structlog.get_logger(__name__)

# Metric name prefixes
TRUST_SERVICE_PREFIX = "trust_service"
SECURITY_PREFIX = "trust_security"
CERTIFICATE_PREFIX = "trust_certificate"
BUSINESS_PREFIX = "trust_business"


class MetricType(Enum):
    """Metric type enumeration."""

    COUNTER = "counter"
    HISTOGRAM = "histogram"
    GAUGE = "gauge"
    SUMMARY = "summary"
    INFO = "info"
    ENUM = "enum"


class CertificateOperation(Enum):
    """Certificate operation types."""

    VALIDATE = "validate"
    VERIFY = "verify"
    PARSE = "parse"
    EXPORT = "export"
    IMPORT = "import"
    STORE = "store"
    RETRIEVE = "retrieve"
    DELETE = "delete"


class AuthMethod(Enum):
    """Authentication method types."""

    MTLS = "mtls"
    JWT = "jwt"
    API_KEY = "api_key"
    BASIC = "basic"
    NONE = "none"


class SecurityEvent(Enum):
    """Security event types."""

    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    RATE_LIMIT = "rate_limit"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    SUSPICIOUS = "suspicious"
    BREACH_ATTEMPT = "breach_attempt"


@dataclass
class MetricConfig:
    """Configuration for metrics collection."""

    enabled: bool = True
    port: int = 8000
    path: str = "/metrics"
    registry: CollectorRegistry | None = None
    buckets: list[float] = None

    def __post_init__(self):
        if self.buckets is None:
            # Default histogram buckets for request duration (in seconds)
            self.buckets = [
                0.001,
                0.005,
                0.01,
                0.025,
                0.05,
                0.075,
                0.1,
                0.25,
                0.5,
                0.75,
                1.0,
                2.5,
                5.0,
                7.5,
                10.0,
                15.0,
                20.0,
                30.0,
                60.0,
            ]


class TrustServiceMetrics:
    """Comprehensive metrics collection for Trust Service."""

    def __init__(self, config: MetricConfig = None):
        self.config = config or MetricConfig()
        self.registry = self.config.registry or CollectorRegistry()
        self._init_metrics()

    def _init_metrics(self):
        """Initialize all Prometheus metrics."""

        # === HTTP/gRPC Request Metrics ===
        self.http_requests_total = Counter(
            f"{TRUST_SERVICE_PREFIX}_http_requests_total",
            "Total HTTP requests",
            ["method", "endpoint", "status_code", "service"],
            registry=self.registry,
        )

        self.http_request_duration = Histogram(
            f"{TRUST_SERVICE_PREFIX}_http_request_duration_seconds",
            "HTTP request duration in seconds",
            ["method", "endpoint", "service"],
            buckets=self.config.buckets,
            registry=self.registry,
        )

        self.grpc_requests_total = Counter(
            f"{TRUST_SERVICE_PREFIX}_grpc_requests_total",
            "Total gRPC requests",
            ["method", "service", "status"],
            registry=self.registry,
        )

        self.grpc_request_duration = Histogram(
            f"{TRUST_SERVICE_PREFIX}_grpc_request_duration_seconds",
            "gRPC request duration in seconds",
            ["method", "service"],
            buckets=self.config.buckets,
            registry=self.registry,
        )

        # === Certificate Operation Metrics ===
        self.certificate_operations_total = Counter(
            f"{CERTIFICATE_PREFIX}_operations_total",
            "Total certificate operations",
            ["operation", "certificate_type", "status", "issuer_country"],
            registry=self.registry,
        )

        self.certificate_validation_duration = Histogram(
            f"{CERTIFICATE_PREFIX}_validation_duration_seconds",
            "Certificate validation duration in seconds",
            ["certificate_type", "validation_type"],
            buckets=[0.001, 0.01, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0],
            registry=self.registry,
        )

        self.certificate_errors_total = Counter(
            f"{CERTIFICATE_PREFIX}_errors_total",
            "Total certificate errors",
            ["error_type", "certificate_type", "issuer_country"],
            registry=self.registry,
        )

        self.certificates_by_status = Gauge(
            f"{CERTIFICATE_PREFIX}_by_status",
            "Certificates grouped by status",
            ["status", "certificate_type", "issuer_country"],
            registry=self.registry,
        )

        self.certificate_expiry_days = Histogram(
            f"{CERTIFICATE_PREFIX}_expiry_days",
            "Days until certificate expiry",
            ["certificate_type", "issuer_country"],
            buckets=[1, 7, 14, 30, 60, 90, 180, 365, 730],
            registry=self.registry,
        )

        # === Security Metrics ===
        self.security_events_total = Counter(
            f"{SECURITY_PREFIX}_events_total",
            "Total security events",
            ["event_type", "source_ip", "user_agent", "endpoint"],
            registry=self.registry,
        )

        self.auth_attempts_total = Counter(
            f"{SECURITY_PREFIX}_auth_attempts_total",
            "Total authentication attempts",
            ["method", "result", "client_type"],
            registry=self.registry,
        )

        self.rate_limit_exceeded_total = Counter(
            f"{SECURITY_PREFIX}_rate_limit_exceeded_total",
            "Total rate limit exceeded events",
            ["client_type", "limit_type"],
            registry=self.registry,
        )

        self.active_sessions = Gauge(
            f"{SECURITY_PREFIX}_active_sessions",
            "Number of active user sessions",
            ["auth_method"],
            registry=self.registry,
        )

        self.vault_operations_total = Counter(
            f"{SECURITY_PREFIX}_vault_operations_total",
            "Total Vault operations",
            ["operation", "status", "secret_type"],
            registry=self.registry,
        )

        # === Database Metrics ===
        self.database_connections_active = Gauge(
            f"{TRUST_SERVICE_PREFIX}_database_connections_active",
            "Active database connections",
            ["database", "pool"],
            registry=self.registry,
        )

        self.database_query_duration = Histogram(
            f"{TRUST_SERVICE_PREFIX}_database_query_duration_seconds",
            "Database query duration in seconds",
            ["operation", "table"],
            buckets=[0.001, 0.01, 0.1, 0.5, 1.0, 2.0, 5.0],
            registry=self.registry,
        )

        self.database_errors_total = Counter(
            f"{TRUST_SERVICE_PREFIX}_database_errors_total",
            "Total database errors",
            ["error_type", "operation"],
            registry=self.registry,
        )

        # === Business Metrics ===
        self.documents_processed_total = Counter(
            f"{BUSINESS_PREFIX}_documents_processed_total",
            "Total documents processed",
            ["document_type", "issuer_country", "status"],
            registry=self.registry,
        )

        self.verification_results_total = Counter(
            f"{BUSINESS_PREFIX}_verification_results_total",
            "Total verification results",
            ["result", "document_type", "verification_type"],
            registry=self.registry,
        )

        self.sla_compliance_ratio = Gauge(
            f"{BUSINESS_PREFIX}_sla_compliance_ratio",
            "SLA compliance ratio (0-1)",
            ["service", "sla_type"],
            registry=self.registry,
        )

        self.revenue_impact = Counter(
            f"{BUSINESS_PREFIX}_revenue_impact_total",
            "Revenue impact in cents",
            ["transaction_type", "client"],
            registry=self.registry,
        )

        # === System Metrics ===
        self.system_memory_usage = Gauge(
            f"{TRUST_SERVICE_PREFIX}_memory_usage_bytes",
            "Memory usage in bytes",
            ["type"],
            registry=self.registry,
        )

        self.system_cpu_usage = Gauge(
            f"{TRUST_SERVICE_PREFIX}_cpu_usage_percent",
            "CPU usage percentage",
            registry=self.registry,
        )

        self.cache_operations_total = Counter(
            f"{TRUST_SERVICE_PREFIX}_cache_operations_total",
            "Total cache operations",
            ["operation", "cache_type", "result"],
            registry=self.registry,
        )

        self.cache_hit_ratio = Gauge(
            f"{TRUST_SERVICE_PREFIX}_cache_hit_ratio",
            "Cache hit ratio (0-1)",
            ["cache_type"],
            registry=self.registry,
        )

        # === Compliance Metrics ===
        self.compliance_checks_total = Counter(
            f"{BUSINESS_PREFIX}_compliance_checks_total",
            "Total compliance checks",
            ["regulation", "check_type", "result"],
            registry=self.registry,
        )

        self.audit_events_total = Counter(
            f"{SECURITY_PREFIX}_audit_events_total",
            "Total audit events",
            ["event_type", "severity", "user"],
            registry=self.registry,
        )

        # === Service Health Metrics ===
        self.service_health = PrometheusEnum(
            f"{TRUST_SERVICE_PREFIX}_health_status",
            "Service health status",
            ["service"],
            states=["healthy", "degraded", "unhealthy", "unknown"],
            registry=self.registry,
        )

        self.dependency_health = PrometheusEnum(
            f"{TRUST_SERVICE_PREFIX}_dependency_health",
            "Dependency health status",
            ["dependency", "type"],
            states=["up", "down", "degraded", "unknown"],
            registry=self.registry,
        )

        self.service_info = Info(
            f"{TRUST_SERVICE_PREFIX}_info", "Service information", registry=self.registry
        )

    # === Decorator Methods ===

    def track_http_request(self, method: str, endpoint: str, service: str = "trust-service"):
        """Decorator to track HTTP request metrics."""

        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                start_time = time.time()
                status_code = "unknown"

                try:
                    if asyncio.iscoroutinefunction(func):
                        result = await func(*args, **kwargs)
                    else:
                        result = func(*args, **kwargs)

                    # Extract status code from result if available
                    if hasattr(result, "status_code"):
                        status_code = str(result.status_code)
                    else:
                        status_code = "200"

                    return result

                except Exception as e:
                    status_code = "500"
                    raise

                finally:
                    duration = time.time() - start_time
                    self.http_requests_total.labels(
                        method=method, endpoint=endpoint, status_code=status_code, service=service
                    ).inc()

                    self.http_request_duration.labels(
                        method=method, endpoint=endpoint, service=service
                    ).observe(duration)

            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                start_time = time.time()
                status_code = "unknown"

                try:
                    result = func(*args, **kwargs)

                    if hasattr(result, "status_code"):
                        status_code = str(result.status_code)
                    else:
                        status_code = "200"

                    return result

                except Exception as e:
                    status_code = "500"
                    raise

                finally:
                    duration = time.time() - start_time
                    self.http_requests_total.labels(
                        method=method, endpoint=endpoint, status_code=status_code, service=service
                    ).inc()

                    self.http_request_duration.labels(
                        method=method, endpoint=endpoint, service=service
                    ).observe(duration)

            return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

        return decorator

    def track_certificate_operation(
        self, operation: CertificateOperation, cert_type: str = "unknown"
    ):
        """Decorator to track certificate operation metrics."""

        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                start_time = time.time()
                status = "success"
                issuer_country = "unknown"

                try:
                    if asyncio.iscoroutinefunction(func):
                        result = await func(*args, **kwargs)
                    else:
                        result = func(*args, **kwargs)

                    # Extract issuer country if available
                    if hasattr(result, "issuer_country"):
                        issuer_country = result.issuer_country

                    return result

                except Exception as e:
                    status = "error"
                    raise

                finally:
                    duration = time.time() - start_time

                    self.certificate_operations_total.labels(
                        operation=operation.value,
                        certificate_type=cert_type,
                        status=status,
                        issuer_country=issuer_country,
                    ).inc()

                    if operation == CertificateOperation.VALIDATE:
                        self.certificate_validation_duration.labels(
                            certificate_type=cert_type, validation_type="full"
                        ).observe(duration)

            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                start_time = time.time()
                status = "success"
                issuer_country = "unknown"

                try:
                    result = func(*args, **kwargs)

                    if hasattr(result, "issuer_country"):
                        issuer_country = result.issuer_country

                    return result

                except Exception as e:
                    status = "error"
                    raise

                finally:
                    duration = time.time() - start_time

                    self.certificate_operations_total.labels(
                        operation=operation.value,
                        certificate_type=cert_type,
                        status=status,
                        issuer_country=issuer_country,
                    ).inc()

                    if operation == CertificateOperation.VALIDATE:
                        self.certificate_validation_duration.labels(
                            certificate_type=cert_type, validation_type="full"
                        ).observe(duration)

            return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

        return decorator

    @asynccontextmanager
    async def track_operation_duration(self, metric_name: str, labels: dict[str, str] = None):
        """Context manager to track operation duration."""
        start_time = time.time()
        labels = labels or {}

        try:
            yield
        finally:
            duration = time.time() - start_time

            # Get the appropriate metric based on name
            if hasattr(self, metric_name):
                metric = getattr(self, metric_name)
                if hasattr(metric, "labels"):
                    metric.labels(**labels).observe(duration)
                else:
                    metric.observe(duration)

    # === Recording Methods ===

    def record_certificate_error(
        self, error_type: str, cert_type: str = "unknown", issuer_country: str = "unknown"
    ):
        """Record a certificate error."""
        self.certificate_errors_total.labels(
            error_type=error_type, certificate_type=cert_type, issuer_country=issuer_country
        ).inc()

    def record_security_event(
        self,
        event_type: SecurityEvent,
        source_ip: str = "unknown",
        user_agent: str = "unknown",
        endpoint: str = "unknown",
    ):
        """Record a security event."""
        self.security_events_total.labels(
            event_type=event_type.value,
            source_ip=source_ip,
            user_agent=user_agent,
            endpoint=endpoint,
        ).inc()

    def record_auth_attempt(self, method: AuthMethod, success: bool, client_type: str = "unknown"):
        """Record an authentication attempt."""
        result = "success" if success else "failure"
        self.auth_attempts_total.labels(
            method=method.value, result=result, client_type=client_type
        ).inc()

    def record_rate_limit_exceeded(self, client_type: str, limit_type: str):
        """Record a rate limit exceeded event."""
        self.rate_limit_exceeded_total.labels(client_type=client_type, limit_type=limit_type).inc()

    def record_document_processed(self, doc_type: str, issuer_country: str, status: str):
        """Record a document processing event."""
        self.documents_processed_total.labels(
            document_type=doc_type, issuer_country=issuer_country, status=status
        ).inc()

    def record_verification_result(self, result: str, doc_type: str, verification_type: str):
        """Record a verification result."""
        self.verification_results_total.labels(
            result=result, document_type=doc_type, verification_type=verification_type
        ).inc()

    def update_sla_compliance(self, service: str, sla_type: str, ratio: float):
        """Update SLA compliance ratio."""
        self.sla_compliance_ratio.labels(service=service, sla_type=sla_type).set(ratio)

    def record_revenue_impact(self, transaction_type: str, client: str, amount_cents: int):
        """Record revenue impact."""
        self.revenue_impact.labels(transaction_type=transaction_type, client=client).inc(
            amount_cents
        )

    def update_service_health(self, service: str, status: str):
        """Update service health status."""
        self.service_health.labels(service=service).state(status)

    def update_dependency_health(self, dependency: str, dep_type: str, status: str):
        """Update dependency health status."""
        self.dependency_health.labels(dependency=dependency, type=dep_type).state(status)

    def set_service_info(self, info: dict[str, str]):
        """Set service information."""
        self.service_info.info(info)

    def update_cache_hit_ratio(self, cache_type: str, ratio: float):
        """Update cache hit ratio."""
        self.cache_hit_ratio.labels(cache_type=cache_type).set(ratio)

    def record_cache_operation(self, operation: str, cache_type: str, result: str):
        """Record a cache operation."""
        self.cache_operations_total.labels(
            operation=operation, cache_type=cache_type, result=result
        ).inc()

    def record_compliance_check(self, regulation: str, check_type: str, result: str):
        """Record a compliance check."""
        self.compliance_checks_total.labels(
            regulation=regulation, check_type=check_type, result=result
        ).inc()

    def record_audit_event(self, event_type: str, severity: str, user: str = "system"):
        """Record an audit event."""
        self.audit_events_total.labels(event_type=event_type, severity=severity, user=user).inc()

    # === Export Methods ===

    def get_metrics(self) -> str:
        """Get metrics in Prometheus format."""
        try:
            return generate_latest(self.registry)
        except Exception as e:
            logger.error("Failed to generate metrics", error=str(e))
            return ""

    def start_metrics_server(self, port: int = None, addr: str = ""):
        """Start HTTP metrics server."""
        port = port or self.config.port
        try:
            start_http_server(port, addr, registry=self.registry)
            logger.info(f"Metrics server started on {addr}:{port}")
        except Exception as e:
            logger.error("Failed to start metrics server", error=str(e))
            raise


# Global metrics instance
_metrics_instance: TrustServiceMetrics | None = None


def get_metrics(config: MetricConfig = None) -> TrustServiceMetrics:
    """Get global metrics instance."""
    global _metrics_instance
    if _metrics_instance is None:
        _metrics_instance = TrustServiceMetrics(config)
    return _metrics_instance


def init_metrics(config: MetricConfig = None) -> TrustServiceMetrics:
    """Initialize metrics with configuration."""
    global _metrics_instance
    _metrics_instance = TrustServiceMetrics(config)
    return _metrics_instance


# Convenience decorators
def track_http_request(method: str, endpoint: str, service: str = "trust-service"):
    """Convenience decorator for HTTP request tracking."""
    return get_metrics().track_http_request(method, endpoint, service)


def track_certificate_operation(operation: CertificateOperation, cert_type: str = "unknown"):
    """Convenience decorator for certificate operation tracking."""
    return get_metrics().track_certificate_operation(operation, cert_type)


# Example usage functions for testing
async def example_certificate_validation():
    """Example function showing certificate validation metrics."""
    metrics = get_metrics()

    @metrics.track_certificate_operation(CertificateOperation.VALIDATE, "csca")
    async def validate_csca_certificate():
        # Simulate validation
        await asyncio.sleep(0.1)
        return {"issuer_country": "US", "valid": True}

    result = await validate_csca_certificate()

    # Record additional metrics
    metrics.record_verification_result("valid", "csca", "full_chain")
    metrics.update_sla_compliance("certificate_validation", "response_time", 0.95)

    return result


if __name__ == "__main__":
    # Example usage
    config = MetricConfig(port=8000)
    metrics = init_metrics(config)

    # Set service info
    metrics.set_service_info({"version": "1.0.0", "build": "abc123", "environment": "production"})

    # Start metrics server
    metrics.start_metrics_server()

    # Keep server running
    try:
        import time

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Metrics server stopped")
