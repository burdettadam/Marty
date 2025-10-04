"""Prometheus metrics for Trust Service."""

import logging
from typing import Optional

from prometheus_client import Counter, Gauge, Histogram, Info

logger = logging.getLogger(__name__)

# Service info metric
SERVICE_INFO = Info("trust_service_info", "Trust Service information")

# Core trust metrics as specified in requirements
MASTER_LIST_AGE_SECONDS = Gauge(
    "master_list_age_seconds", 
    "Age of master list in seconds since last update",
    ["country_code", "source_type"]
)

TRUSTED_CSCA_TOTAL = Gauge(
    "trusted_csca_total", 
    "Total number of trusted CSCA certificates",
    ["country_code", "trust_level", "status"]
)

TRUSTED_DSC_TOTAL = Gauge(
    "trusted_dsc_total", 
    "Total number of trusted DSC certificates", 
    ["country_code", "status"]
)

# Additional operational metrics
PKD_SYNC_OPERATIONS = Counter(
    "pkd_sync_operations_total",
    "Total number of PKD sync operations",
    ["source_type", "country_code", "status"]
)

PKD_SYNC_DURATION = Histogram(
    "pkd_sync_duration_seconds",
    "Duration of PKD sync operations",
    ["source_type", "country_code"]
)

CRL_REFRESH_OPERATIONS = Counter(
    "crl_refresh_operations_total",
    "Total number of CRL refresh operations",
    ["country_code", "status"]
)

CRL_REFRESH_DURATION = Histogram(
    "crl_refresh_duration_seconds",
    "Duration of CRL refresh operations",
    ["country_code"]
)

TRUST_SNAPSHOT_OPERATIONS = Counter(
    "trust_snapshot_operations_total",
    "Total number of trust snapshot operations",
    ["operation_type", "status"]
)

DATABASE_OPERATIONS = Counter(
    "database_operations_total",
    "Total number of database operations",
    ["operation_type", "table", "status"]
)

DATABASE_CONNECTION_POOL = Gauge(
    "database_connection_pool_size",
    "Current database connection pool size",
    ["pool_type"]
)

API_REQUEST_DURATION = Histogram(
    "api_request_duration_seconds",
    "Duration of API requests",
    ["method", "endpoint", "status_code"]
)

API_REQUESTS_TOTAL = Counter(
    "api_requests_total",
    "Total number of API requests",
    ["method", "endpoint", "status_code"]
)

GRPC_REQUEST_DURATION = Histogram(
    "grpc_request_duration_seconds",
    "Duration of gRPC requests",
    ["method", "status"]
)

GRPC_REQUESTS_TOTAL = Counter(
    "grpc_requests_total",
    "Total number of gRPC requests",
    ["method", "status"]
)

# Certificate validation metrics
CERTIFICATE_VALIDATIONS = Counter(
    "certificate_validations_total",
    "Total number of certificate validations",
    ["cert_type", "country_code", "validation_result"]
)

CERTIFICATE_VALIDATION_DURATION = Histogram(
    "certificate_validation_duration_seconds",
    "Duration of certificate validations",
    ["cert_type", "country_code"]
)

# Error metrics
ERROR_TOTAL = Counter(
    "errors_total",
    "Total number of errors",
    ["error_type", "component"]
)

# Health metrics
SERVICE_UPTIME = Gauge(
    "service_uptime_seconds",
    "Service uptime in seconds"
)

SERVICE_HEALTH = Gauge(
    "service_health_status",
    "Service health status (1=healthy, 0=unhealthy)",
    ["component"]
)


def init_metrics() -> None:
    """Initialize metrics with default values."""
    logger.info("Initializing Prometheus metrics...")
    
    # Set service info
    SERVICE_INFO.info({
        "version": "1.0.0",
        "service": "trust-svc",
        "environment": "development"  # This should come from settings
    })
    
    # Initialize health metrics
    SERVICE_HEALTH.labels(component="database").set(0)
    SERVICE_HEALTH.labels(component="pkd_sync").set(0)
    SERVICE_HEALTH.labels(component="crl_refresh").set(0)
    
    # Initialize connection pool metrics
    DATABASE_CONNECTION_POOL.labels(pool_type="active").set(0)
    DATABASE_CONNECTION_POOL.labels(pool_type="idle").set(0)
    
    logger.info("Prometheus metrics initialized")


def update_master_list_age(country_code: str, source_type: str, age_seconds: float) -> None:
    """Update master list age metric."""
    MASTER_LIST_AGE_SECONDS.labels(
        country_code=country_code,
        source_type=source_type
    ).set(age_seconds)


def update_trusted_csca_count(country_code: str, trust_level: str, status: str, count: int) -> None:
    """Update trusted CSCA count metric."""
    TRUSTED_CSCA_TOTAL.labels(
        country_code=country_code,
        trust_level=trust_level,
        status=status
    ).set(count)


def update_trusted_dsc_count(country_code: str, status: str, count: int) -> None:
    """Update trusted DSC count metric."""
    TRUSTED_DSC_TOTAL.labels(
        country_code=country_code,
        status=status
    ).set(count)


def record_pkd_sync(source_type: str, country_code: str, status: str, duration: Optional[float] = None) -> None:
    """Record PKD sync operation."""
    PKD_SYNC_OPERATIONS.labels(
        source_type=source_type,
        country_code=country_code,
        status=status
    ).inc()
    
    if duration is not None:
        PKD_SYNC_DURATION.labels(
            source_type=source_type,
            country_code=country_code
        ).observe(duration)


def record_crl_refresh(country_code: str, status: str, duration: Optional[float] = None) -> None:
    """Record CRL refresh operation."""
    CRL_REFRESH_OPERATIONS.labels(
        country_code=country_code,
        status=status
    ).inc()
    
    if duration is not None:
        CRL_REFRESH_DURATION.labels(
            country_code=country_code
        ).observe(duration)


def record_api_request(method: str, endpoint: str, status_code: int, duration: float) -> None:
    """Record API request metrics."""
    API_REQUESTS_TOTAL.labels(
        method=method,
        endpoint=endpoint,
        status_code=status_code
    ).inc()
    
    API_REQUEST_DURATION.labels(
        method=method,
        endpoint=endpoint,
        status_code=status_code
    ).observe(duration)


def record_grpc_request(method: str, status: str, duration: float) -> None:
    """Record gRPC request metrics."""
    GRPC_REQUESTS_TOTAL.labels(
        method=method,
        status=status
    ).inc()
    
    GRPC_REQUEST_DURATION.labels(
        method=method,
        status=status
    ).observe(duration)


def record_certificate_validation(cert_type: str, country_code: str, validation_result: str, duration: float) -> None:
    """Record certificate validation metrics."""
    CERTIFICATE_VALIDATIONS.labels(
        cert_type=cert_type,
        country_code=country_code,
        validation_result=validation_result
    ).inc()
    
    CERTIFICATE_VALIDATION_DURATION.labels(
        cert_type=cert_type,
        country_code=country_code
    ).observe(duration)


def record_error(error_type: str, component: str) -> None:
    """Record error metric."""
    ERROR_TOTAL.labels(
        error_type=error_type,
        component=component
    ).inc()


def update_service_health(component: str, is_healthy: bool) -> None:
    """Update service health metric."""
    SERVICE_HEALTH.labels(component=component).set(1 if is_healthy else 0)


def update_database_pool_size(active_connections: int, idle_connections: int) -> None:
    """Update database connection pool metrics."""
    DATABASE_CONNECTION_POOL.labels(pool_type="active").set(active_connections)
    DATABASE_CONNECTION_POOL.labels(pool_type="idle").set(idle_connections)