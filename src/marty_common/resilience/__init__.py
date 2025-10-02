"""Resilience utilities: standardized errors, circuit breaker, retries, interceptors.

This package centralizes resilience patterns so each microservice can uniformly
apply graceful error handling and transient fault tolerance.

Exports:
 - Circuit breaker primitives (``CircuitBreaker``, ``CircuitBreakerConfig``)
 - Advanced retry mechanisms with multiple backoff strategies
 - Structured error types + mapping helpers
 - Comprehensive gRPC interceptors for client/server resilience
 - Monitoring and observability for resilience patterns
 - Configuration management for all resilience components
 - Integration testing utilities with failure injection
"""

from .circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerState,
    DefaultErrorClassifier,
    ErrorClassifier,
)
from .error_codes import (
    ConflictError,
    ErrorCategory,
    MartyError,
    NotFoundError,
    TransientBackendError,
    UnauthorizedError,
    ValidationError,
    map_exception_to_status,
)
from .interceptors import FailureInjectionConfig, ResilienceServerInterceptor
from .outbound import async_call_with_resilience
from .retry import default_retry, is_retryable_exception, retry_async, retry_sync
from .retry_enhanced import (
    RetryConfig,
    RetryMetrics,
    create_retry_policy_enhanced,
    get_all_retry_metrics,
    get_retry_metrics,
    is_retryable_exception_enhanced,
)

# Enhanced resilience components
from .enhanced_interceptors import (
    EnhancedResilienceInterceptor,
    AdvancedFailureInjectionConfig,
    RequestMetrics,
)

# Advanced retry mechanisms
from .advanced_retry import (
    AdvancedRetryConfig,
    AdvancedRetryManager,
    AdvancedRetryMetrics,
    BackoffStrategy,
    RetryResult,
    retry_with_advanced_policy,
    async_retry_with_advanced_policy,
    get_retry_manager,
    get_all_retry_manager_stats,
)

# Comprehensive interceptors
from .comprehensive_interceptors import (
    ResilienceClientInterceptor,
    AsyncResilienceClientInterceptor,
    EnhancedResilienceServerInterceptor as ComprehensiveServerInterceptor,
    CompositeResilienceInterceptor,
)

# Monitoring and observability
from .monitoring import (
    ResilienceHealthCheck,
    ResilienceMonitor,
    get_global_monitor,
    register_circuit_breaker_for_monitoring,
    register_retry_manager_for_monitoring,
    get_resilience_health_status,
    generate_resilience_health_report,
)

# Configuration management
from .config import (
    ResilienceConfig,
    load_config,
    get_development_config,
    get_production_config,
    get_testing_config,
)
from .enhanced_errors import (
    EnhancedErrorCategory,
    ErrorDetails,
    EnhancedMartyError,
    TransientError,
    ExternalServiceError,
    DatabaseError,
    AuthorizationError,
    BusinessLogicError,
    ConfigurationError,
    ResourceError,
    map_grpc_error_enhanced,
)
from .graceful_degradation import (
    GracefulDegradationManager,
    DegradationLevel,
    FeatureToggle,
    FallbackProvider,
    DefaultValueProvider,
    CachedValueProvider,
    ServiceFallbackProvider,
    HealthBasedDegradationMonitor,
)
from .metrics import (
    MetricsCollector,
    ResilienceMetrics,
    MetricType,
    MetricValue,
    HistogramBucket,
    get_resilience_metrics,
    reset_resilience_metrics,
)
from .chaos_testing import (
    ChaosConfig,
    ChaosInjector,
    ChaosType,
    ResilienceTestSuite,
    chaos_context,
)
from .integration_tests import (
    ResilienceIntegrationTest,
    MockService,
    TestMetrics,
)

__all__ = [
    # Advanced retry mechanisms
    "AdvancedRetryConfig",
    "AdvancedRetryManager", 
    "AdvancedRetryMetrics",
    "async_retry_with_advanced_policy",
    "BackoffStrategy",
    "get_all_retry_manager_stats",
    "get_retry_manager",
    "retry_with_advanced_policy",
    "RetryResult",
    
    # Circuit breaker
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerState",
    "DefaultErrorClassifier",
    "ErrorClassifier",
    
    # Comprehensive interceptors
    "AsyncResilienceClientInterceptor",
    "CompositeResilienceInterceptor",
    "ComprehensiveServerInterceptor",
    "ResilienceClientInterceptor",
    
    # Configuration management
    "get_development_config",
    "get_production_config",
    "get_testing_config",
    "load_config",
    "ResilienceConfig",
    
    # Errors / mapping
    "ConflictError",
    "ErrorCategory",
    "MartyError",
    "NotFoundError",
    "TransientBackendError",
    "UnauthorizedError",
    "ValidationError",
    "map_exception_to_status",
    
    # Interceptor / failure injection
    "AdvancedFailureInjectionConfig",
    "FailureInjectionConfig",
    "ResilienceServerInterceptor",
    
    # Monitoring and observability
    "generate_resilience_health_report",
    "get_global_monitor",
    "get_resilience_health_status",
    "register_circuit_breaker_for_monitoring",
    "register_retry_manager_for_monitoring",
    "ResilienceHealthCheck",
    "ResilienceMonitor",
    
    # Retry helpers
    "create_retry_policy_enhanced",
    "default_retry",
    "get_all_retry_metrics",
    "get_retry_metrics",
    "is_retryable_exception",
    "is_retryable_exception_enhanced",
    "retry_async",
    "retry_sync",
    "RetryConfig",
    "RetryMetrics",
    
    # Enhanced interceptors
    "EnhancedResilienceInterceptor",
    "RequestMetrics",
    
    # Outbound helpers
    "async_call_with_resilience",
    
    # Enhanced errors
    "AuthorizationError",
    "BusinessLogicError",
    "ConfigurationError",
    "DatabaseError",
    "EnhancedErrorCategory",
    "EnhancedMartyError",
    "ErrorDetails",
    "ExternalServiceError",
    "map_grpc_error_enhanced",
    "ResourceError",
    "TransientError",
    
    # Graceful degradation
    "CachedValueProvider",
    "DefaultValueProvider",
    "DegradationLevel",
    "FallbackProvider",
    "GracefulDegradationManager",
    "FeatureToggle",
    "HealthBasedDegradationMonitor",
    "ServiceFallbackProvider",
    
    # Metrics
    "get_resilience_metrics",
    "HistogramBucket",
    "MetricsCollector",
    "MetricType",
    "MetricValue",
    "reset_resilience_metrics",
    "ResilienceMetrics",
    
    # Chaos testing
    "chaos_context",
    "ChaosConfig",
    "ChaosInjector",
    "ChaosType",
    "ResilienceTestSuite",
    
    # Integration testing
    "MockService",
    "ResilienceIntegrationTest",
    "TestMetrics",
]

