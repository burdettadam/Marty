# Resilience Patterns Implementation Guide

This guide provides comprehensive instructions for implementing error handling and resilience patterns in Marty microservices using the enhanced resilience framework.

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Circuit Breakers](#circuit-breakers)
4. [Retry Mechanisms](#retry-mechanisms)
5. [gRPC Interceptors](#grpc-interceptors)
6. [Configuration Management](#configuration-management)
7. [Monitoring and Observability](#monitoring-and-observability)
8. [Testing with Failure Injection](#testing-with-failure-injection)
9. [Best Practices](#best-practices)
10. [Examples](#examples)

## Overview

The Marty resilience framework provides comprehensive patterns for building fault-tolerant microservices:

- **Circuit Breakers**: Prevent cascading failures by stopping calls to failing services
- **Advanced Retry Mechanisms**: Multiple backoff strategies with adaptive behavior
- **gRPC Interceptors**: Standardized error handling and translation
- **Monitoring**: Comprehensive metrics and health checks
- **Configuration**: Environment-specific settings with multiple sources
- **Testing**: Built-in failure injection for resilience validation

## Quick Start

### Basic Setup

```python
from marty_common.resilience import (
    ResilienceConfig,
    CompositeResilienceInterceptor,
    get_development_config
)

# Load configuration
config = get_development_config()  # or load_config() for auto-detection

# Create composite interceptor
resilience = CompositeResilienceInterceptor(
    service_name="my_service",
    client_retry_config=config.retry,
    client_circuit_breaker_config=config.circuit_breaker,
    enable_metrics=config.enable_metrics,
)

# Use with gRPC client
channel = grpc.insecure_channel("localhost:50051")
channel = grpc.intercept_channel(
    channel, 
    *resilience.get_client_interceptors()
)

# Use with gRPC server
server = grpc.server(
    futures.ThreadPoolExecutor(max_workers=10),
    interceptors=resilience.get_server_interceptors()
)
```

### Configuration from YAML

```python
from marty_common.resilience import load_config

# Load from YAML file
config = load_config("config/resilience_production.yaml")

# Or from environment variables
config = load_config()  # Uses MARTY_RESILIENCE_* env vars
```

## Circuit Breakers

Circuit breakers prevent cascading failures by monitoring service health and stopping calls when failure thresholds are exceeded.

### Basic Usage

```python
from marty_common.resilience import CircuitBreaker, CircuitBreakerConfig

# Create circuit breaker
config = CircuitBreakerConfig(
    failure_threshold=5,        # Open after 5 failures
    recovery_timeout=30.0,      # Try to recover after 30 seconds
    half_open_success_threshold=2,  # Need 2 successes to close
)

circuit_breaker = CircuitBreaker("external_service", config)

# Use as decorator
@circuit_breaker.decorate
def call_external_service():
    # Your service call here
    return external_api.get_data()

# Use programmatically
if circuit_breaker.allow_request():
    try:
        result = external_api.get_data()
        circuit_breaker.record_success()
        return result
    except Exception as e:
        circuit_breaker.record_failure(e)
        raise
else:
    raise RuntimeError("Circuit breaker is open")
```

### Circuit Breaker States

- **CLOSED**: Normal operation, requests pass through
- **OPEN**: Failure threshold exceeded, requests rejected immediately
- **HALF_OPEN**: Testing recovery, limited requests allowed

### Advanced Configuration

```python
from marty_common.resilience import CircuitBreakerConfig, DefaultErrorClassifier

class CustomErrorClassifier:
    def should_trip_circuit(self, exception):
        # Don't trip on validation errors
        return not isinstance(exception, ValueError)

config = CircuitBreakerConfig(
    failure_threshold=5,
    recovery_timeout=30.0,
    half_open_success_threshold=2,
    failure_reset_timeout=60.0,
    max_concurrent_requests=10,
    error_classifier=CustomErrorClassifier(),
    enable_metrics=True,
)
```

## Retry Mechanisms

The framework provides advanced retry mechanisms with multiple backoff strategies and adaptive behavior.

### Basic Retry

```python
from marty_common.resilience import (
    AdvancedRetryConfig,
    AdvancedRetryManager,
    BackoffStrategy
)

# Create retry configuration
config = AdvancedRetryConfig(
    max_attempts=5,
    base_delay=0.1,
    max_delay=60.0,
    backoff_strategy=BackoffStrategy.EXPONENTIAL_JITTER,
    enable_circuit_breaker=True,
)

# Create retry manager
retry_manager = AdvancedRetryManager("service_calls", config)

# Synchronous retry
def unreliable_function():
    if random.random() < 0.3:  # 30% failure rate
        raise ConnectionError("Network error")
    return "Success!"

result = retry_manager.retry_sync(unreliable_function)

# Asynchronous retry
async def unreliable_async_function():
    if random.random() < 0.3:
        raise ConnectionError("Network error")
    return "Async Success!"

result = await retry_manager.retry_async(unreliable_async_function)
```

### Backoff Strategies

Available backoff strategies:

- `FIXED`: Constant delay between retries
- `LINEAR`: Linearly increasing delay
- `EXPONENTIAL`: Exponentially increasing delay
- `EXPONENTIAL_JITTER`: Exponential with random jitter
- `FIBONACCI`: Fibonacci sequence delays
- `POLYNOMIAL`: Polynomial delay progression
- `ADAPTIVE`: Self-adjusting based on success rates

### Retry Decorators

```python
from marty_common.resilience import retry_with_advanced_policy

config = AdvancedRetryConfig(max_attempts=3, base_delay=0.1)

@retry_with_advanced_policy("api_calls", config)
def call_api():
    # This function will be retried automatically
    return requests.get("https://api.example.com/data")

# For async functions
@async_retry_with_advanced_policy("async_api_calls", config)
async def call_async_api():
    async with aiohttp.ClientSession() as session:
        async with session.get("https://api.example.com/data") as response:
            return await response.json()
```

## gRPC Interceptors

The framework provides comprehensive gRPC interceptors for both client and server-side resilience.

### Client Interceptors

```python
from marty_common.resilience import ResilienceClientInterceptor

# Create client interceptor
interceptor = ResilienceClientInterceptor(
    service_name="user_service",
    retry_config=AdvancedRetryConfig(max_attempts=3),
    circuit_breaker_config=CircuitBreakerConfig(failure_threshold=5),
    enable_metrics=True,
)

# Use with gRPC channel
channel = grpc.insecure_channel("localhost:50051")
channel = grpc.intercept_channel(channel, interceptor)

stub = UserServiceStub(channel)
response = stub.GetUser(GetUserRequest(id="123"))
```

### Server Interceptors

```python
from marty_common.resilience import EnhancedResilienceServerInterceptor

# Create server interceptor with failure injection
failure_config = AdvancedFailureInjectionConfig(
    enabled=True,
    base_failure_rate=0.05,  # 5% failure rate
    method_specific_rates={
        "/health": 0.0,      # Never fail health checks
        "/test": 0.2,        # Higher failure rate for test endpoints
    }
)

interceptor = EnhancedResilienceServerInterceptor(
    service_name="user_service",
    failure_injection_config=failure_config,
    enable_metrics=True,
)

# Use with gRPC server
server = grpc.server(
    futures.ThreadPoolExecutor(max_workers=10),
    interceptors=[interceptor]
)
```

### Composite Interceptors

For complete resilience coverage, use the composite interceptor:

```python
from marty_common.resilience import CompositeResilienceInterceptor

resilience = CompositeResilienceInterceptor(
    service_name="user_service",
    client_retry_config=retry_config,
    client_circuit_breaker_config=circuit_breaker_config,
    server_failure_injection_config=failure_injection_config,
    enable_metrics=True,
)

# Client-side
client_interceptors = resilience.get_client_interceptors()
async_client_interceptors = resilience.get_async_client_interceptors()

# Server-side
server_interceptors = resilience.get_server_interceptors()
```

## Configuration Management

### Environment-Specific Configurations

```python
from marty_common.resilience import (
    get_development_config,
    get_production_config,
    get_testing_config
)

# Pre-configured environments
dev_config = get_development_config()    # Lenient settings for development
prod_config = get_production_config()   # Conservative settings for production
test_config = get_testing_config()      # Fast recovery for testing
```

### YAML Configuration

Create configuration files for different environments:

```yaml
# config/resilience_production.yaml
service_name: "user_service"
environment: "production"

circuit_breaker:
  failure_threshold: 5
  recovery_timeout: 30.0
  enable_metrics: true

retry:
  max_attempts: 5
  base_delay: 0.2
  max_delay: 60.0
  backoff_strategy: "exponential_jitter"
  enable_adaptive_delays: true

failure_injection:
  enabled: false  # Disabled in production
```

Load configuration:

```python
from marty_common.resilience import load_config

config = load_config("config/resilience_production.yaml")
```

### Environment Variables

Configure using environment variables:

```bash
export MARTY_RESILIENCE_SERVICE_NAME="user_service"
export MARTY_RESILIENCE_CIRCUIT_BREAKER_FAILURE_THRESHOLD=5
export MARTY_RESILIENCE_RETRY_MAX_ATTEMPTS=5
export MARTY_RESILIENCE_FAILURE_INJECTION_ENABLED=false
```

```python
config = load_config()  # Automatically loads from environment
```

## Monitoring and Observability

### Health Monitoring

```python
from marty_common.resilience import (
    get_global_monitor,
    register_circuit_breaker_for_monitoring,
    register_retry_manager_for_monitoring
)

# Register components for monitoring
monitor = get_global_monitor()
monitor.register_circuit_breaker("user_service", circuit_breaker)
monitor.register_retry_manager("user_service", retry_manager)

# Get health status
health = monitor.get_overall_health()
print(f"Overall healthy: {health['overall_healthy']}")

# Generate health report
report = monitor.generate_health_report()
print(report)
```

### Metrics Collection

```python
from marty_common.resilience import MetricsCollector

metrics = MetricsCollector()

# Record custom metrics
metrics.increment_counter("user_requests_total", {"endpoint": "/users"})
metrics.observe_histogram("request_duration_ms", 150.0, {"method": "GET"})
metrics.set_gauge("active_connections", 42, {"service": "user_service"})

# Get metrics summary
summary = metrics.get_metrics_summary()
```

### Health Check Endpoint

```python
from flask import Flask, jsonify
from marty_common.resilience import get_resilience_health_status

app = Flask(__name__)

@app.route("/health")
def health_check():
    health_status = get_resilience_health_status()
    status_code = 200 if health_status["overall_healthy"] else 503
    return jsonify(health_status), status_code

@app.route("/health/report")
def health_report():
    from marty_common.resilience import generate_resilience_health_report
    report = generate_resilience_health_report()
    return report, 200, {'Content-Type': 'text/plain'}
```

## Testing with Failure Injection

### Integration Tests

```python
from marty_common.resilience.comprehensive_integration_tests import (
    run_comprehensive_resilience_test,
    run_async_resilience_test
)

# Run comprehensive test suite
sync_report = run_comprehensive_resilience_test()
print(sync_report)

# Run async-specific tests
import asyncio
async_report = asyncio.run(run_async_resilience_test())
print(async_report)
```

### Custom Failure Scenarios

```python
from marty_common.resilience.comprehensive_integration_tests import (
    ResilienceTestOrchestrator,
    FailureScenario
)

# Create test orchestrator
orchestrator = ResilienceTestOrchestrator()

# Create mock services
service = orchestrator.create_service("test_service")
circuit_breaker = orchestrator.create_circuit_breaker("test_cb")

# Define failure scenario
scenario = FailureScenario(
    name="high_latency",
    failure_rate=0.3,
    description="Test behavior under high latency conditions"
)

# Run test with failure injection
with orchestrator.failure_injection(scenario):
    results = orchestrator.run_circuit_breaker_test("test_service", "test_cb")

print(orchestrator.generate_test_report())
```

### Failure Injection in Production

⚠️ **Warning**: Only enable failure injection in non-production environments!

```python
# Enable failure injection via metadata
metadata = [("x-failure-inject", "true")]
response = stub.GetUser(request, metadata=metadata)

# Or via environment variable
import os
os.environ["MARTY_FAILURE_INJECTION"] = "enabled"
os.environ["MARTY_FAILURE_INJECTION_RATE"] = "0.1"  # 10% failure rate
```

## Best Practices

### 1. Circuit Breaker Guidelines

- Set failure thresholds based on your service's normal error rate
- Use shorter recovery timeouts for critical services
- Implement custom error classifiers to avoid tripping on client errors
- Monitor circuit breaker state changes

```python
# Good: Service-specific thresholds
user_service_cb = CircuitBreakerConfig(failure_threshold=5, recovery_timeout=30.0)
payment_service_cb = CircuitBreakerConfig(failure_threshold=3, recovery_timeout=60.0)

# Good: Custom error classification
class ServiceErrorClassifier:
    def should_trip_circuit(self, exception):
        # Don't trip on client errors (4xx)
        if hasattr(exception, 'code'):
            return exception.code not in [400, 401, 403, 404]
        return not isinstance(exception, ValueError)
```

### 2. Retry Strategy Selection

- Use exponential backoff with jitter for most scenarios
- Enable adaptive delays in production for self-tuning
- Set reasonable maximum delays to avoid blocking too long
- Configure appropriate exception types for retries

```python
# Good: Production retry configuration
production_retry = AdvancedRetryConfig(
    max_attempts=5,
    base_delay=0.2,
    max_delay=60.0,
    backoff_strategy=BackoffStrategy.EXPONENTIAL_JITTER,
    enable_adaptive_delays=True,
    retry_on_exceptions=(ConnectionError, TimeoutError, OSError),
    abort_on_exceptions=(ValueError, TypeError),
)
```

### 3. Monitoring and Alerting

- Monitor circuit breaker state changes
- Alert on high failure rates
- Track retry attempt patterns
- Set up health check endpoints

```python
# Set up alerts based on health status
health = get_resilience_health_status()
if not health["overall_healthy"]:
    # Send alert to monitoring system
    send_alert("Resilience health degraded", health)
```

### 4. Configuration Management

- Use environment-specific configuration files
- Override with environment variables for deployment flexibility
- Version your configuration files
- Validate configuration on startup

```python
# Good: Environment-aware configuration loading
def load_resilience_config():
    env = os.getenv("ENVIRONMENT", "development")
    config_file = f"config/resilience_{env}.yaml"
    
    try:
        return load_config(config_file)
    except FileNotFoundError:
        logger.warning(f"Config file {config_file} not found, using defaults")
        return load_config()  # Load from environment variables
```

### 5. Testing Strategy

- Test resilience patterns in isolation
- Use failure injection to validate behavior
- Include performance testing under load
- Test recovery scenarios

```python
# Good: Comprehensive resilience testing
def test_service_resilience():
    # Test circuit breaker activation
    test_circuit_breaker_opens_on_failures()
    
    # Test retry behavior
    test_retries_with_exponential_backoff()
    
    # Test recovery
    test_circuit_breaker_recovers_after_success()
    
    # Test combined behavior
    test_circuit_breaker_and_retry_interaction()
```

## Examples

### Complete Service Setup

```python
import grpc
from concurrent import futures
from marty_common.resilience import (
    load_config,
    CompositeResilienceInterceptor,
    register_circuit_breaker_for_monitoring,
    register_retry_manager_for_monitoring,
)

class UserService:
    def __init__(self):
        # Load configuration
        self.config = load_config()
        
        # Set up resilience
        self.resilience = CompositeResilienceInterceptor(
            service_name="user_service",
            client_retry_config=self.config.retry,
            client_circuit_breaker_config=self.config.circuit_breaker,
            enable_metrics=self.config.enable_metrics,
        )
        
        # Register for monitoring
        register_circuit_breaker_for_monitoring(
            "user_service", 
            self.resilience.client_interceptor.circuit_breaker
        )
        register_retry_manager_for_monitoring(
            "user_service",
            self.resilience.client_interceptor.retry_manager
        )
    
    def start_server(self, port=50051):
        server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=10),
            interceptors=self.resilience.get_server_interceptors()
        )
        
        # Add your service implementation
        # add_UserServiceServicer_to_server(UserServiceImplementation(), server)
        
        listen_addr = f"[::]:{port}"
        server.add_insecure_port(listen_addr)
        server.start()
        print(f"User service listening on {listen_addr}")
        return server
    
    def create_client(self, target="localhost:50051"):
        channel = grpc.insecure_channel(target)
        channel = grpc.intercept_channel(
            channel,
            *self.resilience.get_client_interceptors()
        )
        return channel
```

### Async Service with Resilience

```python
import asyncio
import grpc.aio
from marty_common.resilience import (
    AdvancedRetryConfig,
    AdvancedRetryManager,
    AsyncResilienceClientInterceptor,
)

class AsyncUserServiceClient:
    def __init__(self, target="localhost:50051"):
        self.target = target
        
        # Configure retry behavior
        retry_config = AdvancedRetryConfig(
            max_attempts=3,
            base_delay=0.1,
            backoff_strategy=BackoffStrategy.EXPONENTIAL_JITTER,
        )
        
        # Create interceptor
        self.interceptor = AsyncResilienceClientInterceptor(
            service_name="async_user_service",
            retry_config=retry_config,
        )
    
    async def get_user(self, user_id: str):
        async with grpc.aio.insecure_channel(self.target) as channel:
            channel = grpc.aio.intercept_channel(channel, self.interceptor)
            stub = UserServiceStub(channel)
            
            request = GetUserRequest(id=user_id)
            response = await stub.GetUser(request)
            return response

# Usage
async def main():
    client = AsyncUserServiceClient()
    user = await client.get_user("123")
    print(f"Retrieved user: {user.name}")

if __name__ == "__main__":
    asyncio.run(main())
```

This comprehensive guide covers all aspects of implementing resilience patterns in your Marty microservices. For additional examples and advanced configurations, see the test files and example configurations in the repository.