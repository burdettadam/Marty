# Performance Testing Framework

Comprehensive performance testing suite for the Marty Platform, including load testing, stress testing, and performance monitoring integration.

## Overview

The performance testing framework provides:

- **Load Testing**: Test services under normal expected load
- **Stress Testing**: Test services under increasing load to find breaking points
- **Performance Monitoring**: Integration with Prometheus/Grafana for real-time metrics
- **Automated Reporting**: HTML reports with detailed performance metrics
- **CI/CD Integration**: Easy integration with build pipelines

## Quick Start

### Prerequisites

1. **Install Dependencies**:

   ```bash
   uv add --dev aiohttp prometheus-client
   ```

2. **Start Services**: Ensure the services you want to test are running

   ```bash
   make run-pkd-service     # Port 8088
   make run-document-processing  # Port 8080  
   make run-ui-app          # Port 8000
   ```

### Running Tests

#### Quick Test (All Services)

```bash
make perf-test-quick
```

#### Load Test (Single Service)

```bash
# Using make
make perf-test-load SERVICE=pkd_service USERS=10 DURATION=60

# Using script directly
./scripts/run_perf_test.sh pkd_service load 10 60
```

#### Stress Test

```bash
make perf-test-stress SERVICE=pkd_service MAX_USERS=100 RAMP_UP=300
```

#### Comprehensive Testing

```bash
make perf-test-all
```

## Test Types

### Load Testing

Tests service performance under normal expected load with a constant number of concurrent users.

**Parameters**:

- `concurrent_users`: Number of simultaneous virtual users (default: 10)
- `duration_seconds`: Test duration in seconds (default: 60)
- `requests_per_second`: Optional RPS limit

**Example**:

```bash
./scripts/run_perf_test.sh document_processing load 20 120
```

### Stress Testing

Gradually increases load to find the breaking point of the service.

**Parameters**:

- `max_users`: Maximum number of concurrent users (default: 100)
- `ramp_up_time`: Time to reach max users in seconds (default: 300)

**Example**:

```bash
uv run python scripts/performance_test.py stress ui_app --max-users 50 --ramp-up 180
```

## Performance Metrics

The framework collects and reports the following metrics:

### Response Time Metrics

- **Average Response Time**: Mean response time across all requests
- **Median Response Time**: 50th percentile response time
- **95th Percentile**: 95% of requests completed within this time
- **99th Percentile**: 99% of requests completed within this time

### Throughput Metrics

- **Requests per Second (RPS)**: Average request rate
- **Total Requests**: Total number of requests made
- **Successful Requests**: Number of successful requests (2xx, 3xx status codes)

### Error Metrics

- **Error Rate**: Percentage of failed requests
- **Failed Requests**: Number of failed requests
- **Error Types**: Breakdown of error types (timeouts, connection errors, etc.)

## Performance Thresholds

The framework uses the following performance thresholds:

| Metric | ✅ Good | ⚠️ Warning | ❌ Critical |
|--------|---------|------------|-------------|
| Error Rate | < 1% | < 5% | ≥ 5% |
| Average Response Time | < 1s | < 3s | ≥ 3s |
| 95th Percentile | < 2s | < 5s | ≥ 5s |
| Throughput | > 10 RPS | > 1 RPS | ≤ 1 RPS |

## Reports and Output

### Directory Structure

```
reports/performance/
├── load_test_pkd_service_20231201_143022/
│   ├── results.csv                    # Raw test results
│   ├── metrics.json                   # Aggregated metrics
│   └── report.html                    # Visual performance report
└── stress_test_document_processing_20231201_144530/
    ├── results.csv
    ├── metrics.json
    └── report.html
```

### Report Contents

1. **results.csv**: Raw data for each request including:
   - Timestamp
   - Endpoint
   - HTTP method
   - Status code
   - Response time
   - Success/failure
   - Error messages
   - Response size

2. **metrics.json**: Aggregated performance metrics:

   ```json
   {
     "total_requests": 1200,
     "successful_requests": 1198,
     "failed_requests": 2,
     "average_response_time": 0.145,
     "p95_response_time": 0.312,
     "requests_per_second": 19.8,
     "error_rate": 0.17
   }
   ```

3. **report.html**: Interactive HTML report with:
   - Performance metrics table
   - Color-coded status indicators
   - Threshold comparisons
   - Test configuration details

## Monitoring Integration

### Prometheus Metrics

The framework exposes metrics to Prometheus:

- `perf_test_requests_total`: Total number of requests
- `perf_test_request_duration_seconds`: Request duration histogram
- `perf_test_errors_total`: Total number of errors

### Grafana Dashboard

Set up monitoring dashboard:

```bash
python scripts/performance_monitoring.py --setup
```

This creates:

- Grafana dashboard configuration (`monitoring/grafana/dashboards/performance-testing.json`)
- Prometheus alerting rules (`monitoring/prometheus/rules/performance-alerts.yml`)

### Real-time Monitoring

Start metrics server during testing:

```bash
# Metrics available at http://localhost:9090/metrics
uv run python scripts/performance_test.py load pkd_service --metrics-port 9090
```

## Service Configurations

The framework includes pre-configured test scenarios for each Marty service:

### PKD Service (Port 8088)

- Root endpoint (`/`)
- API documentation (`/docs`)
- Master list endpoint (`/v1/masterlist`)
- DSC list endpoint (`/v1/dsclist`)
- CRL endpoint (`/v1/crl`)

### Document Processing (Port 8080)

- Root endpoint (`/`)
- Health check (`/api/health`)
- Ping endpoint (`/api/ping`)
- API documentation (`/docs`)

### UI Application (Port 8000)

- Root endpoint (`/`)
- Health check (`/health`)
- API documentation (`/docs`)

## CI/CD Integration

### GitHub Actions

Add to your workflow:

```yaml
- name: Run Performance Tests
  run: |
    make perf-test-quick

- name: Upload Performance Reports
  uses: actions/upload-artifact@v3
  with:
    name: performance-reports
    path: reports/performance/
```

### Jenkins Pipeline

```groovy
stage('Performance Testing') {
    steps {
        sh 'make perf-test-quick'
        publishHTML([
            allowMissing: false,
            alwaysLinkToLastBuild: true,
            keepAll: true,
            reportDir: 'reports/performance',
            reportFiles: '**/report.html',
            reportName: 'Performance Test Report'
        ])
    }
}
```

## Advanced Usage

### Custom Test Scenarios

Create custom test configurations:

```python
from scripts.performance_test import PerformanceTestFramework

async def custom_test():
    async with PerformanceTestFramework() as framework:
        # Custom endpoint configuration
        framework.service_configs["custom_service"] = {
            "port": 8090,
            "endpoints": [
                {"path": "/api/custom", "method": "POST"},
                {"path": "/api/status", "method": "GET"},
            ],
            "auth_header": {"Authorization": "Bearer token"}
        }

        # Run custom test
        results = await framework.load_test("custom_service", 15, 90)
        metrics = framework.calculate_metrics(results)
        framework.save_results(results, "custom_test", metrics)
```

### Performance Regression Testing

Compare results across test runs:

```bash
python scripts/performance_monitoring.py --summary reports/performance/
```

## Troubleshooting

### Common Issues

1. **Service Not Running**

   ```
   ❌ Service pkd_service is not running on port 8088
   ```

   **Solution**: Start the service first: `make run-pkd-service`

2. **High Error Rates**
   - Check service logs for errors
   - Verify API keys and authentication
   - Ensure database connections are stable

3. **Low Throughput**
   - Check system resources (CPU, memory)
   - Verify network connectivity
   - Review service configuration

4. **Timeouts**
   - Increase timeout values in test configuration
   - Check for database query performance issues
   - Review service response times

### Performance Tuning

1. **Database Optimization**
   - Add appropriate indexes
   - Optimize slow queries
   - Configure connection pooling

2. **Service Configuration**
   - Tune thread/worker pools
   - Adjust memory limits
   - Configure caching

3. **Infrastructure**
   - Scale horizontally (more instances)
   - Scale vertically (more resources)
   - Use load balancers

## Make Targets Reference

| Target | Description |
|--------|-------------|
| `make perf-test` | Run quick performance tests |
| `make perf-test-quick` | Test all services with light load |
| `make perf-test-load` | Run load test on specific service |
| `make perf-test-stress` | Run stress test on specific service |
| `make perf-test-all` | Run comprehensive tests on all services |
| `make perf-reports-clean` | Clean performance test reports |

### Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVICE` | `pkd_service` | Service to test |
| `USERS` | `10` | Number of concurrent users |
| `DURATION` | `60` | Test duration in seconds |
| `MAX_USERS` | `100` | Maximum users for stress test |
| `RAMP_UP` | `300` | Ramp-up time for stress test |

---

*Performance testing framework for the Marty Platform - ensuring reliability and scalability*
