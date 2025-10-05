# Performance Test Reports

This directory contains performance test results and reports for the Marty platform.

## Structure

- `*.csv` - Raw performance test data with individual request results
- `*_summary.json` - Aggregated metrics and summaries
- `baseline/` - Baseline performance metrics for comparison
- `trends/` - Historical performance trend data
- `charts/` - Generated performance charts and visualizations

## File Naming Convention

Performance test files follow this naming pattern:
```
{service}_{test_type}_{timestamp}.csv
{service}_{test_type}_{timestamp}_summary.json
```

Examples:
- `pkd_service_load_20251004_143022.csv`
- `trust-svc_stress_20251004_143022_summary.json`

## Metrics Included

### Raw Data (CSV)
- `timestamp`: Request timestamp
- `endpoint`: Target endpoint
- `method`: HTTP method
- `status_code`: HTTP response status
- `response_time`: Response time in seconds
- `success`: Boolean success indicator
- `response_size`: Response size in bytes
- `error_message`: Error details (if any)

### Summary Metrics (JSON)
- `total_requests`: Total number of requests
- `successful_requests`: Number of successful requests
- `success_rate`: Success rate percentage
- `avg_response_time`: Average response time (ms)
- `p50_response_time`: 50th percentile response time (ms)
- `p95_response_time`: 95th percentile response time (ms)
- `p99_response_time`: 99th percentile response time (ms)
- `throughput`: Requests per second
- `min_response_time`: Minimum response time (ms)
- `max_response_time`: Maximum response time (ms)

## Performance Thresholds

Service-specific thresholds are defined in `scripts/validate_performance_thresholds.py`:

| Service | Max Avg (ms) | Max P95 (ms) | Min Success Rate | Min Throughput (req/s) |
|---------|--------------|--------------|------------------|------------------------|
| trust-svc | 300 | 800 | 98% | 100 |
| pkd_service | 500 | 1000 | 95% | 50 |
| csca-service | 400 | 1000 | 95% | 80 |
| passport-engine | 2000 | 5000 | 90% | 10 |
| mdl-engine | 1500 | 4000 | 92% | 15 |
| inspection-system | 1000 | 3000 | 95% | 30 |
| ui_app | 200 | 500 | 99% | 200 |

## CI Integration

Performance tests are integrated into the CI pipeline with threshold validation:

```bash
# Run performance smoke test
./scripts/run_perf_test.sh trust-svc load 5 30

# Results are automatically validated against thresholds
# Test fails if any threshold is exceeded
```

## Usage

### Run Performance Test
```bash
# Basic load test
./scripts/run_perf_test.sh <service> <test_type> <users> <duration>

# Example: Load test pkd_service with 10 users for 60 seconds
./scripts/run_perf_test.sh pkd_service load 10 60
```

### View Results
```bash
# Latest results for a service
ls -la reports/performance/pkd_service_*

# View summary
cat reports/performance/pkd_service_load_latest_summary.json
```

### Analyze Trends
```bash
# Generate trend report (future enhancement)
python scripts/analyze_performance_trends.py --service=pkd_service --days=30
```