# Centralized Logging Infrastructure

## Overview

The Marty platform includes a comprehensive centralized logging infrastructure built on the ELK stack (Elasticsearch, Logstash, Kibana) with Filebeat for log aggregation. This system provides structured logging, request tracing, performance monitoring, and security auditing across all Marty services.

## Features

### 🏗️ **Structured Logging**

- JSON-formatted logs with consistent schema
- Service context (name, version, environment, hostname)
- Request tracing with correlation IDs
- Performance metrics and timing data
- Security events and audit trails
- Business logic tracking

### 📊 **Log Aggregation**

- ELK stack for centralized log collection and analysis
- Filebeat for log shipping from multiple sources
- Logstash for log processing and enrichment
- Elasticsearch for storage and indexing
- Kibana for visualization and dashboards

### 🔍 **Search & Analytics**

- Full-text search across all logs
- Time-based filtering and analysis
- Service-specific log views
- Performance metrics dashboards
- Security incident tracking
- Business metrics monitoring

### 🚀 **Integration Ready**

- FastAPI middleware for automatic request logging
- Context managers for request-scoped logging
- Prometheus metrics integration
- Docker container log collection
- Development and production configurations

## Quick Start

### 1. Set Up Logging Infrastructure

```bash
# Start the ELK stack
./scripts/setup_logging.sh

# Or manually with docker-compose
docker-compose -f docker/docker-compose.logging.yml up -d
```

### 2. Configure Application Logging

```python
from marty_common.logging.structured_logging import setup_logging_for_service

# Set up logging for your service
logging_config = setup_logging_for_service("my_service")
logger = logging_config.get_logger()

# Basic logging
logger.info("Service started", port=8080, workers=4)
logger.warning("High memory usage", memory_usage="85%")
logger.error("Database connection failed", error="Connection timeout")
```

### 3. Use Specialized Loggers

```python
from marty_common.logging.structured_logging import (
    PerformanceLogger, SecurityLogger, BusinessLogger
)

# Performance logging
perf_logger = PerformanceLogger(logger)
perf_logger.log_request("GET", "/api/docs", 200, 0.145, response_size=1024)

# Security logging
security_logger = SecurityLogger(logger)
security_logger.log_authentication("user123", True, "oauth", "192.168.1.1")

# Business logging
business_logger = BusinessLogger(logger)
business_logger.log_document_processed("doc123", "passport", 2.5, True)
```

### 4. Add Request Context

```python
# Using context manager
with logging_config.request_context(request_id="req-123", user_id="user456"):
    logger.info("Processing user request")
    business_logger.log_document_processed("doc456", "id_card", 1.8, True)

# Manual context management
logging_config.set_request_context(request_id="req-789", session_id="sess-abc")
logger.info("Manual context logging")
logging_config.clear_request_context()
```

## Architecture

### Log Flow

```
Application Logs → Structured Logger → File/Console → Filebeat → Logstash → Elasticsearch → Kibana
                                    ↘ Syslog → Logstash ↗
```

### Components

#### **MartyStructuredLogger**

- Core logging configuration class
- Handles structured logging setup
- Manages request context
- Supports multiple output formats

#### **Specialized Loggers**

- **PerformanceLogger**: HTTP requests, database queries, API calls
- **SecurityLogger**: Authentication, authorization, security events
- **BusinessLogger**: Document processing, verification results, business metrics

#### **Middleware Integration**

- **LoggingMiddleware**: FastAPI middleware for automatic request/response logging
- Request ID generation and context management
- Performance metrics collection

### Log Schema

```json
{
  "@timestamp": "2024-01-15T10:30:00.000Z",
  "service": "document_processing",
  "version": "1.0.0",
  "environment": "production",
  "hostname": "marty-worker-01",
  "pid": 12345,
  "level": "INFO",
  "logger": "business",
  "request_id": "req-1705315800000-abc123",
  "user_id": "user456",
  "session_id": "sess-def789",
  "correlation_id": "corr-ghi012",
  "event": "document_processed",
  "event_type": "business",
  "document_id": "doc123",
  "document_type": "passport",
  "processing_time": 2.5,
  "success": true,
  "file": "document_processor.py",
  "line": 142,
  "function": "process_document"
}
```

## Configuration

### Environment Variables

```bash
# Service configuration
MARTY_VERSION=1.0.0
MARTY_ENVIRONMENT=production

# Logging configuration
LOG_LEVEL=INFO
LOG_CONSOLE=true
LOG_FILE=true
LOG_SYSLOG=false
LOG_DIR=logs

# ELK stack URLs
ELASTICSEARCH_URL=http://localhost:9200
KIBANA_URL=http://localhost:5601
LOGSTASH_HOST=localhost
LOGSTASH_PORT=5000
```

### Service-Specific Setup

```python
# PKD Service
logging_config = setup_logging_for_service(
    "pkd_service",
    version="1.2.0",
    environment="production",
    log_level="INFO",
    enable_syslog=True
)

# Document Processing Service
logging_config = setup_logging_for_service(
    "document_processing",
    log_dir="/var/log/marty",
    enable_console=False  # Production: only file and syslog
)
```

## FastAPI Integration

```python
from fastapi import FastAPI
from marty_common.logging.structured_logging import (
    setup_logging_for_service, LoggingMiddleware
)

app = FastAPI()

# Set up logging
logging_config = setup_logging_for_service("my_api")
logger = logging_config.get_logger()

# Add logging middleware
app.add_middleware(LoggingMiddleware, logger=logger)

@app.get("/api/health")
async def health_check():
    logger.info("Health check requested")
    return {"status": "healthy"}
```

## Kibana Dashboards

### Index Patterns

- `marty-*`: All Marty logs
- `marty-performance-*`: Performance metrics
- `marty-security-*`: Security events
- `marty-business-*`: Business metrics
- `marty-{service}-*`: Service-specific logs

### Pre-built Dashboards

1. **Service Overview**: Request rates, response times, error rates
2. **Performance Dashboard**: API performance, database query times
3. **Security Dashboard**: Authentication attempts, authorization failures
4. **Business Metrics**: Document processing rates, verification results
5. **Error Analysis**: Error tracking and investigation

### Sample Queries

```kql
# Find all errors for a specific service
service_name:"document_processing" AND log_level:"ERROR"

# Performance issues (slow requests)
metric_type:"performance" AND log_data.response_time:>5.0

# Authentication failures
metric_type:"security" AND log_data.success:false

# Business metrics for specific document type
metric_type:"business" AND log_data.document_type:"passport"

# Request tracing
request_id:"req-1705315800000-abc123"
```

## Development

### Local Setup

```bash
# Start logging infrastructure
./scripts/setup_logging.sh

# Test logging
python3 -c "
from marty_common.logging.structured_logging import setup_logging_for_service
logger_config = setup_logging_for_service('test_service')
logger = logger_config.get_logger()
logger.info('Test log entry', test=True)
"

# View logs in Kibana
open http://localhost:5601
```

### Testing

```python
import pytest
from marty_common.logging.structured_logging import setup_logging_for_service

def test_structured_logging():
    logging_config = setup_logging_for_service("test_service", environment="test")
    logger = logging_config.get_logger()

    # Test basic logging
    logger.info("Test message", test_field="test_value")

    # Test context management
    with logging_config.request_context(request_id="test-123"):
        logger.info("Context test")
```

## Production Deployment

### Security Considerations

- Enable Elasticsearch authentication in production
- Use TLS for all ELK communications
- Implement log retention policies
- Secure Kibana with authentication
- Network isolation for logging infrastructure

### Performance Tuning

- Adjust Elasticsearch heap size based on log volume
- Configure appropriate log retention and rotation
- Use index lifecycle management (ILM)
- Optimize Logstash pipeline for throughput
- Monitor logging infrastructure performance

### Monitoring

- Set up alerts for logging infrastructure health
- Monitor disk space for log storage
- Track log ingestion rates and processing delays
- Set up dashboards for logging system metrics

## Troubleshooting

### Common Issues

#### No logs appearing in Kibana

1. Check if services are running: `docker-compose -f docker/docker-compose.logging.yml ps`
2. Verify Filebeat is reading logs: `docker logs marty-filebeat`
3. Check Logstash processing: `docker logs marty-logstash`
4. Verify Elasticsearch indices: `curl localhost:9200/_cat/indices`

#### Performance issues

1. Check Elasticsearch cluster health: `curl localhost:9200/_cluster/health`
2. Monitor resource usage: `docker stats`
3. Adjust heap sizes in docker-compose.logging.yml
4. Review log volume and retention policies

#### Missing log fields

1. Verify log format matches expected schema
2. Check Logstash pipeline configuration
3. Review index mapping in Elasticsearch
4. Test with sample log entries

### Log Analysis Commands

```bash
# View recent logs from all services
docker-compose -f docker/docker-compose.logging.yml logs -f --tail=100

# Check Elasticsearch indices
curl -X GET "localhost:9200/_cat/indices?v&s=index"

# View index mapping
curl -X GET "localhost:9200/marty-logs-*/_mapping"

# Search logs via API
curl -X GET "localhost:9200/marty-*/_search?q=service_name:document_processing&size=10"
```

## Integration Examples

### Custom Service Integration

```python
# my_service.py
from marty_common.logging.structured_logging import (
    setup_logging_for_service, PerformanceLogger, SecurityLogger
)

class MyService:
    def __init__(self):
        self.logging_config = setup_logging_for_service("my_service")
        self.logger = self.logging_config.get_logger()
        self.perf_logger = PerformanceLogger(self.logger)
        self.security_logger = SecurityLogger(self.logger)

    async def process_request(self, request_id: str, user_id: str):
        with self.logging_config.request_context(
            request_id=request_id,
            user_id=user_id
        ):
            start_time = time.time()

            try:
                self.logger.info("Processing request started")

                # Process request
                result = await self._do_processing()

                # Log success
                processing_time = time.time() - start_time
                self.perf_logger.log_external_api_call(
                    "my_service", "/process", "POST",
                    processing_time, 200
                )

                self.logger.info("Request processed successfully",
                               result_id=result.id)
                return result

            except Exception as e:
                self.logger.error("Request processing failed",
                                error=str(e), error_type=type(e).__name__)
                raise
```

### Microservice Communication Tracing

```python
# service_a.py
import httpx
from marty_common.logging.structured_logging import setup_logging_for_service

logging_config = setup_logging_for_service("service_a")
logger = logging_config.get_logger()

async def call_service_b(data: dict, correlation_id: str):
    with logging_config.request_context(correlation_id=correlation_id):
        logger.info("Calling service B", target_service="service_b")

        headers = {"X-Correlation-ID": correlation_id}
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://service-b/api/process",
                json=data,
                headers=headers
            )

        logger.info("Service B response received",
                   status_code=response.status_code)
        return response.json()

# service_b.py
from fastapi import FastAPI, Header

app = FastAPI()
logging_config = setup_logging_for_service("service_b")
logger = logging_config.get_logger()

@app.post("/api/process")
async def process_data(
    data: dict,
    x_correlation_id: str = Header(None)
):
    with logging_config.request_context(correlation_id=x_correlation_id):
        logger.info("Processing data from service A",
                   data_size=len(str(data)))

        # Process data
        result = {"processed": True, "items": len(data)}

        logger.info("Data processing complete",
                   result_items=result["items"])
        return result
```

This centralized logging infrastructure provides comprehensive observability for the Marty platform, enabling effective monitoring, debugging, and performance analysis across all services.
