# Cross-Zone Consistency Engine

## Overview

The Cross-Zone Consistency Engine is a comprehensive service that performs deterministic cross-zone consistency checks across multiple document verification zones including Visual OCR, MRZ (Machine Readable Zone), barcodes, and RFID chip data. This service provides unified validation with detailed audit trails and observability.

## Features

### Core Functionality
- **Multi-Zone Validation**: Supports Visual OCR, MRZ, 1D/2D Barcodes, RFID chip, and magnetic stripe data
- **Canonical Field Mapping**: Standardized field mappings across all document zones
- **Rule-Based Validation**: Configurable consistency rules with exact and fuzzy matching
- **Confidence Scoring**: Detailed confidence metrics for each validation
- **Comprehensive Audit Trail**: Full audit logging for compliance and debugging

### Supported Consistency Rules
1. **Field Exact Match**: Fields must match exactly across zones
2. **Field Fuzzy Match**: Fields must match within similarity threshold
3. **Date Format Validation**: Date consistency and format validation
4. **Checksum Validation**: MRZ check digit validation
5. **Cross-Reference Validation**: Complex cross-zone validation logic

### API Interfaces
- **gRPC Service**: High-performance primary interface
- **REST API**: HTTP wrapper for easier integration
- **OpenAPI Documentation**: Auto-generated API documentation

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   REST API      │    │   gRPC Service   │    │  Observability  │
│   (Port 8080)   │    │   (Port 50051)   │    │   & Metrics     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │           Consistency Engine Core             │
         ├─────────────────────────────────────────────────┤
         │ • Field Mapping Engine                        │
         │ • Rule Execution Engine                       │
         │ • Confidence Calculation                      │
         │ • Audit Trail Management                      │
         └─────────────────────────────────────────────────┘
```

## Quick Start

### Using Docker

```bash
# Build the image
docker build -f docker/consistency-engine.Dockerfile -t marty/consistency-engine .

# Run the service
docker run -p 8080:8080 -p 50051:50051 marty/consistency-engine
```

### Using Kubernetes

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/consistency-engine.yaml

# Check deployment status
kubectl get pods -l app=consistency-engine -n marty-services
```

### Development Setup

```bash
# Install dependencies
uv sync

# Generate protobuf files
python src/compile_protos.py

# Run tests
pytest tests/test_consistency_engine.py -v

# Start development server
python -m src.services.consistency_engine_server
```

## API Usage

### REST API Examples

#### Basic Consistency Check

```bash
curl -X POST http://localhost:8080/api/v1/consistency/check \
  -H "Content-Type: application/json" \
  -d '{
    "zone_data": [
      {
        "zone": "VISUAL_OCR",
        "fields": {
          "document_number": "AB1234567",
          "surname": "SMITH",
          "given_names": "JOHN DAVID",
          "date_of_birth": "1985-03-15",
          "nationality": "USA"
        },
        "extraction_confidence": 0.95
      },
      {
        "zone": "MRZ",
        "fields": {
          "document_number": "AB1234567",
          "surname": "SMITH",
          "given_names": "JOHN DAVID",
          "date_of_birth": "850315",
          "nationality": "USA"
        },
        "extraction_confidence": 1.0
      }
    ],
    "include_audit_trail": true,
    "fuzzy_match_threshold": 0.8
  }'
```

#### Response Format

```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "overall_status": "PASS",
  "rule_results": [
    {
      "rule": "FIELD_EXACT_MATCH",
      "rule_description": "Fields must match exactly across zones",
      "status": "PASS",
      "mismatches": [],
      "confidence_score": 1.0,
      "confidence_level": "VERY_HIGH",
      "explanation": "All checks passed for Exact Field Match with 100.0% confidence",
      "checked_at": "2024-01-15T10:30:00Z",
      "execution_time_ms": 25
    }
  ],
  "critical_mismatches": [],
  "warnings": [],
  "overall_confidence": 0.975,
  "overall_confidence_level": "VERY_HIGH",
  "summary": "Consistency check PASS with 97.5% confidence. All cross-zone consistency checks passed.",
  "processed_at": "2024-01-15T10:30:00Z",
  "total_processing_time_ms": 150,
  "audit_id": "audit_550e8400-e29b-41d4-a716-446655440000"
}
```

### gRPC Usage

```python
import grpc
from src.proto import consistency_engine_pb2, consistency_engine_pb2_grpc

# Create gRPC channel
channel = grpc.insecure_channel('localhost:50051')
stub = consistency_engine_pb2_grpc.ConsistencyEngineStub(channel)

# Create request
request = consistency_engine_pb2.ConsistencyCheckRequest()
request.request_id = "test-request-123"

# Add zone data
zone_data = request.zone_data.add()
zone_data.zone = consistency_engine_pb2.VISUAL_OCR
zone_data.fields["document_number"] = "AB1234567"
zone_data.fields["surname"] = "SMITH"

# Make request
response = stub.CheckConsistency(request)
print(f"Status: {response.overall_status}")
print(f"Confidence: {response.overall_confidence}")
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GRPC_PORT` | `50051` | gRPC server port |
| `HTTP_PORT` | `8080` | HTTP server port |
| `LOG_LEVEL` | `INFO` | Logging level |
| `ENABLE_HTTP` | `true` | Enable HTTP server |
| `ENABLE_PROMETHEUS` | `true` | Enable Prometheus metrics |
| `DATABASE_URL` | - | Database connection string |
| `REDIS_URL` | - | Redis connection string |

### Configuration File

```yaml
service:
  name: consistency-engine
  version: "1.0.0"
  grpc_port: 50051
  http_port: 8080

logging:
  level: INFO
  format: json
  enable_audit: true

metrics:
  enabled: true
  prometheus_enabled: true
  collection_interval: 30

consistency_rules:
  default_fuzzy_threshold: 0.8
  enable_cross_validation: true
  enable_checksum_validation: true

field_mappings:
  strict_validation: true
  normalize_dates: true
  normalize_names: true

performance:
  max_concurrent_checks: 100
  processing_timeout_seconds: 30
  audit_retention_days: 90
```

## Field Mappings

### Canonical Field Types

| Canonical Field | Visual OCR | MRZ | RFID | Description |
|----------------|------------|-----|------|-------------|
| `DOCUMENT_NUMBER` | `document_number` | `document_number` | `document_number` | Primary document identifier |
| `SURNAME` | `surname` | `surname` | `surname` | Family name |
| `GIVEN_NAMES` | `given_names` | `given_names` | `given_names` | First and middle names |
| `DATE_OF_BIRTH` | `date_of_birth` | `date_of_birth` | `date_of_birth` | Birth date |
| `DATE_OF_EXPIRY` | `date_of_expiry` | `date_of_expiry` | `date_of_expiry` | Document expiry |
| `NATIONALITY` | `nationality` | `nationality` | `nationality` | Nationality code |
| `GENDER` | `gender` | `sex` | `gender` | Gender/sex |
| `ISSUING_COUNTRY` | `issuing_country` | `issuing_state` | `issuing_state` | Issuing authority |

### Date Format Handling

The service automatically handles various date formats:
- **ISO Format**: `YYYY-MM-DD` (e.g., `1985-03-15`)
- **MRZ Format**: `YYMMDD` (e.g., `850315`)
- **Short Century**: Automatically determines century for 2-digit years

## Consistency Rules

### Exact Match Rules
- Document numbers must match exactly
- Country codes must match exactly
- Gender codes must match exactly

### Fuzzy Match Rules
- Name fields allow minor variations (OCR errors, formatting)
- Configurable similarity threshold (default: 0.8)
- Handles common OCR issues (O/0, I/l, etc.)

### Date Validation Rules
- Format consistency across zones
- Logical date validation (birth < expiry)
- Century inference for 2-digit years

### Checksum Validation
- MRZ check digit validation
- Document number checksums
- Date field checksums
- Composite checksums

## Observability

### Metrics

The service exposes Prometheus metrics at `/metrics`:

```
# Consistency checks performed
consistency_engine_consistency_checks_total{status="pass|fail|warning"}

# Processing duration
consistency_engine_consistency_check_duration_seconds{status="pass|fail|warning"}

# Rule execution metrics
consistency_engine_consistency_rules_executed_total{rule_type="exact_match|fuzzy_match|...",status="pass|fail"}

# Field mismatch detection
consistency_engine_field_mismatches_total{field_name="document_number|surname|...",severity="critical|warning"}

# Confidence score distribution
consistency_engine_confidence_score_distribution

# Active checks
consistency_engine_active_consistency_checks
```

### Structured Logging

All operations are logged with structured JSON format:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "logger": "consistency_engine",
  "message": "Consistency check completed",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "audit_id": "audit_550e8400-e29b-41d4-a716-446655440000",
  "overall_status": "PASS",
  "processing_time_ms": 150,
  "critical_mismatches": 0,
  "warnings": 0,
  "service": "consistency_engine"
}
```

### Audit Trail

Complete audit trail for all consistency checks:

```json
{
  "audit_id": "audit_550e8400-e29b-41d4-a716-446655440000",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2024-01-15T10:30:00Z",
  "operation_type": "consistency_check",
  "input_data": {
    "zones": [
      {"zone": "VISUAL_OCR", "fields_count": 5},
      {"zone": "MRZ", "fields_count": 5}
    ],
    "context": {"user_id": "test_user"}
  },
  "processing_details": {
    "rules_executed": 3,
    "processing_time_ms": 150,
    "overall_status": "PASS",
    "confidence_score": 0.975
  },
  "results": {
    "mismatches_count": 0,
    "warnings_count": 0,
    "critical_issues": []
  }
}
```

## Testing

### Unit Tests

```bash
# Run all tests
pytest tests/test_consistency_engine.py -v

# Run specific test categories
pytest tests/test_consistency_engine.py::TestConsistencyEngine::test_successful_consistency_check -v
pytest tests/test_consistency_engine.py::TestConsistencyEngineEdgeCases -v
pytest tests/test_consistency_engine.py::TestConsistencyEnginePerformance -v
```

### Integration Tests

```bash
# REST API tests
pytest tests/test_consistency_engine_rest_api.py -v

# End-to-end tests
pytest tests/test_consistency_engine_rest_api.py::TestConsistencyEngineRESTAPIIntegration -v
```

### Load Testing

```bash
# Performance tests
pytest tests/test_consistency_engine.py::TestConsistencyEnginePerformance::test_large_dataset_performance -v
pytest tests/test_consistency_engine.py::TestConsistencyEnginePerformance::test_multiple_concurrent_requests -v
```

## Deployment

### Production Deployment

The service is designed for production deployment with:

- **High Availability**: 3+ replicas with anti-affinity rules
- **Security**: mTLS, RBAC, non-root containers, read-only filesystems
- **Observability**: Prometheus metrics, structured logging, health checks
- **Scalability**: Horizontal pod autoscaling, resource limits
- **Persistence**: Audit trail storage with PVC

### Health Checks

- **Readiness Probe**: `/health` endpoint
- **Liveness Probe**: `/health` endpoint with extended timeout
- **gRPC Health**: gRPC health checking protocol support

### Security

- **Service Mesh**: Istio integration with mTLS
- **Authorization**: RBAC with service-specific permissions
- **Secrets Management**: Kubernetes secrets for sensitive data
- **Container Security**: Non-root user, read-only filesystem

## Troubleshooting

### Common Issues

1. **Low Confidence Scores**
   - Check input data quality
   - Verify field mappings are correct
   - Review fuzzy match thresholds

2. **Performance Issues**
   - Monitor processing times in metrics
   - Check resource utilization
   - Review concurrent request limits

3. **Consistency Failures**
   - Examine specific field mismatches
   - Review audit trail for detailed analysis
   - Validate input data formatting

### Debug Mode

Enable debug logging:

```bash
export LOG_LEVEL=DEBUG
python -m src.services.consistency_engine_server
```

### Monitoring

Key metrics to monitor:
- `consistency_check_duration_seconds` - Processing performance
- `field_mismatches_total` - Data quality issues
- `confidence_score_distribution` - Overall system reliability
- `active_consistency_checks` - System load

## Contributing

1. **Code Style**: Follow PEP 8 and type hints
2. **Testing**: Add tests for new features
3. **Documentation**: Update API documentation
4. **Performance**: Consider performance impact of changes

## License

This project is proprietary software. All rights reserved.