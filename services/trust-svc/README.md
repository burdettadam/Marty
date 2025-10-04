# Trust Service (trust-svc)

A comprehensive microservice for managing trust relationships, certificate validation, and PKD/HML data ingestion in the Marty digital identity verification system.

## Overview

The Trust Service provides centralized management of:
- **Trust Anchors**: Country Signing Certificate Authorities (CSCAs)
- **Document Signing Certificates (DSCs)**: For passport and document validation
- **Certificate Revocation Lists (CRLs)**: Real-time revocation status
- **Master Lists**: Official lists of trusted certificates by country
- **PKD/HML Ingestion**: Automated data synchronization from ICAO and national sources

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   PKD Sources   │───▶│   Trust Service  │───▶│   PostgreSQL    │
│  (ICAO, LDAP)   │    │                  │    │   (trust_svc)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   Prometheus     │
                       │    Metrics       │
                       └──────────────────┘
```

## Features

### REST API Endpoints
- `GET /trust/status` - Service status and data freshness
- `GET /trust/snapshot` - Immutable trust state snapshot  
- `GET /trust/anchors` - List trusted CSCAs with filtering

### gRPC Service
- High-performance certificate validation
- Streaming PKD data updates
- Real-time trust status queries

### Monitoring & Metrics
- `master_list_age_seconds` - Age of master lists by country
- `trusted_csca_total` - Count of trusted CSCAs
- `trusted_dsc_total` - Count of trusted DSCs
- Complete operational metrics for PKD sync operations

### Database Schema
- **master_lists** - PKD master list data with provenance
- **cscas** - Country Signing Certificate Authorities
- **dscs** - Document Signing Certificates  
- **crls** - Certificate Revocation Lists
- **sources** - PKD/HML data source configurations
- **provenance** - Complete audit trail for data lineage

## Quick Start

### Development

1. **Set up environment:**
   ```bash
   cd services/trust-svc
   export DATABASE_URL="postgresql+asyncpg://user:pass@localhost:5432/martydb"
   ```

2. **Install dependencies:**
   ```bash
   pip install -r ../../pyproject.toml
   ```

3. **Run database migrations:**
   ```bash
   python -m alembic upgrade head
   ```

4. **Start the service:**
   ```bash
   python main.py
   ```

### Docker

```bash
docker build -f docker/trust-svc.Dockerfile -t marty/trust-svc .
docker run -p 8080:8080 -p 9090:9090 -p 8081:8081 marty/trust-svc
```

### Kubernetes

```bash
kubectl apply -f k8s/trust-svc/
```

### Helm

```bash
helm install trust-svc helm/charts/trust-svc/
```

## Configuration

Key environment variables:

```bash
# Application
HOST=0.0.0.0
PORT=8080
GRPC_PORT=9090
METRICS_PORT=8081
LOG_LEVEL=INFO

# Database  
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/db
DATABASE_POOL_SIZE=10

# PKD/HML Sync
PKD_SYNC_INTERVAL=3600
HML_SYNC_INTERVAL=1800
ICAO_PKD_URL=https://pkd.icao.int
ICAO_PKD_USERNAME=username
ICAO_PKD_PASSWORD=password

# Trust Settings
TRUST_SNAPSHOT_RETENTION_DAYS=90
MAX_CERT_AGE_DAYS=1095
```

## API Documentation

### Trust Status
```http
GET /api/v1/trust/status
```

Returns current service status and data freshness information.

**Response:**
```json
{
  "service_name": "trust-svc",
  "status": "healthy", 
  "timestamp": "2024-10-03T12:00:00Z",
  "data_freshness_hours": 2.5,
  "total_master_lists": 195,
  "total_active_cscas": 1247,
  "total_active_dscs": 5892,
  "active_sources_count": 12,
  "countries_covered": ["USA", "DEU", "FRA", "...]
}
```

### Trust Anchors
```http
GET /api/v1/trust/anchors?country_code=USA&trust_level=standard&limit=100
```

Returns paginated list of trusted CSCAs with filtering options.

### Trust Snapshot  
```http
GET /api/v1/trust/snapshot?country_code=USA&include_inactive=false
```

Returns immutable snapshot of current trust state.

## Testing

```bash
# Unit tests
python -m pytest tests/test_models.py -v

# Contract tests  
python -m pytest tests/test_api.py -v

# Integration tests
python -m pytest tests/test_integration.py -v

# Coverage report
python -m pytest --cov=trust_svc --cov-report=html
```

## Monitoring

The service exposes metrics on port 8081:

```bash
curl http://localhost:8081/metrics
```

Key metrics:
- `master_list_age_seconds{country_code, source_type}`
- `trusted_csca_total{country_code, trust_level, status}`  
- `trusted_dsc_total{country_code, status}`
- `pkd_sync_operations_total{source_type, country_code, status}`

## Development

### Adding New PKD Sources

1. Create source configuration in database:
```sql
INSERT INTO trust_svc.sources (name, source_type, country_code, url, credentials) 
VALUES ('Germany PKD', 'national_pki', 'DEU', 'https://pki.germany.gov', '{}');
```

2. Implement source-specific parser in `ingestion.py`

3. Add monitoring for the new source

### Database Migrations

```bash
# Create new migration
python -m alembic revision --autogenerate -m "Add new feature"

# Apply migrations
python -m alembic upgrade head

# Rollback
python -m alembic downgrade -1
```

## Security Considerations

- All certificate data is validated before storage
- PKD sources require authenticated connections
- Database credentials are encrypted
- Complete audit trail via provenance tracking
- Regular security scanning of dependencies

## Performance

- Async/await throughout for high concurrency
- Connection pooling for database efficiency  
- Caching of frequently accessed trust data
- Prometheus metrics for performance monitoring
- Horizontal scaling via Kubernetes

## Support

For issues and questions:
- Check logs: `kubectl logs -f deployment/trust-svc`
- Monitor metrics: Grafana dashboard
- Database health: `GET /ready` endpoint
- Debug mode: Set `DEBUG=true`

## gRPC Service

The Trust Service provides a gRPC API for high-performance, strongly-typed access to trust data.

### Service Definition

The gRPC service is defined in `proto/trust_service.proto` and provides the following methods:

- **GetTrustStatus**: Get service status and health information
- **GetTrustAnchors**: Get trust anchors with filtering and pagination
- **GetTrustSnapshot**: Get complete trust snapshot
- **ValidateCertificate**: Validate certificate chains
- **CheckRevocationStatus**: Check certificate revocation status  
- **StreamPKDUpdates**: Stream real-time PKD data updates
- **RefreshPKDData**: Trigger PKD data refresh
- **GetDataSources**: Get information about data sources

### gRPC Server Configuration

- **Address**: `localhost:50051` (configurable via `GRPC_PORT`)
- **Reflection**: Enabled in development mode
- **Authentication**: None (internal service)
- **Max Workers**: 10 (configurable via `GRPC_MAX_WORKERS`)

### Protocol Buffer Compilation

To compile the Protocol Buffer definitions:

```bash
# Install gRPC tools
pip install grpcio-tools

# Compile protobuf files
python compile_protos.py
```

This generates the Python gRPC client and server code in the `grpc_generated/` directory.

### Quick Start Script

Use the quick start script to set up everything automatically:

```bash
# Development mode with auto-reload
python quickstart.py --dev

# Production mode  
python quickstart.py --prod

# Skip dependency installation
python quickstart.py --skip-deps
```