# Database Per Service - Quick Start Guide

This guide will walk you through setting up and testing the database per service implementation.

## Prerequisites

- PostgreSQL 16+ (or Docker)
- Python with `uv` package manager
- Alembic for database migrations

## Option 1: Using Docker (Recommended for Testing)

### 1. Start Test PostgreSQL

```bash
# Start PostgreSQL with pre-created databases
docker-compose -f docker/docker-compose.test-db.yml up -d

# Wait for PostgreSQL to be ready
docker-compose -f docker/docker-compose.test-db.yml exec postgres-test pg_isready -U postgres
```

### 2. Test Database Connections

```bash
# Test that each service can connect to its database
python scripts/test_databases.py

# Test backward compatibility (default database)
python scripts/test_databases.py --default
```

### 3. Generate Initial Migrations

```bash
# Generate initial migration for each service
make db-revision SERVICE=document_signer MESSAGE="Initial schema"
make db-revision SERVICE=csca_service MESSAGE="Initial schema"
make db-revision SERVICE=pkd_service MESSAGE="Initial schema"
make db-revision SERVICE=passport_engine MESSAGE="Initial schema"
```

### 4. Run Migrations

```bash
# Run migrations for all services
make db-upgrade-all

# Or run for individual services
make db-upgrade SERVICE=document_signer
make db-upgrade SERVICE=csca_service
make db-upgrade SERVICE=pkd_service
make db-upgrade SERVICE=passport_engine
```

### 5. Verify Schema Creation

```bash
# Check current migration status
make db-current SERVICE=document_signer
make db-current SERVICE=csca_service
make db-current SERVICE=pkd_service
make db-current SERVICE=passport_engine

# View migration history
make db-history SERVICE=document_signer
```

## Option 2: Using Existing PostgreSQL

### 1. Setup Databases

```bash
# Automated setup (creates databases and runs migrations)
python scripts/setup_databases.py

# Manual database creation
createdb -U postgres marty_document_signer
createdb -U postgres marty_csca
createdb -U postgres marty_pkd
createdb -U postgres marty_passport_engine
```

### 2. Follow steps 2-5 from Option 1

## Configuration

### Current Configuration (Single Database)

```yaml
# config/development.yaml
database:
  url: "postgresql+asyncpg://dev_user:dev_password@localhost:5432/marty_dev"
  # ... other settings
```

### New Configuration (Per-Service Databases)

```yaml
# config/development.yaml
database:
  # Default database (backward compatibility)
  default:
    url: "postgresql+asyncpg://dev_user:dev_password@localhost:5432/marty_dev"
    
  # Service-specific databases
  document_signer:
    url: "postgresql+asyncpg://dev_user:dev_password@localhost:5432/marty_document_signer"
  csca_service:
    url: "postgresql+asyncpg://dev_user:dev_password@localhost:5432/marty_csca"
  pkd_service:
    url: "postgresql+asyncpg://dev_user:dev_password@localhost:5432/marty_pkd"
  passport_engine:
    url: "postgresql+asyncpg://dev_user:dev_password@localhost:5432/marty_passport_engine"
```

## Common Commands

```bash
# Database Management
make db-upgrade SERVICE=<service_name>           # Run migrations
make db-revision SERVICE=<service_name> MESSAGE="description"  # Create migration
make db-downgrade SERVICE=<service_name>         # Rollback migration
make db-current SERVICE=<service_name>           # Show current status
make db-history SERVICE=<service_name>           # Show history
make db-upgrade-all                              # Upgrade all services

# Testing
python scripts/test_databases.py                 # Test all service connections
python scripts/test_databases.py --default       # Test default database only

# Development Environment
docker-compose -f docker/docker-compose.test-db.yml up -d    # Start test DB
docker-compose -f docker/docker-compose.test-db.yml down     # Stop test DB
```

## Service Schemas Overview

### document_signer
- `document_signer_outbox` - Event outbox
- `credential_offers` - OIDC4VCI offers
- `access_tokens` - OAuth2 tokens
- `issued_credential_audit` - Audit trail

### csca_service
- `csca_outbox` - Event outbox
- `csca_certificates` - CSCA certificates
- `certificate_chains` - Certificate chains
- `crl_cache` - CRL cache
- `ocsp_cache` - OCSP cache

### pkd_service
- `pkd_outbox` - Event outbox
- `pkd_download_manifest` - PKD manifests
- `pkd_certificate_entries` - PKD certificates
- `pkd_sync_jobs` - Sync jobs

### passport_engine
- `passport_engine_outbox` - Event outbox
- `passport_validation_requests` - Validation requests
- `passport_validation_cache` - Validation cache

## Troubleshooting

### Migration Issues

```bash
# Check Alembic configuration
cd src/services/document_signer
uv run alembic current

# Reset migrations (DEV ONLY)
cd src/services/document_signer
rm alembic/versions/*.py
uv run alembic revision --autogenerate -m "Reset schema"
```

### Connection Issues

```bash
# Test direct database connection
psql -h localhost -p 5432 -U dev_user -d marty_document_signer

# Check environment variables
echo $MARTY_DOCUMENT_SIGNER_DB_URL
echo $MARTY_CSCA_DB_URL
echo $MARTY_PKD_DB_URL
echo $MARTY_PASSPORT_ENGINE_DB_URL
```

### Docker Issues

```bash
# Check container logs
docker-compose -f docker/docker-compose.test-db.yml logs postgres-test

# Reset Docker volumes
docker-compose -f docker/docker-compose.test-db.yml down -v
docker-compose -f docker/docker-compose.test-db.yml up -d
```

## Next Steps

1. **Update Service Code**: Modify service startup to use `build_dependencies_async(service_name="xxx")`
2. **Environment Variables**: Set up per-service database URLs in production
3. **CI/CD Integration**: Add migration steps to deployment pipeline
4. **Data Migration**: Plan migration from shared database to per-service databases
5. **Monitoring**: Set up per-service database monitoring