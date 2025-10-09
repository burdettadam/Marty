# Standardized Docker Architecture

This directory contains the standardized Docker configuration for all Marty services, implementing DRY principles to reduce duplication and improve maintainability.

## Architecture Overview

### Base Image (`base.Dockerfile`)

The `base.Dockerfile` contains all common configuration shared across services:

- Python 3.10 runtime environment
- System dependencies (libxml2, protobuf, PostgreSQL client, etc.)
- UV package manager
- Common Python dependencies
- Proto file compilation
- Shared source code (marty_common, shared utilities)
- Health check configuration
- Standard environment variables

### Service-Specific Dockerfiles

Each service extends the base image with only service-specific configuration:

- Service source code
- Service-specific environment variables
- Service-specific data directories
- Service-specific port configuration
- Service startup command

## Usage

### Building the Base Image

```bash
# Build the base image first (required for all services)
docker build -f docker/base.Dockerfile -t marty-base:latest .
```

### Building Service Images

```bash
# Build a specific service (e.g., PKD service)
docker build -f docker/pkd-service-new.Dockerfile -t marty-pkd-service:latest .

# Build trust anchor service
docker build -f docker/trust-anchor-new.Dockerfile -t marty-trust-anchor:latest .

# Build DTC engine service
docker build -f docker/dtc-engine-new.Dockerfile -t marty-dtc-engine:latest .
```

### Creating New Service Dockerfiles

1. Copy `service-template.Dockerfile`
2. Replace placeholder values:
   - `your-service-name` → actual service name
   - `your_service` → actual service directory
   - `50055` → actual service port
   - Service-specific directories and dependencies
3. Customize the CMD instruction for your service startup

## Benefits of Standardization

### Reduced Duplication

- **Before**: Each service Dockerfile contained 40-60 lines with repeated system setup
- **After**: Service Dockerfiles are 20-30 lines, focusing only on service-specific config

### Improved Consistency

- All services use the same base Python environment
- Consistent dependency management across services
- Standardized directory structure and environment variables

### Better Caching

- Base image layers are cached and reused across all services
- Faster builds for service-specific changes
- Reduced total image size through layer sharing

### Easier Maintenance

- System dependency updates only need to be made in `base.Dockerfile`
- Consistent security patterns (non-root user, proper permissions)
- Standardized health checks and environment configuration

## Migration Guide

### For Existing Services

1. Review current service Dockerfile
2. Identify service-specific configuration (source code, ports, directories)
3. Create new Dockerfile using the template
4. Update docker-compose files to reference new Dockerfile
5. Test the build and runtime behavior

### Environment Variable Standards

All services now support these standard environment variables:

- `SERVICE_NAME`: Name of the service for logging/monitoring
- `GRPC_PORT`: gRPC port for the service
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARN, ERROR)
- `PYTHONPATH`: Set to `/app` in base image
- `PYTHONUNBUFFERED`: Set to `1` for proper log output

## Directory Structure

```
docker/
├── base.Dockerfile              # Base image with common setup
├── service-template.Dockerfile  # Template for new services
├── pkd-service-new.Dockerfile  # PKD service using base
├── trust-anchor-new.Dockerfile # Trust anchor using base
├── dtc-engine-new.Dockerfile   # DTC engine using base
└── README.md                   # This documentation
```

## Legacy Files

The following files are legacy and should be migrated to the new architecture:

- `pkd-service.Dockerfile` → `pkd-service-new.Dockerfile`
- `trust-anchor.Dockerfile` → `trust-anchor-new.Dockerfile`
- `dtc-engine.Dockerfile` → `dtc-engine-new.Dockerfile`
- Other service-specific Dockerfiles

## Best Practices

### Security

- All services run as non-root user `appuser`
- Proper file permissions set during build
- Minimal attack surface through base image

### Performance

- Multi-stage builds for optimal image size
- Dependency caching through proper layer ordering
- Health checks for container orchestration

### Development

- Use the template for consistent new service setup
- Test both base image and service image builds
- Validate service startup and health checks

## Troubleshooting

### Common Issues

1. **Base image not found**: Ensure `marty-base:latest` is built first
2. **Permission errors**: Verify `appuser` has proper permissions
3. **Port conflicts**: Check `GRPC_PORT` environment variable settings
4. **Missing dependencies**: Add service-specific deps after base image

### Build Optimization

- Use `.dockerignore` to exclude unnecessary files
- Order COPY commands from least to most frequently changing
- Use multi-stage builds to minimize final image size
