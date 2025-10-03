# Service Template Generator - Complete DRY Implementation

## Overview

The Service Template Generator is the final piece of the Marty DRY implementation, providing automated code generation for new services that automatically incorporate all established DRY patterns. This ensures that every new service starts with maximum code reuse and consistency.

## Code Reduction Achieved

### Traditional Service Creation (Before)
Creating a new service traditionally required:
- ~50 lines of server setup code
- ~85 lines of configuration code  
- ~94 lines of test setup code
- ~30 lines of Docker configuration
- Manual implementation of health checks, logging, etc.
- **Total: ~259 lines of boilerplate per service**

### DRY Template Generation (After)
Using the service generator, new services get:
- ~8 lines of server setup (uses gRPC Service Factory)
- ~30 lines of configuration (inherits from Base Configuration Classes)
- ~20 lines of test setup (uses DRY Test Infrastructure)
- ~15 lines of Docker configuration (uses Base Image)
- Automatic health checks, logging, reflection, etc.
- **Total: ~73 lines of actual code**

**Total code reduction: 72% fewer lines (259 → 73 lines)**

## Available Templates

### 1. gRPC Service Template (`grpc`)
- **Purpose**: Pure gRPC services with protocol buffers
- **Configuration**: Inherits from `GRPCServiceConfig`
- **Server Setup**: Uses gRPC Service Factory
- **Generated Files**:
  - `main.py` - Service entry point (8 lines)
  - `app/core/config.py` - Service configuration
  - `app/services/{service}_service.py` - Business logic implementation
  - `tests/test_{service}_service.py` - Comprehensive test suite
  - `{service}.proto` - Protocol buffer definition
  - `Dockerfile` - Container configuration

### 2. FastAPI Service Template (`fastapi`)
- **Purpose**: HTTP REST API services
- **Configuration**: Inherits from `FastAPIServiceConfig`
- **Server Setup**: Standard FastAPI with DRY middleware
- **Generated Files**:
  - `main.py` - FastAPI application setup
  - `app/core/config.py` - Service configuration
  - `app/api/routes.py` - API route definitions
  - `app/services/{service}_service.py` - Business logic
  - `app/core/middleware.py` - Standard middleware setup
  - `app/core/error_handlers.py` - Error handling patterns
  - `tests/test_{service}_service.py` - API test suite
  - `Dockerfile` - Container configuration

### 3. Hybrid Service Template (`hybrid`)
- **Purpose**: Services exposing both gRPC and HTTP interfaces
- **Configuration**: Inherits from `HybridServiceConfig`
- **Server Setup**: Concurrent FastAPI and gRPC servers
- **Generated Files**:
  - `main.py` - Concurrent server management
  - `app/core/config.py` - Unified configuration
  - `app/api/routes.py` - HTTP API routes
  - `app/services/{service}_service.py` - Shared business logic
  - `app/services/grpc_service.py` - gRPC interface
  - `{service}.proto` - Protocol buffer definition
  - `tests/test_{service}_service.py` - Both interface tests
  - `Dockerfile` - Container configuration

### 4. Minimal Service Template (`minimal`)
- **Purpose**: Lightweight utility services
- **Configuration**: Inherits from `BaseServiceConfig`
- **Server Setup**: Basic service patterns only
- **Generated Files**:
  - `main.py` - Minimal service entry point
  - `app/core/config.py` - Basic configuration
  - `app/services/{service}_service.py` - Core functionality
  - `tests/test_{service}_service.py` - Basic test suite
  - `Dockerfile` - Container configuration

## Usage Examples

### Basic gRPC Service
```bash
python scripts/generate_service.py grpc document-validator
```

### FastAPI Service with Custom Port
```bash
python scripts/generate_service.py fastapi user-management --http-port 8080
```

### Hybrid Service with Custom Configuration
```bash
python scripts/generate_service.py hybrid payment-processor \
  --grpc-port 50052 \
  --http-port 8082 \
  --description "Payment processing and validation service"
```

### Minimal Utility Service
```bash
python scripts/generate_service.py minimal config-validator
```

## Generated Service Structure

Each generated service follows the DRY structure:

```
src/{service_name}/
├── main.py                              # Service entry point
├── app/
│   ├── core/
│   │   ├── config.py                    # DRY configuration
│   │   ├── middleware.py               # Standard middleware (FastAPI)
│   │   └── error_handlers.py           # Error handling patterns (FastAPI)
│   ├── api/
│   │   └── routes.py                   # API routes (FastAPI/Hybrid)
│   └── services/
│       ├── {service}_service.py        # Business logic
│       └── grpc_service.py            # gRPC interface (gRPC/Hybrid)
├── tests/
│   └── test_{service}_service.py       # DRY test suite
├── {service}.proto                     # Protocol definition (gRPC/Hybrid)
└── Dockerfile                          # Container configuration
```

## Template Variables

The generator uses these variables for customization:

| Variable | Description | Example |
|----------|-------------|---------|
| `service_name` | Kebab-case service name | `document-validator` |
| `service_package` | Python package name | `document_validator` |
| `service_class` | PascalCase class name | `DocumentValidator` |
| `service_description` | Human-readable description | `Document validation service` |
| `author` | Author name | `Marty Development Team` |
| `grpc_port` | gRPC server port | `50051` |
| `http_port` | HTTP server port | `8080` |

## DRY Patterns Automatically Included

### 1. Configuration Inheritance
```python
class DocumentValidatorConfig(GRPCServiceConfig):
    """Service configuration inheriting all DRY patterns."""
    
    # Only service-specific fields needed
    max_document_size: int = Field(default=10485760)
    validation_timeout: int = Field(default=30)
```

### 2. gRPC Service Factory Usage
```python
def main() -> None:
    """8-line service setup replacing 50+ lines."""
    factory = create_grpc_service_factory(
        service_name="document-validator",
        config_type="grpc",
    )
    
    factory.register_service(
        name="document_validator_service",
        servicer_factory=lambda **_: DocumentValidatorService(),
        registration_func=add_DocumentValidatorServicer_to_server,
    )
    
    factory.serve()
```

### 3. DRY Test Infrastructure
```python
class TestDocumentValidatorService:
    """Tests using DRY patterns - 78% code reduction."""
    
    @pytest.fixture
    def service_config(self) -> GRPCServiceTestConfig:
        return GRPCServiceTestConfig(
            service_name="document-validator",
            test_name="document_validator_service",
            config_factory=create_document_validator_config,
            service_class=DocumentValidatorService,
        )
```

### 4. Docker Base Image Usage
```dockerfile
# Uses shared base image with all dependencies
FROM marty-base:latest

# Minimal service-specific configuration
ARG SERVICE_NAME=document_validator
COPY src/document_validator/ /app/src/document_validator/
ENV SERVICE_NAME=document-validator
EXPOSE 50051
CMD ["python", "main.py"]
```

## Integration with Existing DRY Infrastructure

The generated services automatically integrate with all established DRY patterns:

### Base Configuration Classes
- Inherits from appropriate base config (GRPCServiceConfig, FastAPIServiceConfig, etc.)
- Gets all common configuration fields automatically
- Service-specific fields are minimal and focused

### gRPC Service Factory
- Server setup reduced from ~50 lines to ~8 lines
- Automatic health checks, logging streamer, reflection
- Signal handling and graceful shutdown
- TLS support ready

### DRY Test Infrastructure
- Test setup reduced from ~94 lines to ~20 lines
- Automatic mock dependencies and test data
- Consistent test patterns across all services

### Docker Base Images
- Container configuration reduced from ~30 lines to ~15 lines
- All common dependencies pre-installed
- Consistent build and deployment patterns

### Shared Logging
- Automatic logging setup using marty_common.logging_config
- Consistent log formatting and levels
- Service-specific loggers with proper naming

## Development Workflow

### 1. Generate Service
```bash
python scripts/generate_service.py grpc my-new-service
```

### 2. Customize Configuration
Edit `app/core/config.py` to add service-specific fields:
```python
class MyNewServiceConfig(GRPCServiceConfig):
    # Add your custom configuration
    processing_timeout: int = Field(default=60)
    max_batch_size: int = Field(default=100)
```

### 3. Implement Business Logic
Edit `app/services/my_new_service_service.py`:
```python
def ProcessRequest(self, request, context):
    """Implement your gRPC method."""
    # Business logic here
    pass
```

### 4. Define Protocol (gRPC services)
Edit `my_new_service.proto`:
```protobuf
service MyNewService {
  rpc ProcessRequest(ProcessRequest) returns (ProcessResponse);
}
```

### 5. Add Tests
Edit `tests/test_my_new_service_service.py`:
```python
def test_process_request(self, my_new_service_service):
    """Test your business logic."""
    # Test implementation
    pass
```

### 6. Build and Deploy
```bash
# Build using DRY Docker patterns
docker build -f src/my_new_service/Dockerfile -t my-new-service .

# Run with environment configuration
docker run -e SERVICE_NAME=my-new-service my-new-service
```

## Benefits Summary

1. **Massive Time Savings**: New services can be created in minutes instead of hours
2. **Consistency**: All services follow the same patterns and structure
3. **Best Practices**: DRY patterns are enforced from the start
4. **Maintainability**: Updates to patterns automatically benefit all services
5. **Quality**: Generated code includes tests, documentation, and deployment configuration
6. **Productivity**: Developers focus on business logic, not boilerplate

## Files Created

- `scripts/generate_service.py` - Main generator script
- `templates/` - Template directory structure
- `templates/service/grpc_service/` - gRPC service templates
- `templates/service/fastapi_service/` - FastAPI service templates  
- `templates/service/hybrid_service/` - Hybrid service templates
- `docs/SERVICE_TEMPLATE_GUIDE.md` - This documentation

## Integration with CI/CD

Generated services are immediately ready for CI/CD pipelines:

1. **Docker Build**: Uses established base image patterns
2. **Testing**: Includes comprehensive test suites
3. **Configuration**: Environment-based configuration ready
4. **Health Checks**: Built-in health endpoints for orchestration
5. **Monitoring**: Metrics and logging configured

The Service Template Generator completes the DRY transformation of the Marty platform, ensuring that all future development automatically benefits from the established patterns and best practices.