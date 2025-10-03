# Marty Repository DRY Refactoring Recommendations

## Executive Summary

Your repository has already implemented excellent DRY patterns, particularly with the gRPC Service Factory and shared configuration management. However, there are still opportunities to eliminate remaining duplication and inconsistencies. This document provides actionable recommendations to make your codebase even more DRY.

## Current DRY Implementation Status ✅

### Already Well Implemented:
1. **gRPC Service Factory** - Excellent implementation reducing service setup from ~50 lines to ~8 lines
2. **Base Configuration Classes** - Good inheritance hierarchy with `GRPCServiceConfig` and `BaseServiceConfig`
3. **Docker Base Images** - `base.Dockerfile` and `service-template.Dockerfile` patterns
4. **Shared Testing Utilities** - `marty_common/testing/` package with reusable fixtures
5. **Common Logging Configuration** - Centralized logging setup
6. **Protobuf and gRPC Patterns** - Standardized service registration

## Remaining DRY Opportunities 🔄

### 1. Service Main Files - High Priority

**Issue**: Services still have inconsistent main.py patterns and some haven't migrated to the gRPC Service Factory.

**Current State**:
```python
# src/mdoc_engine/src/main.py (84 lines)
class MDocGrpcService(BaseGrpcService):
    def create_servicer(self) -> MDocEngineServicer:
        return MDocEngineServicer()
    
    def get_add_servicer_function(self) -> Callable:
        return mdoc_engine_pb2_grpc.add_MDocEngineServicer_to_server

def serve_grpc() -> None:
    port = config_manager.get_env_int("GRPC_PORT", 8086)
    service = MDocGrpcService(service_name="mdoc-engine", default_port=port, max_workers=10)
    service.start_server()
```

**DRY Solution**:
```python
# src/mdoc_engine/src/main.py (15 lines)
from marty_common.grpc_service_factory import create_grpc_service_factory
from src.proto.mdoc_engine_pb2_grpc import add_MDocEngineServicer_to_server
from src.services.mdoc_engine import MDocEngineServicer

def main() -> None:
    factory = create_grpc_service_factory(
        service_name="mdoc-engine",
        config_type="grpc"
    )
    
    factory.register_service(
        name="mdoc_engine",
        servicer_factory=lambda **_: MDocEngineServicer(),
        registration_func=add_MDocEngineServicer_to_server,
    )
    
    factory.serve()

if __name__ == "__main__":
    main()
```

**Action Items**:
- [ ] Migrate `src/mdoc_engine/src/main.py` to use gRPC Service Factory
- [ ] Migrate `src/mdl_engine/src/main.py` to use gRPC Service Factory
- [ ] Update any remaining services in `src/services/` that have manual gRPC setup

### 2. Database Initialization Patterns - Medium Priority

**Issue**: Database setup code is duplicated across services.

**Current Duplication**:
```python
# Found in multiple main.py files
def create_db_and_tables() -> None:
    """Creates database tables."""
    logger.info("Creating database tables for {SERVICE_NAME}...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully.")
```

**DRY Solution**:
```python
# src/marty_common/database/setup.py
def create_service_database(service_name: str, base_metadata, engine) -> None:
    """Standard database setup for services."""
    logger = get_logger(f"{service_name}.database")
    logger.info(f"Creating database tables for {service_name}...")
    base_metadata.create_all(bind=engine)
    logger.info("Database tables created successfully.")

# In service main.py
from marty_common.database.setup import create_service_database
from src.shared.database import Base, engine

def main():
    create_service_database("mdoc-engine", Base.metadata, engine)
    # ... rest of service setup
```

### 3. Configuration File Consolidation - Medium Priority

**Issue**: Configuration files have repeated structure across environments.

**Current Duplication**:
```yaml
# config/development.yaml, config/production.yaml, config/testing.yaml
ports:
  csca_service: 8081
  document_signer: 8082
  passport_engine: 8084
  inspection_system: 8083
  trust_anchor: 8080

hosts:
  csca_service: localhost  # or service names in production
  document_signer: localhost
  # ... repeated structure
```

**DRY Solution**:
```yaml
# config/base.yaml
defaults: &defaults
  ports:
    csca_service: 8081
    document_signer: 8082
    passport_engine: 8084
    inspection_system: 8083
    trust_anchor: 8080
  
  service_config: &service_config
    document_signer:
      signing_algorithm: rsa2048
      signing_key_id: document-signer-default

# config/development.yaml
<<: *defaults
hosts:
  csca_service: localhost
  document_signer: localhost

# config/production.yaml  
<<: *defaults
hosts:
  csca_service: csca-service
  document_signer: document-signer
```

### 4. Docker Dockerfile Patterns - Low Priority

**Issue**: Some services still use old Docker patterns instead of the base image.

**Current Issue**:
```dockerfile
# docker/trust-anchor.Dockerfile (64 lines)
FROM python:3.10-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc cmake pkg-config libxml2-dev libxslt1-dev libxmlsec1-dev swig libpcsclite-dev \
    && rm -rf /var/lib/apt/lists/*
# ... duplicated setup
```

**DRY Solution**:
```dockerfile
# docker/trust-anchor.Dockerfile (15 lines)
FROM marty-base:latest

ENV SERVICE_NAME=trust-anchor
ENV GRPC_PORT=8080

COPY src/trust_anchor/ /app/src/trust_anchor/
COPY data/trust/ /app/data/trust/

RUN mkdir -p /data/trust_anchor

EXPOSE 8080
CMD ["python", "-m", "src.trust_anchor.app.main"]
```

### 5. Test Setup Patterns - Low Priority

**Issue**: Test configuration files have some duplication.

**Current State**:
```python
# Multiple conftest.py files with similar patterns
@pytest.fixture
def app() -> FastAPI:
    return service_app

@pytest.fixture  
def client(app: FastAPI) -> TestClient:
    return TestClient(app)
```

**DRY Solution**:
```python
# src/marty_common/testing/fastapi_fixtures.py
@pytest.fixture
def create_test_app():
    """Factory for creating FastAPI test apps."""
    def _create_app(app_module: str) -> FastAPI:
        module = importlib.import_module(app_module)
        return module.app
    return _create_app

# In service conftest.py
from marty_common.testing.fastapi_fixtures import create_test_app

@pytest.fixture
def app(create_test_app):
    return create_test_app("app.main")
```

## Implementation Priority

### Phase 1: High Impact, Low Risk
1. **Service Factory Migration** (2-3 hours)
   - Migrate remaining main.py files to use gRPC Service Factory
   - Update `mdoc_engine` and `mdl_engine` main files
   - Test each service migration individually

### Phase 2: Medium Impact, Medium Risk  
2. **Database Setup Consolidation** (1-2 hours)
   - Create shared database setup utility
   - Update services to use shared pattern
   
3. **Configuration Consolidation** (2-3 hours)
   - Implement YAML anchors and references
   - Test configuration inheritance across environments

### Phase 3: Low Impact, Low Risk
4. **Docker Standardization** (1-2 hours)
   - Migrate remaining Dockerfiles to use base image pattern
   - Update trust-anchor and other services

5. **Test Pattern Consolidation** (1-2 hours)
   - Expand shared testing utilities
   - Update service test configurations

## Metrics and Validation

### Expected Reductions:
- **Service main.py files**: 70-80 lines → 15-20 lines (75% reduction)
- **Database setup code**: 15 lines per service → 2 lines per service (87% reduction)  
- **Docker configurations**: 40-60 lines → 15-20 lines (70% reduction)
- **Configuration redundancy**: 50% reduction through YAML inheritance

### Validation Steps:
1. Run full test suite after each migration
2. Verify services start correctly with new patterns
3. Check Docker builds and container functionality
4. Validate configuration loading across environments

## Template for New Services

With these improvements, new services would follow this ultra-DRY pattern:

```python
# src/new_service/app/main.py (12 lines)
from marty_common.grpc_service_factory import create_grpc_service_factory
from marty_common.database.setup import create_service_database
from src.proto.new_service_pb2_grpc import add_NewServiceServicer_to_server
from src.new_service.app.services.new_service import NewService
from src.shared.database import Base, engine

def main() -> None:
    create_service_database("new-service", Base.metadata, engine)
    
    factory = create_grpc_service_factory(service_name="new-service")
    factory.register_service(
        name="new_service",
        servicer_factory=lambda **_: NewService(),
        registration_func=add_NewServiceServicer_to_server,
    )
    factory.serve()

if __name__ == "__main__":
    main()
```

## Conclusion

Your repository is already quite DRY with excellent foundational patterns. These recommendations will eliminate the remaining 20-30% of duplication and create even more consistent patterns across all services. The gRPC Service Factory pattern you've implemented is exemplary and should be the template for other similar projects.

**Estimated Time Investment**: 6-10 hours total
**Expected Code Reduction**: 25-30% reduction in remaining duplicated code
**Maintenance Benefit**: Significantly easier onboarding and service creation
