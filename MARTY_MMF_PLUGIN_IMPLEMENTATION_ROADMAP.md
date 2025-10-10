# Marty to MMF Plugin Migration: Detailed Implementation Roadmap

## Overview

This document provides detailed implementation steps for each migration phase, including specific tasks, timelines, acceptance criteria, and validation procedures for transforming Marty into an MMF plugin.

## Phase 1: Infrastructure Foundation (4 weeks)

### Week 1: MMF Infrastructure Assessment & Enhancement

#### Day 1-2: Configuration System Integration
**Tasks:**
- [ ] Audit existing MMF configuration sections for Marty compatibility
- [ ] Extend `CryptographicConfigSection` with missing Marty fields
- [ ] Enhance `TrustStoreConfigSection` for PKD integration patterns
- [ ] Add `ServiceDiscoveryConfigSection` Kubernetes service mesh support

**Implementation Steps:**
```python
# Extend MMF configuration in src/framework/config.py
@dataclass
class CryptographicConfigSection(BaseConfigSection):
    signing: SigningConfig = field(default_factory=SigningConfig)
    sd_jwt: SDJWTConfig = field(default_factory=SDJWTConfig)
    vault: VaultConfig = field(default_factory=VaultConfig)
    key_rotation: KeyRotationConfig = field(default_factory=KeyRotationConfig)  # New
    hsm_integration: HSMConfig = field(default_factory=HSMConfig)  # New
```

**Acceptance Criteria:**
- [ ] All Marty configuration patterns supported in MMF
- [ ] Backward compatibility maintained
- [ ] Configuration validation passes all tests

#### Day 3-5: Database Infrastructure Validation
**Tasks:**
- [ ] Verify MMF database per-service pattern works with Marty schemas
- [ ] Test connection pooling and transaction management
- [ ] Validate Alembic migration integration
- [ ] Ensure proper database isolation between services

**Implementation Steps:**
```python
# Test database integration
async def test_marty_database_integration():
    config = ServiceConfig(service_name="document_signer")
    db_manager = DatabaseManager(config)
    
    # Verify service-specific database creation
    db = await db_manager.get_service_database("document_signer")
    assert db.database_name == "marty_document_signer"
```

**Acceptance Criteria:**
- [ ] All Marty services can connect to service-specific databases
- [ ] Database migrations work with MMF patterns
- [ ] Connection pooling performs within acceptable limits

### Week 2: Plugin System Foundation

#### Day 1-3: Plugin Interface Design & Implementation
**Tasks:**
- [ ] Design `MMFPlugin` base class and `PluginContext`
- [ ] Implement plugin discovery and lifecycle management
- [ ] Create plugin configuration schema validation
- [ ] Build plugin dependency resolution

**Implementation Steps:**
```python
# Create src/framework/plugins/__init__.py
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

class PluginMetadata:
    def __init__(self, name: str, version: str, description: str, 
                 dependencies: List[str] = None):
        self.name = name
        self.version = version
        self.description = description
        self.dependencies = dependencies or []

class PluginContext:
    def __init__(self, config: ServiceConfig, services: Dict[str, Any]):
        self.config = config
        self.database = services.get('database')
        self.event_bus = services.get('event_bus')
        self.security = services.get('security')
        self.observability = services.get('observability')

class MMFPlugin(ABC):
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        pass
    
    @abstractmethod
    async def initialize(self, context: PluginContext) -> None:
        pass
    
    @abstractmethod
    def get_service_definitions(self) -> List[ServiceDefinition]:
        pass

class PluginManager:
    def __init__(self):
        self.plugins: Dict[str, MMFPlugin] = {}
        self.plugin_contexts: Dict[str, PluginContext] = {}
    
    async def load_plugin(self, plugin_class: type[MMFPlugin], 
                         context: PluginContext) -> None:
        plugin = plugin_class()
        await plugin.initialize(context)
        self.plugins[plugin.metadata.name] = plugin
        self.plugin_contexts[plugin.metadata.name] = context
```

**Acceptance Criteria:**
- [ ] Plugin interface supports all required operations
- [ ] Plugin discovery mechanism works
- [ ] Plugin lifecycle (load, initialize, unload) functions correctly

#### Day 4-5: Service Definition Framework
**Tasks:**
- [ ] Design `ServiceDefinition` class for plugin services
- [ ] Implement service routing and middleware integration
- [ ] Create service dependency injection framework
- [ ] Build service health checking system

**Implementation Steps:**
```python
# Create src/framework/plugins/services.py
@dataclass
class ServiceDefinition:
    name: str
    handler_class: type
    routes: List[Route]
    middleware: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    health_check_path: str = "/health"
    metrics_enabled: bool = True
    database_required: bool = True

class ServiceRegistry:
    def __init__(self, plugin_manager: PluginManager):
        self.plugin_manager = plugin_manager
        self.services: Dict[str, ServiceDefinition] = {}
    
    async def register_plugin_services(self, plugin_name: str) -> None:
        plugin = self.plugin_manager.plugins[plugin_name]
        for service_def in plugin.get_service_definitions():
            await self._register_service(service_def)
    
    async def _register_service(self, service_def: ServiceDefinition) -> None:
        # Validate dependencies
        for dep in service_def.dependencies:
            if dep not in self.services:
                raise PluginError(f"Service dependency not found: {dep}")
        
        self.services[service_def.name] = service_def
```

**Acceptance Criteria:**
- [ ] Services can be defined and registered through plugins
- [ ] Service dependencies are resolved correctly
- [ ] Health checks and metrics integration work

### Week 3: Security & Middleware Integration

#### Day 1-3: Security Framework Integration
**Tasks:**
- [ ] Verify MMF security middleware meets Marty requirements
- [ ] Test JWT authentication with Marty's token format
- [ ] Validate rate limiting configuration for high-throughput services
- [ ] Ensure RBAC policies work with Marty's user roles

**Implementation Steps:**
```python
# Test security integration
async def test_marty_security_integration():
    # Test JWT authentication
    config = SecurityConfig(
        jwt_secret_key="marty-secret",
        jwt_algorithm="ES256",
        excluded_paths=["/health", "/metrics"]
    )
    
    auth_middleware = AuthenticationMiddleware(config)
    
    # Test with Marty JWT token
    token = generate_marty_jwt_token()
    result = await auth_middleware.authenticate(token)
    assert result.authenticated is True
```

**Acceptance Criteria:**
- [ ] All Marty authentication patterns work with MMF security
- [ ] Rate limiting handles Marty's traffic patterns
- [ ] Security headers and policies are properly applied

#### Day 4-5: Observability Integration
**Tasks:**
- [ ] Validate metrics collection for Marty services
- [ ] Test distributed tracing across service boundaries
- [ ] Ensure log aggregation captures Marty-specific events
- [ ] Verify alerting rules work with Marty operational patterns

**Implementation Steps:**
```python
# Test observability integration
async def test_marty_observability():
    observability = ObservabilityManager(config)
    
    # Test metrics collection
    metrics = observability.get_metrics_collector()
    metrics.increment_counter("marty.document.signed")
    
    # Test tracing
    with observability.tracer.start_span("document-signing") as span:
        span.set_attribute("document.type", "passport")
        # ... signing logic
    
    # Test logging
    logger = observability.get_logger("document-signer")
    logger.info("Document signed successfully", extra={
        "document_id": "123",
        "signing_algorithm": "ES256"
    })
```

**Acceptance Criteria:**
- [ ] All Marty metrics are collected and exposed
- [ ] Distributed tracing works across all services
- [ ] Logs are properly structured and searchable

### Week 4: Initial Plugin Implementation

#### Day 1-3: Marty Plugin Skeleton
**Tasks:**
- [ ] Create basic Marty plugin structure
- [ ] Implement `MartyTrustPKIPlugin` class
- [ ] Define all Marty service definitions
- [ ] Create plugin configuration schema

**Implementation Steps:**
```python
# Create marty_plugin/plugin.py
from mmf.plugins import MMFPlugin, PluginMetadata, PluginContext
from .services import (
    DocumentSignerService, TrustAnchorService, 
    PKDService, ConsistencyEngineService
)

class MartyTrustPKIPlugin(MMFPlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="marty-trust-pki",
            version="2.0.0",
            description="Trust and PKI services for identity document verification",
            dependencies=["database", "security", "observability"]
        )
    
    async def initialize(self, context: PluginContext) -> None:
        self.context = context
        
        # Initialize Marty-specific components
        await self._init_trust_store()
        await self._init_pkd_client()
        await self._init_crypto_services()
    
    def get_service_definitions(self) -> List[ServiceDefinition]:
        return [
            ServiceDefinition(
                name="document-signer",
                handler_class=DocumentSignerService,
                routes=[
                    Route("/api/v1/sign", methods=["POST"]),
                    Route("/api/v1/verify", methods=["POST"])
                ],
                middleware=["authentication", "rate-limiting"],
                dependencies=["trust-anchor", "crypto-service"]
            ),
            ServiceDefinition(
                name="trust-anchor",
                handler_class=TrustAnchorService,
                routes=[
                    Route("/api/v1/trust/verify", methods=["POST"]),
                    Route("/api/v1/trust/entities", methods=["GET"])
                ],
                dependencies=["database"]
            ),
            # ... other services
        ]
```

**Acceptance Criteria:**
- [ ] Plugin loads successfully in MMF
- [ ] All service definitions are valid
- [ ] Plugin initialization completes without errors

#### Day 4-5: Integration Testing
**Tasks:**
- [ ] Test plugin loading and initialization
- [ ] Verify service registration works
- [ ] Test basic service functionality
- [ ] Validate configuration integration

**Implementation Steps:**
```python
# Create integration tests
async def test_marty_plugin_integration():
    # Load plugin
    context = PluginContext(config, services)
    plugin = MartyTrustPKIPlugin()
    await plugin.initialize(context)
    
    # Test service registration
    service_registry = ServiceRegistry(plugin_manager)
    await service_registry.register_plugin_services("marty-trust-pki")
    
    # Verify services are available
    assert "document-signer" in service_registry.services
    assert "trust-anchor" in service_registry.services
```

**Acceptance Criteria:**
- [ ] Plugin integration tests pass
- [ ] Services respond to health checks
- [ ] Basic API endpoints are functional

## Phase 2: Service Migration (6 weeks)

### Week 1-2: Core Services Migration

#### Trust Anchor Service Migration
**Tasks:**
- [ ] Refactor `TrustAnchor` class to use MMF patterns
- [ ] Migrate database models to use MMF repository pattern
- [ ] Update gRPC/REST endpoints to use MMF routing
- [ ] Integrate with MMF security and observability

**Implementation Steps:**
```python
# Migrate src/services/trust_anchor.py
class TrustAnchorService:
    def __init__(self, context: PluginContext):
        self.context = context
        self.config = context.config.trust_store
        self.db = context.database.get_service_database("trust-anchor")
        self.logger = context.observability.get_logger("trust-anchor")
        self.metrics = context.observability.get_metrics_collector()
    
    async def verify_trust(self, request: TrustVerificationRequest) -> TrustVerificationResponse:
        with self.context.observability.tracer.start_span("trust-verification") as span:
            span.set_attribute("entity", request.entity_id)
            
            # Use MMF repository pattern
            repo = await self.db.get_repository(TrustEntityRepository)
            trust_entity = await repo.find_by_id(request.entity_id)
            
            # Record metrics
            self.metrics.increment_counter("trust_verifications_total")
            
            return TrustVerificationResponse(
                trusted=trust_entity.is_trusted if trust_entity else False
            )
```

**Acceptance Criteria:**
- [ ] Trust Anchor service uses MMF infrastructure exclusively
- [ ] All existing functionality preserved
- [ ] Performance within 5% of original implementation

#### Document Signer Service Migration
**Tasks:**
- [ ] Migrate cryptographic operations to use MMF configuration
- [ ] Update certificate management to use MMF security patterns
- [ ] Integrate with MMF event bus for audit logging
- [ ] Refactor API endpoints to use MMF routing

**Implementation Steps:**
```python
# Migrate src/services/document_signer.py
class DocumentSignerService:
    def __init__(self, context: PluginContext):
        self.context = context
        self.crypto_config = context.config.cryptographic
        self.vault_client = context.security.get_vault_client()
        self.event_bus = context.event_bus
    
    async def sign_document(self, request: SigningRequest) -> SigningResponse:
        # Get signing key from MMF vault
        signing_key = await self.vault_client.get_signing_key(
            self.crypto_config.signing.key_id
        )
        
        # Perform signing
        signature = await self._create_signature(request.document, signing_key)
        
        # Publish audit event
        await self.event_bus.publish(DocumentSignedEvent(
            document_id=request.document_id,
            algorithm=self.crypto_config.signing.algorithm,
            timestamp=datetime.utcnow()
        ))
        
        return SigningResponse(signature=signature)
```

**Acceptance Criteria:**
- [ ] Document signing uses MMF security infrastructure
- [ ] Audit events are properly published to event bus
- [ ] Cryptographic operations maintain security standards

### Week 3-4: Supporting Services Migration

#### PKD Service Migration
**Tasks:**
- [ ] Migrate PKD client to use MMF HTTP client patterns
- [ ] Update certificate storage to use MMF database patterns
- [ ] Integrate with MMF caching middleware
- [ ] Add MMF resilience patterns (circuit breaker, retry)

**Implementation Steps:**
```python
# Migrate src/services/pkd_service.py
class PKDService:
    def __init__(self, context: PluginContext):
        self.context = context
        self.pkd_config = context.config.trust_store.pkd
        self.http_client = context.http_client
        self.cache = context.cache_manager
        self.circuit_breaker = context.resilience.get_circuit_breaker("pkd")
    
    async def fetch_certificates(self, country_code: str) -> List[Certificate]:
        cache_key = f"pkd:certificates:{country_code}"
        
        # Try cache first
        cached = await self.cache.get(cache_key)
        if cached:
            return cached
        
        # Fetch from PKD with circuit breaker
        async with self.circuit_breaker:
            response = await self.http_client.get(
                f"{self.pkd_config.service_url}/certificates/{country_code}"
            )
            certificates = self._parse_certificates(response.content)
        
        # Cache results
        await self.cache.set(cache_key, certificates, ttl=3600)
        return certificates
```

**Acceptance Criteria:**
- [ ] PKD service uses MMF HTTP client and caching
- [ ] Circuit breaker prevents cascade failures
- [ ] Certificate caching improves performance

#### Consistency Engine Migration
**Tasks:**
- [ ] Migrate event processing to use MMF event bus
- [ ] Update state management to use MMF database patterns
- [ ] Integrate with MMF workflow engine
- [ ] Add MMF monitoring and alerting

**Implementation Steps:**
```python
# Migrate src/services/consistency_engine.py
class ConsistencyEngineService:
    def __init__(self, context: PluginContext):
        self.context = context
        self.event_bus = context.event_bus
        self.workflow_engine = context.workflow_engine
    
    async def initialize(self):
        # Subscribe to relevant events
        await self.event_bus.subscribe(
            "document.signed", 
            self.handle_document_signed
        )
        await self.event_bus.subscribe(
            "trust.updated", 
            self.handle_trust_updated
        )
    
    async def handle_document_signed(self, event: DocumentSignedEvent):
        # Process event using MMF workflow engine
        workflow = await self.workflow_engine.create_workflow(
            "consistency-check",
            input_data={"document_id": event.document_id}
        )
        await workflow.execute()
```

**Acceptance Criteria:**
- [ ] Event processing uses MMF event bus exclusively
- [ ] Workflow orchestration integrates with MMF patterns
- [ ] Consistency checks maintain data integrity

### Week 5-6: Integration & Testing

#### End-to-End Testing
**Tasks:**
- [ ] Create comprehensive test suite for migrated services
- [ ] Test service interactions through MMF infrastructure
- [ ] Validate performance under load
- [ ] Test failure scenarios and recovery

**Implementation Steps:**
```python
# Create comprehensive E2E tests
class TestMartyPluginE2E:
    async def test_document_signing_flow(self):
        # Test complete document signing flow
        signing_request = SigningRequest(
            document_id="test-passport-123",
            document_type="passport",
            document_data=passport_data
        )
        
        # Sign document
        response = await document_signer.sign_document(signing_request)
        assert response.signature is not None
        
        # Verify trust
        trust_request = TrustVerificationRequest(
            entity_id=response.signer_id
        )
        trust_response = await trust_anchor.verify_trust(trust_request)
        assert trust_response.trusted is True
        
        # Check consistency
        await asyncio.sleep(1)  # Allow event processing
        consistency_status = await consistency_engine.get_status(
            signing_request.document_id
        )
        assert consistency_status.consistent is True
```

**Acceptance Criteria:**
- [ ] All E2E tests pass
- [ ] Performance is within acceptable limits
- [ ] Failure recovery works correctly

## Phase 3: Infrastructure Consolidation (4 weeks)

### Week 1-2: Deployment Migration

#### Kustomize Migration
**Tasks:**
- [ ] Convert Helm charts to Kustomize using MMF converter
- [ ] Create environment-specific overlays
- [ ] Validate manifest generation
- [ ] Test deployment to staging environment

**Implementation Steps:**
```bash
# Use MMF Helm to Kustomize converter
marty migrate helm-to-kustomize \
  --helm-chart-path ./helm/charts/document-signer \
  --output-path ./k8s/document-signer \
  --service-name document-signer \
  --values-file ./helm/values-dev.yaml \
  --values-file ./helm/values-prod.yaml \
  --validate

# Review generated Kustomize structure
tree k8s/document-signer/
k8s/document-signer/
├── base/
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── configmap.yaml
│   └── kustomization.yaml
└── overlays/
    ├── development/
    ├── staging/
    └── production/
```

**Acceptance Criteria:**
- [ ] All Helm charts successfully converted to Kustomize
- [ ] Generated manifests are valid and deploy successfully
- [ ] Environment-specific customizations work correctly

#### CI/CD Migration
**Tasks:**
- [ ] Update GitHub Actions to use MMF reusable workflows
- [ ] Migrate build processes to use MMF patterns
- [ ] Update deployment scripts to use Kustomize
- [ ] Integrate with MMF quality gates

**Implementation Steps:**
```yaml
# Update .github/workflows/deploy.yml
name: Deploy Marty Plugin
on:
  push:
    branches: [main]

jobs:
  deploy:
    uses: marty-microservices-framework/.github/workflows/deploy-plugin.yml@main
    with:
      plugin-name: marty-trust-pki
      environment: ${{ github.ref == 'refs/heads/main' && 'production' || 'staging' }}
      kustomize-path: k8s/overlays
    secrets:
      DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

**Acceptance Criteria:**
- [ ] CI/CD uses MMF reusable workflows exclusively
- [ ] Deployment process is fully automated
- [ ] Quality gates prevent bad deployments

### Week 3-4: Final Cleanup

#### Infrastructure Code Removal
**Tasks:**
- [ ] Remove duplicate configuration management code
- [ ] Delete custom middleware implementations
- [ ] Remove Helm charts and deployment scripts
- [ ] Clean up database connection management

**Implementation Steps:**
```bash
# Remove infrastructure directories
rm -rf marty/monitoring/
rm -rf marty/terraform/
rm -rf marty/helm/
rm -rf marty/docker/
rm -rf marty/k8s/

# Remove duplicate code
rm marty/src/marty_common/middleware/
rm marty/src/marty_common/config/
rm marty/src/marty_common/infrastructure/

# Update imports to use MMF
find marty/src -name "*.py" -exec sed -i 's/from marty_common.config/from mmf.config/g' {} \;
find marty/src -name "*.py" -exec sed -i 's/from marty_common.middleware/from mmf.middleware/g' {} \;
```

**Acceptance Criteria:**
- [ ] No duplicate infrastructure code remains in Marty
- [ ] All imports use MMF modules
- [ ] Repository structure matches plugin-only design

#### Documentation Update
**Tasks:**
- [ ] Update README with plugin architecture
- [ ] Create migration documentation
- [ ] Update API documentation
- [ ] Create operational runbooks

**Implementation Steps:**
```markdown
# Update marty/README.md
# Marty Trust & PKI Plugin

Marty is now a specialized plugin for the Marty Microservices Framework (MMF) 
that provides trust and PKI services for identity document verification.

## Quick Start

1. Install MMF:
   ```bash
   pip install marty-microservices-framework
   ```

2. Install Marty plugin:
   ```bash
   pip install marty-trust-pki-plugin
   ```

3. Configure and run:
   ```python
   from mmf import create_application
   from marty_plugin import MartyTrustPKIPlugin
   
   app = create_application()
   app.load_plugin(MartyTrustPKIPlugin)
   app.run()
   ```
```

**Acceptance Criteria:**
- [ ] Documentation accurately reflects plugin architecture
- [ ] Migration guide helps other projects
- [ ] Operational procedures are updated

## Phase 4: Production Deployment (2 weeks)

### Week 1: Staging Deployment

#### Blue-Green Deployment Setup
**Tasks:**
- [ ] Deploy plugin version to staging environment
- [ ] Configure traffic splitting between old and new versions
- [ ] Set up monitoring and alerting for both versions
- [ ] Create rollback procedures

**Implementation Steps:**
```yaml
# Configure blue-green deployment
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: marty-trust-pki
spec:
  replicas: 3
  strategy:
    blueGreen:
      autoPromotionEnabled: false
      prePromotionAnalysis:
        templates:
        - templateName: success-rate
        args:
        - name: service-name
          value: marty-trust-pki
      scaleDownDelaySeconds: 30
  selector:
    matchLabels:
      app: marty-trust-pki
  template:
    metadata:
      labels:
        app: marty-trust-pki
    spec:
      containers:
      - name: marty-plugin
        image: marty/trust-pki-plugin:v2.0.0
```

**Acceptance Criteria:**
- [ ] Blue-green deployment configured and tested
- [ ] Traffic can be split between versions
- [ ] Rollback procedures validated

#### Performance & Load Testing
**Tasks:**
- [ ] Run load tests against plugin version
- [ ] Compare performance with original implementation
- [ ] Test scaling behavior under load
- [ ] Validate resource usage and efficiency

**Implementation Steps:**
```python
# Load testing script
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor

async def load_test_document_signing():
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i in range(1000):
            task = sign_document(session, f"doc-{i}")
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        # Analyze results
        success_rate = sum(1 for r in results if r.status == 200) / len(results)
        avg_response_time = sum(r.response_time for r in results) / len(results)
        
        assert success_rate > 0.99
        assert avg_response_time < 500  # milliseconds
```

**Acceptance Criteria:**
- [ ] Performance meets or exceeds original implementation
- [ ] System handles expected load without degradation
- [ ] Resource usage is optimal

### Week 2: Production Cutover

#### Traffic Migration
**Tasks:**
- [ ] Gradually shift traffic from old to new implementation
- [ ] Monitor system health and performance metrics
- [ ] Validate all functionality works correctly
- [ ] Complete traffic cutover

**Implementation Steps:**
```bash
# Gradual traffic shift
kubectl argo rollouts set weight marty-trust-pki 10  # 10% traffic
# Monitor for 30 minutes
kubectl argo rollouts set weight marty-trust-pki 50  # 50% traffic  
# Monitor for 30 minutes
kubectl argo rollouts promote marty-trust-pki         # 100% traffic
```

**Acceptance Criteria:**
- [ ] Traffic migration completed without incidents
- [ ] All services functioning normally
- [ ] No data loss or corruption

#### Legacy System Cleanup
**Tasks:**
- [ ] Remove old Marty deployment infrastructure
- [ ] Clean up unused resources and configurations
- [ ] Archive old deployment artifacts
- [ ] Update DNS and service discovery

**Implementation Steps:**
```bash
# Remove old deployments
kubectl delete deployment marty-document-signer-legacy
kubectl delete deployment marty-trust-anchor-legacy
kubectl delete deployment marty-pkd-service-legacy

# Clean up old ConfigMaps and Secrets
kubectl delete configmap marty-legacy-config
kubectl delete secret marty-legacy-secrets

# Update Istio/Linkerd configurations
kubectl apply -f k8s/service-mesh/new-routing-rules.yaml
```

**Acceptance Criteria:**
- [ ] All legacy infrastructure removed
- [ ] No unused resources consuming costs
- [ ] Service discovery points to new implementation

## Validation & Testing Strategy

### Automated Testing
```python
# Comprehensive test suite structure
tests/
├── unit/
│   ├── test_plugin_initialization.py
│   ├── test_service_registration.py
│   └── test_configuration_validation.py
├── integration/
│   ├── test_database_integration.py
│   ├── test_security_integration.py
│   └── test_observability_integration.py
├── e2e/
│   ├── test_document_signing_flow.py
│   ├── test_trust_verification_flow.py
│   └── test_service_interactions.py
└── performance/
    ├── test_load_handling.py
    ├── test_scaling_behavior.py
    └── test_resource_usage.py
```

### Manual Testing Checklist
- [ ] All API endpoints respond correctly
- [ ] Authentication and authorization work as expected
- [ ] Database operations complete successfully
- [ ] Event bus messaging functions properly
- [ ] Monitoring and logging capture expected data
- [ ] Service mesh routing works correctly
- [ ] Health checks and readiness probes function
- [ ] Configuration changes apply without restart

### Rollback Procedures
```bash
# Emergency rollback procedure
kubectl argo rollouts abort marty-trust-pki
kubectl argo rollouts undo marty-trust-pki
kubectl scale deployment marty-legacy --replicas=3
```

## Success Metrics & KPIs

### Technical Metrics
- **Code Reduction**: 80%+ reduction in infrastructure code
- **Performance**: <5% degradation in response times
- **Reliability**: 99.9%+ uptime during migration
- **Security**: No security vulnerabilities introduced

### Operational Metrics  
- **Deployment Time**: 50%+ reduction in deployment time
- **Configuration Changes**: 70%+ reduction in config complexity
- **Incident Response**: 40%+ faster incident resolution
- **Onboarding Time**: 60%+ faster new developer onboarding

### Business Metrics
- **Feature Velocity**: 30%+ increase in feature delivery speed
- **Maintenance Cost**: 50%+ reduction in operational overhead
- **Team Productivity**: 25%+ increase in developer productivity
- **Innovation Time**: 40%+ more time spent on business logic vs infrastructure

This roadmap ensures a systematic, low-risk migration of Marty to an MMF plugin while maintaining all functionality and improving operational efficiency.