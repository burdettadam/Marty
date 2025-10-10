# Marty as MMF Plugin Strategy: Complete Migration Plan

## Executive Summary

This document outlines a comprehensive strategy to transform Marty from an independent microservices platform into a **specialized plugin of the Marty Microservices Framework (MMF)**. The goal is to achieve complete separation of concerns where:

- **MMF**: Handles all cross-cutting infrastructure, middleware, and framework capabilities
- **Marty**: Contains only domain-specific trust & PKI business logic as an MMF plugin

## Current State Analysis

### Marty's Current Infrastructure (To Be Migrated to MMF)

**Services Architecture** (`/src/services/`):
- 20+ microservices including Document Signer, PKD Service, Trust Anchor, Consistency Engine
- Each service has its own database, models, and gRPC/REST APIs
- Custom middleware stack for auth, logging, metrics, rate limiting

**Infrastructure Components** (To become MMF standard patterns):
- **Deployment**: Helm charts with 9 template files per service, complex Kubernetes manifests
- **Databases**: Per-service PostgreSQL databases with custom connection management
- **Configuration**: Custom YAML-based config system with environment overrides
- **Monitoring**: Prometheus/Grafana setup with ServiceMonitor configurations
- **Security**: Custom authentication, authorization, and rate limiting implementations
- **Terraform Modules**: AWS, Azure, GCP infrastructure provisioning

**Framework Capabilities Already in MMF**:
- ✅ Authentication & Authorization middleware
- ✅ Configuration system with Marty-specific sections (CryptographicConfig, TrustStoreConfig)
- ✅ Database management with per-service support
- ✅ Messaging middleware with validation, transformation, authentication
- ✅ Deployment automation (Kubernetes, Helm, Kustomize)
- ✅ Observability framework with metrics, logging, tracing
- ✅ Security framework with JWT auth, rate limiting, security headers
- ✅ Service mesh integration patterns

## Plugin Architecture Strategy

### Core Principle: MMF as Infrastructure, Marty as Domain Plugin

```
┌─────────────────────────────────────────────────────────────┐
│                 Marty Microservices Framework               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                Infrastructure Layer                 │    │
│  │ • Auth/Security • Config • Database • Messaging   │    │
│  │ • Deployment • Observability • Service Mesh       │    │
│  └─────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                  Plugin System                     │    │
│  │        ┌─────────────────────────────────┐         │    │
│  │        │        Marty Trust & PKI        │         │    │
│  │        │           Plugin               │         │    │
│  │        │                                │         │    │
│  │        │ • Trust Store Management       │         │    │
│  │        │ • PKD Integration              │         │    │
│  │        │ • Document Signing Services    │         │    │
│  │        │ • Certificate Lifecycle        │         │    │
│  │        │ • Passport/Visa Processing     │         │    │
│  │        └─────────────────────────────────┘         │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Plugin System Design

#### 1. MMF Plugin Interface

```python
# In MMF framework
from abc import ABC, abstractmethod
from typing import Dict, Any, List

class MMFPlugin(ABC):
    """Base class for all MMF plugins."""
    
    @property
    @abstractmethod
    def plugin_name(self) -> str:
        """Unique plugin identifier."""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version."""
        pass
    
    @abstractmethod
    async def initialize(self, context: PluginContext) -> None:
        """Initialize plugin with MMF context."""
        pass
    
    @abstractmethod
    def get_services(self) -> List[ServiceDefinition]:
        """Return list of services this plugin provides."""
        pass
    
    @abstractmethod
    def get_configuration_schema(self) -> Dict[str, Any]:
        """Return configuration schema for this plugin."""
        pass

class PluginContext:
    """Context provided by MMF to plugins."""
    
    def __init__(self, 
                 config: ServiceConfig,
                 database_manager: DatabaseManager,
                 event_bus: EventBus,
                 security_manager: SecurityManager,
                 observability: ObservabilityManager):
        self.config = config
        self.database = database_manager
        self.event_bus = event_bus
        self.security = security_manager
        self.observability = observability
```

#### 2. Marty as Trust & PKI Plugin

```python
# In Marty plugin
from mmf.plugins import MMFPlugin, PluginContext
from mmf.services import ServiceDefinition

class MartyTrustPKIPlugin(MMFPlugin):
    """Marty Trust & PKI domain plugin for MMF."""
    
    @property
    def plugin_name(self) -> str:
        return "marty-trust-pki"
    
    @property
    def version(self) -> str:
        return "2.0.0"
    
    async def initialize(self, context: PluginContext) -> None:
        """Initialize Marty plugin with MMF infrastructure."""
        self.context = context
        
        # Use MMF's infrastructure
        self.config = context.config
        self.database = context.database
        self.event_bus = context.event_bus
        self.security = context.security
        self.observability = context.observability
        
        # Initialize Marty-specific components
        await self._initialize_trust_store()
        await self._initialize_pkd_client()
        await self._initialize_crypto_services()
    
    def get_services(self) -> List[ServiceDefinition]:
        """Define Marty's domain services."""
        return [
            ServiceDefinition(
                name="document-signer",
                handler=DocumentSignerService,
                routes=["/api/v1/sign", "/api/v1/verify"],
                dependencies=["trust-anchor", "crypto-service"]
            ),
            ServiceDefinition(
                name="trust-anchor",
                handler=TrustAnchorService,
                routes=["/api/v1/trust", "/api/v1/verify-trust"],
                dependencies=["database"]
            ),
            ServiceDefinition(
                name="pkd-service",
                handler=PKDService,
                routes=["/api/v1/pkd", "/api/v1/certificates"],
                dependencies=["database", "trust-anchor"]
            ),
            # ... other Marty services
        ]
    
    def get_configuration_schema(self) -> Dict[str, Any]:
        """Return Marty's configuration requirements."""
        return {
            "cryptographic": {
                "signing": {...},
                "sd_jwt": {...},
                "vault": {...}
            },
            "trust_store": {
                "pkd": {...},
                "trust_anchor": {...}
            },
            "service_discovery": {...}
        }
```

## Migration Phases

### Phase 1: Infrastructure Foundation (4 weeks)

**Goal**: Establish MMF as the infrastructure foundation while maintaining Marty functionality.

#### Week 1-2: MMF Infrastructure Enhancement
- **Extend MMF Configuration**: Enhance existing Marty-specific config sections
- **Database per Service**: Ensure MMF supports Marty's database patterns
- **Security Integration**: Verify MMF security middleware meets Marty's requirements

#### Week 3-4: Plugin System Implementation
- **Create Plugin Interface**: Implement `MMFPlugin` base class and `PluginContext`
- **Plugin Discovery**: Add plugin loading and lifecycle management to MMF
- **Initial Marty Plugin**: Create basic Marty plugin structure

**Success Criteria**:
- [ ] MMF can load and initialize plugins
- [ ] Marty configuration seamlessly integrates with MMF
- [ ] All MMF infrastructure components work with Marty services

### Phase 2: Service Migration (6 weeks)

**Goal**: Migrate Marty services to use MMF infrastructure while maintaining all functionality.

#### Week 1-2: Core Services Migration
- **Trust Anchor Service**: Migrate to use MMF database, security, observability
- **Document Signer**: Refactor to use MMF configuration and middleware
- **PKD Service**: Convert to MMF service pattern

#### Week 3-4: Supporting Services Migration
- **Consistency Engine**: Migrate to MMF event bus and messaging
- **Certificate Lifecycle**: Use MMF's resilience and monitoring patterns
- **Passport/Visa Services**: Integrate with MMF service mesh

#### Week 5-6: Integration & Testing
- **End-to-End Testing**: Verify all services work through MMF
- **Performance Validation**: Ensure no regression in performance
- **Security Audit**: Validate security posture is maintained

**Success Criteria**:
- [ ] All Marty services run as MMF plugin services
- [ ] Functional parity with existing Marty deployment
- [ ] All tests pass with new architecture

### Phase 3: Infrastructure Consolidation (4 weeks)

**Goal**: Remove all infrastructure duplication from Marty, making it purely a domain plugin.

#### Week 1-2: Deployment Migration
- **Kustomize Transition**: Migrate from Helm to MMF's Kustomize patterns
- **CI/CD Integration**: Use MMF's reusable workflows
- **Infrastructure as Code**: Migrate Terraform to MMF modules

#### Week 3-4: Final Cleanup
- **Remove Duplicated Code**: Delete all infrastructure code from Marty
- **Documentation Update**: Update all documentation for new architecture
- **Migration Validation**: Final validation of clean separation

**Success Criteria**:
- [ ] Marty repository contains only domain logic
- [ ] All infrastructure managed by MMF
- [ ] Deployment process uses MMF patterns exclusively

### Phase 4: Production Deployment (2 weeks)

**Goal**: Deploy Marty as MMF plugin to production with zero downtime.

#### Week 1: Staging Deployment
- **Blue-Green Deployment**: Deploy plugin version alongside existing
- **Traffic Switching**: Gradually move traffic to plugin version
- **Monitoring & Validation**: Ensure system health and functionality

#### Week 2: Production Cutover
- **Final Traffic Switch**: Complete migration to plugin architecture
- **Legacy Cleanup**: Remove old Marty deployment infrastructure
- **Documentation & Training**: Finalize operational documentation

**Success Criteria**:
- [ ] Production runs Marty as MMF plugin
- [ ] Zero downtime migration achieved
- [ ] All monitoring and alerting functional

## Repository Structure After Migration

### Marty Repository (Domain Plugin Only)
```
marty/
├── pyproject.toml                 # Plugin dependencies only
├── README.md                      # Plugin documentation
├── src/
│   └── marty_plugin/
│       ├── __init__.py           # Plugin entry point
│       ├── plugin.py             # MartyTrustPKIPlugin implementation
│       ├── services/             # Domain services only
│       │   ├── trust_anchor.py
│       │   ├── document_signer.py
│       │   ├── pkd_service.py
│       │   └── crypto_services.py
│       ├── models/               # Domain models
│       ├── schemas/              # Business logic schemas
│       └── utils/                # Domain-specific utilities
├── config/
│   └── plugin-config.yaml        # Plugin-specific configuration
├── tests/                        # Plugin tests
└── docs/                         # Plugin documentation
```

### MMF Repository (Infrastructure Only)
```
marty-microservices-framework/
├── src/framework/
│   ├── plugins/                  # Plugin system
│   ├── config/                   # Configuration management
│   ├── database/                 # Database infrastructure
│   ├── security/                 # Security middleware
│   ├── messaging/                # Event bus & messaging
│   ├── deployment/               # Deployment automation
│   ├── observability/            # Monitoring & logging
│   └── service_mesh/             # Service mesh integration
├── k8s/                          # Kustomize base manifests
├── terraform/                    # Infrastructure modules
├── .github/workflows/            # Reusable CI/CD workflows
└── docs/                         # Framework documentation
```

## Technical Implementation Details

### Configuration Integration

```yaml
# MMF configuration with Marty plugin
service:
  name: "marty-platform"
  environment: "production"
  plugins:
    - name: "marty-trust-pki"
      version: "2.0.0"
      config:
        cryptographic:
          signing:
            algorithm: "ES256"
            key_id: "marty-signing-key"
          vault:
            url: "https://vault.marty.internal"
        trust_store:
          pkd:
            service_url: "https://pkd.icao.int"
          trust_anchor:
            certificate_store_path: "/data/trust-store"
```

### Service Discovery Integration

```python
# Services registered by Marty plugin
class MartyTrustPKIPlugin(MMFPlugin):
    def get_services(self) -> List[ServiceDefinition]:
        return [
            ServiceDefinition(
                name="document-signer",
                port=8080,
                health_check="/health",
                routes=[
                    Route("/api/v1/sign", methods=["POST"]),
                    Route("/api/v1/verify", methods=["POST"])
                ],
                middleware=[
                    "authentication",
                    "rate-limiting", 
                    "request-logging"
                ],
                dependencies=["trust-anchor"]
            )
        ]
```

### Database Integration

```python
# Plugin uses MMF's database infrastructure
class TrustAnchorService:
    def __init__(self, context: PluginContext):
        # Get service-specific database from MMF
        self.db = context.database.get_service_database("trust-anchor")
        
    async def verify_trust(self, entity: str) -> bool:
        # Use MMF's repository pattern
        repo = self.db.get_repository(TrustEntityRepository)
        return await repo.is_trusted(entity)
```

## Migration Benefits

### For Marty
- **Reduced Complexity**: 80% reduction in infrastructure code
- **Faster Development**: Focus on trust & PKI domain logic
- **Better Reliability**: Leverage battle-tested MMF infrastructure
- **Easier Maintenance**: No infrastructure maintenance overhead

### For MMF
- **Production Validation**: Real-world enterprise usage
- **Feature Completeness**: Drive development of missing capabilities
- **Plugin Ecosystem**: Establish plugin pattern for other domains
- **Reference Implementation**: Demonstrate MMF capabilities

### For the Ecosystem
- **Reusable Infrastructure**: Other projects can leverage MMF
- **Standardization**: Common patterns across microservices
- **Reduced Duplication**: Single source of truth for infrastructure
- **Faster Innovation**: Teams focus on domain logic, not infrastructure

## Risk Mitigation

### Technical Risks
- **Performance Impact**: Mitigated by gradual migration with performance testing
- **Breaking Changes**: Mitigated by maintaining API compatibility
- **Data Migration**: Mitigated by schema compatibility testing

### Operational Risks
- **Deployment Complexity**: Mitigated by blue-green deployment strategy
- **Knowledge Transfer**: Mitigated by comprehensive documentation and training
- **Rollback Capability**: Mitigated by maintaining rollback procedures

## Success Metrics

### Migration Success
- [ ] Zero downtime migration to production
- [ ] All existing functionality preserved
- [ ] Performance parity or improvement
- [ ] Security posture maintained or improved

### Architecture Success
- [ ] 80%+ reduction in Marty infrastructure code
- [ ] All services running as MMF plugins
- [ ] Single deployment pipeline for all services
- [ ] Unified monitoring and observability

### Long-term Success
- [ ] Faster feature development cycles
- [ ] Reduced operational overhead
- [ ] Improved system reliability
- [ ] Easier onboarding for new team members

## Conclusion

This migration strategy transforms Marty from an independent platform into a specialized domain plugin of MMF, achieving:

1. **Clean Separation of Concerns**: MMF handles infrastructure, Marty provides domain expertise
2. **Reduced Duplication**: Single source of truth for microservices infrastructure
3. **Improved Maintainability**: Focus on core competencies
4. **Enhanced Reliability**: Leverage proven infrastructure patterns
5. **Faster Innovation**: Accelerated development through reduced infrastructure overhead

The phased approach ensures minimal risk while delivering maximum value through systematic migration of services, infrastructure, and operational processes.