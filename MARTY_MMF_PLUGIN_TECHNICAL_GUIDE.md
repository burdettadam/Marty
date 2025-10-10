# Marty to MMF Plugin Migration: Technical Guidelines

## Overview

This document provides detailed technical guidance for implementing the Marty to MMF plugin migration. It covers configuration patterns, service refactoring techniques, testing strategies, and infrastructure consolidation approaches.

## Configuration Migration Patterns

### 1. MMF Configuration Integration

#### Current Marty Configuration Pattern
```yaml
# config/development.yaml (Marty current)
database:
  host: localhost
  port: 5432
  username: marty_user
  password: marty_pass

cryptographic:
  signing:
    algorithm: ES256
    key_id: marty-signing-key
    key_directory: "/opt/marty/keys"
  vault:
    url: "https://vault.marty.internal"
    auth_method: "kubernetes"

trust_store:
  pkd:
    service_url: "https://pkd.icao.int"
    timeout_seconds: 30
  trust_anchor:
    certificate_store_path: "/data/trust-store"
    update_interval_hours: 24
```

#### Target MMF Plugin Configuration
```yaml
# config/marty-plugin.yaml (MMF plugin format)
service:
  name: "marty-platform"
  environment: "development"
  
plugins:
  - name: "marty-trust-pki"
    version: "2.0.0"
    enabled: true
    config:
      # Marty-specific configuration nested under plugin
      cryptographic:
        signing:
          algorithm: "ES256"
          key_id: "marty-signing-key"
          key_directory: "/opt/marty/keys"
          rotation_policy:
            enabled: true
            interval_days: 90
        sd_jwt:
          issuer: "https://marty.example.com"
          ttl_seconds: 3600
        vault:
          url: "https://vault.marty.internal"
          auth_method: "kubernetes"
          namespace: "marty"
      
      trust_store:
        pkd:
          service_url: "https://pkd.icao.int"
          timeout_seconds: 30
          cache_ttl_hours: 24
          retry_attempts: 3
        trust_anchor:
          certificate_store_path: "/data/trust-store"
          update_interval_hours: 24
          validation_timeout_seconds: 30
          enable_online_verification: false
      
      service_discovery:
        consul:
          host: "consul.service.consul"
          port: 8500
        kubernetes:
          namespace: "marty"
          service_account: "marty-sa"

# Standard MMF infrastructure configuration
database:
  default:
    host: ${DB_HOST:localhost}
    port: ${DB_PORT:5432}
    username: ${DB_USER:mmf_user}
    password: ${DB_PASSWORD:mmf_pass}
    database: "mmf_default"
  services:
    document_signer: "marty_document_signer"
    trust_anchor: "marty_trust_anchor"
    pkd_service: "marty_pkd"

security:
  authentication:
    jwt:
      secret_key: ${JWT_SECRET_KEY}
      algorithm: "HS256"
      expiration_hours: 24
  rate_limiting:
    default_requests_per_hour: 1000
    redis_url: ${REDIS_URL:redis://localhost:6379}

observability:
  metrics:
    enabled: true
    prometheus_port: 9090
  logging:
    level: "INFO"
    structured: true
  tracing:
    enabled: true
    jaeger_endpoint: ${JAEGER_ENDPOINT}
```

#### Configuration Migration Script
```python
#!/usr/bin/env python3
"""
Configuration migration script for Marty to MMF plugin.
"""

import yaml
from pathlib import Path
from typing import Dict, Any

class ConfigurationMigrator:
    def __init__(self, marty_config_path: Path, output_path: Path):
        self.marty_config_path = marty_config_path
        self.output_path = output_path
    
    def migrate(self) -> None:
        """Migrate Marty configuration to MMF plugin format."""
        # Load existing Marty configuration
        with open(self.marty_config_path, 'r') as f:
            marty_config = yaml.safe_load(f)
        
        # Transform to MMF plugin format
        mmf_config = self._transform_config(marty_config)
        
        # Write MMF configuration
        with open(self.output_path, 'w') as f:
            yaml.dump(mmf_config, f, default_flow_style=False, indent=2)
    
    def _transform_config(self, marty_config: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Marty config to MMF plugin format."""
        return {
            "service": {
                "name": "marty-platform",
                "environment": marty_config.get("environment", "development")
            },
            "plugins": [{
                "name": "marty-trust-pki",
                "version": "2.0.0",
                "enabled": True,
                "config": {
                    "cryptographic": marty_config.get("cryptographic", {}),
                    "trust_store": marty_config.get("trust_store", {}),
                    "service_discovery": marty_config.get("service_discovery", {})
                }
            }],
            "database": self._transform_database_config(marty_config.get("database", {})),
            "security": self._extract_security_config(marty_config),
            "observability": self._extract_observability_config(marty_config)
        }
    
    def _transform_database_config(self, db_config: Dict[str, Any]) -> Dict[str, Any]:
        """Transform database configuration to MMF format."""
        return {
            "default": {
                "host": db_config.get("host", "localhost"),
                "port": db_config.get("port", 5432),
                "username": db_config.get("username", "mmf_user"),
                "password": db_config.get("password", "mmf_pass"),
                "database": "mmf_default"
            },
            "services": {
                "document_signer": "marty_document_signer",
                "trust_anchor": "marty_trust_anchor", 
                "pkd_service": "marty_pkd",
                "consistency_engine": "marty_consistency"
            }
        }

# Usage example
if __name__ == "__main__":
    migrator = ConfigurationMigrator(
        Path("config/development.yaml"),
        Path("config/mmf-development.yaml")
    )
    migrator.migrate()
```

### 2. Environment-Specific Configuration

#### Development Environment
```yaml
# config/environments/development.yaml
service:
  environment: "development"
  debug: true

plugins:
  - name: "marty-trust-pki"
    config:
      cryptographic:
        vault:
          url: "https://vault-dev.marty.internal"
      trust_store:
        pkd:
          service_url: "https://pkd-staging.icao.int"

database:
  default:
    host: "localhost"
    database: "mmf_dev"

observability:
  logging:
    level: "DEBUG"
  tracing:
    enabled: false  # Disable in dev for performance
```

#### Production Environment
```yaml
# config/environments/production.yaml
service:
  environment: "production"
  debug: false

plugins:
  - name: "marty-trust-pki"
    config:
      cryptographic:
        vault:
          url: "https://vault.marty.internal"
          auth_method: "kubernetes"
        signing:
          rotation_policy:
            enabled: true
            interval_days: 30  # More frequent in prod
      trust_store:
        pkd:
          service_url: "https://pkd.icao.int"
          cache_ttl_hours: 6  # Shorter cache in prod

database:
  default:
    host: ${DB_HOST}
    pool_size: 20
    max_overflow: 30

security:
  rate_limiting:
    default_requests_per_hour: 10000

observability:
  logging:
    level: "INFO"
  tracing:
    enabled: true
    sampling_rate: 0.1  # 10% sampling in prod
```

## Service Refactoring Patterns

### 1. Service Class Migration Pattern

#### Before: Marty Service Pattern
```python
# src/services/document_signer.py (Original Marty)
import logging
from typing import Optional
import grpc

from marty_common.config import Config
from marty_common.database import DatabaseManager
from marty_common.crypto import CryptoManager
from marty_common.logging_config import get_logger

class DocumentSigner:
    def __init__(self, config_path: Optional[str] = None):
        # Marty-specific initialization
        self.config = Config(config_path)
        self.logger = get_logger("document-signer")
        self.database = DatabaseManager(self.config.database())
        self.crypto = CryptoManager(self.config.cryptographic)
        
        # Manual middleware setup
        self._setup_metrics()
        self._setup_auth()
    
    def _setup_metrics(self):
        """Manual metrics setup."""
        self.metrics = PrometheusMetrics(port=9090)
    
    def _setup_auth(self):
        """Manual authentication setup.""" 
        self.auth = JWTAuthenticator(
            secret=self.config.jwt_secret,
            algorithm="HS256"
        )
    
    async def sign_document(self, request):
        # Manual auth check
        if not self.auth.verify(request.token):
            raise AuthenticationError("Invalid token")
        
        # Manual metrics
        self.metrics.increment("documents_signed")
        
        # Business logic
        signature = await self.crypto.sign(request.document)
        
        # Manual database operation
        await self.database.store_signature(signature)
        
        return signature
```

#### After: MMF Plugin Service Pattern
```python
# marty_plugin/services/document_signer.py (MMF Plugin)
from mmf.plugins import PluginService, PluginContext
from mmf.decorators import requires_auth, track_metrics, trace_operation
from mmf.exceptions import AuthenticationError, SigningError

class DocumentSignerService(PluginService):
    def __init__(self, context: PluginContext):
        super().__init__(context)
        
        # Use MMF-provided infrastructure
        self.crypto_config = context.config.get_plugin_config("marty-trust-pki").cryptographic
        self.vault_client = context.security.get_vault_client()
        self.database = context.database.get_service_database("document_signer")
        
        # MMF handles metrics, logging, auth automatically
        self.logger = context.observability.get_logger("document-signer")
        
    @requires_auth(roles=["signer", "admin"])
    @track_metrics("documents_signed")
    @trace_operation("document-signing")
    async def sign_document(self, request: SigningRequest) -> SigningResponse:
        """Sign a document using the configured algorithm."""
        try:
            # Get signing key from MMF vault
            signing_key = await self.vault_client.get_signing_key(
                self.crypto_config.signing.key_id
            )
            
            # Perform signing (pure business logic)
            signature = await self._create_signature(request.document, signing_key)
            
            # Use MMF repository pattern
            repo = await self.database.get_repository(SignatureRepository)
            await repo.store(signature)
            
            # Publish event through MMF event bus
            await self.context.event_bus.publish(DocumentSignedEvent(
                document_id=request.document_id,
                signature_id=signature.id,
                algorithm=self.crypto_config.signing.algorithm
            ))
            
            return SigningResponse(signature=signature)
            
        except Exception as e:
            self.logger.error(f"Document signing failed: {e}")
            raise SigningError(f"Failed to sign document: {e}")
    
    async def _create_signature(self, document: bytes, signing_key) -> Signature:
        """Create signature using configured algorithm."""
        # Pure cryptographic business logic
        if self.crypto_config.signing.algorithm == "ES256":
            return await self._sign_with_ecdsa(document, signing_key)
        elif self.crypto_config.signing.algorithm == "RS256":
            return await self._sign_with_rsa(document, signing_key)
        else:
            raise ValueError(f"Unsupported algorithm: {self.crypto_config.signing.algorithm}")
```

### 2. Database Repository Migration Pattern

#### Before: Marty Repository Pattern
```python
# src/marty_common/infrastructure/repositories.py (Original)
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List

class TrustEntityRepository:
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def find_by_id(self, entity_id: str) -> Optional[TrustEntity]:
        # Custom session management
        result = await self.session.execute(
            select(TrustEntity).where(TrustEntity.id == entity_id)
        )
        return result.scalar_one_or_none()
    
    async def is_trusted(self, entity_id: str) -> bool:
        entity = await self.find_by_id(entity_id)
        return entity.trusted if entity else False
```

#### After: MMF Repository Pattern
```python
# marty_plugin/repositories/trust_entity.py (MMF Plugin)
from mmf.database import BaseRepository, DatabaseSession
from mmf.decorators import transactional, cached
from typing import Optional, List

class TrustEntityRepository(BaseRepository[TrustEntity]):
    """Repository for trust entity operations using MMF patterns."""
    
    @cached(ttl=300)  # Cache for 5 minutes
    async def find_by_id(self, entity_id: str) -> Optional[TrustEntity]:
        """Find trust entity by ID with caching."""
        return await self.session.get(TrustEntity, entity_id)
    
    @cached(ttl=300)
    async def is_trusted(self, entity_id: str) -> bool:
        """Check if entity is trusted with caching."""
        entity = await self.find_by_id(entity_id)
        return entity.trusted if entity else False
    
    @transactional
    async def update_trust_status(self, entity_id: str, trusted: bool) -> bool:
        """Update trust status with automatic transaction management."""
        entity = await self.find_by_id(entity_id)
        if not entity:
            return False
        
        entity.trusted = trusted
        entity.updated_at = datetime.utcnow()
        
        # MMF handles session commit/rollback
        await self.session.merge(entity)
        
        # Invalidate cache
        await self._invalidate_cache(f"find_by_id:{entity_id}")
        await self._invalidate_cache(f"is_trusted:{entity_id}")
        
        return True
    
    async def find_by_country(self, country_code: str) -> List[TrustEntity]:
        """Find all trust entities for a country."""
        result = await self.session.execute(
            select(TrustEntity)
            .where(TrustEntity.country_code == country_code)
            .where(TrustEntity.trusted == True)
        )
        return result.scalars().all()
```

### 3. Event Processing Migration Pattern

#### Before: Custom Event Processing
```python
# src/services/consistency_engine.py (Original)
import asyncio
from typing import Dict, Any

class ConsistencyEngine:
    def __init__(self):
        self.event_queue = asyncio.Queue()
        self.processors = {}
    
    async def process_events(self):
        """Custom event processing loop."""
        while True:
            try:
                event = await self.event_queue.get()
                processor = self.processors.get(event.type)
                if processor:
                    await processor(event)
            except Exception as e:
                logger.error(f"Event processing error: {e}")
    
    async def handle_document_signed(self, event):
        """Handle document signed event."""
        # Custom consistency checking logic
        pass
```

#### After: MMF Event Bus Pattern
```python
# marty_plugin/services/consistency_engine.py (MMF Plugin)
from mmf.events import EventHandler, event_handler
from mmf.plugins import PluginService

class ConsistencyEngineService(PluginService):
    def __init__(self, context: PluginContext):
        super().__init__(context)
        self.workflow_engine = context.workflow_engine
    
    async def initialize(self):
        """Initialize event subscriptions using MMF event bus."""
        # Subscribe to events using MMF decorators
        await self.context.event_bus.subscribe_handler(self)
    
    @event_handler("document.signed")
    async def handle_document_signed(self, event: DocumentSignedEvent):
        """Handle document signed event with MMF workflow engine."""
        # Use MMF workflow engine for consistency checking
        workflow = await self.workflow_engine.create_workflow(
            "document-consistency-check",
            input_data={
                "document_id": event.document_id,
                "signature_id": event.signature_id,
                "algorithm": event.algorithm
            }
        )
        
        await workflow.execute()
    
    @event_handler("trust.updated")
    async def handle_trust_updated(self, event: TrustUpdatedEvent):
        """Handle trust status updates."""
        # Trigger re-validation of affected documents
        affected_docs = await self._find_documents_by_entity(event.entity_id)
        
        for doc_id in affected_docs:
            validation_workflow = await self.workflow_engine.create_workflow(
                "trust-revalidation",
                input_data={"document_id": doc_id, "entity_id": event.entity_id}
            )
            await validation_workflow.execute_async()  # Background processing
```

## Testing Strategy

### 1. Unit Testing with MMF Infrastructure

```python
# tests/unit/test_document_signer.py
import pytest
from unittest.mock import AsyncMock, MagicMock

from mmf.testing import PluginTestCase, mock_plugin_context
from marty_plugin.services import DocumentSignerService

class TestDocumentSignerService(PluginTestCase):
    async def setup_method(self):
        """Setup test with mocked MMF context."""
        self.context = await mock_plugin_context(
            config_overrides={
                "cryptographic": {
                    "signing": {
                        "algorithm": "ES256",
                        "key_id": "test-key"
                    }
                }
            }
        )
        self.service = DocumentSignerService(self.context)
    
    async def test_sign_document_success(self):
        """Test successful document signing."""
        # Setup mocks
        self.context.vault_client.get_signing_key = AsyncMock(return_value="test-key")
        self.context.database.get_repository = AsyncMock()
        
        # Create test request
        request = SigningRequest(
            document_id="test-doc",
            document=b"test document content"
        )
        
        # Execute
        response = await self.service.sign_document(request)
        
        # Verify
        assert response.signature is not None
        self.context.vault_client.get_signing_key.assert_called_once_with("test-key")
        self.context.event_bus.publish.assert_called_once()
    
    async def test_sign_document_auth_failure(self):
        """Test authentication failure handling."""
        # Mock authentication failure
        self.context.security.authenticate = AsyncMock(return_value=False)
        
        request = SigningRequest(document_id="test", document=b"test")
        
        # Should raise authentication error
        with pytest.raises(AuthenticationError):
            await self.service.sign_document(request)
```

### 2. Integration Testing

```python
# tests/integration/test_plugin_integration.py
import pytest
from mmf.testing import IntegrationTestCase
from marty_plugin import MartyTrustPKIPlugin

class TestMartyPluginIntegration(IntegrationTestCase):
    async def setup_method(self):
        """Setup integration test environment."""
        await self.setup_test_database()
        await self.setup_test_redis()
        await self.setup_test_vault()
        
        # Load plugin
        self.plugin = MartyTrustPKIPlugin()
        await self.plugin.initialize(self.test_context)
    
    async def test_complete_document_signing_flow(self):
        """Test complete document signing and verification flow."""
        # Sign document
        signing_response = await self.call_service_endpoint(
            "document-signer",
            "/api/v1/sign",
            method="POST",
            json={
                "document_id": "integration-test-doc",
                "document_type": "passport",
                "document_data": "test passport data"
            },
            headers={"Authorization": f"Bearer {self.test_jwt_token}"}
        )
        
        assert signing_response.status_code == 200
        signature_data = signing_response.json()
        
        # Verify trust
        trust_response = await self.call_service_endpoint(
            "trust-anchor",
            "/api/v1/trust/verify",
            method="POST",
            json={
                "entity_id": signature_data["signer_id"]
            }
        )
        
        assert trust_response.status_code == 200
        assert trust_response.json()["trusted"] is True
        
        # Check consistency engine processed the event
        await self.wait_for_async_processing(timeout=5.0)
        
        consistency_status = await self.call_service_endpoint(
            "consistency-engine",
            f"/api/v1/status/{signature_data['document_id']}",
            method="GET"
        )
        
        assert consistency_status.status_code == 200
        assert consistency_status.json()["consistent"] is True
```

### 3. Performance Testing

```python
# tests/performance/test_load_handling.py
import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
import pytest

from mmf.testing import PerformanceTestCase

class TestMartyPluginPerformance(PerformanceTestCase):
    
    @pytest.mark.performance
    async def test_document_signing_throughput(self):
        """Test document signing throughput under load."""
        concurrent_requests = 100
        requests_per_second_target = 50
        
        async def sign_document():
            start_time = time.time()
            response = await self.call_service_endpoint(
                "document-signer",
                "/api/v1/sign",
                method="POST",
                json=self.generate_test_document()
            )
            end_time = time.time()
            
            return {
                "success": response.status_code == 200,
                "response_time": end_time - start_time,
                "timestamp": start_time
            }
        
        # Execute concurrent requests
        tasks = [sign_document() for _ in range(concurrent_requests)]
        results = await asyncio.gather(*tasks)
        
        # Analyze results
        successful_requests = sum(1 for r in results if r["success"])
        avg_response_time = sum(r["response_time"] for r in results) / len(results)
        
        total_duration = max(r["timestamp"] for r in results) - min(r["timestamp"] for r in results)
        actual_rps = successful_requests / total_duration
        
        # Assertions
        assert successful_requests >= concurrent_requests * 0.99  # 99% success rate
        assert avg_response_time < 0.5  # 500ms average response time
        assert actual_rps >= requests_per_second_target
```

## Infrastructure Consolidation Guidelines

### 1. Deployment Migration Process

#### Step 1: Kustomize Conversion
```bash
#!/bin/bash
# scripts/migrate-to-kustomize.sh

set -e

HELM_CHART_DIR="./helm/charts"
KUSTOMIZE_OUTPUT_DIR="./k8s"
SERVICES=("document-signer" "trust-anchor" "pkd-service" "consistency-engine")

for service in "${SERVICES[@]}"; do
    echo "Converting $service Helm chart to Kustomize..."
    
    marty migrate helm-to-kustomize \
        --helm-chart-path "$HELM_CHART_DIR/$service" \
        --output-path "$KUSTOMIZE_OUTPUT_DIR/$service" \
        --service-name "$service" \
        --values-file "./helm/values-dev.yaml" \
        --values-file "./helm/values-staging.yaml" \
        --values-file "./helm/values-prod.yaml" \
        --validate
    
    echo "✅ $service converted successfully"
done

echo "🎉 All services converted to Kustomize"
```

#### Step 2: CI/CD Pipeline Migration
```yaml
# .github/workflows/deploy-plugin.yml
name: Deploy Marty Plugin

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    uses: marty-microservices-framework/.github/workflows/test-plugin.yml@main
    with:
      plugin-name: marty-trust-pki
      test-types: "unit,integration,e2e"
    secrets:
      TEST_DATABASE_URL: ${{ secrets.TEST_DATABASE_URL }}
      TEST_REDIS_URL: ${{ secrets.TEST_REDIS_URL }}

  security-scan:
    uses: marty-microservices-framework/.github/workflows/security-scan.yml@main
    with:
      plugin-name: marty-trust-pki

  build:
    needs: [test, security-scan]
    uses: marty-microservices-framework/.github/workflows/build-plugin.yml@main
    with:
      plugin-name: marty-trust-pki
      registry: ghcr.io/marty/plugins

  deploy-staging:
    if: github.ref == 'refs/heads/develop'
    needs: build
    uses: marty-microservices-framework/.github/workflows/deploy-plugin.yml@main
    with:
      plugin-name: marty-trust-pki
      environment: staging
      kustomize-path: k8s/overlays/staging
    secrets:
      KUBE_CONFIG: ${{ secrets.STAGING_KUBE_CONFIG }}

  deploy-production:
    if: github.ref == 'refs/heads/main'
    needs: build
    uses: marty-microservices-framework/.github/workflows/deploy-plugin.yml@main
    with:
      plugin-name: marty-trust-pki
      environment: production
      kustomize-path: k8s/overlays/production
      approval-required: true
    secrets:
      KUBE_CONFIG: ${{ secrets.PRODUCTION_KUBE_CONFIG }}
```

### 2. Infrastructure Code Cleanup

#### Remove Duplicate Infrastructure
```bash
#!/bin/bash
# scripts/cleanup-infrastructure.sh

echo "🧹 Cleaning up duplicate infrastructure code..."

# Remove Marty-specific infrastructure directories
INFRASTRUCTURE_DIRS=(
    "terraform/"
    "helm/"
    "monitoring/"
    "docker/"
    "k8s/base/"  # Keep overlays for now
    "scripts/deployment/"
    ".github/workflows/"  # Replace with plugin workflows
)

for dir in "${INFRASTRUCTURE_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo "Removing $dir..."
        rm -rf "$dir"
    fi
done

# Remove duplicate code modules
DUPLICATE_MODULES=(
    "src/marty_common/config/"
    "src/marty_common/middleware/"
    "src/marty_common/infrastructure/"
    "src/marty_common/database/connection.py"
    "src/marty_common/observability/"
)

for module in "${DUPLICATE_MODULES[@]}"; do
    if [ -e "$module" ]; then
        echo "Removing duplicate module $module..."
        rm -rf "$module"
    fi
done

echo "✅ Infrastructure cleanup complete"
```

#### Update Import Statements
```python
#!/usr/bin/env python3
# scripts/update-imports.py

import os
import re
from pathlib import Path

def update_imports_in_file(file_path: Path):
    """Update import statements to use MMF instead of marty_common."""
    
    import_mappings = {
        'from marty_common.config': 'from mmf.config',
        'from marty_common.database': 'from mmf.database',
        'from marty_common.middleware': 'from mmf.middleware',
        'from marty_common.observability': 'from mmf.observability',
        'from marty_common.security': 'from mmf.security',
        'from marty_common.events': 'from mmf.events',
        'import marty_common.config': 'import mmf.config',
        'import marty_common.database': 'import mmf.database',
    }
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        original_content = content
        
        for old_import, new_import in import_mappings.items():
            content = content.replace(old_import, new_import)
        
        if content != original_content:
            with open(file_path, 'w') as f:
                f.write(content)
            print(f"Updated imports in {file_path}")
    
    except Exception as e:
        print(f"Error updating {file_path}: {e}")

def main():
    # Update all Python files in the plugin
    plugin_dir = Path("marty_plugin")
    
    for py_file in plugin_dir.rglob("*.py"):
        update_imports_in_file(py_file)
    
    print("✅ Import statements updated")

if __name__ == "__main__":
    main()
```

## Validation & Quality Assurance

### 1. Migration Validation Checklist
```yaml
# migration-validation.yml
validation_steps:
  configuration:
    - [ ] All Marty configuration sections supported in MMF
    - [ ] Environment-specific overrides work correctly
    - [ ] No configuration validation errors
    - [ ] Backward compatibility maintained
  
  services:
    - [ ] All services migrated to plugin pattern
    - [ ] Service dependencies resolved correctly
    - [ ] Health checks pass for all services
    - [ ] API endpoints respond correctly
  
  database:
    - [ ] Service-specific databases work
    - [ ] Data migration completed successfully
    - [ ] Repository patterns use MMF base classes
    - [ ] Database connections pooled correctly
  
  security:
    - [ ] Authentication works with MMF middleware
    - [ ] Authorization policies applied correctly
    - [ ] Rate limiting functions properly
    - [ ] Security headers present
  
  observability:
    - [ ] Metrics collected and exposed
    - [ ] Logs structured and searchable
    - [ ] Distributed tracing works
    - [ ] Alerting rules functional
  
  performance:
    - [ ] Response times within acceptable limits
    - [ ] Throughput meets requirements
    - [ ] Resource usage optimized
    - [ ] No memory leaks detected
  
  infrastructure:
    - [ ] Kustomize deployments work
    - [ ] CI/CD pipelines functional
    - [ ] No duplicate infrastructure code
    - [ ] Rollback procedures tested
```

### 2. Automated Validation Script
```python
#!/usr/bin/env python3
# scripts/validate-migration.py

import asyncio
import aiohttp
import yaml
from pathlib import Path
from typing import List, Dict, Any

class MigrationValidator:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.results = {}
    
    async def validate_all(self) -> Dict[str, Any]:
        """Run all validation checks."""
        validations = [
            self.validate_configuration(),
            self.validate_service_health(),
            self.validate_api_endpoints(),
            self.validate_database_connectivity(),
            self.validate_security(),
            self.validate_observability()
        ]
        
        await asyncio.gather(*validations)
        return self.results
    
    async def validate_configuration(self):
        """Validate configuration is loaded correctly."""
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.base_url}/admin/config") as response:
                if response.status == 200:
                    config = await response.json()
                    self.results["configuration"] = {
                        "status": "pass",
                        "plugin_loaded": "marty-trust-pki" in config.get("plugins", []),
                        "services_configured": len(config.get("services", {}))
                    }
                else:
                    self.results["configuration"] = {
                        "status": "fail",
                        "error": f"HTTP {response.status}"
                    }
    
    async def validate_service_health(self):
        """Validate all services are healthy."""
        services = ["document-signer", "trust-anchor", "pkd-service", "consistency-engine"]
        health_results = {}
        
        async with aiohttp.ClientSession() as session:
            for service in services:
                try:
                    async with session.get(f"{self.base_url}/{service}/health") as response:
                        health_results[service] = {
                            "status": "pass" if response.status == 200 else "fail",
                            "response_code": response.status
                        }
                except Exception as e:
                    health_results[service] = {
                        "status": "fail",
                        "error": str(e)
                    }
        
        self.results["service_health"] = health_results
    
    async def validate_api_endpoints(self):
        """Validate key API endpoints work."""
        test_cases = [
            {
                "service": "document-signer",
                "endpoint": "/api/v1/sign",
                "method": "POST",
                "data": {"document_id": "test", "document": "test_data"}
            },
            {
                "service": "trust-anchor", 
                "endpoint": "/api/v1/trust/verify",
                "method": "POST",
                "data": {"entity_id": "test_entity"}
            }
        ]
        
        api_results = {}
        async with aiohttp.ClientSession() as session:
            for test_case in test_cases:
                service = test_case["service"]
                url = f"{self.base_url}/{service}{test_case['endpoint']}"
                
                try:
                    if test_case["method"] == "POST":
                        async with session.post(url, json=test_case["data"]) as response:
                            api_results[f"{service}_{test_case['endpoint']}"] = {
                                "status": "pass" if response.status < 500 else "fail",
                                "response_code": response.status
                            }
                except Exception as e:
                    api_results[f"{service}_{test_case['endpoint']}"] = {
                        "status": "fail",
                        "error": str(e)
                    }
        
        self.results["api_endpoints"] = api_results

async def main():
    validator = MigrationValidator("http://localhost:8080")
    results = await validator.validate_all()
    
    # Print results
    print("🔍 Migration Validation Results")
    print("=" * 50)
    
    for category, result in results.items():
        status = "✅" if result.get("status") == "pass" else "❌"
        print(f"{status} {category.title()}: {result}")
    
    # Generate report
    with open("migration-validation-report.yaml", "w") as f:
        yaml.dump(results, f, default_flow_style=False)
    
    print("\n📄 Detailed report saved to migration-validation-report.yaml")

if __name__ == "__main__":
    asyncio.run(main())
```

This comprehensive technical guide provides the specific implementation details needed to successfully migrate Marty to an MMF plugin while maintaining all functionality and improving operational efficiency.