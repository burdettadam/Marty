# Legacy Configuration Cleanup Guide

## Overview

This guide outlines the process for removing legacy configuration mechanisms after all services have been migrated to the unified observability framework. This cleanup should only be performed after confirming all services are successfully using the new configuration system.

## Pre-Cleanup Validation

### 1. Verify All Services Migrated

Run the migration validation script to ensure all services are using unified observability:

```bash
python scripts/validate_observability_migration.py
```

**Required Results:**
- All services must show ✅ validation status
- Zero failures or warnings
- All services must have unified configuration files

### 2. Audit Service Configurations

Check that all services have migrated from legacy configurations:

```bash
# Find any remaining legacy config patterns
find . -name "*.py" -type f -exec grep -l "legacy_config\|old_config\|ServiceConfig" {} \;

# Look for deprecated configuration imports
find . -name "*.py" -type f -exec grep -l "from.*config.*import.*Config" {} \; | grep -v unified

# Check for hardcoded configuration values
find . -name "*.py" -type f -exec grep -l "host.*=.*localhost\|port.*=.*50" {} \;
```

### 3. Confirm Production Deployment Status

Verify all migrated services are deployed and healthy in production:

```bash
# Check service health in production
kubectl get pods -n marty-production -l app.kubernetes.io/component=service
kubectl get services -n marty-production -l monitoring=true

# Verify metrics collection
curl -s http://prometheus.marty.example.com/api/v1/label/__name__/values | jq '.data[]' | grep marty_
```

## Legacy Components to Remove

### 1. Configuration Classes

**Files to Remove:**
```
src/marty_common/config/
├── legacy_config.py          # Legacy configuration base class
├── service_config.py         # Old service configuration
├── database_config.py        # Deprecated database configuration
├── grpc_config.py           # Old gRPC configuration
└── monitoring_config.py      # Legacy monitoring setup
```

**Action:**
```bash
# Create backup of legacy configurations
mkdir -p temp_backup/legacy_config
cp -r src/marty_common/config/ temp_backup/legacy_config/

# Remove legacy configuration files
rm -rf src/marty_common/config/legacy_config.py
rm -rf src/marty_common/config/service_config.py
rm -rf src/marty_common/config/database_config.py
rm -rf src/marty_common/config/grpc_config.py
rm -rf src/marty_common/config/monitoring_config.py
```

### 2. Legacy Environment Configuration

**Files to Update/Remove:**

Remove legacy environment files:
```bash
# Remove old environment configuration
rm -f config/legacy_development.yaml
rm -f config/legacy_testing.yaml
rm -f config/legacy_production.yaml

# Remove deprecated configuration includes
rm -f config/includes/legacy_*.yaml
```

### 3. Deprecated Service Startup Scripts

**Files to Remove:**
```bash
# Remove legacy service launchers
find scripts/ -name "*legacy*" -type f -delete
find scripts/ -name "*old_*" -type f -delete

# Remove deprecated Docker startup scripts
find docker/ -name "*legacy*" -type f -delete
```

### 4. Legacy Monitoring Components

**Components to Remove:**

Remove old monitoring setup:
```bash
# Remove legacy Prometheus configurations
rm -f monitoring/legacy_prometheus.yml
rm -f monitoring/legacy_service_discovery.yml

# Remove deprecated Grafana dashboards
find monitoring/grafana/dashboards/ -name "*legacy*" -type f -delete
find monitoring/grafana/dashboards/ -name "*old_*" -type f -delete

# Remove old health check implementations
find src/ -name "*legacy_health*" -type f -delete
```

### 5. Deprecated Container Images

**Dockerfiles to Remove:**
```bash
# Remove legacy Dockerfiles
find docker/ -name "*.legacy.Dockerfile" -type f -delete
find docker/ -name "*-old.Dockerfile" -type f -delete

# Update docker-compose files to remove legacy service definitions
# Manual review required for:
# - docker-compose.yml
# - docker-compose.demo.yml
# - docker-compose.integration.yml
```

## Code Cleanup Tasks

### 1. Remove Legacy Imports

Create a cleanup script to remove legacy imports:

```python
#!/usr/bin/env python3
"""
Legacy import cleanup script.
"""

import os
import re
from pathlib import Path

def cleanup_legacy_imports():
    """Remove legacy configuration imports from Python files."""
    
    legacy_patterns = [
        r'from\s+marty_common\.config\.legacy_config\s+import.*',
        r'from\s+marty_common\.config\.service_config\s+import.*',
        r'from\s+marty_common\.config\.database_config\s+import.*',
        r'from\s+marty_common\.config\.grpc_config\s+import.*',
        r'from\s+marty_common\.config\.monitoring_config\s+import.*',
        r'import\s+marty_common\.config\.legacy_config.*',
        r'LegacyConfig',
        r'ServiceConfig',
        r'DatabaseConfig',
        r'GrpcConfig',
        r'MonitoringConfig'
    ]
    
    # Find all Python files
    python_files = list(Path('.').rglob('*.py'))
    
    for file_path in python_files:
        if 'temp_backup' in str(file_path) or '.git' in str(file_path):
            continue
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            original_content = content
            
            # Remove legacy import patterns
            for pattern in legacy_patterns:
                content = re.sub(pattern, '', content, flags=re.MULTILINE)
            
            # Clean up empty lines
            content = re.sub(r'\n\s*\n\s*\n', '\n\n', content)
            
            if content != original_content:
                print(f"Cleaning up legacy imports in: {file_path}")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                    
        except Exception as e:
            print(f"Error processing {file_path}: {e}")

if __name__ == "__main__":
    cleanup_legacy_imports()
```

### 2. Update Import Statements

Replace legacy imports with unified framework imports:

```bash
# Create import update script
cat > scripts/update_imports.py << 'EOF'
#!/usr/bin/env python3
"""Update imports to use unified framework."""

import os
import re
from pathlib import Path

def update_imports():
    """Update import statements to use unified framework."""
    
    import_replacements = {
        r'from\s+marty_common\.config\s+import\s+Config': 'from framework.config_factory import create_service_config',
        r'from\s+marty_common\.monitoring\s+import.*': 'from framework.observability.unified_observability import MartyMetrics',
        r'from\s+marty_common\.grpc\s+import\s+GrpcServer': 'from framework.grpc.unified_grpc_server import UnifiedGrpcServer',
        r'from\s+marty_common\.health\s+import.*': 'from framework.observability.monitoring import HealthStatus',
    }
    
    python_files = list(Path('.').rglob('*.py'))
    
    for file_path in python_files:
        if 'temp_backup' in str(file_path) or '.git' in str(file_path):
            continue
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            original_content = content
            
            for old_pattern, new_import in import_replacements.items():
                content = re.sub(old_pattern, new_import, content, flags=re.MULTILINE)
            
            if content != original_content:
                print(f"Updating imports in: {file_path}")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                    
        except Exception as e:
            print(f"Error processing {file_path}: {e}")

if __name__ == "__main__":
    update_imports()
EOF

chmod +x scripts/update_imports.py
python scripts/update_imports.py
```

### 3. Remove Legacy Configuration Usage

Find and update code that still uses legacy configuration patterns:

```bash
# Find legacy configuration usage
grep -r "legacy_config\|old_config" src/ --include="*.py" | grep -v temp_backup

# Find hardcoded configuration values that should use unified config
grep -r "localhost:50" src/ --include="*.py"
grep -r "port.*=.*50" src/ --include="*.py"
grep -r "host.*=.*localhost" src/ --include="*.py"
```

## Infrastructure Cleanup

### 1. Kubernetes Manifests

Remove legacy Kubernetes resources:

```bash
# Remove legacy ConfigMaps
kubectl delete configmap legacy-config -n marty-production
kubectl delete configmap old-monitoring-config -n marty-production

# Remove deprecated Services that don't have observability ports
kubectl delete service legacy-service-1 -n marty-production
kubectl delete service legacy-service-2 -n marty-production

# Update remaining services to ensure they have observability annotations
kubectl patch service service-name -n marty-production -p '{"metadata":{"annotations":{"prometheus.io/scrape":"true","prometheus.io/port":"8080","prometheus.io/path":"/metrics"}}}'
```

### 2. Monitoring Infrastructure

Clean up legacy monitoring components:

```yaml
# Remove from monitoring/prometheus.yml
# Delete legacy scrape configurations:
# - job_name: 'legacy-services'
#   static_configs:
#   - targets: ['legacy-service:8080']

# Remove from monitoring/grafana/datasources.yml
# Delete legacy Prometheus datasources

# Remove legacy alerting rules
rm -f monitoring/alerts/legacy_*.yml
rm -f monitoring/alerts/old_*.yml
```

### 3. Service Discovery

Update service discovery configurations:

```bash
# Remove legacy service discovery entries
# Update consul/etcd configurations to remove old service entries

# Update DNS configurations
# Remove legacy service DNS entries

# Update load balancer configurations
# Remove legacy service targets from load balancer pools
```

## Validation After Cleanup

### 1. Build and Test

Ensure the system still builds and tests pass after cleanup:

```bash
# Build all services
make build

# Run unit tests
make test

# Run integration tests
make integration-test

# Run end-to-end tests
make e2e-test
```

### 2. Deployment Validation

Verify services deploy correctly with only unified configuration:

```bash
# Deploy to testing environment
kubectl apply -f k8s/testing/ -n marty-testing

# Check all pods are healthy
kubectl get pods -n marty-testing -l app.kubernetes.io/part-of=marty

# Verify metrics collection
kubectl port-forward -n marty-testing svc/prometheus 9090:9090 &
curl -s http://localhost:9090/api/v1/label/__name__/values | jq '.data[]' | grep marty_
```

### 3. Monitoring Validation

Confirm monitoring still works after legacy cleanup:

```bash
# Check Prometheus targets
curl -s http://prometheus.marty.example.com/api/v1/targets | jq '.data.activeTargets[] | select(.labels.job | contains("marty"))'

# Verify Grafana dashboards
curl -s http://grafana.marty.example.com/api/dashboards/tags/marty

# Test alerting rules
curl -s http://prometheus.marty.example.com/api/v1/rules | jq '.data.groups[] | select(.name | contains("marty"))'
```

## Rollback Plan

In case issues are discovered after cleanup:

### 1. Restore Legacy Components

```bash
# Restore legacy configuration files from backup
cp -r temp_backup/legacy_config/* src/marty_common/config/

# Restore legacy monitoring configurations
git checkout HEAD~1 -- monitoring/legacy_prometheus.yml
git checkout HEAD~1 -- monitoring/legacy_service_discovery.yml

# Restore legacy Kubernetes manifests
git checkout HEAD~1 -- k8s/legacy/
```

### 2. Revert Import Changes

```bash
# Revert import changes using git
git checkout HEAD~1 -- src/

# Or restore from backup if git history isn't available
cp -r temp_backup/src_before_cleanup/* src/
```

### 3. Redeploy Legacy Monitoring

```bash
# Redeploy legacy monitoring stack
kubectl apply -f monitoring/legacy/ -n marty-monitoring

# Restart affected services
kubectl rollout restart deployment -n marty-production -l app.kubernetes.io/part-of=marty
```

## Post-Cleanup Tasks

### 1. Update Documentation

- [ ] Update deployment documentation to remove legacy configuration references
- [ ] Update developer onboarding guides to use only unified configuration
- [ ] Update troubleshooting guides to reference new observability features
- [ ] Archive legacy configuration documentation

### 2. Team Communication

- [ ] Notify development teams about completed cleanup
- [ ] Update team knowledge base articles
- [ ] Schedule training sessions on unified observability if needed
- [ ] Update CI/CD pipelines to remove legacy configuration validation

### 3. Monitoring and Alerting

- [ ] Update alerting rules to use new metric names
- [ ] Create alerts for unified observability framework health
- [ ] Update runbooks to reference new monitoring endpoints
- [ ] Verify all dashboards use new metrics and are functioning

## Success Criteria

The legacy cleanup is considered successful when:

- [ ] All services use only unified observability configuration
- [ ] No legacy configuration files remain in the codebase
- [ ] All monitoring and alerting uses unified framework metrics
- [ ] All tests pass with unified configuration only
- [ ] Production deployment is stable with unified configuration
- [ ] Development team can use only unified configuration for new services
- [ ] Documentation reflects only unified configuration approach

## Maintenance

After successful cleanup:

1. **Code Review Standards**: Ensure code reviews catch any attempts to reintroduce legacy patterns
2. **CI/CD Validation**: Add checks to prevent legacy configuration from being committed
3. **Monitoring**: Set up alerts if any services start using deprecated configuration patterns
4. **Regular Audits**: Periodically audit for configuration drift or legacy pattern reintroduction

The cleanup process ensures the Marty platform uses only modern, unified observability patterns while maintaining system reliability and developer productivity.