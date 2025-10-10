# Marty MMF Plugin - Dual Environment Testing Framework

This document describes the comprehensive testing strategy for the Marty MMF Plugin, supporting both Kind (local development) and real Kubernetes (CI/CD) environments.

## Testing Architecture

```
Local Development (Kind)           CI/CD Pipeline (Real K8s)
┌─────────────────────┐           ┌─────────────────────────┐
│                     │           │                         │
│  ┌───────────────┐  │           │  ┌───────────────────┐  │
│  │  Kind Cluster │  │           │  │ Minikube/Real K8s │  │
│  │               │  │           │  │                   │  │
│  │ • Fast startup│  │           │  │ • Multiple K8s    │  │
│  │ • Port mapping│  │           │  │   versions        │  │
│  │ • Live reload │  │           │  │ • Performance     │  │
│  │               │  │           │  │   testing         │  │
│  └───────────────┘  │           │  │ • Load testing    │  │
│                     │           │  │ • Scaling tests   │  │
│  ┌───────────────┐  │           │  │                   │  │
│  │ Test Suite    │  │           │  └───────────────────┘  │
│  │               │  │           │                         │
│  │ • Basic tests │  │           │  ┌───────────────────┐  │
│  │ • Plugin func │  │           │  │    Test Suite     │  │
│  │ • Health      │  │           │  │                   │  │
│  │ • Config      │  │           │  │ • Extended tests  │  │
│  └───────────────┘  │           │  │ • E2E workflows   │  │
│                     │           │  │ • Performance     │  │
└─────────────────────┘           │  │ • Security scans  │  │
                                  │  │ • Load testing    │  │
                                  │  └───────────────────┘  │
                                  │                         │
                                  └─────────────────────────┘
```

## Test Categories

### 1. Local Development Tests (Kind)

**Purpose**: Fast feedback during development

**Test Types**:
- Basic functionality tests
- Plugin service discovery
- Health endpoint validation
- Configuration loading
- Network connectivity

**Tools**:
- `k8s/dev.sh` - Development workflow
- `k8s/test.sh basic` - Basic test suite
- `k8s/kind/manage-cluster.sh` - Cluster management

**Execution**:
```bash
# Quick setup and test
./k8s/dev.sh setup

# Live development with file watching
./k8s/dev.sh watch

# Run tests
./k8s/test.sh basic
```

### 2. Extended Integration Tests (Kind/Real K8s)

**Purpose**: Comprehensive functionality validation

**Test Types**:
- Resource usage monitoring
- RBAC permissions
- Service mesh integration
- Multi-pod scenarios
- Configuration management

**Execution**:
```bash
# Extended test suite
./k8s/test.sh extended

# With status reporting
./k8s/test.sh extended && ./k8s/test.sh status
```

### 3. End-to-End Tests (Real Kubernetes)

**Purpose**: Production-like validation

**Test Types**:
- Horizontal scaling
- Rolling updates
- Load testing
- Performance benchmarks
- Multi-version compatibility
- Security scanning

**Execution**:
```bash
# Full E2E test suite
./k8s/test.sh e2e

# Performance testing
./k8s/dev.sh perf
```

## Environment Configurations

### Kind Development Configuration

**File**: `k8s/kind/cluster-config.yaml`

**Features**:
- 3-node cluster (1 control-plane, 2 workers)
- Port mappings for external access
- Development-optimized settings
- Plugin-specific node labels

**Usage**:
```bash
kind create cluster --config=k8s/kind/cluster-config.yaml --name=marty-dev
```

### Kind CI Configuration

**File**: `k8s/kind/ci-config.yaml`

**Features**:
- 2-node cluster (minimal resources)
- Fast startup for CI
- Essential features only
- Optimized for automated testing

**Usage**:
```bash
kind create cluster --config=k8s/kind/ci-config.yaml --name=marty-ci
```

## Test Scripts

### 1. Cluster Management (`k8s/kind/manage-cluster.sh`)

**Commands**:
```bash
./manage-cluster.sh create [cluster-name]    # Create cluster
./manage-cluster.sh delete [cluster-name]    # Delete cluster
./manage-cluster.sh setup [cluster-name]     # Full setup with dependencies
./manage-cluster.sh info [cluster-name]      # Show cluster information
./manage-cluster.sh load-images [cluster]    # Load plugin images
```

### 2. Deployment (`k8s/deploy.sh`)

**Commands**:
```bash
./deploy.sh deploy [environment] [cluster]   # Full deployment
./deploy.sh build [cluster]                  # Build and load images
./deploy.sh apply [environment]              # Apply manifests
./deploy.sh status                           # Show deployment status
./deploy.sh test                             # Test deployment
./deploy.sh delete                           # Delete deployment
```

### 3. Testing (`k8s/test.sh`)

**Commands**:
```bash
./test.sh basic                              # Basic tests
./test.sh extended                           # Extended tests
./test.sh e2e                                # End-to-end tests
./test.sh health                             # Health check only
./test.sh functionality                      # Plugin functionality only
./test.sh status                             # Detailed status
```

### 4. Development Workflow (`k8s/dev.sh`)

**Commands**:
```bash
./dev.sh setup [cluster]                     # Complete dev setup
./dev.sh watch [cluster]                     # Live development mode
./dev.sh rebuild [cluster]                   # Rebuild and redeploy
./dev.sh logs [follow]                       # Show logs
./dev.sh test [type]                         # Run tests
./dev.sh status                              # Development status
./dev.sh shell                               # Interactive shell
./dev.sh debug                               # Debug deployment
./dev.sh cleanup [cluster] [full]            # Cleanup environment
```

## CI/CD Integration

### GitHub Actions Workflow

**File**: `.github/workflows/k8s-e2e.yml`

**Stages**:
1. **Unit & Integration Tests** - Standard Python testing
2. **Code Quality** - Linting, type checking, security scanning
3. **Build** - Container image building and caching
4. **Kind Tests** - Fast Kubernetes simulation
5. **Real K8s E2E** - Production-like testing with multiple K8s versions
6. **Security Scan** - Container vulnerability scanning

**Triggers**:
- Push to main/develop branches
- Pull requests
- Daily scheduled runs for E2E tests

### Test Matrix

| Test Type | Kind (Local) | Kind (CI) | Real K8s (CI) |
|-----------|--------------|-----------|----------------|
| Unit Tests | ✅ | ✅ | ✅ |
| Plugin Functionality | ✅ | ✅ | ✅ |
| Health Checks | ✅ | ✅ | ✅ |
| Configuration | ✅ | ✅ | ✅ |
| Network Connectivity | ✅ | ✅ | ✅ |
| RBAC Permissions | ✅ | ✅ | ✅ |
| Resource Usage | ⚠️* | ✅ | ✅ |
| Load Testing | ❌ | ❌ | ✅ |
| Scaling Tests | ❌ | ❌ | ✅ |
| Rolling Updates | ❌ | ❌ | ✅ |
| Multi-version | ❌ | ❌ | ✅ |

*Requires metrics-server installation

## Test Environments

### Local Development

**Cluster**: Kind with development configuration
**Purpose**: Fast iteration and debugging
**Access**: Direct port mapping (localhost:30080, etc.)
**Duration**: Persistent (developer-managed)

### CI Testing

**Cluster**: Kind with minimal configuration
**Purpose**: Automated validation of basic functionality
**Access**: Internal cluster networking only
**Duration**: Ephemeral (per CI run)

### E2E Testing

**Cluster**: Minikube or real Kubernetes cluster
**Purpose**: Production-like validation
**Access**: Service-based networking
**Duration**: Ephemeral (per CI run)

## Monitoring and Observability

### Metrics Collection

**Local Development**:
- Plugin metrics: `http://localhost:30081/metrics`
- Health checks: `http://localhost:30081/health`
- Kubernetes metrics: `kubectl top`

**CI/CD**:
- Test result artifacts
- Performance benchmarks
- Security scan reports
- Log aggregation

### Logging Strategy

**Levels**:
- Development: DEBUG level with verbose output
- CI: INFO level with structured logging
- E2E: INFO level with performance metrics

**Collection**:
```bash
# Local development
kubectl logs -f deployment/marty-mmf-plugin -n marty-mmf

# CI artifacts
kubectl logs -l app.kubernetes.io/name=marty-mmf-plugin -n marty-mmf --all-containers=true > logs/pod-logs.txt
```

## Best Practices

### For Developers

1. **Use Kind for daily development** - Fast, consistent, isolated
2. **Run basic tests frequently** - Quick validation of changes
3. **Test configuration changes** - Validate plugin config updates
4. **Use live development mode** - Automatic rebuild on file changes

### For CI/CD

1. **Layer tests appropriately** - Fast tests first, comprehensive tests for integration
2. **Cache aggressively** - Docker layers, dependencies, test artifacts
3. **Collect comprehensive logs** - Full debugging information on failures
4. **Test multiple scenarios** - Different Kubernetes versions, scaling patterns

### For Production

1. **Run E2E tests regularly** - Daily scheduled validation
2. **Monitor performance trends** - Track regression over time
3. **Validate security posture** - Regular vulnerability scanning
4. **Test upgrade scenarios** - Rolling updates, blue-green deployments

## Troubleshooting

### Common Issues

**Kind cluster won't start**:
```bash
# Check Docker and system resources
docker system df
./k8s/kind/manage-cluster.sh info marty-dev
```

**Plugin deployment fails**:
```bash
# Debug deployment
./k8s/dev.sh debug
kubectl describe deployment marty-mmf-plugin -n marty-mmf
```

**Tests failing inconsistently**:
```bash
# Check resource constraints
kubectl top nodes
kubectl describe nodes
```

**Network connectivity issues**:
```bash
# Verify DNS and service discovery
kubectl exec -it <pod> -n marty-mmf -- nslookup kubernetes.default.svc.cluster.local
```

### Debug Commands

```bash
# Complete environment status
./k8s/dev.sh status

# Detailed test information
./k8s/test.sh status

# Interactive debugging
./k8s/dev.sh shell

# Clean slate restart
./k8s/dev.sh cleanup marty-dev true
./k8s/dev.sh setup marty-dev
```

This dual-environment testing framework ensures reliable plugin development with fast local iteration and comprehensive production validation.