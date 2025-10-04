# Trust Services Kubernetes Deployment

This directory contains Kubernetes manifests for deploying the Trust Services microservice.

## Overview

The Trust Services deployment includes:
- **Deployment**: Main application pods with health checks and resource limits
- **Service**: Internal and external service definitions
- **ConfigMap**: Configuration settings
- **Secret**: Sensitive data (database passwords, KMS keys)
- **PVC**: Persistent storage for trust data
- **RBAC**: Service account and permissions
- **Jobs**: Initialization and scheduled refresh jobs
- **Ingress**: External access configuration

## Quick Start

1. **Create namespace**:
   ```bash
   kubectl create namespace marty
   ```

2. **Update secrets** in `secret.yaml`:
   ```bash
   # Update database-password and kms-key-id with actual values
   kubectl apply -f secret.yaml
   ```

3. **Deploy all resources**:
   ```bash
   kubectl apply -f .
   ```

4. **Verify deployment**:
   ```bash
   kubectl get pods -n marty -l app=trust-svc
   kubectl logs -n marty -l app=trust-svc
   ```

5. **Run initialization job**:
   ```bash
   kubectl apply -f jobs.yaml
   kubectl logs -n marty job/trust-svc-init
   ```

## Using Kustomize

For advanced deployments with environment-specific configurations:

```bash
# Build and apply with kustomize
kubectl apply -k .

# Or preview the generated manifests
kubectl kustomize .
```

## Configuration

### Environment Variables

Key environment variables in the deployment:

- `TRUST_DB_HOST`: Database host (default: postgres)
- `TRUST_DB_PASSWORD`: Database password (from secret)
- `TRUST_SERVICE_LOG_LEVEL`: Logging level (INFO, DEBUG, etc.)
- `TRUST_PKD_REFRESH_INTERVAL`: CRL refresh interval in seconds
- `KMS_KEY_ID`: AWS KMS key for signing snapshots

### Resource Requirements

Default resource allocation:
- **Requests**: 256Mi memory, 100m CPU
- **Limits**: 1Gi memory, 500m CPU

Adjust based on your workload requirements.

### Storage

The deployment uses a PersistentVolumeClaim for data storage:
- **Size**: 10Gi (adjustable)
- **Access Mode**: ReadWriteOnce
- **Storage Class**: gp2 (AWS EBS, adjust for your provider)

## Monitoring

The service exposes Prometheus metrics on port 8080 at `/metrics`.

Service annotations for Prometheus scraping:
```yaml
prometheus.io/scrape: "true"
prometheus.io/port: "8080"
prometheus.io/path: "/metrics"
```

## Health Checks

The deployment includes comprehensive health checks:

- **Startup Probe**: Allows up to 2 minutes for startup
- **Readiness Probe**: Checks if service is ready to accept traffic
- **Liveness Probe**: Restarts pod if service becomes unhealthy

All probes use the `/api/v1/admin/status` endpoint.

## Jobs

### Initialization Job

The `trust-svc-init` job loads initial synthetic data:
- Runs once after deployment
- Creates 1000 synthetic certificates across 10 countries
- Auto-cleans up after 1 hour

### Scheduled Refresh Job

The `trust-svc-refresh` CronJob runs every 6 hours to:
- Refresh CRL data from external sources
- Create new trust snapshots
- Update metrics

## External Access

### Ingress

The ingress configuration provides external access via:
- **Host**: trust.marty.example.com (update with your domain)
- **TLS**: Automatic certificate management with cert-manager
- **Rate Limiting**: 100 requests per minute

### Load Balancer

Alternatively, use the LoadBalancer service for direct access:
```bash
kubectl get svc trust-svc-external -n marty
```

## Security

### RBAC

The service account has minimal required permissions:
- Read access to Secrets and ConfigMaps
- Pod listing for service discovery

### Security Context

Containers run with security hardening:
- Non-root user (UID 1000)
- Read-only root filesystem where possible
- Security contexts applied

### Network Policies

Consider implementing NetworkPolicies to restrict pod-to-pod communication:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: trust-svc-netpol
spec:
  podSelector:
    matchLabels:
      app: trust-svc
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: prometheus
    ports:
    - protocol: TCP
      port: 8080
```

## Scaling

The deployment is configured for horizontal scaling:

```bash
# Scale to 3 replicas
kubectl scale deployment trust-svc -n marty --replicas=3

# Or use HPA for automatic scaling
kubectl autoscale deployment trust-svc -n marty --cpu-percent=70 --min=2 --max=10
```

## Troubleshooting

### Common Issues

1. **Pod not starting**:
   ```bash
   kubectl describe pod -n marty -l app=trust-svc
   kubectl logs -n marty -l app=trust-svc
   ```

2. **Database connection issues**:
   ```bash
   # Check if postgres is running
   kubectl get pods -n marty -l app=postgres
   
   # Verify secret
   kubectl get secret trust-svc-secrets -n marty -o yaml
   ```

3. **Health check failures**:
   ```bash
   # Check service endpoint
   kubectl port-forward -n marty svc/trust-svc 8080:8080
   curl http://localhost:8080/api/v1/admin/status
   ```

4. **Storage issues**:
   ```bash
   kubectl get pvc -n marty
   kubectl describe pvc trust-svc-data -n marty
   ```

### Debug Commands

```bash
# Get all trust-svc resources
kubectl get all -n marty -l app=trust-svc

# Check events
kubectl get events -n marty --sort-by='.lastTimestamp'

# Debug a specific pod
kubectl exec -it -n marty deployment/trust-svc -- /bin/bash

# View logs from all replicas
kubectl logs -n marty -l app=trust-svc --all-containers --follow
```

## Cleanup

To remove all trust-svc resources:

```bash
kubectl delete -f .
kubectl delete pvc trust-svc-data -n marty
```

Or with kustomize:
```bash
kubectl delete -k .
```