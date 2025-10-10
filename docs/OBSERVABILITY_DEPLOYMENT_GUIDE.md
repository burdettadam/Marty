# Unified Observability Deployment Guide

This guide provides step-by-step instructions for deploying the unified observability infrastructure for Marty microservices.

## Prerequisites

- Kubernetes cluster with monitoring namespace
- Helm 3.x installed
- kubectl configured for target cluster
- Docker images for Marty services with observability framework

## Infrastructure Components

### 1. Prometheus Stack Deployment

Deploy Prometheus with the Marty-specific configuration:

```bash
# Add Prometheus community Helm repo
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Create monitoring namespace
kubectl create namespace marty-monitoring

# Deploy Prometheus stack
helm install marty-prometheus prometheus-community/kube-prometheus-stack \
  --namespace marty-monitoring \
  --values monitoring/prometheus-values.yaml
```

### 2. Grafana Dashboard Import

Import the unified observability dashboard:

```bash
# Copy dashboard to Grafana pod
kubectl cp monitoring/grafana_dashboard.json marty-monitoring/grafana-pod:/tmp/

# Import dashboard via Grafana API
kubectl exec -n marty-monitoring grafana-pod -- \
  curl -X POST http://localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @/tmp/grafana_dashboard.json
```

### 3. Jaeger Tracing Deployment

Deploy Jaeger for distributed tracing:

```bash
# Add Jaeger Helm repo
helm repo add jaegertracing https://jaegertracing.github.io/helm-charts
helm repo update

# Deploy Jaeger
helm install marty-jaeger jaegertracing/jaeger \
  --namespace marty-monitoring \
  --values monitoring/jaeger-values.yaml
```

## Service Configuration

### 1. Update Service Configurations

Ensure all services have monitoring configuration:

```yaml
# Example: config/services/trust_anchor.yaml
monitoring:
  metrics:
    enabled: true
    port: 8080
    path: "/metrics"
  tracing:
    enabled: true
    jaeger_endpoint: "http://marty-jaeger-collector:14268/api/traces"
  health_checks:
    enabled: true
    endpoint: "/health"
```

### 2. Service Discovery Configuration

Update Kubernetes service definitions to include monitoring ports:

```yaml
# k8s/services/trust-anchor-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: trust-anchor
  labels:
    app: trust-anchor
    monitoring: "true"
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
spec:
  ports:
  - name: grpc
    port: 50051
    targetPort: 50051
  - name: metrics
    port: 8080
    targetPort: 8080
  - name: health
    port: 8081
    targetPort: 8081
  selector:
    app: trust-anchor
```

## Prometheus Configuration

### 1. Service Monitor Configuration

Create ServiceMonitor for automatic metric scraping:

```yaml
# monitoring/service-monitors.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: marty-services
  namespace: marty-monitoring
  labels:
    app: marty-microservices
spec:
  selector:
    matchLabels:
      monitoring: "true"
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
  namespaceSelector:
    matchNames:
    - default
    - marty-production
```

### 2. Alert Manager Configuration

Configure AlertManager for Marty-specific routing:

```yaml
# monitoring/alertmanager-config.yaml
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'marty-monitoring@example.com'

route:
  group_by: ['alertname', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'marty-alerts'
  routes:
  - match:
      team: security
    receiver: 'security-team'
  - match:
      team: platform
    receiver: 'platform-team'

receivers:
- name: 'marty-alerts'
  email_configs:
  - to: 'marty-ops@example.com'
    subject: '[Marty] {{ .GroupLabels.alertname }}'
    body: |
      {{ range .Alerts }}
      Alert: {{ .Annotations.summary }}
      Description: {{ .Annotations.description }}
      Service: {{ .Labels.service }}
      {{ end }}

- name: 'security-team'
  email_configs:
  - to: 'security-team@example.com'
    subject: '[Security Alert] {{ .GroupLabels.alertname }}'

- name: 'platform-team'
  slack_configs:
  - api_url: 'https://hooks.slack.com/services/...'
    channel: '#platform-alerts'
    title: 'Platform Alert: {{ .GroupLabels.alertname }}'
```

## Deployment Steps

### Phase 1: Infrastructure Setup

```bash
#!/bin/bash
# deploy-observability.sh

set -e

echo "Deploying Marty Observability Infrastructure..."

# Create namespace
kubectl create namespace marty-monitoring --dry-run=client -o yaml | kubectl apply -f -

# Deploy Prometheus stack
echo "Deploying Prometheus..."
helm upgrade --install marty-prometheus prometheus-community/kube-prometheus-stack \
  --namespace marty-monitoring \
  --values monitoring/prometheus-values.yaml \
  --wait

# Deploy Jaeger
echo "Deploying Jaeger..."
helm upgrade --install marty-jaeger jaegertracing/jaeger \
  --namespace marty-monitoring \
  --values monitoring/jaeger-values.yaml \
  --wait

# Apply service monitors
echo "Applying service monitors..."
kubectl apply -f monitoring/service-monitors.yaml

# Apply alerting rules
echo "Applying alerting rules..."
kubectl apply -f monitoring/prometheus-rules.yaml

echo "Observability infrastructure deployed successfully!"
```

### Phase 2: Service Deployment

```bash
#!/bin/bash
# deploy-services.sh

set -e

echo "Deploying Marty Services with Observability..."

# Deploy services with observability enabled
kubectl apply -f k8s/services/

# Wait for services to be ready
kubectl wait --for=condition=ready pod -l app=trust-anchor --timeout=300s
kubectl wait --for=condition=ready pod -l app=document-signer --timeout=300s

# Verify metrics endpoints
kubectl get pods -l monitoring=true
kubectl port-forward service/trust-anchor 8080:8080 &
curl http://localhost:8080/metrics

echo "Services deployed with observability enabled!"
```

### Phase 3: Dashboard Configuration

```bash
#!/bin/bash
# configure-dashboards.sh

set -e

echo "Configuring Grafana dashboards..."

# Get Grafana admin password
GRAFANA_PASSWORD=$(kubectl get secret marty-prometheus-grafana -o jsonpath="{.data.admin-password}" | base64 --decode)

# Port forward to Grafana
kubectl port-forward service/marty-prometheus-grafana 3000:80 &
GRAFANA_PID=$!

sleep 10

# Import dashboard
curl -X POST http://admin:${GRAFANA_PASSWORD}@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @monitoring/grafana_dashboard.json

# Kill port forward
kill $GRAFANA_PID

echo "Dashboards configured successfully!"
```

## Verification Steps

### 1. Check Prometheus Targets

```bash
# Port forward to Prometheus
kubectl port-forward service/marty-prometheus-kube-prom-prometheus 9090:9090

# Visit http://localhost:9090/targets
# Verify all Marty services are being scraped
```

### 2. Verify Metrics Collection

```bash
# Query Marty-specific metrics
curl -s http://localhost:9090/api/v1/query?query=marty_service_requests_total | jq

# Expected output should show metrics from all services
```

### 3. Check Distributed Tracing

```bash
# Port forward to Jaeger
kubectl port-forward service/marty-jaeger-query 16686:16686

# Visit http://localhost:16686
# Verify traces are being collected from services
```

### 4. Test Health Endpoints

```bash
# Check service health
kubectl exec -it deployment/trust-anchor -- curl localhost:8081/health

# Expected output:
# {"status": "healthy", "checks": {"trust_store": "healthy", "pkd_connectivity": "healthy"}}
```

## Troubleshooting

### Common Issues

1. **Metrics not appearing in Prometheus**
   - Check service annotations: `prometheus.io/scrape: "true"`
   - Verify network policies allow scraping
   - Check service monitor configuration

2. **Traces not appearing in Jaeger**
   - Verify Jaeger endpoint configuration in services
   - Check service mesh configuration if using Istio
   - Verify OTLP collector is receiving traces

3. **Alerts not firing**
   - Check Prometheus rules syntax
   - Verify AlertManager routing configuration
   - Test alert expressions manually in Prometheus

### Debug Commands

```bash
# Check Prometheus configuration
kubectl get prometheusrules -n marty-monitoring

# Check service monitor status
kubectl describe servicemonitor marty-services -n marty-monitoring

# Check Grafana logs
kubectl logs deployment/marty-prometheus-grafana -n marty-monitoring

# Check Jaeger collector logs
kubectl logs deployment/marty-jaeger-collector -n marty-monitoring
```

## Performance Tuning

### Metrics Optimization

```yaml
# Reduce metric cardinality
monitoring:
  metrics:
    cardinality_limits:
      max_labels: 10
      max_label_values: 1000
    retention_policies:
      - metric_regex: "marty_.*_bucket"
        retention: "7d"
      - metric_regex: "marty_.*_total"
        retention: "30d"
```

### Tracing Sampling

```yaml
# Implement sampling for high-throughput services
tracing:
  sampling:
    type: "probabilistic"
    rate: 0.1  # Sample 10% of traces
  batch_processor:
    timeout: 1s
    send_batch_size: 1024
```

### Storage Configuration

```yaml
# Optimize Prometheus storage
prometheus:
  retention: "30d"
  retention_size: "100GiB"
  storage:
    volumeClaimTemplate:
      spec:
        storageClassName: "fast-ssd"
        resources:
          requests:
            storage: 200Gi
```

## Maintenance

### Regular Tasks

1. **Dashboard Updates**: Update dashboards when adding new services
2. **Alert Tuning**: Adjust alert thresholds based on operational experience
3. **Metric Cleanup**: Remove unused metrics to control cardinality
4. **Performance Review**: Regular performance analysis and optimization

### Backup Procedures

```bash
# Backup Grafana dashboards
kubectl exec marty-prometheus-grafana-pod -- \
  sqlite3 /var/lib/grafana/grafana.db ".backup /tmp/grafana_backup.db"

# Backup Prometheus data
kubectl exec marty-prometheus-pod -- \
  tar czf /tmp/prometheus_backup.tar.gz /prometheus/data
```

This deployment guide provides comprehensive instructions for implementing the unified observability infrastructure across the Marty microservices platform.