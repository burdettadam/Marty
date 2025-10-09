# Marty Monitoring Stack

This directory contains the complete monitoring infrastructure for the Marty digital identity platform, including Prometheus, Grafana, and Alertmanager configured specifically for microservices observability.

## Overview

The monitoring stack provides:

- **Prometheus**: Metrics collection and storage with custom alerting rules
- **Grafana**: Visualization dashboards for business and technical metrics
- **Alertmanager**: Alert routing and notification management
- **Health Checks**: Advanced dependency monitoring for all services

## Components

### 1. Prometheus Configuration

**Location**: `prometheus/`

- **alert_rules.yml**: Comprehensive alerting for service health, business metrics, SLA violations, and infrastructure
- **recording_rules.yml**: SLI/SLO tracking with pre-calculated metrics for performance

**Key Features**:

- Multi-tier alerting (Critical, Warning, Info)
- Business-specific metrics for digital identity operations
- SLA compliance monitoring with error budgets
- Automatic service discovery via Kubernetes annotations

### 2. Grafana Dashboards

**Location**: `grafana/dashboards/`

- **marty-overview.json**: High-level platform overview with key business metrics
- **marty-service-detail.json**: Detailed service monitoring with performance metrics
- **marty-sla.json**: SLA tracking and compliance monitoring

**Dashboard Features**:

- Real-time metrics visualization
- Service health status indicators
- Business operation tracking (document verification, certificate validation)
- Performance percentiles and error rates
- Resource utilization monitoring

### 3. Helm Chart

**Location**: `helm/`

Complete Kubernetes deployment with:

- Environment-specific configurations
- Persistent storage for metrics and dashboards
- RBAC and security contexts
- Ingress configurations for external access
- Resource management and scaling

## Quick Start

### Prerequisites

- Kubernetes cluster (1.20+)
- Helm 3.x
- kubectl configured for your cluster

### Deploy Monitoring Stack

1. **Basic Development Deployment**:

   ```bash
   ./deploy-monitoring.sh
   ```

2. **Production Deployment**:

   ```bash
   ./deploy-monitoring.sh --environment production \
     --namespace marty-monitoring-prod
   ```

3. **Custom Configuration**:

   ```bash
   GRAFANA_ADMIN_PASSWORD="secure-password" \
   GRAFANA_INGRESS_ENABLED=true \
   DOMAIN="marty.example.com" \
   ./deploy-monitoring.sh --environment staging
   ```

### Access Services

After deployment, access the monitoring services:

```bash
# Prometheus
kubectl port-forward svc/marty-monitoring-prometheus 9090:9090 -n marty-monitoring

# Grafana
kubectl port-forward svc/marty-monitoring-grafana 3000:3000 -n marty-monitoring

# Alertmanager
kubectl port-forward svc/marty-monitoring-alertmanager 9093:9093 -n marty-monitoring
```

## Configuration

### Service Annotation for Monitoring

To enable monitoring for your Marty services, add these annotations:

```yaml
apiVersion: v1
kind: Service
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
spec:
  # ... service configuration
```

## Health Checks

Advanced health checking system with:

- **Database Connectivity**: PostgreSQL connection monitoring
- **gRPC Services**: Service mesh health verification
- **HTTP Endpoints**: REST API availability checking
- **System Resources**: CPU, memory, disk space monitoring
- **External Dependencies**: Trust stores, PKD synchronization

### Custom Health Checks

Services can register custom health check functions:

```python
from marty_common.health_checks import create_database_health_check
from marty_common.metrics_server import MetricsServer

# Create health check functions
db_check = create_database_health_check("postgresql://...")
api_check = create_http_health_check("https://external-api.com/health")

# Register with metrics server
metrics_server = MetricsServer()
metrics_server.health_checker.add_dependency("database", db_check)
metrics_server.health_checker.add_dependency("external_api", api_check)
```

# Install monitoring stack

helm install marty-monitoring ./helm/charts/monitoring

```

### Access Grafana

```bash
# Get Grafana URL
kubectl get svc marty-monitoring-grafana -n marty-monitoring

# Default credentials: admin/admin (change in production)
```

### Access Prometheus

```bash
# Get Prometheus URL
kubectl get svc marty-monitoring-prometheus-server -n marty-monitoring
```

## Metrics Collection

The monitoring stack collects metrics from:

### Service Metrics

- HTTP request/response metrics
- Error rates and latency percentiles
- Dead letter queue sizes
- Event processing queue sizes
- Database connection usage

### Infrastructure Metrics

- Container CPU and memory usage
- Kubernetes pod and node metrics
- Disk and network I/O

## Alerting

### Alert Rules

**Service Availability**

- `MartyServiceDown`: Service is down for >5 minutes
- `MartyServiceHighErrorRate`: Error rate >10% for >5 minutes
- `MartyServiceHighLatency`: 95th percentile latency >5s for >5 minutes

**Business Logic**

- `MartyDeadLetterQueueGrowing`: DLQ growing by >10 messages in 10 minutes
- `MartyDatabaseConnectionIssues`: DB connection usage >80%
- `MartyEventProcessingBacklog`: Event queue >1000 pending events

**Infrastructure**

- `KubernetesNodeDown`: K8s node down for >5 minutes
- `HighCPUUsage`: Container CPU >80% for >5 minutes
- `HighMemoryUsage`: Container memory >90% for >5 minutes
- `LowDiskSpace`: Disk usage >85% for >5 minutes

## Dashboards

### Marty Platform Overview

- Service health status
- Active alerts count
- Request rates by service
- Error rates and latency percentiles
- Dead letter queue sizes
- Event processing queues
- Database connection usage
- Container resource usage
- Node disk usage

## Configuration

### Adding New Metrics

1. **Service Metrics**: Add Prometheus client to your service and expose `/metrics` endpoint
2. **Custom Metrics**: Define new metric collectors in your service code
3. **Alert Rules**: Add rules to `prometheus/alert_rules.yml`
4. **Dashboards**: Update Grafana dashboard JSON files

### Example Service Metrics

```python
from prometheus_client import Counter, Histogram, Gauge

# Request metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
REQUEST_LATENCY = Histogram('http_request_duration_seconds', 'HTTP request latency', ['method', 'endpoint'])

# Business metrics
DLQ_SIZE = Gauge('marty_dead_letter_queue_size', 'Dead letter queue size', ['service'])
EVENT_QUEUE_SIZE = Gauge('marty_event_processing_queue_size', 'Event processing queue size', ['service'])
DB_CONNECTIONS = Gauge('marty_database_connections_active', 'Active database connections', ['service'])
DB_CONNECTIONS_MAX = Gauge('marty_database_connections_max', 'Maximum database connections', ['service'])
```

## Production Considerations

### Security

- Change default Grafana admin password
- Configure proper authentication (LDAP, OAuth)
- Use TLS for all monitoring endpoints
- Restrict network access to monitoring services

### Scaling

- Configure Prometheus retention policies
- Set up remote storage for long-term metrics
- Use Prometheus federation for multi-cluster setups
- Configure Grafana high availability

### Alerting

- Configure SMTP or webhook integrations
- Set up alert routing based on severity
- Define escalation policies
- Test alert configurations regularly

### Backup

- Backup Grafana dashboards and datasources
- Export Prometheus configuration
- Document alert rules and thresholds

## Troubleshooting

### Common Issues

**Metrics not appearing in Grafana**

- Check service `/metrics` endpoint is accessible
- Verify Prometheus service discovery configuration
- Check Prometheus targets status

**Alerts not firing**

- Validate alert rule expressions
- Check Prometheus rule evaluation
- Verify alertmanager configuration

**Dashboard not loading**

- Check Grafana datasource configuration
- Validate dashboard JSON syntax
- Ensure proper permissions

### Debugging Commands

```bash
# Check Prometheus targets
kubectl exec -it marty-monitoring-prometheus-server-0 -n marty-monitoring -- wget -qO- http://localhost:9090/api/v1/targets

# Check alert rules
kubectl exec -it marty-monitoring-prometheus-server-0 -n marty-monitoring -- wget -qO- http://localhost:9090/api/v1/rules

# Check Grafana logs
kubectl logs -f deployment/marty-monitoring-grafana -n marty-monitoring

# Check Alertmanager status
kubectl exec -it marty-monitoring-alertmanager-0 -n marty-monitoring -- wget -qO- http://localhost:9093/api/v2/status
```
