# Marty Platform Monitoring

This directory contains monitoring configuration for the Marty microservices platform using Prometheus, Grafana, and Alertmanager.

## Components

- **Prometheus**: Metrics collection and alerting
- **Grafana**: Visualization and dashboards
- **Alertmanager**: Alert routing and notification

## Quick Start

### Deploy Monitoring Stack

```bash
# Add Helm repositories
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

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