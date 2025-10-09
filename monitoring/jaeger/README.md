# Marty Observability Stack

This directory contains the observability infrastructure for local development and testing of the Marty microservices platform.

## Components

### Jaeger Tracing

- **Jaeger All-in-One**: Complete tracing backend with UI, collector, and storage
- **OpenTelemetry Collector**: Optional advanced routing and processing (use profile `with-collector`)

## Quick Start

### Basic Jaeger Setup

```bash
# Start Jaeger for basic tracing
docker-compose up -d jaeger

# View traces at: http://localhost:16686
```

### Advanced Setup with OTEL Collector

```bash
# Start with OpenTelemetry Collector for advanced processing
docker-compose --profile with-collector up -d

# Jaeger UI: http://localhost:16686
# OTEL Collector metrics: http://localhost:8889/metrics
# OTEL Collector health: http://localhost:13133
```

## Service Configuration

Configure your Marty services to send traces to the local setup:

### Environment Variables

```bash
# Enable tracing
export OTEL_TRACING_ENABLED=true
export OTEL_SERVICE_NAME=your-service-name
export OTEL_SERVICE_VERSION=1.0.0
export OTEL_ENVIRONMENT=development

# Configure OTLP endpoint
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
export OTEL_EXPORTER_OTLP_INSECURE=true

# Optional: Enable console export for debugging
export OTEL_CONSOLE_EXPORT=true
```

### Direct Jaeger (without collector)

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
```

### Via OTEL Collector

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4319
```

## Ports Reference

| Service | Port | Purpose |
|---------|------|---------|
| Jaeger UI | 16686 | Web interface for viewing traces |
| Jaeger OTLP gRPC | 4317 | OpenTelemetry gRPC endpoint |
| Jaeger OTLP HTTP | 4318 | OpenTelemetry HTTP endpoint |
| Jaeger Thrift | 14268 | Native Jaeger HTTP endpoint |
| Jaeger gRPC | 14250 | Native Jaeger gRPC endpoint |
| Jaeger Agent UDP | 6831/6832 | Legacy Jaeger agent |
| Jaeger Health | 5778 | Health check endpoint |
| Zipkin | 9411 | Zipkin compatibility |
| OTEL Collector gRPC | 4319 | OTEL Collector gRPC (when using profile) |
| OTEL Collector HTTP | 4320 | OTEL Collector HTTP (when using profile) |
| OTEL Metrics | 8889 | Prometheus metrics from collector |
| OTEL Health | 13133 | OTEL Collector health check |

## Integration with Marty Services

The Marty services are configured to automatically instrument gRPC calls when tracing is enabled. The `marty_common.otel` module provides:

- Automatic OTLP exporter configuration
- gRPC client/server instrumentation
- Environment-based feature toggles
- Structured logging with trace correlation

## Viewing Traces

1. Start the observability stack: `docker-compose up -d`
2. Run your Marty services with tracing enabled
3. Generate some traffic to create traces
4. Visit <http://localhost:16686> to view traces in Jaeger UI

## Troubleshooting

### No traces appearing

1. Check service logs for OpenTelemetry initialization messages
2. Verify `OTEL_TRACING_ENABLED=true` is set
3. Check network connectivity to OTLP endpoint
4. Use `OTEL_CONSOLE_EXPORT=true` to see traces in service logs

### Collector not starting

1. Check the collector configuration: `docker-compose logs otel-collector`
2. Verify Jaeger is healthy: `docker-compose ps jaeger`
3. Check for port conflicts

### Performance impact

- Adjust sampling rates in production
- Use head-based sampling in the collector
- Monitor memory usage with the memory_limiter processor

## Production Considerations

This setup is designed for development. For production:

1. Replace Jaeger all-in-one with distributed components
2. Use persistent storage (Elasticsearch, Cassandra)
3. Configure proper sampling strategies
4. Set up authentication and TLS
5. Use the Helm charts in `helm/` directory for Kubernetes deployment
