# Marty Platform Demo Environment

A comprehensive "golden path" demonstration of the Marty digital identity platform with full observability stack, sample data, and a user-friendly web interface.

## 🚀 Quick Start

Get the complete Marty demo environment running in one command:

```bash
# Start the demo environment
docker-compose -f docker/docker-compose.demo.yml --env-file .env.demo up -d

# View logs (optional)
docker-compose -f docker/docker-compose.demo.yml logs -f
```

Once running, access the demo at: **<http://localhost:8093>**

## 📋 What's Included

### Core Services

- **All gRPC Services**: Trust Anchor, CSCA Service, Document Signer, Inspection System, Passport Engine, MDL Engine, mDoc Engine, DTC Engine, Credential Ledger
- **PKD Service**: Public Key Directory synchronization
- **Issuer REST API**: OID4VCI-compliant credential issuance
- **Demo UI**: Web interface for credential operations

### Infrastructure

- **PostgreSQL**: Multi-database setup (trust_db, credentials_db, audit_db)
- **MinIO**: S3-compatible object storage with pre-created buckets
- **HashiCorp Vault**: Secrets management (dev mode with demo data)

### Observability Stack

- **OpenTelemetry Collector**: Centralized telemetry collection
- **Jaeger**: Distributed tracing and request flow analysis
- **Prometheus**: Metrics collection and time-series database
- **Grafana**: Metrics visualization and dashboards

### Sample Data

- Pre-loaded passport and MDL samples
- Demo certificates and trust anchors
- Sample verifiable credentials
- Mock API keys and secrets

## 🌐 Service Endpoints

| Service | URL | Description |
|---------|-----|-------------|
| **Demo UI** | <http://localhost:8093> | Main demo interface |
| **Service Registry** | <http://localhost:8099> | Service overview dashboard |
| **Issuer API** | <http://localhost:8092> | OID4VCI REST API |
| **Trust Service** | <http://localhost:8090> | Trust anchor HTTP API |
| **PKD Service** | <http://localhost:8088> | Public Key Directory API |
| **Grafana** | <http://localhost:3000> | Metrics dashboards (admin/admin) |
| **Jaeger** | <http://localhost:16686> | Tracing interface |
| **Prometheus** | <http://localhost:9090> | Metrics collection |
| **MinIO Console** | <http://localhost:9001> | Object storage (minioadmin/minioadmin123) |
| **Vault UI** | <http://localhost:8200> | Secrets management (token: demo-root-token) |

## 🎯 Demo Scenarios

### 1. Issue a Verifiable Credential

1. Navigate to <http://localhost:8093/issue>
2. Select credential type (Passport, MDL, or mDoc)
3. Fill in the form or use "Fill Sample Data"
4. Submit to create a verifiable credential
5. View the generated credential JSON

### 2. Verify a Presentation

1. Go to <http://localhost:8093/verify>
2. Use "Use Sample Data" to populate a test presentation
3. Submit for verification
4. Review the verification results and security checks

### 3. Explore Observability

1. **Traces**: Visit <http://localhost:8093/traces> or <http://localhost:16686>
   - Search for traces by service name (e.g., "issuer-api")
   - Filter by operation or error status
   - Analyze request flows across microservices

2. **Metrics**: Visit <http://localhost:8093/metrics> or <http://localhost:3000>
   - View system performance dashboards
   - Monitor business metrics (credentials issued, verifications)
   - Check resource utilization

### 4. Manage Demo Data

1. Access <http://localhost:8093/demo-data>
2. View pre-loaded sample passports and MDLs
3. See issued credentials and their status
4. Generate additional test data

## ⚙️ Configuration

### Environment Variables

The `.env.demo` file contains all configuration. Key variables:

```bash
# Database
POSTGRES_USER=martyuser
POSTGRES_PASSWORD=martypassword

# Object Storage  
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin123

# Vault
VAULT_ROOT_TOKEN=demo-root-token

# Demo Features
ENABLE_MOCK_DATA=true
DEMO_AUTO_APPROVE_CREDENTIALS=true
```

### Service Ports

All services use non-conflicting ports from the main development setup:

- Demo services use ports 8090-8099
- Observability uses standard ports (3000, 9090, 16686)
- Infrastructure uses standard ports (5432, 9000/9001, 8200)

## 🔧 Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Demo UI       │────│   Issuer API     │────│  gRPC Services  │
│   (Port 8093)   │    │   (Port 8092)    │    │  (Various ports)│
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
    ┌────────────────────────────┼────────────────────────────┐
    │                            │                            │
┌───▼──────┐  ┌─────────────┐  ┌─▼──────────┐  ┌─────────────┐
│PostgreSQL│  │    MinIO    │  │   Vault    │  │OTEL Collector│
│(Port 5432)│  │(9000/9001) │  │(Port 8200) │  │(4317/4318)  │
└──────────┘  └─────────────┘  └────────────┘  └─────────────┘
                                                      │
              ┌──────────────────────────────────────┼──────────────┐
              │                                      │              │
      ┌───────▼────┐            ┌─────────────┐     ┌▼──────────┐   │
      │  Jaeger    │            │  Prometheus │     │  Grafana  │   │
      │(Port 16686)│            │(Port 9090)  │     │(Port 3000)│   │
      └────────────┘            └─────────────┘     └───────────┘   │
                                                                    │
                              ┌─────────────────────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   All Services    │
                    │ (Auto-instrumented│
                    │   with OTEL)      │
                    └───────────────────┘
```

## 🛠️ Troubleshooting

### Common Issues

**Services won't start:**

```bash
# Check for port conflicts
docker-compose -f docker/docker-compose.demo.yml ps
netstat -ln | grep :8093

# Restart specific service
docker-compose -f docker/docker-compose.demo.yml restart ui-app-demo
```

**Database connection issues:**

```bash
# Check PostgreSQL logs
docker-compose -f docker/docker-compose.demo.yml logs postgres-demo

# Connect to database manually
docker exec -it marty-demo-postgres psql -U martyuser -d martydb
```

**Missing sample data:**

```bash
# Re-run the seed script
docker-compose -f docker/docker-compose.demo.yml restart demo-seed

# Check seed logs
docker-compose -f docker/docker-compose.demo.yml logs demo-seed
```

### Health Checks

All services include health checks. Monitor status:

```bash
# Check all service health
docker-compose -f docker/docker-compose.demo.yml ps

# Individual service logs
docker-compose -f docker/docker-compose.demo.yml logs [service-name]
```

### Performance Tuning

For better performance on resource-constrained systems:

1. **Reduce replicas**: Edit docker-compose.demo.yml to remove unused services
2. **Memory limits**: Add memory constraints to service definitions
3. **Selective startup**: Start only core services first, then observability

## 🧹 Cleanup

Stop and remove all demo resources:

```bash
# Stop all services
docker-compose -f docker/docker-compose.demo.yml down

# Remove all demo data (destructive!)
docker-compose -f docker/docker-compose.demo.yml down -v

# Remove demo images (optional)
docker system prune -f
```

## 🔒 Security Notes

⚠️ **DEMO ONLY**: This environment is configured for demonstration purposes with:

- Default passwords and API keys
- Insecure connections allowed
- Self-signed certificates
- Disabled TLS verification
- Mock data and simplified security

**Never use this configuration in production!**

## 📚 Next Steps

1. **Explore the API**: Use the OpenAPI docs at <http://localhost:8092/docs>
2. **Custom Dashboards**: Create Grafana dashboards for your specific metrics
3. **Production Setup**: Review the production deployment guides in `/docs`
4. **Integration**: Integrate with your existing identity systems
5. **Customization**: Modify credential schemas and verification policies

## 🤝 Contributing

To contribute improvements to the demo:

1. Test changes against the demo environment
2. Update documentation for new features
3. Ensure backward compatibility with existing demo scenarios
4. Add appropriate health checks for new services

---

**Happy exploring the Marty platform! 🎉**

For questions or issues, check the logs or create an issue in the repository.
