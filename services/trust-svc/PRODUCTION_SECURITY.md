# Production Security Implementation

## Overview

The Trust Service now includes enterprise-grade security features designed for production environments. This implementation provides comprehensive protection through multiple layers of security controls, including Vault integration, mutual TLS (mTLS), authentication, authorization, audit logging, and comprehensive monitoring.

## Architecture

### Security Layers

1. **Network Security** - mTLS, firewall rules, IP filtering
2. **Authentication** - JWT tokens, API keys, certificate-based auth
3. **Authorization** - Role-based access control (RBAC)
4. **Data Protection** - Encryption at rest and in transit
5. **Secrets Management** - HashiCorp Vault integration
6. **Audit & Compliance** - Comprehensive logging and monitoring

### Core Components

1. **`vault_client.py`** - HashiCorp Vault integration for secrets management
2. **`security.py`** - Authentication, authorization, and security middleware
3. **`secure_database.py`** - Database security with encryption and credential rotation
4. **`audit_logging.py`** - Comprehensive audit logging and compliance tracking
5. **`security_config.py`** - Configuration management for security settings
6. **`config/security.yaml`** - Production security configuration

## Features

### 1. HashiCorp Vault Integration

**Capabilities:**
- Dynamic secrets generation and rotation
- Certificate storage and management
- PKI certificate generation
- Database credential rotation
- JWT signing key management
- Encryption key storage

**Authentication Methods:**
- Direct token authentication (development)
- AppRole authentication (production)
- Kubernetes service account (optional)

**Secret Engines:**
- KV v2 for static secrets
- PKI for certificate management
- Database for dynamic credentials

```python
from vault_client import get_vault_client

# Get Vault client
vault_client = await get_vault_client()

# Store secret
await vault_client.set_secret("database/credentials", {
    "username": "app_user",
    "password": "secure_password"
})

# Generate certificate
cert_data = await vault_client.generate_certificate(
    common_name="trust-service.internal",
    alt_names=["trust-service", "localhost"],
    ttl="30d"
)
```

### 2. Mutual TLS (mTLS) Authentication

**Features:**
- Client certificate validation
- Certificate chain verification
- Common Name (CN) authorization
- Certificate revocation checking
- Automatic certificate rotation

**Configuration:**
```yaml
mtls:
  enabled: true
  require_client_cert: true
  verify_client_cert: true
  allowed_clients:
    - "trust-service-client"
    - "pkd-ingestion-service"
  min_tls_version: "TLSv1.2"
```

**Usage:**
```python
from security import MTLSAuthenticator

# Create mTLS authenticator
mtls_auth = MTLSAuthenticator(config)

# Add allowed client
mtls_auth.add_allowed_client("trusted-client")

# Validate client certificate
cert_info = mtls_auth.validate_client_certificate(cert_der_bytes)
```

### 3. JWT Token Authentication

**Features:**
- RS256 algorithm with key rotation
- Custom claims support
- Token expiry and validation
- Issuer and audience verification
- Automatic key loading from Vault

**Token Generation:**
```python
from security import JWTAuthenticator

jwt_auth = JWTAuthenticator(config)
await jwt_auth.initialize()

# Generate token
token = jwt_auth.generate_token(
    subject="user123",
    claims={"role": "admin", "permissions": ["read", "write"]},
    expires_in_minutes=60
)

# Validate token
payload = jwt_auth.validate_token(token)
```

### 4. API Key Authentication

**Features:**
- Secure API key generation
- Usage tracking and statistics
- Permission-based authorization
- Automatic rotation
- Storage in Vault

**API Key Management:**
```python
from security import APIKeyAuthenticator

api_auth = APIKeyAuthenticator(config)
await api_auth.initialize()

# Generate API key
api_key = api_auth.generate_api_key(
    client_name="integration-service",
    permissions=["certificate:validate", "trust:query"]
)

# Validate API key
key_data = api_auth.validate_api_key(api_key)
```

### 5. Rate Limiting

**Features:**
- Per-IP rate limiting
- Per-user rate limiting
- Per-API key rate limiting
- Configurable burst limits
- Real-time monitoring

**Configuration:**
```yaml
rate_limiting:
  enabled: true
  requests_per_minute: 1000
  burst_size: 100
  by_ip: true
  by_api_key: true
```

### 6. Database Security

**Features:**
- SSL/TLS encrypted connections
- Dynamic credential rotation via Vault
- Connection pool security
- Query logging and monitoring
- Connection lifetime management

**Secure Database Usage:**
```python
from secure_database import get_secure_database

# Get secure database manager
db_manager = await get_secure_database()

# Get secure session
async with db_manager.get_session() as session:
    result = await session.execute(text("SELECT * FROM certificates"))
    
# Health check
health = await db_manager.health_check()
```

### 7. Comprehensive Audit Logging

**Features:**
- Structured audit events
- Multiple log destinations (file, database, SIEM)
- Sensitive data encryption
- Compliance reporting
- Event correlation and analysis

**Event Types:**
- Authentication (success/failure)
- Authorization decisions
- Certificate operations
- Data access and modification
- Security events and alerts
- System events

**Audit Event Creation:**
```python
from audit_logging import AuditEventBuilder, AuditEventType, AuditSeverity

# Create audit event
event = AuditEventBuilder() \
    .event_type(AuditEventType.AUTH_SUCCESS) \
    .severity(AuditSeverity.MEDIUM) \
    .user_id("user123") \
    .source_ip("192.168.1.100") \
    .action("login") \
    .outcome("success") \
    .detail("method", "jwt") \
    .build()

# Log event
audit_logger = await get_audit_logger()
await audit_logger.log_event(event)
```

### 8. Security Configuration Management

**Features:**
- Environment-specific configurations
- YAML-based configuration files
- Environment variable overrides
- Configuration validation
- Production security enforcement

**Configuration Structure:**
```
config/
├── security.yaml              # Base security configuration
├── security-development.yaml  # Development overrides
├── security-staging.yaml      # Staging overrides
└── security-production.yaml   # Production overrides
```

**Loading Configuration:**
```python
from security_config import get_security_config

# Load configuration
config = get_security_config()

# Check environment
if config.security_level == SecurityLevel.PRODUCTION:
    # Production-specific logic
    pass
```

## Security Middleware Integration

### FastAPI Integration

```python
from fastapi import FastAPI, Depends
from security import get_security_middleware

app = FastAPI()
security_middleware = await get_security_middleware()

@app.middleware("http")
async def security_middleware_handler(request: Request, call_next):
    # Authenticate request
    auth_context = await security_middleware.authenticate_request(request)
    
    # Check rate limits
    if not auth_context.get('authenticated'):
        raise HTTPException(status_code=401, detail="Authentication required")
    
    response = await call_next(request)
    
    # Add security headers
    security_middleware.add_security_headers(response)
    
    return response
```

### gRPC Integration

```python
from security import MTLSServerInterceptor, RateLimitInterceptor

# Create gRPC server with security interceptors
server = grpc.server(
    futures.ThreadPoolExecutor(max_workers=10),
    interceptors=[
        MTLSServerInterceptor(mtls_auth),
        RateLimitInterceptor(rate_limiter)
    ]
)
```

## Deployment Configuration

### Environment Variables

```bash
# Vault configuration
export VAULT_ADDR=https://vault.internal:8200
export VAULT_ROLE_ID=your-role-id
export VAULT_SECRET_ID=your-secret-id

# Security settings
export ENVIRONMENT=production
export MTLS_ENABLED=true
export AUDIT_LOGGING_ENABLED=true

# Database security
export DB_SSL_MODE=require
export DB_CREDENTIAL_ROTATION=true
```

### Docker Secrets

```yaml
# docker-compose.yml
version: '3.8'
services:
  trust-service:
    image: trust-service:latest
    secrets:
      - vault_role_id
      - vault_secret_id
      - tls_server_cert
      - tls_server_key
      - tls_client_ca
    environment:
      - VAULT_ADDR=https://vault.internal:8200
      - VAULT_ROLE_ID_FILE=/run/secrets/vault_role_id
      - VAULT_SECRET_ID_FILE=/run/secrets/vault_secret_id

secrets:
  vault_role_id:
    external: true
  vault_secret_id:
    external: true
  tls_server_cert:
    file: ./secrets/server.crt
  tls_server_key:
    file: ./secrets/server.key
  tls_client_ca:
    file: ./secrets/ca.crt
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: trust-service
spec:
  template:
    spec:
      serviceAccountName: trust-service
      containers:
      - name: trust-service
        image: trust-service:latest
        env:
        - name: VAULT_ADDR
          value: "https://vault.vault.svc.cluster.local:8200"
        - name: VAULT_ROLE_ID
          valueFrom:
            secretKeyRef:
              name: vault-auth
              key: role-id
        - name: VAULT_SECRET_ID
          valueFrom:
            secretKeyRef:
              name: vault-auth
              key: secret-id
        volumeMounts:
        - name: tls-certs
          mountPath: /secrets/tls
          readOnly: true
      volumes:
      - name: tls-certs
        secret:
          secretName: trust-service-tls
```

## Security Monitoring

### Metrics Collection

The security implementation provides comprehensive metrics:

```python
# Authentication metrics
security_auth_attempts_total{method="jwt", result="success"}
security_auth_attempts_total{method="mtls", result="failure"}

# Rate limiting metrics
security_rate_limit_exceeded_total{client_type="ip"}
security_rate_limit_requests_per_second{client_id="api_key_123"}

# Certificate metrics
security_certificate_validations_total{type="csca", result="valid"}
security_certificate_errors_total{error_type="expired"}

# Audit metrics
security_audit_events_total{event_type="auth_success", severity="medium"}
security_audit_log_errors_total{destination="database"}
```

### Alerting Rules

```yaml
# Prometheus alerting rules
groups:
- name: trust-service-security
  rules:
  - alert: HighFailedAuthenticationRate
    expr: rate(security_auth_attempts_total{result="failure"}[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High authentication failure rate detected"
      
  - alert: SecurityAuditLogFailure
    expr: increase(security_audit_log_errors_total[5m]) > 0
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: "Audit logging failure detected"
      
  - alert: CertificateValidationErrors
    expr: rate(security_certificate_errors_total[5m]) > 0.05
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Increased certificate validation errors"
```

## Security Testing

### Running Security Tests

```bash
# Run all security tests
pytest tests/test_security.py -v

# Run specific test categories
pytest tests/test_security.py::TestMTLSAuthentication -v
pytest tests/test_security.py::TestVaultClient -v
pytest tests/test_security.py::TestAuditLogging -v

# Run with coverage
pytest tests/test_security.py --cov=security --cov-report=html
```

### Security Benchmarks

```bash
# Performance testing
pytest tests/test_security.py::TestSecurityBenchmarks -v

# Load testing authentication
pytest tests/test_security.py::TestSecurityBenchmarks::test_authentication_performance -v
```

### Vulnerability Scanning

```bash
# Static analysis
bandit -r . -f json -o security-report.json

# Dependency scanning
safety check --json

# Container scanning
trivy image trust-service:latest
```

## Compliance Features

### GDPR Compliance

- **Data Protection**: Encryption at rest and in transit
- **Right to Erasure**: Automated data deletion capabilities
- **Data Portability**: Structured data export functionality
- **Audit Trail**: Comprehensive logging of data access and modifications
- **Privacy by Design**: Minimal data collection and retention policies

### SOC 2 Compliance

- **Security**: Multi-factor authentication, encryption, access controls
- **Availability**: High availability architecture, monitoring, alerting
- **Processing Integrity**: Data validation, error handling, audit trails
- **Confidentiality**: Access controls, data classification, encryption
- **Privacy**: Data minimization, consent management, privacy controls

### ISO 27001 Compliance

- **Information Security Management**: Comprehensive security framework
- **Risk Assessment**: Automated vulnerability scanning and assessment
- **Incident Response**: Security event detection and response procedures
- **Access Control**: Role-based access control and privileged access management
- **Cryptography**: Strong encryption and key management practices

## Troubleshooting

### Common Issues

**Vault Connection Errors:**
```
VaultConnectionError: Vault connection failed
```
- Check Vault server availability
- Verify authentication credentials
- Check network connectivity and firewall rules

**mTLS Certificate Validation Failures:**
```
CertificateValidationError: Client 'unknown-client' not authorized
```
- Verify client certificate CN is in allowed clients list
- Check certificate validity period
- Verify certificate chain and CA

**Rate Limiting Issues:**
```
RateLimitError: Rate limit exceeded
```
- Check rate limiting configuration
- Monitor client request patterns
- Adjust limits based on usage patterns

**Audit Logging Errors:**
```
Failed to log audit event: Database connection failed
```
- Check database connectivity
- Verify audit table exists
- Check disk space for file logging

### Debug Mode

Enable debug logging for detailed security information:

```python
import logging
logging.getLogger('security').setLevel(logging.DEBUG)
logging.getLogger('vault_client').setLevel(logging.DEBUG)
logging.getLogger('audit_logging').setLevel(logging.DEBUG)
```

### Health Checks

```bash
# Check Vault connectivity
curl -k https://vault.internal:8200/v1/sys/health

# Check mTLS configuration
openssl s_client -connect trust-service:50051 -cert client.crt -key client.key

# Check database security
psql "sslmode=require host=db.internal" -c "SELECT version()"
```

## Best Practices

### Security Configuration

1. **Use environment-specific configurations** for different deployment environments
2. **Enable all security features in production** (mTLS, audit logging, encryption)
3. **Regularly rotate secrets and certificates** using automated processes
4. **Monitor security metrics and alerts** for anomalous behavior
5. **Keep security dependencies updated** and scan for vulnerabilities

### Operational Security

1. **Implement defense in depth** with multiple security layers
2. **Follow principle of least privilege** for all access controls
3. **Regular security audits and penetration testing**
4. **Incident response procedures** for security events
5. **Security training** for development and operations teams

### Development Security

1. **Security by design** - integrate security from the start
2. **Code reviews** with security focus
3. **Static analysis** and vulnerability scanning
4. **Security testing** in CI/CD pipelines
5. **Threat modeling** for new features

## Future Enhancements

### Planned Security Features

- **Zero Trust Architecture** - Never trust, always verify
- **Behavioral Analytics** - ML-based anomaly detection
- **Hardware Security Modules (HSM)** - Hardware-backed key protection
- **Certificate Transparency Monitoring** - Monitor certificate issuance
- **Advanced Threat Protection** - Real-time threat detection and response

### Integration Roadmap

- **SIEM Integration** - Security Information and Event Management
- **Identity Providers** - OIDC/SAML integration
- **Privileged Access Management** - PAM solution integration
- **Data Loss Prevention** - DLP policy enforcement
- **Compliance Automation** - Automated compliance reporting

## Conclusion

The production security implementation provides enterprise-grade security for the Trust Service with comprehensive protection across all layers. The implementation follows security best practices, industry standards, and compliance requirements to ensure robust protection of sensitive certificate data and operations.

The modular design allows for easy extension and customization while maintaining security standards. Regular updates and monitoring ensure continued protection against evolving threats.