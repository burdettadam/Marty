# Marty gRPC Service

[![CI](https://github.com/burdettadam/Marty/workflows/Marty%20CI/badge.svg)](https://github.com/burdettadam/Marty/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Educational Use Only](https://img.shields.io/badge/License-Educational%20Use%20Only-red.svg)](#license)
[![gRPC](https://img.shields.io/badge/gRPC-1.59+-green.svg)](https://grpc.io/)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)](https://docs.docker.com/compose/)

## Documentation

🗺️ **[Platform Architecture](docs/architecture.md)** - The complete "Map of Marty" - system architecture, service layers, and reference flows

🏢 **[Business Overview](docs/BUSINESS_OVERVIEW.md)** - Executive summary and ROI analysis for stakeholders

⚡ **[User Guide](docs/USER_GUIDE.md)** - Get started quickly with practical examples

🛠️ **[Developer Guide](docs/DEVELOPER_GUIDE.md)** - Complete technical documentation and development guides

📄 **[API Reference](docs/api/openapi.yaml)** - OpenAPI specification for REST endpoints

### Implementation Guides

- **[DRY Implementation Guide](docs/DRY_IMPLEMENTATION_GUIDE.md)** - Don't Repeat Yourself patterns and code reduction
- **[gRPC Service Factory Guide](docs/GRPC_SERVICE_FACTORY_GUIDE.md)** - Ultra-DRY service creation patterns
- **[Security Implementation](docs/SECURITY.md)** - Production security features and compliance
- **[Prometheus Monitoring](docs/PROMETHEUS_MONITORING.md)** - Enterprise-grade monitoring and alerting
- **[Resilience Framework](docs/RESILIENCE.md)** - Circuit breakers, retries, and error handling
- **[MyPy Type Checking](docs/MYPY_QUICKSTART.md)** - Strong typing implementation guide

### Standards and Protocols

- **[Cryptographic Boundaries](docs/CRYPTOGRAPHIC_BOUNDARIES_GUIDE.md)** - Crypto security and role separation
- **[Trust Services Architecture](docs/TRUST_SERVICES_ARCHITECTURE.md)** - PKI and certificate management
- **[Unified Verification Protocol](docs/UNIFIED_VERIFICATION_PROTOCOL.md)** - Multi-document verification flows
- **[SPHEREON OIDC4VC Integration](docs/SPHEREON_OIDC4VC_INTEGRATION.md)** - OpenID4VC compatibility testing-Compose-blue.svg)](<https://docs.docker.com/compose/>)

🎓 **Educational Portfolio Project - ICAO Standards Learning Implementation**

> ⚠️ **EDUCATIONAL USE ONLY** - This project is developed for learning ICAO standards and portfolio demonstration purposes. Not intended for production use.

Marty is a comprehensive learning project that implements ICAO PKI standards for electronic passport (eMRTD) issuance and verification, mobile driving licenses (mDL), and digital travel credentials (DTC). This project serves as both a portfolio demonstration and a practical exploration of international digital identity standards.

## 🎯 Educational Goals

This project was developed to:

- **Learn ICAO Standards**: Practical implementation of ICAO Doc 9303 and ISO/IEC 18013-5
- **Portfolio Demonstration**: Showcase microservices architecture and cryptographic implementations
- **Standards Exploration**: Deep dive into international digital identity document specifications
- **Security Learning**: Hands-on experience with PKI, certificate management, and cryptographic protocols

## 🔑 Key Features (Educational Implementation)

- **ICAO Compliant**: Educational implementation of ICAO Doc 9303 and ISO/IEC 18013-5 standards
- **Microservices Architecture**: Learning-focused service-oriented design patterns
- **Cryptographic Implementation**: Educational exploration of PKI and certificate management
- **Multi-Document Support**: Academic study of eMRTDs, mDLs, mDocs, and Digital Travel Credentials
- **Modern Development Practices**: Portfolio demonstration using Python 3.10+, gRPC, Docker, PostgreSQL
- **Standards Research**: Comprehensive documentation and implementation notes

### 🚀 Recent Platform Enhancements

- **Ultra-DRY Architecture**: 60-90% code reduction through service factory patterns and shared components
- **Enterprise Monitoring**: Prometheus metrics, health checks, and Grafana dashboards for all services
- **Production Security**: HashiCorp Vault integration, mTLS authentication, RBAC, and audit logging
- **Strong Typing**: MyPy strict mode with comprehensive type annotations and protocol interfaces
- **Resilience Framework**: Circuit breakers, retry mechanisms, and failure injection for reliability testing
- **EUDI Bridge**: European Digital Identity Wallet compatibility and cross-border verification
- **OpenID4VC Integration**: Full OIDC4VCI/OID4VP support with Sphereon compatibility testing

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client Apps   │    │  Verification   │    │   Admin UI      │
│  (Mobile/Web)   │    │    Systems      │    │   (FastAPI)     │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │      UI App Service     │
                    │     (Port 8090)        │
                    │    gRPC Gateway        │
                    └────────────┬────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                       │                        │
        ▼                       ▼                        ▼
┌──────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ Passport     │    │   MDL Engine     │    │   mDoc Engine    │
│ Engine       │    │  (ISO 18013-5)   │    │  (ISO 18013-5)   │
│ (ICAO 9303)  │    │   Port 8085      │    │   Port 8086      │
│ Port 8084    │    └─────────┬────────┘    └─────────┬────────┘
└──────┬───────┘              │                       │
       │                      │                       │
       └──────────────────────┼───────────────────────┤
                              │                       │
                              │           ┌──────────────────┐
                              │           │   DTC Engine     │
                              │           │ (Digital Travel) │
                              │           │   Port 8087      │
                              │           └─────────┬────────┘
                              │                     │
                              └─────────────────────┤
                                                    │
                        ┌───────────────▼───────────▼───┐
                        │    Document Signer Service    │
                        │      (Certificate Mgmt)       │
                        │         Port 8082             │
                        └───────────────┬───────────────┘
                                        │
          ┌─────────────────────────────┼─────────────────────────────┐
          │                             │                             │
          ▼                             ▼                             ▼
┌─────────────┐           ┌─────────────────┐           ┌─────────────────┐
│ CSCA Service│           │  Trust Anchor   │           │  Inspection     │
│ Port 8081   │           │   Management    │           │   System        │
└──────┬──────┘           │ Port 9080/8080  │           │  Port 8083      │
       │                  └─────────┬───────┘           └─────────┬───────┘
       │                            │                             │
       └────────────────────────────┼─────────────────────────────┘
                                    │
                        ┌───────────▼───────────┐
                        │    PKD Service        │
                        │  (OpenXPKI Bridge)   │
                        │    Port 8088          │
                        └───────────┬───────────┘
                                    │
                          ┌─────────▼─────────┐
                          │   PostgreSQL      │
                          │ (Certificate DB)  │
                          │   Port 5432       │
                          └───────────────────┘
                                    │
                          ┌─────────▼─────────┐
                          │     OpenXPKI      │
                          │  (External PKI)   │
                          └───────────────────┘

                    ┌────────────────────────────┐
                    │      BRIDGE SERVICES       │
                    ├────────────────────────────┤
                    │ EUDI Bridge │ OIDC4VCI     │
                    │ OID4VP      │ Sphereon     │
                    └────────────────────────────┘

                    ┌────────────────────────────┐
                    │     OBSERVABILITY          │
                    ├────────────────────────────┤
                    │ Prometheus  │ Centralized  │
                    │ Monitoring  │ Logging      │
                    │ (Metrics)   │ (Audit)      │
                    └────────────────────────────┘
```

                          ┌─────────▼─────────┐
                          │   PostgreSQL      │
                          │ (Certificate DB)  │
                          │   Port 5432       │
                          └───────────────────┘
                                    │
                          ┌─────────▼─────────┐
                          │     OpenXPKI      │
                          │  (External PKI)   │
                          └───────────────────┘

```

## 📁 Project Structure

The project follows a modular service-oriented architecture:

- `/src/` - Contains all service code
  - `/src/csca-service/` - Country Signing Certificate Authority service
  - `/src/document-signer/` - Document Signer service
  - `/src/passport-engine/` - Passport Personalization engine
  - `/src/inspection-system/` - Passport verification service
  - `/src/trust-anchor/` - Trust anchor management service
  - `/src/pkd-service/` - PKD and CSCA Master List management service
  - `/src/marty_common/` - Shared library used across services
  - `/src/proto/` - Generated Python code from protobuf definitions

- `/proto/` - Protocol buffer definition files (.proto)
- `/config/` - Environment-specific configuration files
- `/scripts/` - Utility scripts for development and operations
- `/docs/` - User documentation and API specifications
- `/tests/` - Test suites organized by type
- `/data/` - Directory for data files used during development

## 🚀 Quick Start

Get Marty running in under 5 minutes:

```bash
# Clone the repository
git clone https://github.com/burdettadam/Marty.git
cd Marty

# Set up the development environment (installs dependencies)
make setup

# Start all services with Docker
docker-compose -f docker/docker-compose.yml up --build

# Run the comprehensive test suite
make test
```

**🎯 Verify installation**: Open <http://localhost:8090> to access the operator UI, or check service status.

> **💡 Tip**: Use `make help` to see all available commands and development shortcuts.

### Alternative Setup Options

```bash
# Set up Kubernetes development environment
make k8s-setup

# Set up OpenXPKI for certificate management
make setup-openxpki

# Run specific test categories
make test-unit                    # Unit tests only
make test-integration            # Integration tests
make test-openid4vp             # OpenID4VC presentation tests
make test-comprehensive         # All tests including E2E
```

## Certificate Management with OpenXPKI

This educational project demonstrates integration with OpenXPKI for certificate management in CSCA and Master List operations. OpenXPKI provides enterprise-grade PKI functionality including:

- Complete certificate lifecycle management
- Master list import and validation
- Certificate revocation checking
- Certificate trust path validation
- Secure storage of cryptographic materials

### Setting up OpenXPKI

Use the provided make command to set up OpenXPKI:

```bash
# Set up OpenXPKI with all necessary configuration
make setup-openxpki
```

Or run the setup script manually:

```bash
# Alternative: Run setup script directly
./scripts/development/setup_openxpki.sh
```

This will:

1. Create necessary directories
2. Start OpenXPKI using Docker Compose
3. Configure the system for CSCA & Master List Management
4. Display connection information

**Access OpenXPKI (Development)**:

- Web UI: <https://localhost:8443/openxpki/>
- API Endpoint: <https://localhost:8443/api/v2>
- Username: `pkiadmin` (override with `OPENXPKI_ADMIN_USER`)
- Password: stored in `data/openxpki/secrets/admin_password.txt` (not committed)

> ⚠️ **Security Note**: Development defaults are for local use only. In production you MUST supply strong credentials via a secret manager (Kubernetes Secret, Docker secret, HashiCorp Vault, AWS Secrets Manager, etc.) and set `OPENXPKI_USERNAME` / `OPENXPKI_PASSWORD` or the corresponding secret file paths. See `docs/SECRETS_MANAGEMENT.md`.

### OpenXPKI Integration

The PKD Service integrates with OpenXPKI through a dedicated service layer that provides:

- Certificate storage and retrieval
- Master list import and processing
- Certificate verification
- Expiry monitoring and notifications
- Offline certificate verification through synchronized trust stores

Configuration settings for the OpenXPKI integration are in the environment-specific configuration files (e.g., `config/development.yaml`).

### Certificate Expiry Notification Service

The Trust Anchor service includes a Certificate Expiry Notification Service that provides:

- Automated monitoring of certificate expiration dates
- Configurable notification thresholds (e.g., 30, 15, 7, 5, 3, 1 days before expiry)
- Tracking of sent notifications to prevent duplicates
- Integration with the Trust Anchor gRPC service

## Development Setup

### Quick Start with Make

This project provides a comprehensive Makefile for common development tasks:

```bash
# Setup development environment
make setup

# Code quality and formatting
make format lint type-check security

# Run tests
make test                    # Complete test suite
make test-unit              # Unit tests only
make test-integration       # Integration tests
make test-openid4vp         # OpenID4VC tests

# Development environment
make k8s-setup             # Set up Kubernetes
make setup-openxpki        # Configure PKI integration

# Show all available commands
make help
```

### Python Environment Management

This project uses modern Python package management. Dependencies are managed through `pyproject.toml` with support for multiple package managers.

### Running with Docker

The project includes Docker configuration for all services:

```bash
# Start all services
docker-compose -f docker/docker-compose.yml up --build

# Start specific services
docker-compose up ui-app passport-engine trust-anchor
```

### Operator UI

An operator-friendly UI is available at `src/ui_app` providing:

- Service health monitoring
- Certificate management
- Document issuance workflows
- Verification testing tools

Access at <http://localhost:8090> when services are running.

### Configuration

Marty uses a **unified configuration system** based on the Marty Microservices Framework (MMF) that provides type-safe, validated configuration with environment variable expansion.

#### Modern Configuration Architecture

- **Service-specific configs**: `/config/services/{service_name}.yaml` - Individual service configurations
- **Environment configs**: `/config/{environment}.yaml` - Environment-wide settings (development, testing, production)
- **Type safety**: Configuration sections are validated using dataclasses with runtime validation
- **Environment expansion**: Support for `${VAR:-default}` patterns in YAML files

#### Configuration Structure

```yaml
# Example: config/services/trust_anchor.yaml
database:
  trust_anchor:
    host: "${TRUST_ANCHOR_DB_HOST:-localhost}"
    port: ${TRUST_ANCHOR_DB_PORT:-5432}
    database: "${TRUST_ANCHOR_DB_NAME:-marty_trust_anchor}"

security:
  grpc_tls:
    enabled: true
    server_cert: "${TLS_SERVER_CERT:-/etc/tls/server/tls.crt}"
  auth:
    required: true
    jwt_enabled: true

trust_store:
  trust_anchor:
    certificate_store_path: "${CERT_STORE_PATH:-/app/data/trust}"
    update_interval_hours: ${TRUST_UPDATE_INTERVAL:-24}

service_discovery:
  hosts:
    trust_anchor: "${TRUST_ANCHOR_HOST:-trust-anchor}"
  ports:
    trust_anchor: ${TRUST_ANCHOR_PORT:-8080}
```

#### Creating New Services

Use the modern service template system:

```bash
# Copy configuration template
cp marty-microservices-framework/templates/service_config_template.yaml config/services/your_service.yaml

# Copy service template
cp marty-microservices-framework/templates/modern_service_template.py src/services/your_service/modern_your_service.py

# Replace template variables with your service name
```

See the [Modern Service Guide](marty-microservices-framework/docs/modern_service_guide.md) for complete documentation.

#### Environment Variables

Set the environment using the `MARTY_ENV` variable:

```bash
export MARTY_ENV=development  # Uses config/development.yaml + service configs
export MARTY_ENV=production   # Uses config/production.yaml + service configs
```

## Testing

### Comprehensive Test Strategy

The project includes multiple testing layers:

```bash
# Core test categories
make test-unit                    # Unit tests for individual components
make test-integration            # Service integration testing
make test-e2e                    # End-to-end workflow validation
make test-cert-validator         # Certificate validation testing

# Protocol-specific testing
make test-openid4vp              # OpenID4VC presentation flows
make test-presentations          # mDL/mDoc presentation testing

# Comprehensive testing
make test                        # All standard tests
make test-comprehensive          # Includes advanced protocol tests
```

### Integration Testing

The project includes comprehensive integration tests adapted from industry-standard libraries:

**ICAO Standards Testing** (from ZeroPass/pymrtd):

- Basic infrastructure: ElementaryFile, DataGroup functionality
- MRZ and DG1: Machine Readable Zone processing
- Security: SOD, DG14/DG15, Active Authentication

**OCR and Image Processing** (from PassportEye):

- MRZ extraction from passport images
- OCR functionality validation
- PDF image extraction

**Certificate Validation** (from wbond/certvalidator):

- X.509 certificate validation
- Path building and validation
- Certificate revocation (CRL/OCSP)
- NIST and OpenSSL test suites

### Performance and Security Testing

```bash
# Performance testing
make perf-test                   # Quick performance validation
make perf-test-load             # Load testing
make perf-test-stress           # Stress testing

# Security analysis
make security                   # Comprehensive security scan
make security-quick             # Quick security check
```

## Running Services Locally

Individual services can be run locally for development:

```bash
# Example service startup
python -m src.apps.csca_service
python -m src.apps.passport_engine
python -m src.apps.ui_app
```

Services are configured through environment-specific YAML files in `/config/`.

---

**🌟 Educational Portfolio Project** - This implementation demonstrates modern approaches to international digital identity standards, microservices architecture, and secure certificate management in a comprehensive, well-documented platform.

For questions about educational use or portfolio review, please contact the repository owner.

---

## License

This project is provided under an Educational Use Only license for learning and portfolio demonstration. Commercial or production use is not permitted. See the LICENSE file for full terms.
