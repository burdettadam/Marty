# Marty gRPC Service

[![CI](https://github.com/burdettadam/Marty/workflows/Marty%20CI/badge.svg)](https://github.com/burdettadam/Marty/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Educational Use Only](https://img.shields.io/badge/License-Educational%20Use%20Only-red.svg)](#license)
[![gRPC](https://img.shields.io/badge/gRPC-1.59+-green.svg)](https://grpc.io/)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)](https://docs.docker.com/compose/)

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

# Set up the development environment (installs UV and dependencies)
make setup

# Start all services with Docker
make dev-environment

# Run the test suite
make test
```

**🎯 Verify installation**: Open http://localhost:8090 to access the operator UI, or check service status with `make dev-status`.

> **💡 Tip**: Use `make help` to see all available commands and development shortcuts.

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

**Access OpenXPKI**:
- Web UI: https://localhost:8443/openxpki/
- API Endpoint: https://localhost:8443/api/v2
- Username: `pkiadmin`
- Password: `secret`

> ⚠️ **Educational Note**: Default credentials are for learning purposes only. Production systems require proper authentication configuration.

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

This project provides a Makefile for common tasks:

```bash
# Setup development environment
make setup

# Run all tests
make test

# Format code
make format

# Lint code
make lint

# Generate test data
make generate-test-data

# Run the server
make run

# Show all available commands
make help
```

### Python Environment Management with UV

This project uses [UV](https://github.com/astral-sh/uv) for dependency management. UV is a fast, reliable Python package installer and resolver.

#### Installation

1. Install UV:

```bash
pip install uv
```

2. Install project dependencies:

```bash
uv pip install -e .
```

3. Create a virtual environment (optional but recommended):

```bash
uv venv
source .venv/bin/activate  # On Unix/macOS
# OR
.venv\Scripts\activate     # On Windows
```

#### Adding New Dependencies

To add a new dependency:

```bash
uv pip install package_name
```

And then update your pyproject.toml file with the new dependency.

#### Updating the Lock File

To update the lock file after changing dependencies:

```bash
uv pip sync
```

### Running with Docker

The project includes Docker configuration for all services. Build and run with:

```bash
docker-compose -f docker/docker-compose.yml up --build
```

Each service uses UV for dependency management inside its container.

### Operator UI

An operator-friendly UI lives in `src/ui_app`. Run it locally with:

```bash
uvicorn ui_app.app:app --reload
```

Tune the backing service addresses via environment variables:

| Variable | Purpose | Default |
| --- | --- | --- |
| `UI_PASSPORT_ENGINE_ADDR` | Passport Engine gRPC target | `localhost:8084` |
| `UI_INSPECTION_SYSTEM_ADDR` | Inspection System gRPC target | `localhost:8083` |
| `UI_MDL_ENGINE_ADDR` | MDL Engine gRPC target | `localhost:8085` |
| `UI_TRUST_ANCHOR_ADDR` | Trust Anchor gRPC target | `localhost:8080` |

Set `UI_ENABLE_MOCK_DATA=true` to explore the UI without running the gRPC
services.

### Configuration

Configuration files are stored in the `/config/` directory and are environment-specific:

- `development.yaml` - Used during local development
- `testing.yaml` - Used during test runs
- `production.yaml` - Used in production environments

You can set the environment by setting the `MARTY_ENV` environment variable:

```bash
export MARTY_ENV=development
```

## Testing


### Testing Strategy

See [TESTING.md](./TESTING.md) for a detailed overview of the project's testing strategy, coverage goals, and contribution guidelines.

#### Quick Start

- **All tests:**
   ```bash
   make test
   ```
- **Unit tests:**
   ```bash
   make test-unit
   ```
- **Integration tests:**
   ```bash
   make test-integration
   ```
- **End-to-end tests:**
   ```bash
   make test-e2e
   ```
- **Certificate validation tests:**
   ```bash
   make test-cert-validator
   ```
- **Docker integration tests:**
   ```bash
   python tests/integration/docker/run_docker_tests.py [options]
   ```

#### Improvements Roadmap

- Increase coverage for all services (>90%)
- Expand E2E scenarios (error handling, security, performance)
- Integrate automated coverage reporting and CI enforcement
- Improve test data diversity and documentation
- Expand OpenXPKI integration tests

### Integrated Tests from ZeroPass/pymrtd

The project includes tests adapted from the [ZeroPass/pymrtd](https://github.com/ZeroPass/pymrtd) repository to validate ePassport functionality according to ICAO standards. These tests have been modified to work with Marty's implementation:

1. **Basic Infrastructure Tests**:
   - `tests/unit/ef/ef_base_test.py` - Tests for ElementaryFile functionality
   - `tests/unit/ef/dg_base_test.py` - Tests for DataGroup and DataGroupType functionality

2. **MRZ and DG1 Tests**:
   - `tests/unit/ef/mrz_test.py` - Tests for MRZ data model, formatting, and parsing
   - `tests/unit/ef/dg1_test.py` - Tests for DG1 content parsing (which contains MRZ data)

3. **Security Tests**:
   - `tests/unit/ef/sod_test.py` - Tests for SOD (Document Security Object) functionality
   - `tests/unit/ef/dg14_test.py` - Tests for DG14 (Security Options) handling
   - `tests/unit/ef/dg15_test.py` - Tests for DG15 (Active Authentication Public Key) functionality
   - `tests/unit/pki/iso9796e2_test.py` - Tests for ISO 9796-2 signature scheme used in Active Authentication

To run these specific tests:

```bash
# Run all integrated tests
pytest tests/unit/ef/ tests/unit/pki/

# Run a specific test file
pytest tests/unit/ef/dg1_test.py

# Run a specific test function
pytest tests/unit/ef/sod_test.py::test_sod_basic
```

The tests use pytest-depends to maintain proper test dependencies and ensure they run in the correct order.

### Integrated Tests from PassportEye

The project includes tests adapted from the [PassportEye](https://github.com/konstantint/PassportEye) repository to validate Machine Readable Zone (MRZ) extraction, OCR functionality, and PDF image processing capabilities:

1. **MRZ Tests**:
   - `tests/test_mrz.py` - Tests for Machine Readable Zone (MRZ) detection and parsing from passport images
   - Tests different passport format types (TD2, TD3) and validates extracted data fields

2. **OCR Tests**:
   - `tests/test_ocr.py` - Tests for the Optical Character Recognition functionality
   - Validates text extraction capabilities using test images with known content

3. **PDF Extraction Tests**:
   - `tests/test_pdf_extraction.py` - Tests for extracting JPEG images from PDF documents
   - Validates the extraction of images from various PDF file formats

These tests include test data in the `tests/data/` directory:
- Sample passport images in different formats (TD2, TD3)
- Test PDF files with various embedded image formats
- OCR test images with known content

To run the PassportEye tests:

```bash
# Run all PassportEye tests
pytest tests/test_mrz.py tests/test_ocr.py tests/test_pdf_extraction.py

# Run a specific test file
pytest tests/test_mrz.py
```

### Integrated Certificate Validation Tests

The project includes tests from the [wbond/certvalidator](https://github.com/wbond/certvalidator) repository to validate X.509 certificates and paths. These tests are essential for ensuring proper certificate validation in the passport issuance and verification process:

1. **Core Validation Tests**:
   - `tests/cert_validator/test_certificate_validator.py` - Tests for the certificate validator functionality
   - `tests/cert_validator/test_validate.py` - Main validation tests covering various certificate validation scenarios

2. **Certificate Revocation Tests**:
   - `tests/cert_validator/test_crl_client.py` - Tests for Certificate Revocation List (CRL) client
   - `tests/cert_validator/test_ocsp_client.py` - Tests for Online Certificate Status Protocol (OCSP) client

3. **Registry Tests**:
   - `tests/cert_validator/test_registry.py` - Tests for certificate registry functionality

These tests validate various aspects of X.509 certificates including:
- Path building and validation
- Signature verification (RSA, DSA, and EC algorithms)
- Name chaining
- Validity dates checking
- Basic constraints validation
- Extended key usage validation
- Certificate revocation via CRLs and OCSP
- Point-in-time validation

To run these certificate validation tests:

```bash
# Run all certificate validation tests
python tests/cert_validator/run_cert_tests.py

# Run a specific set of tests (e.g., only certificate validator tests)
python tests/cert_validator/run_cert_tests.py certificate_validator

# Run a specific set of tests (e.g., only OCSP client tests)
python tests/cert_validator/run_cert_tests.py ocsp
```

The test fixtures include certificates from the NIST Public Key Interoperability Test Suite and OCSP tests from OpenSSL, providing comprehensive validation of certificate handling capabilities.

### Running Services Locally

To run individual services locally for development:

```bash
make run
```

You can set the environment variables to configure which service to run:

```bash
export SERVICE_NAME=csca-service
export GRPC_PORT=8081
make run
```

## Documentation

� **[Business Overview](docs/BUSINESS_OVERVIEW.md)** - Executive summary and ROI analysis for stakeholders

⚡ **[Quick Integration Guide](docs/USER_GUIDE.md)** - Get started in minutes with code examples

🛠️ **[Developer Guide](docs/DEVELOPER_GUIDE.md)** - Complete technical documentation and architecture details

📄 **[API Reference](docs/api/openapi.yaml)** - OpenAPI specification for REST endpoints

## API Documentation

REST API documentation is available in OpenAPI format at `docs/api/openapi.yaml`. This documentation complements the gRPC service definitions and provides an easier interface for testing.

## Shared Library

Common code that's used across multiple services is located in the `src/marty_common` package. This includes:

- Cryptographic utilities (`src/marty_common/crypto.py`)
- Data validation (`src/marty_common/validation.py`)
- Configuration management (`src/marty_common/config.py`)
- Shared data models (`src/marty_common/models/`)

## License

**EDUCATIONAL USE ONLY - RESTRICTIVE LICENSE**

This project is licensed under a restrictive educational license:

- ✅ **Permitted**: Educational use, learning, research, portfolio review
- ✅ **Permitted**: Academic study of ICAO standards implementation
- ✅ **Permitted**: Code review for educational purposes
- ❌ **Prohibited**: Commercial use of any kind
- ❌ **Prohibited**: Production deployment
- ❌ **Prohibited**: Distribution without explicit permission
- ❌ **Prohibited**: Use in real document issuance systems

> ⚠️ **IMPORTANT**: This implementation is for educational purposes only. Real-world digital identity document systems require proper certification, security audits, and compliance validation. This project should never be used for actual document issuance or verification in production environments.

## Educational Context

This project serves as:
- A **portfolio piece** demonstrating software architecture and implementation skills
- A **learning exercise** for understanding complex international standards (ICAO, ISO)
- An **educational tool** for exploring cryptographic implementations
- A **reference implementation** for academic study of digital identity systems

For questions about educational use or portfolio review, please contact the repository owner.

## CI/CD Pipeline

The project includes GitHub Actions workflows for continuous integration and deployment:

- `.github/workflows/ci.yml` - Runs tests and linting checks
- `.github/workflows/cd.yml` - Builds and publishes Docker images for tagged releases
