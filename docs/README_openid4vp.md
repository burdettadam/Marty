# OpenID4VP mDoc/mDL Integration Testing

This directory contains comprehensive integration tests for mDoc and mDL credentials over OpenID4VP (OpenID for Verifiable Presentations) with minimal mocking for high confidence testing.

## Overview

The OpenID4VP integration tests validate the complete presentation flow for mobile driver licenses (mDL) and mobile documents (mDoc) following ISO 18013-5 standards and OpenID4VP specifications. These tests provide high confidence by using real cryptographic operations, actual document creation and verification flows, and minimal mocking.

## Test Coverage

### mDoc Integration Tests (`TestMDocOpenID4VPIntegration`)

- **Complete OpenID4VP Flow**: Full end-to-end testing of mDoc issuance, presentation request processing, and verification
- **Selective Disclosure**: Privacy-preserving presentations that only disclose requested claims
- **Age Verification**: Zero-knowledge age proofs without revealing birth dates
- **Credential Status Verification**: Real-time status checking and revocation validation
- **Error Handling**: Comprehensive testing of invalid requests, expired documents, and unsigned credentials
- **Multiple Credential Presentations**: Support for presentations requiring multiple mDoc credentials

### mDL Integration Tests (`TestMDLOpenID4VPIntegration`)

- **Complete mDL OpenID4VP Flow**: End-to-end mobile driver license presentation testing
- **Age-Restricted Venue Access**: Real-world scenarios for bars, clubs, and age-restricted venues
- **Selective Disclosure Privacy**: Minimal information sharing for identity verification
- **Driving Privilege Verification**: Vehicle rental qualification and category validation
- **Cross-Border Verification**: International validity and authority recognition

## Key Features

### High Confidence Testing

- **Real Cryptographic Operations**: Uses actual JWT/JWK signatures and CBOR/COSE encoding
- **Minimal Mocking**: Only mock external services that aren't part of the core verification flow
- **Actual Service Integration**: Tests against real gRPC services for mDoc/mDL engines
- **End-to-End Flows**: Complete presentation flows from request to verification

### Privacy-Preserving Features

- **Selective Disclosure**: Only requested claims are revealed
- **Zero-Knowledge Proofs**: Age verification without exposing birth dates
- **Minimal Data Sharing**: Privacy-first presentation strategies

### Real-World Scenarios

- **Venue Access Control**: Age verification for bars, clubs, and restricted venues
- **Vehicle Rental**: Driving privilege verification for rental companies
- **Border Control**: International validity and cross-border recognition
- **Identity Verification**: Minimal disclosure for account opening and KYC

## Prerequisites

### Required Dependencies

```bash
# Core testing dependencies
httpx>=0.25.0
pytest>=7.4.0
pytest-asyncio>=0.21.0

# Cryptographic libraries
jwcrypto>=1.5.0
authlib>=1.2.0
sd-jwt>=0.9.0

# CBOR and protocol libraries
cbor2>=5.0.0
responses>=0.23.0

# gRPC client libraries
grpcio>=1.57.0
grpcio-tools>=1.57.0
```

### Service Dependencies

The tests require the following services to be running:

- **mDoc Engine Service** (port 8081): Creates, signs, and manages mDoc credentials
- **mDL Engine Service** (port 8085): Creates, signs, and manages mDL credentials  
- **Document Signer Service** (port 8086): Provides cryptographic signing capabilities

## Setup and Configuration

### 1. Install Dependencies

```bash
# Using uv package manager
uv add httpx pytest pytest-asyncio jwcrypto authlib sd-jwt cbor2 responses grpcio grpcio-tools

# Or using pip
pip install httpx pytest pytest-asyncio jwcrypto authlib sd-jwt cbor2 responses grpcio grpcio-tools
```

### 2. Start Required Services

```bash
# Start all required services
docker-compose up mdoc-engine mdl-engine document-signer

# Or start individually
docker-compose up mdoc-engine
docker-compose up mdl-engine  
docker-compose up document-signer
```

### 3. Run Setup Script

```bash
# Automated setup and validation
python scripts/setup_openid4vp_tests.py
```

## Running Tests

### All OpenID4VP Tests

```bash
# Run all OpenID4VP integration tests
pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py -m openid4vp -v
```

### Specific Test Categories

```bash
# mDoc presentation tests only
pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py -m mdoc_presentation -v

# mDL presentation tests only
pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py -m mdl_presentation -v

# Integration tests only
pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py -m integration -v
```

### Individual Test Cases

```bash
# Specific mDoc test
pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py::TestMDocOpenID4VPIntegration::test_selective_disclosure_mdoc_presentation -v

# Specific mDL test
pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py::TestMDLOpenID4VPIntegration::test_mdl_age_restricted_venue_access -v
```

### Debug Mode

```bash
# Run with detailed output and logging
pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py -v -s --log-cli-level=DEBUG
```

## Test Structure

### Test Classes

```python
@pytest.mark.integration
@pytest.mark.openid4vp
@pytest.mark.mdoc_presentation
class TestMDocOpenID4VPIntegration:
    """Integration tests for mDoc presentation over OpenID4VP with minimal mocking."""

@pytest.mark.integration
@pytest.mark.openid4vp
@pytest.mark.mdl_presentation
class TestMDLOpenID4VPIntegration:
    """Integration tests for mDL presentation over OpenID4VP with minimal mocking."""
```

### Test Flow Pattern

Each test follows a consistent pattern:

1. **Setup**: Create and sign credentials using real gRPC services
2. **Request**: Generate OpenID4VP presentation requests with real JWT signatures
3. **Process**: Handle presentation requests using actual cryptographic operations
4. **Verify**: Validate presentations using real verification services
5. **Assert**: Check results for correctness and security properties

### Example Test Flow

```python
async def test_complete_mdoc_openid4vp_flow(self):
    # Step 1: Create mDoc via gRPC service
    mdoc_data = await self._create_test_mdoc()

    # Step 2: Sign the mDoc to make it active
    signed_mdoc = await self._sign_mdoc(mdoc_data["mdoc_id"])

    # Step 3: Create OpenID4VP presentation request
    presentation_request = await self._create_presentation_request(
        requested_credentials=["driver_license"],
        requested_claims=["given_name", "family_name", "birth_date"]
    )

    # Step 4: Process presentation request as holder
    presentation_response = await self._process_presentation_request(
        mdoc_data["mdoc_id"],
        presentation_request
    )

    # Step 5: Verify presentation response as verifier
    verification_result = await self._verify_presentation_response(
        presentation_response,
        presentation_request
    )

    # Step 6: Validate results
    assert verification_result["valid"]
    assert verification_result["credential_verified"]
    assert verification_result["signature_verified"]
```

## Configuration

### Test Configuration File

```json
{
  "base_url": "http://localhost:8000",
  "mdoc_service_url": "localhost:8081",
  "mdl_service_url": "localhost:8085",
  "timeout": 60
}
```

### Pytest Markers

```toml
[tool.pytest.ini_options]
markers = [
    "integration: Integration tests requiring external services",
    "openid4vp: OpenID4VP protocol tests",
    "mdoc_presentation: mDoc presentation tests",
    "mdl_presentation: mDL presentation tests"
]
```

## Fixtures and Test Data

### Test Fixtures Location

```
tests/fixtures/openid4vp/
├── sample_presentation_definition.json
├── test_config.json
├── test_keys/
│   ├── issuer_key.json
│   ├── holder_key.json
│   └── verifier_key.json
└── test_documents/
    ├── sample_mdoc.json
    └── sample_mdl.json
```

### Sample Presentation Definition

```json
{
  "id": "sample_mdl_presentation",
  "input_descriptors": [
    {
      "id": "mdl_driving_privileges",
      "format": {
        "mso_mdoc": {
          "alg": ["ES256", "ES384", "ES512"]
        }
      },
      "constraints": {
        "fields": [
          {
            "path": ["$.driving_privileges"],
            "purpose": "Verify driving privileges"
          },
          {
            "path": ["$.license_number"],
            "purpose": "Verify license number"
          }
        ]
      }
    }
  ]
}
```

## Security Considerations

### Cryptographic Operations

- **Real Key Generation**: Tests use actual cryptographic keys, not mock keys
- **Signature Verification**: All signatures are cryptographically validated
- **JWT Security**: Proper JWT header validation and expiration checking
- **CBOR/COSE Integrity**: Actual CBOR encoding and COSE signature validation

### Privacy Protection

- **Selective Disclosure**: Only requested claims are included in presentations
- **Zero-Knowledge Proofs**: Age verification without revealing birth dates
- **Minimal Linking**: Different presentations use different identifiers
- **Cryptographic Unlinkability**: Presentations cannot be correlated without cooperation

### Data Protection

- **Ephemeral Test Data**: All test credentials are temporary and non-production
- **Secure Key Management**: Test keys are generated per test run
- **Clean Teardown**: All test data is properly cleaned up after tests complete

## Troubleshooting

### Common Issues

#### Service Connection Errors

```bash
# Check if services are running
docker-compose ps

# Start missing services
docker-compose up mdoc-engine mdl-engine document-signer
```

#### Dependency Conflicts

```bash
# Update dependencies
uv sync

# Or reinstall from scratch
uv remove httpx pytest jwcrypto
uv add httpx pytest pytest-asyncio jwcrypto authlib sd-jwt cbor2
```

#### gRPC Connection Issues

```bash
# Verify service health
grpcurl -plaintext localhost:8081 grpc.health.v1.Health/Check
grpcurl -plaintext localhost:8085 grpc.health.v1.Health/Check
```

#### Test Collection Failures

```bash
# Validate test discovery
pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py --collect-only

# Check for syntax errors
python -m py_compile tests/integration/test_mdoc_mdl_openid4vp_integration.py
```

### Debug Logs

```bash
# Enable debug logging
export PYTEST_LOG_LEVEL=DEBUG
pytest tests/integration/test_mdoc_mdl_openid4vp_integration.py -v -s --log-cli-level=DEBUG

# gRPC debug logging
export GRPC_VERBOSITY=DEBUG
export GRPC_TRACE=all
```

## Contributing

### Adding New Tests

1. Follow the existing test pattern and structure
2. Use real cryptographic operations, not mocks
3. Include comprehensive assertions
4. Add appropriate pytest markers
5. Document any new test scenarios

### Test Naming Conventions

- `test_complete_*_flow`: End-to-end integration tests
- `test_*_verification`: Specific verification scenarios  
- `test_*_error_handling`: Error condition testing
- `test_*_privacy`: Privacy-preserving feature tests

### Code Quality

- All tests must pass linting checks
- Use type hints for all function parameters
- Include comprehensive docstrings
- Follow async/await patterns consistently

## References

- [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [ISO 18013-5 Mobile Driver License](https://www.iso.org/standard/69084.html)
- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)
- [RFC 7519 JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 8152 CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152)
