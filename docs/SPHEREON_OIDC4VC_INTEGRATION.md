# Sphereon OIDC4VC Integration Testing

This document describes the integration of Sphereon OIDC4VC dependencies and testing capabilities in the Marty identity management system.

## Overview

The integration adds support for testing OIDC4VC (OpenID for Verifiable Credentials) flows compatible with Sphereon's wallet and verifier implementations. This enables comprehensive testing of credential issuance and presentation workflows using industry-standard protocols.

## Dependencies Added

### Main Dependencies (pyproject.toml)

- `oidc4vc>=0.2.1` - Core OIDC4VC protocol implementation
- `did-resolver>=1.0.0` - DID resolution capabilities  
- `jwcrypto>=1.5.4` - Enhanced JWT/JWE/JWK cryptographic operations
- `didcomm-messaging>=0.5.0` - DIDComm messaging protocol support

### Development Dependencies

- `httpx>=0.25.0` - Modern HTTP client for testing
- `websockets>=12.0` - WebSocket support for real-time communication
- `mock-server>=0.8.0` - Mock server for testing external services
- `responses>=0.24.0` - HTTP response mocking for unit tests

## Test Implementation

### Integration Test Structure

The integration tests are located in:

```
tests/integration/test_sphereon_oidc4vc_integration.py
```

### Test Classes

1. **TestSphereonOIDC4VCIntegration**: Core OIDC4VC protocol testing
   - Issuer metadata discovery
   - Credential offer creation and retrieval
   - Pre-authorized code flow
   - mDoc/MDL credential issuance
   - JWT VC-SD (Selective Disclosure) format compatibility

2. **TestSphereonWalletSimulation**: Sphereon wallet interaction simulation
   - Complete wallet flow simulation
   - QR code credential offer processing
   - Multi-step authentication and credential retrieval

### Test Features

#### Supported Credential Types

- **Passport Credentials**: Digital passport credentials in VC+SD-JWT format
- **Mobile Driver License (mDL)**: ISO 18013-5 compliant mDoc credentials
- **Custom Credential Types**: Extensible framework for additional credential types

#### Protocol Support

- **OIDC4VCI**: OpenID for Verifiable Credential Issuance
- **Pre-authorized Code Flow**: PIN-less credential issuance
- **Proof of Possession**: JWT-based cryptographic binding
- **Selective Disclosure**: SD-JWT format for privacy-preserving credentials

#### Sphereon Compatibility

- Metadata format compatibility with Sphereon issuer/verifier
- Wallet simulation matching Sphereon wallet behavior
- Error response formats compatible with Sphereon standards
- JWT signing and verification using Sphereon-compatible algorithms

## Running Tests

### Setup Dependencies

```bash
# Install dependencies
python setup_sphereon_oidc4vc.py

# Or manually install
pip install -e .
```

### Run Integration Tests

```bash
# Run all Sphereon OIDC4VC tests
pytest tests/integration/test_sphereon_oidc4vc_integration.py -v

# Run with specific markers
pytest -m oidc4vc -v
pytest -m sphereon -v

# Run specific test class
pytest tests/integration/test_sphereon_oidc4vc_integration.py::TestSphereonOIDC4VCIntegration -v
```

### Test Runner Script

```bash
# Use the provided test runner
python run_sphereon_tests.py
```

## Configuration

### Test Environment Variables

```bash
# Optional: Set custom base URL for testing
export OIDC4VC_BASE_URL="http://localhost:8000"

# Optional: Enable debug logging
export OIDC4VC_DEBUG=true
```

### pytest Markers

The following markers are available for test selection:

- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.oidc4vc` - OIDC4VC specific tests  
- `@pytest.mark.sphereon` - Sphereon compatibility tests

## Integration Points

### Existing System Integration

The tests integrate with existing Marty system components:

- **UI App**: Tests the OIDC4VC endpoints in `src/ui_app/app.py`
- **Repositories**: Uses `Oidc4VciSessionStateStore` for session management
- **Models**: Leverages `Oidc4VciSessionRecord` for data persistence

### Credential Formats

- **VC+SD-JWT**: Verifiable Credentials with Selective Disclosure
- **mso_mdoc**: Mobile Security Object for mDoc credentials
- **Custom Formats**: Extensible for additional credential types

## Security Considerations

### Key Management

- Tests use ephemeral keys for testing (P-256 elliptic curve)
- Production implementations should use proper key management
- Hardware Security Module (HSM) integration recommended for production

### Protocol Security

- JWT proof of possession prevents credential theft
- Pre-authorized codes are single-use and time-limited
- All communications should use HTTPS in production

## Troubleshooting

### Common Issues

1. **Dependency Installation Failures**

   ```bash
   # Try upgrading pip first
   pip install --upgrade pip
   python setup_sphereon_oidc4vc.py
   ```

2. **Test Connection Failures**

   ```bash
   # Ensure the Marty services are running
   docker-compose up -d

   # Check service health
   curl http://localhost:8000/health
   ```

3. **JWT Verification Errors**
   - Ensure system clock is synchronized
   - Check key formats match expected algorithms
   - Verify audience and issuer claims

### Debug Mode

Enable verbose logging by setting environment variables:

```bash
export PYTHONPATH=.
export LOG_LEVEL=DEBUG
pytest tests/integration/test_sphereon_oidc4vc_integration.py -v -s
```

## Extending the Tests

### Adding New Credential Types

1. Define credential configuration in test metadata
2. Add test cases for the new credential type
3. Update parametrized tests to include new type

### Adding New Protocol Flows

1. Implement flow logic in test methods
2. Add mock responses for external services
3. Validate against Sphereon compatibility requirements

## References

- [OpenID for Verifiable Credentials (OIDC4VC)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [Sphereon Documentation](https://sphereon-opensource.github.io/)
- [ISO/IEC 18013-5 (mDL Standard)](https://www.iso.org/standard/69084.html)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)

## Support

For issues related to Sphereon OIDC4VC integration:

1. Check existing test documentation
2. Review Sphereon compatibility requirements
3. Consult the OpenID4VC specification
4. File issues with detailed reproduction steps
