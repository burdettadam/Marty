# Cryptographic Boundaries and Key Management

## Overview

This document describes the comprehensive cryptographic boundaries and key management system implemented for the Marty platform, providing enterprise-grade security through role separation, KMS/HSM integration, and tamper-evident evidence signing.

## Architecture

### Core Components

1. **Role Separation** (`src/marty_common/crypto/role_separation.py`)
   - Enforces strict separation between cryptographic roles
   - Prevents key misuse through runtime enforcement
   - Supports 8 distinct crypto roles with specific policies

2. **KMS/HSM Provider** (`src/marty_common/crypto/kms_provider.py`)
   - Multi-provider abstraction for cloud KMS and HSM
   - Comprehensive audit logging
   - Key lifecycle management

3. **Evidence Signing** (`src/marty_common/crypto/evidence_signing.py`)
   - Tamper-evident audit logs
   - Cryptographic chain integrity
   - Non-repudiation capabilities

## Crypto Role Separation

### Supported Roles

1. **CSCA (Country Signing Certificate Authority)**
   - Purpose: Certificate signing for national authorities
   - Security: HSM required, maximum isolation
   - Key lifetime: 10 years

2. **DSC (Document Signer Certificate)**
   - Purpose: Document signing certificates
   - Security: HSM required, controlled access
   - Key lifetime: 5 years

3. **READER_VERIFIER**
   - Purpose: Document verification
   - Security: Public key access only
   - Key lifetime: 2 years

4. **WALLET_HOLDER**
   - Purpose: End-user credential storage
   - Security: Completely isolated from authorities
   - Key lifetime: 1 year

5. **EVIDENCE_SIGNER**
   - Purpose: Audit log signing
   - Security: HSM preferred
   - Key lifetime: 3 years

6. **TRANSPORT_ENCRYPTION**
   - Purpose: Communication encryption
   - Security: Standard protection
   - Key lifetime: 1 year

7. **DATA_ENCRYPTION**
   - Purpose: Data at rest encryption
   - Security: Standard protection
   - Key lifetime: 2 years

8. **AUTHENTICATION**
   - Purpose: Service authentication
   - Security: Standard protection
   - Key lifetime: 90 days

### Role Policies

Each role has specific policies defining:

- **Purposes**: Allowed cryptographic operations
- **Security Level**: Required security (software/HSM)
- **Key Lifetime**: Maximum key validity period
- **Audit Requirements**: Logging and compliance needs
- **Cross-Boundary Access**: Inter-role restrictions

### Implementation Features

- **Runtime Enforcement**: Boundary violations detected and blocked
- **Automatic Validation**: Key policies verified on every operation
- **Audit Integration**: All role activities logged
- **Configuration Driven**: Policies defined in YAML configuration

## KMS/HSM Integration

### Supported Providers

1. **AWS KMS**
   - Customer managed keys (CMK)
   - Automatic key rotation
   - CloudTrail integration

2. **Azure Key Vault**
   - Premium HSM support
   - FIPS 140-2 Level 2 validation
   - Azure Monitor integration

3. **Google Cloud KMS**
   - Cloud HSM support
   - FIPS 140-2 Level 3 validation
   - Cloud Audit Logs integration

4. **Software HSM**
   - Development and testing
   - Local key storage
   - File-based audit logs

### Provider Abstraction

```python
class KMSProvider:
    def generate_key(self, key_spec: KeySpec) -> KeyHandle
    def sign_data(self, key_handle: KeyHandle, data: bytes) -> bytes
    def verify_signature(self, key_handle: KeyHandle, data: bytes, signature: bytes) -> bool
    def encrypt_data(self, key_handle: KeyHandle, plaintext: bytes) -> bytes
    def decrypt_data(self, key_handle: KeyHandle, ciphertext: bytes) -> bytes
```

### Audit Logging

All KMS operations include:

- Operation type and parameters
- Key identifiers and roles
- Success/failure status
- Timestamps and request IDs
- User/service identity
- Performance metrics

## Evidence Signing

### Tamper-Evident Logs

Every verification operation generates a signed evidence entry:

```python
class EvidenceEntry:
    id: str
    timestamp: datetime
    operation_type: str
    verification_result: VerificationResult
    document_hash: str
    verifier_identity: str
    signature: str  # Cryptographic signature of entry
    previous_hash: str  # Links to previous entry
```

### Chain Integrity

Evidence entries form a cryptographic chain:

- Each entry includes hash of previous entry
- Tampering with any entry breaks the chain
- Chain integrity verifiable at any point
- Immutable audit trail

### Non-Repudiation

Evidence signatures provide:

- **Timestamp Integrity**: Signed timestamps prevent backdating
- **Identity Verification**: Verifier identity cryptographically bound
- **Result Authenticity**: Verification results cannot be forged
- **Complete Audit Trail**: Every verification decision recorded

## Security Configuration

### Production Settings

```yaml
crypto_boundaries:
  enforcement_level: strict
  audit_all_operations: true
  require_hsm_for_authorities: true
  evidence_signing_required: true

kms_settings:
  default_provider: aws_kms
  key_rotation_days: 90
  audit_retention_days: 2555  # 7 years

role_policies:
  csca:
    security_level: hsm_required
    max_key_lifetime_days: 3650
    requires_audit: true
    can_cross_boundaries: false
```

### Development Settings

```yaml
crypto_boundaries:
  enforcement_level: permissive
  audit_all_operations: false
  require_hsm_for_authorities: false
  evidence_signing_required: false

kms_settings:
  default_provider: software_hsm
  key_rotation_days: 30
  audit_retention_days: 90
```

## Algorithms and Standards

### Supported Algorithms

- **RSA**: 2048, 3072, 4096 bit keys
- **ECDSA**: P-256, P-384, P-521 curves
- **EdDSA**: Ed25519, Ed448
- **Hash Functions**: SHA-256, SHA-384, SHA-512

### Compliance Standards

- **FIPS 140-2**: Level 2 minimum for production HSM
- **Common Criteria**: EAL4+ for HSM products
- **NIST SP 800-57**: Key management guidelines
- **RFC 3647**: Certificate policy framework

## Implementation Status

| Component | Status | Features |
|-----------|--------|----------|
| Role Separation | ✅ Complete | 8 roles, runtime enforcement, audit integration |
| KMS/HSM Provider | ✅ Complete | Multi-provider, audit logging, key lifecycle |
| Evidence Signing | ✅ Complete | Tamper-evident logs, chain integrity, non-repudiation |
| Security Config | ✅ Complete | Production policies, compliance settings |
| Integration Tests | ✅ Complete | Comprehensive test coverage |

## Migration and Deployment

### Existing Systems

1. **Assess Current Keys**: Inventory existing cryptographic material
2. **Plan Role Assignment**: Map keys to appropriate roles
3. **Configure KMS**: Set up cloud KMS or HSM providers
4. **Migrate Gradually**: Phase migration to avoid disruption
5. **Validate Boundaries**: Test role enforcement thoroughly

### New Deployments

1. **Configure Roles**: Define role policies for your use case
2. **Set Up KMS**: Choose and configure KMS/HSM provider
3. **Generate Keys**: Create keys with appropriate role assignment
4. **Enable Evidence**: Configure evidence signing and audit retention
5. **Monitor Compliance**: Implement ongoing monitoring and alerting

This implementation provides enterprise-grade cryptographic boundaries that ensure proper key separation, comprehensive audit trails, and regulatory compliance for production environments.
