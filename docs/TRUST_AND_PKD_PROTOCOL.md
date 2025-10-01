# Unified Trust, Keys, and PKD Distribution Protocol

## Overview

This document defines the unified trust story for Marty's identity verification system, aligning chip/LDS and VDS-NC barcode verification with ICAO Doc 9303 Parts 11-12 and VDS-NC specifications.

## Trust Architecture

### 1. Dual Trust Paths

```
┌─────────────────────────────────────────────────────────────┐
│                  Unified PKD Distribution                    │
│  ┌──────────────────────┐  ┌───────────────────────────┐   │
│  │   Chip/LDS Path      │  │   VDS-NC Barcode Path     │   │
│  │                      │  │                           │   │
│  │  CSCA → DSC → SOD   │  │   VDS-NC Signer Keys      │   │
│  │  (Part 11-12)        │  │   (Part 13, VDS-NC)       │   │
│  └──────────────────────┘  └───────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              ▼
                    ┌──────────────────┐
                    │  Trust Anchor    │
                    │  Verification    │
                    └──────────────────┘
```

## Protocol Rules

### 2.1 Chip/LDS (ICAO Doc 9303 Part 11-12)

#### Trust Chain Structure
- **CSCA (Country Signing CA)**: Root of trust for each issuing country
- **DSC (Document Signer Certificate)**: Issued by CSCA, signs document data
- **SOD (Security Object Document)**: Signed by DSC, contains hashes of data groups

#### Certificate Standards
```yaml
CSCA:
  key_usage: [keyCertSign, cRLSign]
  basic_constraints: CA=TRUE
  validity_period: 3-10 years
  key_algorithms: [RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384]
  
DSC:
  key_usage: [digitalSignature]
  basic_constraints: CA=FALSE
  validity_period: 90 days - 3 years
  key_algorithms: [RSA-2048, ECDSA-P256, ECDSA-P384]
  extended_key_usage: [ICAO MRTD Security Object - 2.23.136.1.1.1]
```

#### PKD Distribution
- **Endpoint**: `/api/v1/pkd/dsc/{country_code}`
- **Format**: ASN.1 DER-encoded DSCList or PEM
- **Metadata**:
  - Serial number
  - Subject DN
  - Validity period (notBefore, notAfter)
  - Country code (ISO 3166-1 alpha-3)
  - Fingerprint (SHA-256)
  - Key identifier (Subject Key Identifier)

#### SOD Verification Process
1. Extract DSC certificate from SOD
2. Validate DSC against known CSCA certificates
3. Verify DSC certificate chain (signature, validity, revocation)
4. Verify SOD signature using DSC public key
5. Validate data group hashes match computed hashes

### 2.2 VDS-NC Barcode Path

#### Trust Model
- **VDS-NC Signer Keys**: Separate key pairs per issuer/role
- **No CA hierarchy**: Direct trust relationship with verifiers
- **Public key distribution**: Via PKD or parallel endpoint

#### Key Standards
```yaml
VDS-NC_Signer:
  key_algorithms: [ECDSA-P256]  # ES256 mandatory per ICAO
  signature_algorithm: ES256 (ECDSA with SHA-256)
  key_validity: 1-3 years
  metadata:
    kid: Key Identifier (UUID or deterministic)
    issuer: Country code (ISO 3166-1 alpha-3)
    role: Certificate type (e.g., "CMC", "VISA")
    not_before: Activation timestamp
    not_after: Expiration timestamp
    rotation_generation: Rotation sequence number
```

#### PKD Distribution
- **Primary Endpoint**: `/api/v1/pkd/vds-nc-keys/{country_code}`
- **Alternative**: Unified endpoint `/api/v1/pkd/trust-store/{country_code}`
- **Format**: JWKS (JSON Web Key Set) or custom JSON
- **Response Structure**:
```json
{
  "keys": [
    {
      "kid": "VDS-NC-USA-CMC-2025-01",
      "kty": "EC",
      "crv": "P-256",
      "x": "base64url_encoded_x",
      "y": "base64url_encoded_y",
      "use": "sig",
      "alg": "ES256",
      "issuer": "USA",
      "role": "CMC",
      "not_before": "2025-01-01T00:00:00Z",
      "not_after": "2027-01-01T00:00:00Z",
      "status": "active",
      "rotation_generation": 1
    }
  ],
  "metadata": {
    "country": "USA",
    "last_updated": "2025-10-01T12:00:00Z",
    "next_update": "2025-10-02T12:00:00Z"
  }
}
```

#### VDS-NC Verification Process
1. Parse VDS-NC header and extract KID/signer reference
2. Fetch corresponding public key from PKD endpoint
3. Verify key validity period and status
4. Verify barcode signature using public key
5. Validate payload against printed/visual data
6. Check temporal validity (document expiry, signature freshness)

## Key Lifecycle Management

### 3.1 Key Rotation Strategy

#### Rotation Windows
```yaml
rotation_schedule:
  dsc_keys:
    rotation_interval: 90-365 days
    warning_period: 30 days
    overlap_period: 7-30 days  # Both old and new keys valid
    
  vds_nc_keys:
    rotation_interval: 180-1095 days (6 months - 3 years)
    warning_period: 60 days
    overlap_period: 30-90 days
    max_parallel_keys: 3  # Support up to 3 active keys during rotation
```

#### Overlap Period Strategy
During overlap periods, multiple keys are simultaneously valid:
- **Signers**: Use new key for new signatures
- **Verifiers**: Accept signatures from both old and new keys
- **Grace Period**: Allow 30-day grace after key expiration for verification

### 3.2 Key Identifier (KID) Generation

#### Deterministic KID Format
```
Format: {TYPE}-{COUNTRY}-{ROLE}-{YEAR}-{SEQUENCE}
Examples:
  - VDS-NC-USA-CMC-2025-01
  - VDS-NC-FRA-VISA-2025-02
  - DSC-DEU-001-2025
```

#### Alternative: UUID-based KID
```
Format: UUID v4 or v5 (namespace-based)
Example: 550e8400-e29b-41d4-a716-446655440000
```

### 3.3 Key Metadata Tracking

#### Database Schema
```sql
CREATE TABLE signing_keys (
    kid VARCHAR(255) PRIMARY KEY,
    key_type VARCHAR(50) NOT NULL,  -- 'DSC' or 'VDS-NC'
    issuer_country VARCHAR(3) NOT NULL,
    role VARCHAR(50),  -- 'CMC', 'VISA', 'PASSPORT'
    public_key_pem TEXT NOT NULL,
    private_key_id VARCHAR(255),  -- HSM reference or encrypted key ID
    algorithm VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL,  -- 'pending', 'active', 'rotating', 'deprecated', 'revoked'
    rotation_generation INT NOT NULL DEFAULT 1,
    not_before TIMESTAMP NOT NULL,
    not_after TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMP,
    deprecated_at TIMESTAMP,
    revoked_at TIMESTAMP,
    revocation_reason TEXT,
    metadata JSONB,
    INDEX idx_issuer_role (issuer_country, role),
    INDEX idx_status (status),
    INDEX idx_validity (not_before, not_after)
);
```

### 3.4 Rotation Process

#### Pre-Rotation Phase (Warning Period)
1. Monitor key expiration dates
2. Trigger alerts 60 days before expiration
3. Generate new key pair (in HSM if available)
4. Assign KID and metadata
5. Set status to 'pending'

#### Rotation Phase
1. Activate new key (status → 'active')
2. Publish to PKD endpoints
3. Update old key status to 'rotating'
4. Begin overlap period
5. Configure signers to use new key for new signatures
6. Verifiers accept both keys

#### Post-Rotation Phase
1. Monitor signature creation with old key (should cease)
2. After overlap period, deprecate old key (status → 'deprecated')
3. Maintain deprecated key for verification for grace period
4. After grace period, revoke or archive key

#### Rotation API
```python
POST /api/v1/keys/rotate
{
  "key_type": "VDS-NC",
  "issuer": "USA",
  "role": "CMC",
  "activation_date": "2025-10-15T00:00:00Z",
  "overlap_days": 30
}

Response:
{
  "old_kid": "VDS-NC-USA-CMC-2024-01",
  "new_kid": "VDS-NC-USA-CMC-2025-01",
  "overlap_start": "2025-10-15T00:00:00Z",
  "overlap_end": "2025-11-14T23:59:59Z",
  "deprecation_date": "2025-11-15T00:00:00Z"
}
```

## Verifier Behavior

### 4.1 Trust List Management

#### Periodic Fetching
```yaml
fetch_strategy:
  initial_fetch: On verifier startup
  periodic_refresh: Every 24 hours
  on_key_miss: When unknown KID encountered
  cache_duration: 86400 seconds (24 hours)
  max_cache_age: 172800 seconds (48 hours) - trigger warning
```

#### Trust List Structure
```python
@dataclass
class TrustList:
    """Unified trust list for all verification paths"""
    csca_certificates: Dict[str, x509.Certificate]  # country → CSCA
    dsc_certificates: Dict[str, List[x509.Certificate]]  # country → [DSC]
    vds_nc_keys: Dict[str, VDSNCPublicKey]  # kid → public key
    last_updated: datetime
    next_update: datetime
    source: str  # PKD endpoint URL
    signature: Optional[bytes]  # Trust list signature if supported
```

#### Refresh Process
```python
async def refresh_trust_list():
    """Refresh trust list from PKD"""
    try:
        # Fetch DSC certificates
        dsc_response = await pkd_client.get("/api/v1/pkd/dsc/all")
        
        # Fetch VDS-NC keys
        vds_nc_response = await pkd_client.get("/api/v1/pkd/vds-nc-keys/all")
        
        # Validate responses
        if not validate_pkd_response(dsc_response, vds_nc_response):
            logger.error("PKD response validation failed")
            return False
            
        # Update trust store
        trust_store.update_dsc_certificates(dsc_response.certificates)
        trust_store.update_vds_nc_keys(vds_nc_response.keys)
        trust_store.last_updated = datetime.now(timezone.utc)
        
        # Persist to cache
        await trust_store.save_to_cache()
        
        return True
    except Exception as e:
        logger.error(f"Trust list refresh failed: {e}")
        return False
```

### 4.2 Chain Validation

#### CSCA → DSC Chain
```python
def validate_dsc_chain(dsc: x509.Certificate, sod: SecurityObject) -> ValidationResult:
    """Validate DSC certificate chain"""
    
    # 1. Find issuing CSCA
    issuer_dn = dsc.issuer
    csca = trust_store.find_csca_by_subject(issuer_dn)
    
    if not csca:
        return ValidationResult(valid=False, reason="Unknown CSCA")
    
    # 2. Verify DSC signature
    if not verify_certificate_signature(dsc, csca.public_key()):
        return ValidationResult(valid=False, reason="Invalid DSC signature")
    
    # 3. Check validity period
    now = datetime.now(timezone.utc)
    if not (dsc.not_valid_before <= now <= dsc.not_valid_after):
        return ValidationResult(valid=False, reason="DSC expired or not yet valid")
    
    # 4. Check revocation (CRL or OCSP)
    if is_revoked(dsc):
        return ValidationResult(valid=False, reason="DSC revoked")
    
    # 5. Validate key usage
    if not has_required_key_usage(dsc, ["digitalSignature"]):
        return ValidationResult(valid=False, reason="Invalid key usage")
    
    # 6. Verify SOD signature with DSC
    if not verify_sod_signature(sod, dsc.public_key()):
        return ValidationResult(valid=False, reason="Invalid SOD signature")
    
    return ValidationResult(valid=True)
```

#### VDS-NC Signature Validation
```python
def validate_vds_nc_signature(vds_nc: VDSNCBarcode) -> ValidationResult:
    """Validate VDS-NC barcode signature"""
    
    # 1. Extract KID from barcode
    kid = vds_nc.certificate_reference or extract_kid_from_header(vds_nc)
    
    if not kid:
        return ValidationResult(valid=False, reason="Missing key identifier")
    
    # 2. Fetch public key from trust store
    public_key = trust_store.get_vds_nc_key(kid)
    
    if not public_key:
        # Attempt to fetch from PKD
        public_key = await fetch_vds_nc_key_from_pkd(kid)
        
        if not public_key:
            # FAIL CLOSED: Unknown key
            return ValidationResult(valid=False, reason="Unknown VDS-NC key")
    
    # 3. Check key validity
    now = datetime.now(timezone.utc)
    if not (public_key.not_before <= now <= public_key.not_after):
        return ValidationResult(valid=False, reason="VDS-NC key expired or not yet valid")
    
    # 4. Check key status
    if public_key.status in ["revoked", "compromised"]:
        return ValidationResult(valid=False, reason=f"VDS-NC key {public_key.status}")
    
    # 5. Verify signature
    if not verify_ecdsa_signature(
        message=vds_nc.signed_payload,
        signature=vds_nc.signature,
        public_key=public_key.ec_public_key
    ):
        return ValidationResult(valid=False, reason="Invalid VDS-NC signature")
    
    return ValidationResult(valid=True)
```

### 4.3 Fail-Closed Policy

#### Unknown/Untrusted Keys
```python
class TrustPolicy(Enum):
    FAIL_CLOSED = "fail_closed"  # Reject unknown keys
    FAIL_OPEN = "fail_open"      # Accept with warning (NOT RECOMMENDED)
    SELECTIVE = "selective"       # Configurable per issuer

# Default policy: FAIL CLOSED
DEFAULT_POLICY = TrustPolicy.FAIL_CLOSED

def verify_with_policy(credential, policy=DEFAULT_POLICY):
    """Verify credential according to trust policy"""
    
    result = validate_credential(credential)
    
    if not result.valid:
        if result.reason == "Unknown key" or result.reason == "Unknown CSCA":
            if policy == TrustPolicy.FAIL_CLOSED:
                # Strict mode: reject
                return VerificationResult(
                    valid=False,
                    reason=result.reason,
                    security_level="strict"
                )
            elif policy == TrustPolicy.FAIL_OPEN:
                # Permissive mode: accept with warning (NOT RECOMMENDED)
                return VerificationResult(
                    valid=True,
                    warnings=[result.reason],
                    security_level="permissive"
                )
    
    return result
```

### 4.4 Freshness Validation

#### Trust List Freshness
```python
def validate_trust_list_freshness(trust_store: TrustStore) -> bool:
    """Ensure trust list is not stale"""
    
    now = datetime.now(timezone.utc)
    age = now - trust_store.last_updated
    
    # Warning threshold: 24 hours
    if age.total_seconds() > 86400:
        logger.warning(f"Trust list is {age.total_seconds()/3600:.1f} hours old")
    
    # Critical threshold: 48 hours
    if age.total_seconds() > 172800:
        logger.error("Trust list is critically stale")
        return False
    
    return True
```

#### Signature Freshness
```python
def validate_signature_freshness(signature_date: datetime, max_age_days: int = 90) -> bool:
    """Validate signature is not too old"""
    
    now = datetime.now(timezone.utc)
    age = now - signature_date
    
    if age.days > max_age_days:
        logger.warning(f"Signature is {age.days} days old")
        return False
    
    return True
```

## PKD Endpoint Specifications

### 5.1 DSC Distribution

```http
GET /api/v1/pkd/dsc/{country_code}
Accept: application/x-pkcs7-certificates, application/json

Response (JSON format):
{
  "country": "USA",
  "certificates": [
    {
      "serial_number": "0A1B2C3D4E5F",
      "subject": "CN=USA Document Signer,O=US Department of State,C=US",
      "issuer": "CN=USA CSCA,O=US Department of State,C=US",
      "not_before": "2024-01-01T00:00:00Z",
      "not_after": "2025-01-01T00:00:00Z",
      "fingerprint_sha256": "abcd1234...",
      "key_identifier": "1A:2B:3C:4D:5E:6F",
      "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
      "status": "active"
    }
  ],
  "metadata": {
    "last_updated": "2025-10-01T12:00:00Z",
    "total_count": 5,
    "active_count": 3
  }
}
```

### 5.2 VDS-NC Key Distribution

```http
GET /api/v1/pkd/vds-nc-keys/{country_code}
Accept: application/json

Response:
{
  "country": "USA",
  "keys": [
    {
      "kid": "VDS-NC-USA-CMC-2025-01",
      "kty": "EC",
      "crv": "P-256",
      "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
      "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
      "use": "sig",
      "alg": "ES256",
      "issuer": "USA",
      "role": "CMC",
      "not_before": "2025-01-01T00:00:00Z",
      "not_after": "2027-01-01T00:00:00Z",
      "status": "active",
      "rotation_generation": 1
    }
  ],
  "metadata": {
    "last_updated": "2025-10-01T12:00:00Z",
    "next_update": "2025-10-02T12:00:00Z"
  }
}
```

### 5.3 Unified Trust Store Endpoint

```http
GET /api/v1/pkd/trust-store/{country_code}
Accept: application/json

Response:
{
  "country": "USA",
  "csca_certificates": [...],
  "dsc_certificates": [...],
  "vds_nc_keys": [...],
  "metadata": {
    "last_updated": "2025-10-01T12:00:00Z",
    "next_update": "2025-10-02T12:00:00Z",
    "format_version": "1.0"
  }
}
```

## Security Considerations

### 6.1 Key Protection
- Store private keys in HSM or secure key vault
- Use strong key derivation for software keys
- Implement access controls and audit logging

### 6.2 Transport Security
- PKD endpoints MUST use TLS 1.3
- Implement certificate pinning for PKD connections
- Consider signing PKD responses for integrity

### 6.3 Revocation
- Support CRL and OCSP for DSC certificates
- Implement revocation lists for VDS-NC keys
- Provide emergency revocation mechanism

### 6.4 Monitoring
- Track key usage and rotation events
- Alert on approaching expirations
- Monitor verification failures and unknown keys
- Detect anomalous signature patterns

## Implementation Checklist

- [ ] Implement key lifecycle management system
- [ ] Create KID generation and tracking
- [ ] Build PKD distribution endpoints
- [ ] Implement verifier trust list management
- [ ] Add periodic trust list refresh
- [ ] Implement fail-closed verification
- [ ] Add chain validation for CSCA→DSC
- [ ] Add signature validation for VDS-NC
- [ ] Create key rotation automation
- [ ] Implement overlap period handling
- [ ] Add trust list freshness validation
- [ ] Build revocation checking
- [ ] Create monitoring and alerting
- [ ] Write integration tests
- [ ] Document verifier integration guide

## References

- ICAO Doc 9303 Part 11: Security Mechanisms for MRTDs
- ICAO Doc 9303 Part 12: Public Key Infrastructure for MRTDs
- ICAO Doc 9303 Part 13: Visible Digital Seals
- VDS-NC Technical Specification
- RFC 7517: JSON Web Key (JWK)
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
