# Verifier Integration Guide

## Overview

This guide provides step-by-step instructions for integrating Marty's unified trust verification system into verifier applications. The system supports both chip/LDS (ICAO Doc 9303 Parts 11-12) and VDS-NC barcode verification with a single trust model.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Verifier Application                    │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │          Trust List Manager                       │  │
│  │  - Periodic PKD fetch (24h)                      │  │
│  │  - Local caching                                  │  │
│  │  - Freshness validation                           │  │
│  └──────────────────────────────────────────────────┘  │
│                       │                                  │
│       ┌───────────────┴───────────────┐                │
│       ▼                               ▼                 │
│  ┌─────────────────┐           ┌─────────────────┐    │
│  │ CSCA→DSC Chain  │           │  VDS-NC Sig     │    │
│  │   Validator     │           │   Validator     │    │
│  └─────────────────┘           └─────────────────┘    │
└─────────────────────────────────────────────────────────┘
                       │
                       ▼
             ┌──────────────────┐
             │   PKD Service    │
             │  (REST API)      │
             └──────────────────┘
```

## Quick Start

### 1. Installation

```bash
pip install marty-trust-verification
```

Or add to your `requirements.txt`:

```
marty-trust-verification>=1.0.0
```

### 2. Basic Initialization

```python
from marty_common.verification.trust_list_manager import (
    PKDClient,
    TrustListCache,
    TrustListManager,
    TrustPolicy,
)

# Initialize components
pkd_client = PKDClient(
    pkd_base_url="https://pkd.example.com",
    timeout=30
)

cache = TrustListCache(
    cache_dir="/var/cache/myapp/trust_list"
)

trust_manager = TrustListManager(
    pkd_client=pkd_client,
    cache=cache,
    refresh_interval_hours=24,
    trust_policy=TrustPolicy.FAIL_CLOSED  # Recommended
)

# Initialize trust list (async)
await trust_manager.initialize()
```

### 3. Verify VDS-NC Signature

```python
# Parse VDS-NC barcode
kid = extract_kid_from_barcode(vds_nc_data)
message = extract_signed_payload(vds_nc_data)
signature = extract_signature(vds_nc_data)

# Verify signature
result = trust_manager.verify_vds_nc_signature(
    kid=kid,
    message=message,
    signature=signature
)

if result.valid:
    print("✓ VDS-NC signature verified")
else:
    print(f"✗ Verification failed: {result.reason}")
```

## Detailed Integration

### Trust List Initialization

#### Option A: Automatic Initialization

```python
# Loads from cache if available, otherwise fetches from PKD
await trust_manager.initialize()

# Automatically starts periodic refresh background task
```

#### Option B: Manual Control

```python
# Load from cache only
trust_list = await trust_manager.cache.load()

if not trust_list or trust_list.is_stale()[0]:
    # Fetch fresh trust list
    success = await trust_manager.refresh_trust_list()
    if not success:
        raise RuntimeError("Failed to fetch trust list")

# Start periodic refresh manually
trust_manager.start_periodic_refresh()
```

### Configuration Options

#### PKD Client Configuration

```python
pkd_client = PKDClient(
    pkd_base_url="https://pkd.marty.example.com",
    timeout=30,  # Request timeout in seconds
)
```

#### Cache Configuration

```python
cache = TrustListCache(
    cache_dir="/var/cache/myapp/trust_list"
)

# Cache structure:
# /var/cache/myapp/trust_list/
#   └── trust_list.json  # Contains CSCAs, DSCs, VDS-NC keys
```

#### Trust Policy Configuration

```python
# Recommended: FAIL_CLOSED (reject unknown keys)
trust_manager = TrustListManager(
    ...,
    trust_policy=TrustPolicy.FAIL_CLOSED
)

# Alternative: FAIL_OPEN (accept with warnings - NOT RECOMMENDED for production)
trust_manager = TrustListManager(
    ...,
    trust_policy=TrustPolicy.FAIL_OPEN
)

# Selective: Configure per issuer (advanced)
trust_manager = TrustListManager(
    ...,
    trust_policy=TrustPolicy.SELECTIVE
)
```

#### Refresh Interval

```python
trust_manager = TrustListManager(
    ...,
    refresh_interval_hours=24  # Default: 24 hours
)
```

### VDS-NC Signature Verification

#### Complete Example

```python
def verify_vds_nc_barcode(barcode_data: str) -> dict:
    """Verify VDS-NC barcode completely."""

    # 1. Parse barcode
    try:
        header, payload, signature_b64 = parse_vds_nc_barcode(barcode_data)
    except Exception as e:
        return {"valid": False, "reason": f"Barcode parsing failed: {e}"}

    # 2. Extract KID from header or use certificate_reference
    kid = extract_kid_from_header(header)

    # 3. Get public key from trust manager
    key = await trust_manager.get_vds_nc_key(kid)

    if not key:
        return {
            "valid": False,
            "reason": f"Unknown key: {kid}",
            "security_level": "strict"
        }

    # 4. Check key validity
    if not key.is_valid_now():
        return {
            "valid": False,
            "reason": f"Key expired or not active: {key.status}"
        }

    # 5. Verify signature
    import base64
    message = (header + payload).encode('utf-8')
    signature = base64.b64decode(signature_b64)

    result = trust_manager.verify_vds_nc_signature(kid, message, signature)

    # 6. Validate payload against printed/visual data
    if result.valid:
        payload_data = json.loads(payload)
        if not validate_payload_consistency(payload_data, printed_data):
            result.valid = False
            result.reason = "Payload doesn't match printed data"

    return {
        "valid": result.valid,
        "reason": result.reason,
        "security_level": result.security_level,
        "warnings": result.warnings,
        "key_info": {
            "kid": key.kid,
            "issuer": key.issuer_country,
            "role": key.role,
            "rotation_generation": key.rotation_generation
        }
    }
```

#### Signature Format Handling

```python
# VDS-NC signatures are typically base64-encoded
import base64

def extract_signature(vds_nc_data: dict) -> bytes:
    """Extract and decode signature from VDS-NC."""
    signature_b64 = vds_nc_data.get("signature")

    if not signature_b64:
        raise ValueError("Missing signature")

    # Decode from base64
    signature_bytes = base64.b64decode(signature_b64)

    return signature_bytes
```

### CSCA→DSC Chain Validation

#### Basic DSC Verification

```python
from cryptography import x509

def verify_dsc_chain(dsc_cert: x509.Certificate, sod_data: bytes):
    """Verify DSC certificate chain and SOD signature."""

    # 1. Extract issuer from DSC
    issuer_dn = dsc_cert.issuer.rfc4514_string()

    # 2. Find CSCA certificate
    csca_cert = trust_manager.trust_list.csca_certificates.get(country_code)

    if not csca_cert:
        return ValidationResult(
            valid=False,
            reason=f"Unknown CSCA for country: {country_code}"
        )

    # 3. Verify DSC signature with CSCA
    try:
        csca_public_key = csca_cert.public_key()
        csca_public_key.verify(
            dsc_cert.signature,
            dsc_cert.tbs_certificate_bytes,
            # Signature algorithm from DSC
        )
    except Exception as e:
        return ValidationResult(
            valid=False,
            reason=f"DSC signature invalid: {e}"
        )

    # 4. Check DSC validity period
    now = datetime.now(timezone.utc)
    if not (dsc_cert.not_valid_before <= now <= dsc_cert.not_valid_after):
        return ValidationResult(
            valid=False,
            reason="DSC expired or not yet valid"
        )

    # 5. Check key usage
    try:
        key_usage = dsc_cert.extensions.get_extension_for_class(
            x509.KeyUsage
        ).value

        if not key_usage.digital_signature:
            return ValidationResult(
                valid=False,
                reason="DSC missing digital_signature key usage"
            )
    except x509.ExtensionNotFound:
        return ValidationResult(
            valid=False,
            reason="DSC missing key usage extension"
        )

    # 6. Verify SOD signature with DSC
    # (SOD verification implementation depends on format)

    return ValidationResult(valid=True, reason="DSC chain verified")
```

### Trust List Management

#### Check Freshness

```python
# Validate trust list is not stale
freshness_result = trust_manager.validate_trust_list_freshness()

if not freshness_result.valid:
    logger.error(f"Trust list stale: {freshness_result.reason}")
    # Force refresh
    await trust_manager.refresh_trust_list()
```

#### Manual Refresh

```python
# Trigger manual refresh
success = await trust_manager.refresh_trust_list()

if success:
    logger.info("Trust list refreshed successfully")
else:
    logger.error("Trust list refresh failed")
```

#### Get Statistics

```python
if trust_manager.trust_list:
    stats = trust_manager.trust_list.get_stats()

    print(f"CSCAs: {stats['csca_count']}")
    print(f"DSCs: {stats['dsc_count']}")
    print(f"VDS-NC Keys: {stats['vds_nc_key_count']}")
    print(f"Age: {stats['age_hours']:.1f} hours")
```

### Error Handling

#### Unknown Key Handling

```python
result = trust_manager.verify_vds_nc_signature(kid, message, signature)

if not result.valid:
    if "Unknown" in result.reason:
        # Key not in trust list - attempt to fetch
        key = await trust_manager.get_vds_nc_key(kid)

        if key:
            # Retry verification
            result = trust_manager.verify_vds_nc_signature(
                kid, message, signature
            )
        else:
            # Fail closed - reject
            logger.warning(f"Rejecting unknown key: {kid}")
            return {"valid": False, "reason": "Unknown key"}
```

#### Network Failures

```python
try:
    await trust_manager.refresh_trust_list()
except aiohttp.ClientError as e:
    logger.error(f"PKD fetch failed: {e}")

    # Use cached trust list if available
    if trust_manager.trust_list:
        is_critical, msg = trust_manager.trust_list.is_stale()

        if is_critical:
            # Cache too old - fail verification
            raise RuntimeError("Trust list critically stale and refresh failed")
        else:
            # Continue with stale cache
            logger.warning(f"Using stale trust list: {msg}")
```

### Monitoring and Logging

#### Setup Logging

```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Specific loggers
trust_logger = logging.getLogger('marty_common.verification.trust_list_manager')
trust_logger.setLevel(logging.DEBUG)
```

#### Metrics to Track

```python
from prometheus_client import Counter, Gauge, Histogram

# Verification metrics
verifications_total = Counter(
    'vds_nc_verifications_total',
    'Total VDS-NC verifications',
    ['result', 'reason']
)

verification_duration = Histogram(
    'vds_nc_verification_duration_seconds',
    'VDS-NC verification duration'
)

# Trust list metrics
trust_list_age_hours = Gauge(
    'trust_list_age_hours',
    'Age of trust list in hours'
)

trust_list_keys_count = Gauge(
    'trust_list_keys_count',
    'Number of keys in trust list',
    ['key_type']
)

unknown_keys_total = Counter(
    'unknown_keys_total',
    'Total unknown keys encountered',
    ['kid']
)

# Update metrics
def update_trust_list_metrics():
    if trust_manager.trust_list:
        stats = trust_manager.trust_list.get_stats()
        trust_list_age_hours.set(stats['age_hours'])
        trust_list_keys_count.labels('csca').set(stats['csca_count'])
        trust_list_keys_count.labels('dsc').set(stats['dsc_count'])
        trust_list_keys_count.labels('vds_nc').set(stats['vds_nc_key_count'])

# Track verification
import time

def track_verification(kid: str, result: ValidationResult):
    # Count verification
    verifications_total.labels(
        result='success' if result.valid else 'failure',
        reason=result.reason[:50]  # Truncate
    ).inc()

    # Track unknown keys
    if 'Unknown' in result.reason:
        unknown_keys_total.labels(kid=kid).inc()
```

### Production Deployment

#### Docker Configuration

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create cache directory
RUN mkdir -p /var/cache/myapp/trust_list

# Environment variables
ENV PKD_BASE_URL="https://pkd.marty.example.com"
ENV TRUST_CACHE_DIR="/var/cache/myapp/trust_list"
ENV TRUST_REFRESH_INTERVAL_HOURS="24"
ENV TRUST_POLICY="fail_closed"

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \\
    CMD python -c "import requests; requests.get('http://localhost:8000/health').raise_for_status()"

CMD ["python", "app.py"]
```

#### Environment Variables

```bash
# PKD endpoint
export PKD_BASE_URL="https://pkd.marty.example.com"

# Cache directory
export TRUST_CACHE_DIR="/var/cache/myapp/trust_list"

# Refresh interval (hours)
export TRUST_REFRESH_INTERVAL_HOURS="24"

# Trust policy
export TRUST_POLICY="fail_closed"  # fail_closed, fail_open, selective

# Logging
export LOG_LEVEL="INFO"
```

#### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: verifier-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: verifier
  template:
    metadata:
      labels:
        app: verifier
    spec:
      containers:
      - name: verifier
        image: myapp/verifier:latest
        env:
        - name: PKD_BASE_URL
          value: "https://pkd.marty.example.com"
        - name: TRUST_CACHE_DIR
          value: "/cache/trust_list"
        - name: TRUST_REFRESH_INTERVAL_HOURS
          value: "24"
        - name: TRUST_POLICY
          value: "fail_closed"
        volumeMounts:
        - name: trust-cache
          mountPath: /cache
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 10
      volumes:
      - name: trust-cache
        persistentVolumeClaim:
          claimName: trust-cache-pvc
```

## Testing

### Unit Tests

```python
import pytest
from unittest.mock import AsyncMock, Mock, patch

@pytest.mark.asyncio
async def test_vds_nc_verification_valid():
    """Test successful VDS-NC verification."""

    # Mock PKD client
    pkd_client = Mock(spec=PKDClient)
    cache = Mock(spec=TrustListCache)

    trust_manager = TrustListManager(
        pkd_client=pkd_client,
        cache=cache,
        trust_policy=TrustPolicy.FAIL_CLOSED
    )

    # Setup mock trust list with valid key
    mock_key = VDSNCPublicKey(
        kid="VDS-NC-USA-CMC-2025-01",
        public_key=generate_test_key(),
        issuer_country="USA",
        role="CMC",
        not_before=datetime.now(timezone.utc) - timedelta(days=30),
        not_after=datetime.now(timezone.utc) + timedelta(days=300),
        status="active",
        rotation_generation=1
    )

    trust_manager.trust_list = TrustList(
        vds_nc_keys={"VDS-NC-USA-CMC-2025-01": mock_key}
    )

    # Create valid signature
    message = b"test message"
    signature = sign_message(message, test_private_key)

    # Verify
    result = trust_manager.verify_vds_nc_signature(
        "VDS-NC-USA-CMC-2025-01",
        message,
        signature
    )

    assert result.valid
    assert result.reason == "VDS-NC signature verified"

@pytest.mark.asyncio
async def test_vds_nc_verification_unknown_key():
    """Test fail-closed for unknown key."""

    trust_manager = TrustListManager(
        pkd_client=Mock(),
        cache=Mock(),
        trust_policy=TrustPolicy.FAIL_CLOSED
    )

    trust_manager.trust_list = TrustList()

    result = trust_manager.verify_vds_nc_signature(
        "UNKNOWN-KEY",
        b"message",
        b"signature"
    )

    assert not result.valid
    assert "Unknown" in result.reason
    assert result.security_level == "strict"
```

### Integration Tests

```python
@pytest.mark.integration
@pytest.mark.asyncio
async def test_end_to_end_verification():
    """Test complete verification flow."""

    # Use real PKD client with test server
    pkd_client = PKDClient(pkd_base_url="http://localhost:8080")
    cache = TrustListCache(cache_dir="/tmp/test_trust_cache")

    trust_manager = TrustListManager(
        pkd_client=pkd_client,
        cache=cache,
        trust_policy=TrustPolicy.FAIL_CLOSED
    )

    # Initialize
    await trust_manager.initialize()

    assert trust_manager.trust_list is not None
    assert len(trust_manager.trust_list.vds_nc_keys) > 0

    # Verify real VDS-NC barcode
    result = verify_vds_nc_barcode(test_barcode_data)

    assert result["valid"]
    assert result["security_level"] == "strict"
```

## Troubleshooting

### Common Issues

#### 1. Trust List Not Refreshing

```python
# Check periodic refresh task
if not trust_manager._refresh_task or trust_manager._refresh_task.done():
    logger.warning("Refresh task not running, restarting")
    trust_manager.start_periodic_refresh()

# Force manual refresh
await trust_manager.refresh_trust_list()
```

#### 2. Unknown Key Errors

```python
# Verify KID extraction
kid = extract_kid_from_barcode(barcode_data)
logger.info(f"Extracted KID: {kid}")

# Check if key exists in PKD
key = await trust_manager.pkd_client.fetch_vds_nc_key_by_kid(kid)

if not key:
    logger.error(f"Key {kid} not found in PKD")
else:
    logger.info(f"Key {kid} found but not in local trust list")
    # Add to trust list
    trust_manager.trust_list.vds_nc_keys[kid] = key
```

#### 3. Cache Issues

```python
# Clear cache
import shutil
shutil.rmtree(cache.cache_dir)
cache.cache_dir.mkdir(parents=True)

# Force refresh
await trust_manager.refresh_trust_list()
```

## Best Practices

### 1. Always Use FAIL_CLOSED in Production

```python
# ✓ Recommended
trust_policy=TrustPolicy.FAIL_CLOSED

# ✗ Not recommended for production
trust_policy=TrustPolicy.FAIL_OPEN
```

### 2. Monitor Trust List Age

```python
# Check on every verification
freshness = trust_manager.validate_trust_list_freshness()

if not freshness.valid:
    alert_operations(f"Trust list stale: {freshness.reason}")
```

### 3. Implement Graceful Degradation

```python
try:
    result = verify_credential(credential)
except TrustListStaleError:
    # Log but continue with warnings
    logger.error("Trust list critically stale")
    return {"valid": False, "reason": "Trust list unavailable"}
```

### 4. Cache Management

```python
# Implement cache cleanup for old entries
async def cleanup_expired_keys():
    """Remove expired keys from trust list."""
    if not trust_manager.trust_list:
        return

    now = datetime.now(timezone.utc)
    grace_period = timedelta(days=30)

    expired_kids = [
        kid for kid, key in trust_manager.trust_list.vds_nc_keys.items()
        if key.not_after + grace_period < now
    ]

    for kid in expired_kids:
        del trust_manager.trust_list.vds_nc_keys[kid]
        logger.info(f"Removed expired key: {kid}")

    # Save updated trust list
    await trust_manager.cache.save(trust_manager.trust_list)
```

## Support and Resources

- **Documentation**: <https://docs.marty.example.com/trust-verification>
- **API Reference**: <https://api.marty.example.com/docs>
- **PKD Endpoint**: <https://pkd.marty.example.com>
- **Support**: <support@marty.example.com>

## Next Steps

1. Review the [Trust and PKD Protocol](./TRUST_AND_PKD_PROTOCOL.md) specification
2. Set up your PKD client configuration
3. Implement verification in your application
4. Set up monitoring and alerting
5. Test in staging environment
6. Deploy to production
