# Trust Services Architecture Design

## Overview
The Trust Services microservice provides centralized trust management for Marty, including PKD ingestion, revocation processing, and immutable trust snapshots.

## Components

### 1. PostgreSQL Trust Database Schema

#### Core Tables
```sql
-- Trust anchors (CSCA certificates)
CREATE TABLE trust_anchors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    country_code CHAR(3) NOT NULL,
    certificate_hash VARCHAR(64) UNIQUE NOT NULL,
    certificate_data BYTEA NOT NULL,
    subject_dn TEXT NOT NULL,
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_to TIMESTAMP WITH TIME ZONE NOT NULL,
    key_usage TEXT[],
    immutable_flag BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- DSC metadata and status
CREATE TABLE dsc_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    country_code CHAR(3) NOT NULL,
    certificate_hash VARCHAR(64) UNIQUE NOT NULL,
    certificate_data BYTEA NOT NULL,
    issuer_trust_anchor_id UUID REFERENCES trust_anchors(id),
    subject_dn TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_to TIMESTAMP WITH TIME ZONE NOT NULL,
    revocation_status VARCHAR(20) DEFAULT 'unknown', -- good, bad, unknown
    revocation_checked_at TIMESTAMP WITH TIME ZONE,
    revocation_reason INTEGER,
    crl_source TEXT,
    ocsp_source TEXT,
    immutable_flag BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- CRL metadata and status
CREATE TABLE crl_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer_dn TEXT NOT NULL,
    issuer_certificate_hash VARCHAR(64),
    crl_url TEXT,
    this_update TIMESTAMP WITH TIME ZONE NOT NULL,
    next_update TIMESTAMP WITH TIME ZONE NOT NULL,
    crl_data BYTEA NOT NULL,
    fetched_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Revoked certificates from CRLs
CREATE TABLE revoked_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    crl_id UUID REFERENCES crl_cache(id),
    serial_number TEXT NOT NULL,
    revocation_date TIMESTAMP WITH TIME ZONE NOT NULL,
    reason_code INTEGER,
    certificate_hash VARCHAR(64), -- if we can match to DSC
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Master list metadata
CREATE TABLE master_lists (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    country_code CHAR(3),
    sequence_number INTEGER,
    issue_date TIMESTAMP WITH TIME ZONE NOT NULL,
    next_update TIMESTAMP WITH TIME ZONE,
    certificate_count INTEGER NOT NULL,
    data_hash VARCHAR(64) NOT NULL,
    raw_data BYTEA NOT NULL,
    signature_valid BOOLEAN DEFAULT false,
    immutable_flag BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Trust snapshots (immutable views)
CREATE TABLE trust_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    snapshot_hash VARCHAR(64) NOT NULL,
    signature TEXT, -- KMS signed attestation
    trust_anchor_count INTEGER NOT NULL,
    dsc_count INTEGER NOT NULL,
    revoked_count INTEGER NOT NULL,
    metadata JSONB,
    immutable_flag BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### Indexes and Constraints
```sql
CREATE INDEX idx_trust_anchors_country ON trust_anchors(country_code);
CREATE INDEX idx_trust_anchors_hash ON trust_anchors(certificate_hash);
CREATE INDEX idx_dsc_country ON dsc_certificates(country_code);
CREATE INDEX idx_dsc_hash ON dsc_certificates(certificate_hash);
CREATE INDEX idx_dsc_serial ON dsc_certificates(serial_number);
CREATE INDEX idx_dsc_revocation_status ON dsc_certificates(revocation_status);
CREATE INDEX idx_revoked_serial ON revoked_certificates(serial_number);
CREATE INDEX idx_crl_issuer ON crl_cache(issuer_dn);
CREATE INDEX idx_snapshots_time ON trust_snapshots(snapshot_time);
```

### 2. Service Architecture

#### Core Services
- **PKD Ingestion Service**: Fetch and parse master lists from production/synthetic sources
- **Revocation Processor**: Parse CRLs, check OCSP, update DSC status
- **Trust Snapshot Service**: Create immutable trust views with signatures
- **Metrics Service**: Expose Prometheus metrics
- **API Service**: REST endpoints for verifiers

#### Job Scheduler
- **Master List Sync**: Periodic job to fetch updated master lists
- **CRL Refresh**: Fetch and process CRLs based on distribution points
- **OCSP Check**: Validate individual DSC status via OCSP
- **Trust Snapshot Creation**: Generate signed snapshots on schedule
- **Certificate Monitoring**: Track expiring certificates and freshness

### 3. API Endpoints

#### Trust Query API
```
GET /api/v1/trust/status/{certificate_hash}
GET /api/v1/trust/anchors/{country_code}
GET /api/v1/trust/dsc/{country_code}
GET /api/v1/trust/snapshot/{snapshot_id}
GET /api/v1/trust/snapshot/latest
```

#### Administrative API
```
POST /api/v1/admin/masterlist/upload
POST /api/v1/admin/crl/refresh
POST /api/v1/admin/snapshot/create
GET /api/v1/admin/status
```

#### Metrics Endpoint
```
GET /metrics
```

### 4. Prometheus Metrics

```
# Master list age in seconds
master_list_age_seconds{country="XXX"} 3600

# CRL age in seconds  
crl_age_seconds{issuer="CN=CSCA-USA"} 7200

# Total trusted DSCs
trusted_dsc_total{country="XXX",status="good"} 150

# Trust snapshot metrics
trust_snapshot_count 45
trust_snapshot_age_seconds 1800

# Job execution metrics
job_execution_duration_seconds{job="masterlist_sync"} 30.5
job_last_success_timestamp{job="crl_refresh"} 1696345200
```

### 5. Storage Strategy

#### Database Storage (PostgreSQL)
- Trust anchors and metadata
- DSC certificates and revocation status
- CRL cache and revoked certificate lists
- Trust snapshots and signatures

#### Object Storage (S3/MinIO)
- Raw PKD artifacts (master lists, CRLs)
- Large certificate bundles
- Backup snapshots
- Audit logs

#### Immutability Controls
- `immutable_flag` on critical records
- Write-once object storage for raw artifacts
- Cryptographic signatures on trust snapshots
- Audit trail for all changes

### 6. Development Job Design

#### One-shot Development Job
```bash
# Load synthetic master list and print statistics
trust-svc dev-load --synthetic --country=DEV --output=json

# Expected output:
{
  "master_list": {
    "country": "DEV", 
    "certificates": 25,
    "valid_certificates": 23,
    "expired_certificates": 2
  },
  "trust_anchors": {
    "loaded": 5,
    "skipped": 0
  },
  "dsc_certificates": {
    "loaded": 18,
    "revocation_status": {
      "good": 15,
      "bad": 1, 
      "unknown": 2
    }
  }
}
```

#### Grafana Dashboard Panel
- Certificate count by country
- Revocation status distribution
- Master list freshness
- Job execution status
- Trust snapshot timeline

### 7. Security Considerations

#### KMS Integration
- Sign trust snapshots with AWS KMS or external HSM
- Encrypt sensitive certificate data at rest
- Rotate signing keys periodically

#### Access Controls
- Role-based API access (viewer, operator, admin)
- Service-to-service authentication via mTLS
- Audit logging for all trust operations

#### Data Integrity
- Cryptographic hashes for all stored artifacts
- Signature verification on master lists
- Immutable storage for audit trails