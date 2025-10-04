# Conformance & Negative Testing Matrix

## Overview

This document defines comprehensive acceptance criteria and negative test scenarios for the unified document verification system. The matrix covers all supported document types with their specific verification paths and failure modes.

## Document Types and Verification Paths

### Verification Protocol Hierarchy
The system implements a 5-layer hierarchical verification approach:
1. **Document Class Detection** - MRZ pattern matching
2. **MRZ Validation** - Structure and check digit verification
3. **Authenticity Layer** - Cryptographic verification (chip/VDS-NC)
4. **Semantics Validation** - Business rules and policy checks
5. **Trust Verification** - Certificate chain and PKD validation

### Supported Document Types
- **CMC (TD-1)** - Crew Member Certificates
- **MRV Type A/B** - Machine Readable Visas (sticker format)
- **TD-2** - Travel Documents (ID cards, permits)

---

## CMC (TD-1) Conformance Criteria

### 1. MRZ Correctness
| Check | Requirement | Acceptance Criteria |
|-------|-------------|-------------------|
| Structure | 3 lines × 30 characters | All lines exactly 30 chars |
| Format | TD-1 MRZ pattern | Lines 1-3 follow ICAO Doc 9303-5 |
| Check Digits | Document, DOB, Expiry, Composite | All 4 check digits mathematically valid |
| Character Set | A-Z, 0-9, < only | No invalid characters present |
| Padding | < character for empty spaces | Proper filler character usage |

### 2. Chip Path (SOD/DG1/DG2) Verification
| Component | Requirement | Acceptance Criteria |
|-----------|-------------|-------------------|
| SOD Presence | Security Object Document exists | SOD data available and parseable |
| SOD Signature | DSC signature validates | Cryptographic signature verification passes |
| DG1 Hash | MRZ data hash matches SOD | SHA-256 hash of MRZ data = SOD.DG1 hash |
| DG2 Hash | Face image hash matches SOD | SHA-256 hash of face image = SOD.DG2 hash |
| Certificate Chain | DSC → CSCA validation | Full PKI chain validates to trust anchor |
| Active Authentication | Optional chip challenge | If present, AA signature validates |

### 3. VDS-NC Path Verification
| Component | Requirement | Acceptance Criteria |
|-----------|-------------|-------------------|
| Barcode Format | VDS-NC structure | Valid JSON payload with required fields |
| Digital Signature | ECDSA/RSA signature | Signature validates against public key |
| Field Consistency | MRZ vs VDS-NC data | All common fields match exactly |
| Issuer Certificate | Known PKI certificate | Certificate exists in trust store |
| Timestamp Validity | Issue/expiry within bounds | Current time within validity window |

### 4. Annex 9 Policy Pre-checks
| Policy | Requirement | Acceptance Criteria |
|--------|-------------|-------------------|
| Background Check | Annex 9 compliance flag | background_check_verified = true |
| Crew Authorization | Valid crew member status | Employer field populated and verified |
| Geographic Constraints | Route/destination limits | Destination in allowed country list |
| Validity Window | Document not expired | Current date < expiry_date |
| Security Model | Chip or VDS-NC required | Either chip_data OR vds_nc_data present |

### 5. Expiry Handling
| Scenario | Requirement | Acceptance Criteria |
|----------|-------------|-------------------|
| Valid Document | Current date < expiry | Document passes temporal checks |
| Expired Document | Current date >= expiry | Document rejected with EXPIRED status |
| Early Issuance | Issue date <= current date | Document not used before issue date |
| Grace Period | Configurable extension | Optional grace period for operational flexibility |

---

## MRV Type A/B Conformance Criteria

### 1. MRZ Correctness
| Check | Type A (44 chars) | Type B (36 chars) | Acceptance Criteria |
|-------|------------------|------------------|-------------------|
| Structure | 2 lines × 44 chars | 2 lines × 36 chars | Exact character count per type |
| Format | V<country>... pattern | V<country>... pattern | Visa document code validation |
| Check Digits | Document, DOB, Expiry | Document, DOB, Expiry | All check digits valid |
| Character Set | A-Z, 0-9, < only | A-Z, 0-9, < only | No invalid characters |

### 2. VDS-NC E-visa Path
| Component | Requirement | Acceptance Criteria |
|-----------|-------------|-------------------|
| Barcode Decode | QR/DataMatrix format | Successfully decode to JSON payload |
| Signature Verify | Digital signature check | ECDSA/RSA signature validates |
| Certificate Validation | Issuer PKI certificate | Certificate in trust store and valid |
| Field Mapping | JSON to visa fields | All required fields present and mapped |
| Temporal Validity | Issue/expiry dates | Current time within validity window |

### 3. Mismatch Detection (Printed vs VDS-NC)
| Field | Printed Source | VDS-NC Source | Acceptance Criteria |
|-------|---------------|---------------|-------------------|
| Document Number | MRZ line 1 | JSON.doc | Values must match exactly |
| Surname | MRZ line 1 | JSON.sur | Values must match exactly |
| Given Names | MRZ line 1 | JSON.giv | Values must match exactly |
| Nationality | MRZ line 2 | JSON.nat | Values must match exactly |
| Date of Birth | MRZ line 2 | JSON.dob | Values must match exactly |
| Gender | MRZ line 2 | JSON.sex | Values must match exactly |
| Date of Expiry | MRZ line 2 | JSON.exp | Values must match exactly |
| Issuing State | MRZ line 1 | JSON.iss | Values must match exactly |

---

## TD-2 Conformance Criteria

### 1. MRZ Correctness
| Check | Requirement | Acceptance Criteria |
|-------|-------------|-------------------|
| Structure | 2 lines × 36 characters | Both lines exactly 36 chars |
| Format | ID card pattern | Follows ICAO Doc 9303-6 |
| Check Digits | Document, DOB, Expiry, Composite | All check digits mathematically valid |
| Character Set | A-Z, 0-9, < only | No invalid characters present |

### 2. Optional Chip Path
| Component | Requirement | Acceptance Criteria |
|-----------|-------------|-------------------|
| Chip Detection | RFID/contactless presence | If present, chip data readable |
| SOD Verification | Security Object validation | SOD signature and hashes valid |
| DG Hash Check | Minimal profile DGs | DG1 (MRZ) hash verification |
| Fallback Mode | Chip failure handling | System continues without chip if unavailable |

### 3. Truncation/Name Rules
| Rule | Requirement | Acceptance Criteria |
|------|-------------|-------------------|
| Name Truncation | Surname priority | Surname fits, given names truncated if needed |
| Special Characters | Transliteration rules | Non-Latin chars converted per ICAO rules |
| Multiple Given Names | Space handling | Multiple names separated by < or spaces |
| Name Order | Cultural considerations | Surname first, given names follow |

---

## Negative Testing Matrix

### 1. MRZ Check Digit Failures
| Test Case | Invalid Field | Expected Result |
|-----------|---------------|------------------|
| Wrong Document Check | Corrupt document number check digit | MRZ_INVALID, check_digit_error |
| Wrong DOB Check | Corrupt date of birth check digit | MRZ_INVALID, check_digit_error |
| Wrong Expiry Check | Corrupt expiry date check digit | MRZ_INVALID, check_digit_error |
| Wrong Composite Check | Corrupt overall check digit | MRZ_INVALID, check_digit_error |
| Multiple Errors | Multiple check digits wrong | MRZ_INVALID, multiple_errors |

### 2. Altered Printed Fields vs VDS-NC
| Test Case | Altered Field | Expected Result |
|-----------|---------------|------------------|
| Document Number Mismatch | Printed ≠ VDS-NC document number | FIELD_MISMATCH, document_number |
| Name Mismatch | Printed ≠ VDS-NC surname/given names | FIELD_MISMATCH, name_fields |
| DOB Mismatch | Printed ≠ VDS-NC date of birth | FIELD_MISMATCH, date_of_birth |
| Nationality Mismatch | Printed ≠ VDS-NC nationality | FIELD_MISMATCH, nationality |
| Expiry Mismatch | Printed ≠ VDS-NC expiry date | FIELD_MISMATCH, expiry_date |

### 3. Temporal Validity Issues
| Test Case | Scenario | Expected Result |
|-----------|----------|------------------|
| Expired Document | Current date > expiry date | DOCUMENT_EXPIRED |
| Not Yet Valid | Current date < issue date | DOCUMENT_NOT_VALID_YET |
| Future DOB | Date of birth > current date | INVALID_DOB |
| Invalid Date Format | Malformed date fields | DATE_FORMAT_ERROR |

### 4. Unknown/Invalid Signer Keys
| Test Case | Scenario | Expected Result |
|-----------|----------|------------------|
| Unknown CSCA | Certificate not in trust store | UNKNOWN_ISSUER |
| Revoked Certificate | Certificate in CRL | CERTIFICATE_REVOKED |
| Expired Certificate | Certificate past validity | CERTIFICATE_EXPIRED |
| Wrong Key Usage | Certificate wrong purpose | INVALID_KEY_USAGE |
| Untrusted Root | No path to trust anchor | UNTRUSTED_CERTIFICATE |

### 5. Altered SOD Hashes
| Test Case | Scenario | Expected Result |
|-----------|----------|------------------|
| DG1 Hash Mismatch | SOD.DG1 ≠ actual MRZ hash | DG1_HASH_MISMATCH |
| DG2 Hash Mismatch | SOD.DG2 ≠ actual image hash | DG2_HASH_MISMATCH |
| Missing DG Hash | Required DG hash not in SOD | MISSING_DG_HASH |
| Corrupted SOD | SOD signature invalid | SOD_SIGNATURE_INVALID |
| Wrong Hash Algorithm | Unexpected hash algorithm | UNSUPPORTED_HASH_ALGORITHM |

### 6. Barcode Re-encoding Drift
| Test Case | Scenario | Expected Result |
|-----------|----------|------------------|
| Encoding Artifacts | QR/DataMatrix decode errors | BARCODE_DECODE_ERROR |
| Character Corruption | UTF-8/ASCII conversion issues | CHARACTER_ENCODING_ERROR |
| Format Drift | JSON structure changes | JSON_PARSE_ERROR |
| Compression Issues | Data compression/decompression errors | DECOMPRESSION_ERROR |
| Size Limitations | Barcode data truncation | DATA_TRUNCATION_ERROR |

---

## Implementation Guidelines

### Test Execution Framework
1. **Automated Test Suite**: Implement all conformance and negative tests as automated test cases
2. **Test Data Generation**: Create valid and invalid test documents for each scenario
3. **Assertion Framework**: Define clear pass/fail criteria for each test case
4. **Coverage Metrics**: Ensure all verification paths and error conditions are tested

### Integration Points
1. **MRZ Validation Engine**: Test all MRZ parsing and check digit validation
2. **Cryptographic Services**: Test signature verification and certificate validation
3. **Policy Engine**: Test Annex 9 compliance and business rule validation
4. **Trust Store**: Test certificate chain validation and revocation checking

### Continuous Testing
1. **Regression Testing**: Run full test suite on each code change
2. **Performance Testing**: Measure verification throughput and latency
3. **Security Testing**: Test against adversarial documents and attacks
4. **Interoperability Testing**: Test with real-world document samples

### Monitoring and Alerting
1. **Test Results Dashboard**: Real-time visibility into test execution
2. **Failure Analysis**: Detailed logging and error classification
3. **Trend Analysis**: Track test success rates over time
4. **Alert Thresholds**: Notify on test failure patterns or degradation
