# Certificate Lifecycle Management

*Last updated: May 11, 2025*

## Overview

The Marty Certificate Lifecycle Management system provides comprehensive tools for managing the entire lifecycle of digital certificates, from creation to expiration. This document outlines the available features, API endpoints, usage examples, and best practices.

## Features

- Complete certificate lifecycle management (creation, renewal, revocation)
- Certificate status monitoring and validation
- Automated expiry notifications
- Certificate rotation scheduling
- Integration with OpenXPKI for enterprise-grade PKI operations
- Support for both REST and gRPC interfaces

## Architecture

The Certificate Lifecycle Management system consists of the following components:

1. **CSCA Service**: Core service for Country Signing Certificate Authority operations
2. **Certificate Expiry Notification Service**: Monitors certificates and sends alerts
3. **OpenXPKI Integration**: Enterprise PKI backend for certificate operations
4. **Local Certificate Store**: For offline verification and improved performance
5. **Certificate Monitoring System**: For tracking certificate status and lifecycle events

## API Reference

### gRPC API

The primary interface for certificate lifecycle operations is the gRPC API defined in `proto/csca_service.proto`:

#### CreateCertificate

Creates a new certificate.

```protobuf
rpc CreateCertificate (CreateCertificateRequest) returns (CreateCertificateResponse);

message CreateCertificateRequest {
  string subject_name = 1;      // e.g., "CN=Test CSCA, O=Organization"
  int32 validity_days = 2;      // e.g., 365 for 1 year
  string key_algorithm = 3;     // e.g., "RSA", "ECDSA" 
  int32 key_size = 4;           // e.g., 2048 for RSA, 256 for ECDSA
  map<string, string> extensions = 5; // Optional X.509 extensions
}

message CreateCertificateResponse {
  string certificate_id = 1;    // Unique identifier for the certificate
  string certificate_data = 2;  // PEM-encoded certificate data
  string status = 3;            // e.g., "ISSUED", "FAILED"
  string error_message = 4;     // Present only if status is "FAILED"
}
```

#### RenewCertificate

Renews an existing certificate, creating a new one and marking the old one as superseded.

```protobuf
rpc RenewCertificate (RenewCertificateRequest) returns (CreateCertificateResponse);

message RenewCertificateRequest {
  string certificate_id = 1;    // ID of certificate to renew
  int32 validity_days = 2;      // Validity period for new certificate
  bool reuse_key = 3;           // Whether to reuse the existing key pair
}
```

#### RevokeCertificate

Revokes a certificate.

```protobuf
rpc RevokeCertificate (RevokeCertificateRequest) returns (RevokeCertificateResponse);

message RevokeCertificateRequest {
  string certificate_id = 1;    // ID of certificate to revoke
  string reason = 2;            // Revocation reason (e.g., "KEY_COMPROMISE")
}

message RevokeCertificateResponse {
  string certificate_id = 1;    // ID of revoked certificate
  bool success = 2;             // Whether revocation was successful
  string status = 3;            // e.g., "REVOKED", "FAILED"
  string error_message = 4;     // Present only if status is "FAILED"
}
```

#### GetCertificateStatus

Gets the current status of a certificate.

```protobuf
rpc GetCertificateStatus (CertificateStatusRequest) returns (CertificateStatusResponse);

message CertificateStatusRequest {
  string certificate_id = 1;    // ID of certificate to query
}

message CertificateStatusResponse {
  string certificate_id = 1;    // Certificate ID
  string status = 2;            // e.g., "VALID", "REVOKED", "EXPIRED", "SUPERSEDED"
  string not_before = 3;        // Certificate validity start date in ISO format
  string not_after = 4;         // Certificate validity end date in ISO format
  string revocation_reason = 5; // Present only if status is "REVOKED"
  string subject = 6;           // Certificate subject
  string issuer = 7;            // Certificate issuer
}
```

#### ListCertificates

Lists certificates with optional filtering.

```protobuf
rpc ListCertificates (ListCertificatesRequest) returns (ListCertificatesResponse);

message ListCertificatesRequest {
  string status_filter = 1;     // Filter by status (e.g., "VALID", "REVOKED")
  string subject_filter = 2;    // Filter by subject name (substring match)
}

message ListCertificatesResponse {
  repeated CertificateSummary certificates = 1;
}

message CertificateSummary {
  string certificate_id = 1;    // Certificate ID
  string status = 2;            // Certificate status
  string subject = 3;           // Certificate subject
  string issuer = 4;            // Certificate issuer
  string not_after = 5;         // Expiry date in ISO format
}
```

#### CheckExpiringCertificates

Checks for certificates that are expiring soon.

```protobuf
rpc CheckExpiringCertificates (CheckExpiringCertificatesRequest) returns (ListCertificatesResponse);

message CheckExpiringCertificatesRequest {
  int32 days_threshold = 1;     // Days threshold (e.g., 30 for certificates expiring within 30 days)
}
```

### REST API

The system also provides REST endpoints through the PKD service:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/csca/certificates` | GET | List CSCA certificates |
| `/v1/csca/certificates` | POST | Generate new CSCA certificate |
| `/v1/csca/certificates/{id}` | GET | Get certificate details |
| `/v1/csca/certificates/{id}/renew` | POST | Renew a certificate |
| `/v1/csca/certificates/{id}/revoke` | POST | Revoke a certificate |
| `/v1/csca/certificates/expiring` | GET | Get expiring certificates |
| `/v1/csca/check-expiry` | GET | Check for expiring certificates |

## Usage Examples

### Certificate Creation

```python
import grpc
from src.proto import csca_service_pb2, csca_service_pb2_grpc

# Create gRPC channel and stub
channel = grpc.insecure_channel('localhost:8081')
stub = csca_service_pb2_grpc.CscaServiceStub(channel)

# Define certificate parameters
request = csca_service_pb2.CreateCertificateRequest(
    subject_name="CN=Country CSCA, O=Marty System",
    validity_days=1095,  # 3 years
    key_algorithm="RSA",
    key_size=2048,
    extensions={"basicConstraints": "CA:TRUE", "keyUsage": "keyCertSign,cRLSign"}
)

# Create the certificate
response = stub.CreateCertificate(request)

# Check the result
if response.status == "ISSUED":
    print(f"Certificate created successfully. ID: {response.certificate_id}")
    # Store the certificate_id for future operations
else:
    print(f"Certificate creation failed: {response.error_message}")
```

### Certificate Renewal

```python
# Renew an existing certificate
renew_request = csca_service_pb2.RenewCertificateRequest(
    certificate_id="existing_certificate_id",
    validity_days=1095,  # 3 years
    reuse_key=False      # Generate a new key pair
)

renew_response = stub.RenewCertificate(renew_request)

if renew_response.status == "RENEWED":
    print(f"Certificate renewed. New ID: {renew_response.certificate_id}")
else:
    print(f"Certificate renewal failed: {renew_response.error_message}")
```

### Certificate Revocation

```python
# Revoke a certificate
revoke_request = csca_service_pb2.RevokeCertificateRequest(
    certificate_id="certificate_to_revoke_id",
    reason="KEY_COMPROMISE"  # Common reasons: KEY_COMPROMISE, SUPERSEDED, CESSATION_OF_OPERATION
)

revoke_response = stub.RevokeCertificate(revoke_request)

if revoke_response.success:
    print(f"Certificate {revoke_response.certificate_id} revoked successfully")
else:
    print(f"Certificate revocation failed: {revoke_response.error_message}")
```

### Certificate Status Check

```python
# Check certificate status
status_request = csca_service_pb2.CertificateStatusRequest(
    certificate_id="certificate_id_to_check"
)

status_response = stub.GetCertificateStatus(status_request)

print(f"Certificate status: {status_response.status}")
print(f"Valid from: {status_response.not_before}")
print(f"Valid until: {status_response.not_after}")

if status_response.status == "REVOKED":
    print(f"Revocation reason: {status_response.revocation_reason}")
```

### List Certificates

```python
# List all valid certificates
list_request = csca_service_pb2.ListCertificatesRequest(
    status_filter="VALID"
)

list_response = stub.ListCertificates(list_request)

print(f"Found {len(list_response.certificates)} valid certificates:")
for cert in list_response.certificates:
    print(f"ID: {cert.certificate_id}, Subject: {cert.subject}, Expires: {cert.not_after}")
```

### Check Expiring Certificates

```python
# Check for certificates expiring in the next 30 days
expiry_request = csca_service_pb2.CheckExpiringCertificatesRequest(
    days_threshold=30
)

expiry_response = stub.CheckExpiringCertificates(expiry_request)

print(f"Found {len(expiry_response.certificates)} certificates expiring within 30 days:")
for cert in expiry_response.certificates:
    print(f"ID: {cert.certificate_id}, Subject: {cert.subject}, Expires: {cert.not_after}")
```

## Best Practices

### Certificate Creation

1. **Key Size**: Use RSA keys of at least 2048 bits, or ECDSA keys of at least 256 bits.
2. **Validity Period**: For CSCA certificates, follow ICAO recommendations (typically 3-5 years).
3. **Subject Naming**: Use consistent naming conventions that include organization and country.
4. **Extensions**: Include appropriate X.509 extensions for the certificate's intended use.
5. **Key Storage**: Store private keys in a secure hardware security module (HSM) for production.

### Certificate Renewal

1. **Renewal Timing**: Initiate renewals at least 30 days before expiration.
2. **Key Rotation**: Rotate keys regularly according to your security policy.
3. **Validity Periods**: Maintain consistent validity periods across renewals.
4. **Transition Period**: Allow for a transition period where both old and new certificates are valid.
5. **Verification**: After renewal, verify the new certificate chain is working correctly.

### Certificate Revocation

1. **Immediate Action**: Revoke compromised certificates immediately.
2. **Proper Reason**: Always specify the correct revocation reason.
3. **CRL Distribution**: Ensure CRLs are published and accessible.
4. **Backup**: Keep secure backups of critical certificates to aid in recovery.
5. **Audit**: Keep detailed audit logs of all revocation events.

### Certificate Monitoring

1. **Regular Checks**: Configure automated checks for certificate status and expiry.
2. **Notification Setup**: Configure notifications at multiple thresholds (e.g., 30, 15, 7 days).
3. **Response Plan**: Have a clear plan for handling certificate expiry events.
4. **Log Review**: Regularly review certificate operation logs.
5. **Testing**: Test your certificate monitoring and renewal processes periodically.

## Certificate Rotation Policy

A formal certificate rotation policy should include:

1. **Rotation Schedule**: Regular intervals for key and certificate rotation
2. **Roles & Responsibilities**: Who is responsible for certificate operations
3. **Procedures**: Step-by-step procedures for certificate creation, renewal, and revocation
4. **Emergency Procedures**: How to handle key compromise events
5. **Documentation**: Requirements for documenting certificate operations
6. **Audit**: How certificate operations are logged and audited
7. **Compliance**: How the rotation policy complies with relevant standards

## Integration with OpenXPKI

For details on the OpenXPKI integration, refer to [OPENXPKI_INTEGRATION.md](OPENXPKI_INTEGRATION.md).

## Certificate Expiry Notification Service

For details on the Certificate Expiry Notification Service, refer to [CERTIFICATE_EXPIRY_SERVICE.md](CERTIFICATE_EXPIRY_SERVICE.md).

## Troubleshooting

### Common Issues

1. **Certificate Creation Fails**:
   - Check that the key algorithm and size are supported
   - Verify that the subject name is correctly formatted
   - Ensure the OpenXPKI service is running

2. **Certificate Renewal Fails**:
   - Verify the certificate ID exists and is valid
   - Check that the certificate is not already expired
   - Ensure the original certificate's private key is accessible

3. **Certificate Status Shows "NOT_FOUND"**:
   - Verify the certificate ID is correct
   - Check that the certificate has not been deleted
   - Ensure the data directory is correctly mounted

4. **Expiry Notifications Not Received**:
   - Check the notification thresholds configuration
   - Verify the notification service is running
   - Ensure notification history is correctly tracked