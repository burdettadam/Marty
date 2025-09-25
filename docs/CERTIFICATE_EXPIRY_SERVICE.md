# Certificate Expiry Notification Service

*Last updated: May 11, 2025*

## Overview

The Certificate Expiry Notification Service is responsible for monitoring certificate expiration dates and sending notifications when certificates are about to expire. This service is integrated with the Trust Anchor service and works with OpenXPKI to provide timely notifications about certificates that need to be renewed.

## Features

- Monitoring of certificate expiration dates
- Configurable notification thresholds (e.g., 30, 15, 7, 5, 3, 1 days before expiry)
- Tracking of sent notifications to prevent duplicates
- Integration with the Trust Anchor gRPC service
- Support for OpenXPKI certificate management system

## Architecture

The Certificate Expiry Notification Service consists of the following components:

1. **CertificateExpiryService**: Core service class that checks for expiring certificates and sends notifications
2. **OpenXPKIService Integration**: Connects to OpenXPKI for certificate data
3. **Notification History**: Tracks which certificates have been notified at which thresholds
4. **gRPC API**: Exposed through the Trust Anchor service for external access

## Configuration

The service can be configured through the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `CERT_CHECK_INTERVAL_DAYS` | How often to check for expiring certificates (in days) | `1` |
| `CERT_NOTIFICATION_DAYS` | Comma-separated list of days before expiry to send notifications | `30,15,7,5,3,1` |
| `CERT_HISTORY_FILE` | Path to the notification history file | `data/trust/cert_notification_history.json` |

Additionally, all environment variables required by the OpenXPKI service are also needed.

## Usage

### Using the Service Directly

```python
from src.trust_anchor.app.services.openxpki_service import OpenXPKIService
from src.trust_anchor.app.services.certificate_expiry_service import CertificateExpiryService

# Create OpenXPKI service
openxpki_service = OpenXPKIService()

# Create Certificate Expiry Service
expiry_service = CertificateExpiryService(
    openxpki_service=openxpki_service,
    check_interval_days=1,
    notification_days=[30, 15, 7, 5, 3, 1],
    history_file="data/trust/cert_notification_history.json"
)

# Process expiring certificates once
expiry_service.process_expiring_certificates()

# Or run continuously
# expiry_service.run_service()
```

### Using the gRPC API

The service is accessible through the Trust Anchor gRPC API:

```python
import grpc
from src.trust_anchor_pb2 import ExpiryCheckRequest
from src.trust_anchor_pb2_grpc import TrustAnchorStub

# Create gRPC channel and stub
channel = grpc.insecure_channel('localhost:50051')
stub = TrustAnchorStub(channel)

# Check for certificates expiring within 30 days
request = ExpiryCheckRequest(days=30)
response = stub.CheckExpiringCertificates(request)

# Process expiring certificates
for cert in response.expiring_certificates:
    print(f"Certificate {cert.subject} will expire in {cert.days_remaining} days")
```

## Running with Docker

The Certificate Expiry Notification Service runs as part of the Trust Anchor service in Docker:

```bash
docker-compose up trust-anchor
```

Or to build and run only the Trust Anchor service:

```bash
docker-compose build trust-anchor
docker-compose up trust-anchor
```

## Implementation Details

### Notification Process

1. The service retrieves all certificates from OpenXPKI that are expiring within the configured timeframes
2. It filters these certificates based on the notification thresholds
3. It checks the notification history to see which certificates have already been notified at specific thresholds
4. For certificates needing notification, it:
   - Sends a notification (currently via logging, can be extended for email/other methods)
   - Updates the notification history

### Notification History Format

The notification history is stored in a JSON file with the following structure:

```json
{
  "1234567890": {
    "last_notified": "2025-05-11",
    "notify_days": [30, 15]
  },
  "0987654321": {
    "last_notified": "2025-05-10",
    "notify_days": [30, 15, 7]
  }
}
```

Where:
- The keys are certificate serial numbers
- `last_notified` is the date of the last notification
- `notify_days` is a list of day thresholds that have been notified

## Testing

Unit tests for the Certificate Expiry Notification Service are in:
```
tests/unit/trust_anchor/test_certificate_expiry_service.py
```

Run the tests with:

```bash
python -m pytest -v tests/unit/trust_anchor/test_certificate_expiry_service.py
```

## Future Enhancements

1. **Additional Notification Channels**: Add support for email, SMS, Slack, etc.
2. **Configurable Notification Templates**: Allow customization of notification messages
3. **Dashboard Integration**: Provide a web dashboard for viewing expiring certificates
4. **Certificate Renewal Automation**: Integrate with automatic certificate renewal processes
5. **Notification Escalation**: Increase notification frequency or escalate to different channels as expiry approaches