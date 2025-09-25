# OpenXPKI Integration for CSCA & Master List Management

*Last updated: May 11, 2025*

## Overview

Marty uses OpenXPKI as the enterprise-grade PKI system for CSCA certificate and master list management. This document explains the integration, its benefits, and how to configure and use the system.

## What is OpenXPKI?

[OpenXPKI](https://www.openxpki.org/) is an open-source enterprise PKI solution that provides a comprehensive set of tools for certificate management, including:

- Certificate lifecycle management
- Certificate validation and verification
- Secure storage of cryptographic materials
- Trust chain validation
- Master list import and processing
- Certificate revocation through CRLs and OCSP

## Why OpenXPKI for CSCA Management?

CSCA certificates form the trust anchors for passport verification and require robust management. OpenXPKI provides:

1. **Security**: Enterprise-grade security for critical PKI operations
2. **Scalability**: Designed for high-volume certificate management
3. **Standards Compliance**: Full compliance with X.509 standards and ICAO specifications
4. **Completeness**: Comprehensive certificate lifecycle management
5. **Auditability**: Detailed audit trails for all operations

## Architecture

The integration follows a service-oriented architecture:

```
┌─────────────────┐      ┌─────────────────┐
│                 │      │                 │
│   CSCA & PKD    │◄────►│    OpenXPKI     │
│     Service     │      │     Server      │
│                 │      │                 │
└────────┬────────┘      └─────────────────┘
         │                        ▲
         │                        │
         │                        │
         ▼                        │
┌─────────────────┐      ┌────────┴────────┐
│                 │      │                 │
│  Other Marty    │      │    OpenXPKI     │
│   Services      │      │   Database      │
│                 │      │                 │
└─────────────────┘      └─────────────────┘
```

- **OpenXPKI Server**: The main PKI system that handles certificate operations
- **OpenXPKI Database**: Stores certificates, CRLs, and operational data
- **CSCA & PKD Service**: Marty's service that integrates with OpenXPKI
- **Other Marty Services**: Consume certificate data through the CSCA & PKD Service

## Deployed Components

The OpenXPKI integration consists of:

1. **OpenXPKI Server Container**: Runs the OpenXPKI application
2. **PostgreSQL Database Container**: Stores the certificate data
3. **Integration Service**: Marty's `OpenXPKIService` class that connects to the OpenXPKI API
4. **Local Certificate Cache**: Synchronized copy of certificates for offline verification
5. **Certificate Expiry Service**: Monitors certificate expiration and sends notifications

## Configuration

### Docker Compose Configuration

The `docker-compose.openxpki.yml` file configures the OpenXPKI deployment:

```yaml
version: '3.8'

services:
  openxpki:
    image: whiterabbitsecurity/openxpki:latest
    container_name: marty-openxpki
    restart: unless-stopped
    ports:
      - "8443:443"  # HTTPS
      - "8080:80"   # HTTP
    volumes:
      - ./data/openxpki/config:/etc/openxpki
      - ./data/openxpki/tls:/etc/openxpki/tls
      - ./data/openxpki/ca:/etc/openxpki/ca
      - ./data/openxpki/logs:/var/log/openxpki
    environment:
      - OPENXPKI_REALM=marty
      - OPENXPKI_COUNTRY=US
      - OPENXPKI_STATE=State
      - OPENXPKI_ORG=Marty PKI
      - OPENXPKI_OU=CSCA Management
      - OPENXPKI_CN=Marty CSCA Management
      - OPENXPKI_ADMIN_USER=pkiadmin
      - OPENXPKI_ADMIN_PASSWORD=secret  # Change for production
      - OPENXPKI_DB_USER=openxpki
      - OPENXPKI_DB_PASSWORD=openxpki  # Change for production
    depends_on:
      - openxpki-db

  openxpki-db:
    image: postgres:14
    container_name: marty-openxpki-db
    restart: unless-stopped
    volumes:
      - ./data/openxpki/db:/var/lib/postgresql/data
    environment:
      - POSTGRES_USER=openxpki
      - POSTGRES_PASSWORD=openxpki  # Change for production
      - POSTGRES_DB=openxpki
    ports:
      - "5433:5432"  # Expose on a different port to avoid conflict with local PostgreSQL
```

### Marty Configuration

In the Marty configuration files (`config/development.yaml`, etc.), the OpenXPKI integration is configured as follows:

```yaml
# OpenXPKI Integration Settings
openxpki:
  base_url: "https://localhost:8443/api/v2"
  username: "pkiadmin"
  password: "secret"  # Change for production
  realm: "marty"
  connection_timeout: 30
  read_timeout: 60
  # Certificate sync settings
  sync_to_local: true
  local_store_path: "data/trust/openxpki_sync"
  trust_sync_interval_hours: 6
  cert_expiry_warning_days: 90
  cert_check_interval_hours: 24
```

# Certificate Expiry Notification Configuration
certificate_expiry:
  check_interval_days: 1
  notification_days: [30, 15, 7, 5, 3, 1]
  history_file: "data/trust/cert_notification_history.json"
  notification_channels: ["log"]  # Can be extended with "email", "slack", etc.

## Setup and Deployment

### Prerequisites

- Docker and Docker Compose installed
- Network access to the containers

### Setup Steps

1. **Run the setup script**:

   ```bash
   ./scripts/setup_openxpki.sh
   ```

   This script:
   - Creates the necessary directories
   - Starts the OpenXPKI containers
   - Configures the initial environment

2. **Access the OpenXPKI Web UI**:

   - URL: `https://localhost:8443/openxpki/`
   - Username: `pkiadmin`
   - Password: `secret` (change this for production)

3. **Import Initial CSCA Certificates**:

   You can import certificates via:
   - The OpenXPKI Web UI
   - The Marty API endpoint at `/v1/csca/masterlist`
   - The `csca_manager.upload_master_list()` method

## Integration Components

### OpenXPKI Service

The `OpenXPKIService` class (`src/pkd-service/app/services/openxpki_service.py`) provides:

- Authentication with OpenXPKI
- Certificate retrieval and storage
- Master list import and export
- Certificate verification
- Trust store management
- CRL operations

### Certificate Expiry Notification Service

The `CertificateExpiryService` class (`src/trust_anchor/app/services/certificate_expiry_service.py`) provides:

- Monitoring of certificates for upcoming expiration
- Configurable notification thresholds
- Notification tracking to prevent duplicates
- Integration with the Trust Anchor gRPC service

For complete documentation on the Certificate Expiry Notification Service, see [CERTIFICATE_EXPIRY_SERVICE.md](CERTIFICATE_EXPIRY_SERVICE.md).

### CSCA Manager

The `CscaManager` class (`src/pkd-service/app/controllers/csca_manager.py`) provides:

- High-level operations for CSCA management
- Certificate monitoring for expiration
- Notification handling
- Synchronization between OpenXPKI and local storage

## API Endpoints

The CSCA & PKD Service exposes these endpoints for interaction with OpenXPKI:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/csca/masterlist` | GET | Retrieve the CSCA Master List |
| `/v1/csca/masterlist` | POST | Upload a Master List |
| `/v1/csca/masterlist/binary` | GET | Download the ASN.1 encoded Master List |
| `/v1/csca/verify` | POST | Verify a certificate |
| `/v1/csca/sync` | POST | Trigger synchronization |
| `/v1/csca/check-expiry` | GET | Check for expiring certificates |
| `/v1/csca/status` | GET | Get CSCA service status |
| `/v1/csca/health` | GET | Health check |

## Local Certificate Cache

For offline verification and performance optimization, certificates from OpenXPKI are synchronized to a local directory:

- Default path: `data/trust/openxpki_sync`
- Format: Individual `.cer` files named by country code and certificate ID
- Sync interval: Configurable (default: every 6 hours)

## Certificate Lifecycle Management

The integration supports the full CSCA certificate lifecycle:

1. **Import**: Via Master List or individual certificate upload
2. **Validation**: Verification against trust anchors
3. **Monitoring**: Regular checks for expiring certificates through the Certificate Expiry Notification Service
4. **Notification**: Automated alerts for certificates approaching expiration
5. **Revocation**: Support for CRLs and revocation status

## Best Practices

### Security

- Use strong passwords for OpenXPKI admin accounts
- Implement network security measures around the containers
- Regularly back up the OpenXPKI database
- Consider integrating with HSMs for production use

### Performance

- Adjust sync intervals based on your system needs
- Monitor database growth and performance
- Scale PostgreSQL resources as needed

### Maintenance

- Regularly update the OpenXPKI container
- Back up certificate stores
- Monitor logs for issues

## Testing

Test the OpenXPKI integration with:

```bash
pytest tests/unit/test_openxpki_integration.py
```

Test the Certificate Expiry Notification Service with:

```bash
pytest tests/unit/trust_anchor/test_certificate_expiry_service.py
```

## Troubleshooting

### Common Issues

1. **Connection Failures**:
   - Check if OpenXPKI containers are running
   - Verify network connectivity
   - Check SSL certificate issues

2. **Authentication Problems**:
   - Verify credentials in configuration
   - Check for expired sessions

3. **Certificate Import Failures**:
   - Validate certificate format
   - Check for certificate chain issues

### Logs

Check these logs for troubleshooting:

- OpenXPKI logs: `data/openxpki/logs/`
- Marty server logs
- Database logs

## References

- [OpenXPKI Official Documentation](https://openxpki.readthedocs.io/)
- [ICAO Doc 9303](https://www.icao.int/publications/pages/publication.aspx?docnum=9303)
- [X.509 Certificate Standard](https://tools.ietf.org/html/rfc5280)