# Architecture

## Overview
This document outlines the architecture for an interoperable passport and mobile driving license issuance and verification system based on the ICAO Public Key Infrastructure (PKI) model and ISO/IEC 18013-5 standard. The system enables the creation, signing, and verification of electronic Machine Readable Travel Documents (eMRTDs), Mobile Driving Licenses (mDLs), Mobile Documents (mDocs), and Digital Travel Credentials (DTCs) in compliance with international standards.

## System Design
The system follows a service-oriented architecture with the following key principles:
- Strict adherence to ICAO Doc 9303 standards for eMRTD interoperability
- Implementation of ISO/IEC 18013-5 standard for mobile driving licenses and mobile documents
- Support for ICAO Digital Travel Credentials (DTC) specifications
- Security-first approach with proper key management and cryptographic operations
- Clear separation of concerns between certificate authorities, signing services, and verification
- Scalability to handle passport and mobile credential operations at a national level

## Components
### CSCA Management Service (Country Signing Certificate Authority)
- Generates and securely stores CSCA private keys
- Issues and publishes CSCA certificates
- Signs Document Signer Certificates (DSCs)
- Manages certificate lifecycles
- **Leverages OpenXPKI for enterprise-grade certificate management**

### Document Signer (DS) Service
- Maintains DSCs signed by the CSCA
- Signs SOD (Document Security Object) files containing hashes of LDS data groups
- Signs mDL and mDoc security objects in compliance with ISO/IEC 18013-5
- Handles key rotation and certificate expiry

### Passport Personalization Engine
- Generates the Logical Data Structure (LDS) for ePassports
- Creates required Data Groups: DG1 (MRZ), DG2 (photo), etc.
- Produces the complete eMRTD chip content using the DS service

### MDL Engine
- Implements ISO/IEC 18013-5 standard for mobile driving licenses
- Creates and manages mDL data objects (portrait, name, license class, etc.)
- Supports mDL Data Structure formats
- Handles device binding and user verification operations
- Implements mDL device retrieval and transfer protocols
- Generates QR codes and visual representations for offline use

### mDoc Engine
- Implements ISO/IEC 18013-5 standard for general-purpose mobile documents
- Supports various document types (ID cards, residence permits, etc.)
- Creates and manages mDoc data elements based on document type
- Handles selective disclosure of document attributes
- Implements secure storage and transfer protocols
- Generates presentation formats for verification
- Supports offline and online verification methods

### DTC Engine
- Implements ICAO Digital Travel Credential (DTC) specifications
- Supports all three DTC types (virtual, physical, and temporary)
- Creates DTC tokens derived from physical passports
- Manages DTC lifecycle and document binding
- Handles token sharing and presentation
- Implements DTC verification protocols
- Supports travel-specific verification use cases
- Ensures strong security and privacy measures
- Integrates with passport engine for ePassport data extraction
- Implements ICAO-compliant QR code generation for offline verification
- Provides device binding capability for secure mobile storage
- Enforces access control policies based on DTC type
- Supports revocation mechanisms for compromised credentials

### Inspection System (Verification Software)
- Reads MRZ and derives access keys (BAC/PACE)
- Accesses and parses chip data (DGs and SOD)
- Validates signatures against trusted CSCA certificates
- Verifies mDL data objects against trusted certificates
- Supports proximity technologies (NFC and BLE) for mDL verification
- Checks revocation status

### Trust Anchor Management
- Maintains trusted CSCA certificate lists
- Synchronizes with ICAO PKD or private mirrors
- Updates Certificate Revocation Lists (CRLs)
- **Integrates with OpenXPKI for certificate validation and trust store management**

### PKD & Master List Management Service
- Imports and processes CSCA Master Lists
- Facilitates certificate distribution and trust establishment
- Enables offline verification through synchronized certificate stores
- **Uses OpenXPKI for secure storage and validation of certificates**

### Optional/Advanced Services
- LDS2 Service for revocation information
- PKD Mirror Service for global validation
- Monitoring and auditing system
- HSM integration for secure key storage

## OpenXPKI Integration

The system integrates OpenXPKI as a core component for PKI operations, specifically for CSCA and Master List management. This integration provides:

### Certificate Management
- Secure storage of CSCA certificates
- Certificate lifecycle management from issuance to expiry
- Validation of certificate chains and trust paths

### Master List Operations
- Import and parsing of ASN.1 encoded Master Lists
- Validation of Master List signatures
- Export of certificates in standard formats

### Verification Services
- Certificate validation against trusted anchors
- Chain of trust validation
- Signature verification

### Monitoring and Notification
- Certificate expiry monitoring
- Automated notifications for certificate events
- Audit logging of all operations

The OpenXPKI integration architecture follows this pattern:

```
┌─────────────────┐      ┌─────────────────┐
│                 │      │                 │
│  Marty Services │◄────►│ PKD Service API │
│                 │      │                 │
└─────────────────┘      └────────┬────────┘
                                  │
                                  ▼
                         ┌─────────────────┐
                         │                 │
                         │  CSCA Manager   │
                         │                 │
                         └────────┬────────┘
                                  │
                                  ▼
                         ┌─────────────────┐      ┌─────────────────┐
                         │                 │      │                 │
                         │ OpenXPKI Service│◄────►│ OpenXPKI Server │
                         │                 │      │                 │
                         └─────────────────┘      └─────────────────┘
                                                          │
                                                          ▼
                                                  ┌─────────────────┐
                                                  │                 │
                                                  │ PostgreSQL DB   │
                                                  │                 │
                                                  └─────────────────┘
```

For detailed information on the OpenXPKI integration, refer to [OpenXPKI Integration Documentation](docs/OPENXPKI_INTEGRATION.md).

## Technologies
### Libraries
- JMRTD (Java) for LDS handling and inspection
- OpenSSL or BouncyCastle for PKI operations
- BSI TR03110 implementation
- ICAO MRTD tools
- **OpenXPKI for certificate management**

### Standards and Protocols
- ICAO Doc 9303 for eMRTD specifications
- ISO/IEC 18013-5 for mobile driving license specifications
- Support for ICAO Digital Travel Credentials (DTC) specifications
- X.509/RFC 5280 for certificates and PKI
- BAC/PACE for chip access security
- EAC for extended access control
- Active Authentication for anti-cloning
- ASN.1 for binary data encoding
- ISO/IEC 14443 for proximity card communication
- TLS/HTTPS for secure communication
- XMLDSIG/CMS for digital signatures

## Data Flow
1. **Issuance Flow**:
   - CSCA signs Document Signer Certificates
   - Passport Personalization Engine creates passport data (LDS)
   - Document Signer Service signs the SOD
   - Passport is issued with signed data

2. **Verification Flow**:
   - Inspection System reads MRZ and derives access keys
   - Chip data is accessed and parsed
   - SOD signature is validated against trusted CSCA certificates
   - Revocation status is checked

## Deployment
- Deploy core services on secure, redundant infrastructure
- Use HSMs for key storage and cryptographic operations
- Implement secure communication channels (TLS/HTTPS)
- Regularly update trusted CSCA lists and CRLs

## Security Considerations
- Use hardware security modules (HSMs) for key management
- Implement strong access controls and auditing for sensitive operations
- Regularly rotate keys and update certificates
- Monitor and respond to security incidents promptly

## Performance Considerations
- Optimize cryptographic operations for scalability
- Use caching for frequently accessed data (e.g., trusted CSCA lists)
- Implement load balancing for high availability

## Future Improvements
- Integrate with global ICAO PKD for real-time updates
- Enhance inspection system with machine learning for anomaly detection
- Develop mobile-friendly verification tools
- Expand support for additional eMRTD standards and protocols

## Docker Compose Structure

To simplify deployment and management of the system, a Docker Compose structure is used to orchestrate the various services. Below is an overview of the Docker Compose setup:

### Services

1. **CSCA Management Service**
   - **Image:** `csca-service:latest`
   - **Ports:**
     - `8080:8080`
   - **Volumes:**
     - `/data/csca:/app/data`
   - **Environment Variables:**
     - `HSM_CONFIG=/app/config/hsm.json`

2. **Document Signer (DS) Service**
   - **Image:** `document-signer:latest`
   - **Ports:**
     - `8081:8081`
   - **Volumes:**
     - `/data/ds:/app/data`
   - **Environment Variables:**
     - `CSCA_CERT_PATH=/app/certs/csca.pem`

3. **Passport Personalization Engine**
   - **Image:** `passport-engine:latest`
   - **Ports:**
     - `8082:8082`
   - **Volumes:**
     - `/data/passport:/app/data`

4. **MDL Engine**
   - **Image:** `mdl-engine:latest`
   - **Ports:**
     - `8085:8085`
   - **Volumes:**
     - `/data/mdl:/app/data`
   - **Environment Variables:**
     - `DS_SERVICE_URL=document-signer:8081`

5. **Inspection System**
   - **Image:** `inspection-system:latest`
   - **Ports:**
     - `8083:8083`
   - **Volumes:**
     - `/data/inspection:/app/data`
   - **Environment Variables:**
     - `TRUSTED_CSCA_LIST=/app/config/trusted_csca.json`

6. **Trust Anchor Management**
   - **Image:** `trust-anchor:latest`
   - **Ports:**
     - `8084:8084`
   - **Volumes:**
     - `/data/trust:/app/data`
   - **Environment Variables:**
     - `PKD_MIRROR_URL=https://pkd.example.com`

### Example `docker-compose.yml`

```yaml
version: '3.8'
services:
  csca:
    image: csca-service:latest
    ports:
      - "8080:8080"
    volumes:
      - ./data/csca:/app/data
    environment:
      - HSM_CONFIG=/app/config/hsm.json

  document-signer:
    image: document-signer:latest
    ports:
      - "8081:8081"
    volumes:
      - ./data/ds:/app/data
    environment:
      - CSCA_CERT_PATH=/app/certs/csca.pem

  passport-engine:
    image: passport-engine:latest
    ports:
      - "8082:8082"
    volumes:
      - ./data/passport:/app/data

  mdl-engine:
    image: mdl-engine:latest
    ports:
      - "8085:8085"
    volumes:
      - ./data/mdl:/app/data
    environment:
      - DS_SERVICE_URL=document-signer:8081

  inspection-system:
    image: inspection-system:latest
    ports:
      - "8083:8083"
    volumes:
      - ./data/inspection:/app/data
    environment:
      - TRUSTED_CSCA_LIST=/app/config/trusted_csca.json

  trust-anchor:
    image: trust-anchor:latest
    ports:
      - "8084:8084"
    volumes:
      - ./data/trust:/app/data
    environment:
      - PKD_MIRROR_URL=https://pkd.example.com
```

### Notes
- Each service is containerized and can be scaled independently.
- Volumes are used to persist data across container restarts.
- Environment variables are used to configure service-specific settings.
- Ensure that the `docker-compose.yml` file is placed in the root directory of the project.

# File Structure for gRPC-based System

This document outlines the proposed file structure for the Marty project, designed to use gRPC for service-to-service communication.

## Proposed Directory Structure
```
/Marty
├── /proto
│   ├── csca.proto
│   ├── document_signer.proto
│   ├── passport_engine.proto
│   ├── inspection_system.proto
│   └── trust_anchor.proto
├── /src
│   ├── /csca-service
│   │   ├── Dockerfile
│   │   ├── config/
│   │   ├── src/
│   │   │   ├── main.py
│   │   │   ├── grpc_server.py
│   │   │   └── utils.py
│   │   └── tests/
│   ├── /document-signer
│   │   ├── Dockerfile
│   │   ├── config/
│   │   ├── src/
│   │   │   ├── main.py
│   │   │   ├── grpc_server.py
│   │   │   └── utils.py
│   │   └── tests/
│   ├── /passport-engine
│   │   ├── Dockerfile
│   │   ├── config/
│   │   ├── src/
│   │   │   ├── main.py
│   │   │   ├── grpc_server.py
│   │   │   └── utils.py
│   │   └── tests/
│   ├── /mdl-engine
│   │   ├── Dockerfile
│   │   ├── config/
│   │   ├── src/
│   │   │   ├── main.py
│   │   │   ├── grpc_server.py
│   │   │   └── utils.py
│   │   └── tests/
│   ├── /inspection-system
│   │   ├── Dockerfile
│   │   ├── config/
│   │   ├── src/
│   │   │   ├── main.py
│   │   │   ├── grpc_server.py
│   │   │   └── utils.py
│   │   └── tests/
│   └── /trust-anchor
│       ├── Dockerfile
│       ├── config/
│       ├── src/
│       │   ├── main.py
│       │   ├── grpc_server.py
│       │   └── utils.py
│       └── tests/
├── /data
│   ├── /csca
│   ├── /ds
│   ├── /passport
│   ├── /mdl
│   ├── /inspection
│   └── /trust
├── /docs
│   ├── ARCHITECTURE.md
│   ├── PROTOCOLS.md
│   └── README.md
├── docker-compose.yml
└── .gitignore
```

## Key Directories and Files

### `/proto`
- Contains `.proto` files defining gRPC service interfaces and message types for each service.

### `/src`
- Each service has its own subdirectory with:
  - `Dockerfile`: For containerizing the service.
  - `config/`: Configuration files specific to the service.
  - `src/`: Source code, including `grpc_server.py` to implement the gRPC server.
  - `tests/`: Unit and integration tests for the service.

### `/data`
- Persistent storage for service-specific data.

### `/docs`
- Documentation files, including architecture and protocol details.

### `docker-compose.yml`
- Orchestrates the deployment of all services using Docker Compose.

### `.gitignore`
- Specifies files and directories to be ignored by Git.