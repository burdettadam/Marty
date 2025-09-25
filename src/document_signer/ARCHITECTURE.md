# Document Signer Service Architecture

## Overview
The Document Signer Service is responsible for signing Document Security Object (SOD) files and managing Document Signer Certificates (DSCs). It ensures the integrity and authenticity of ePassport data.

## Responsibilities
- Maintain DSCs signed by the CSCA.
- Sign SOD files containing hashes of Logical Data Structure (LDS) data groups.
- Handle key rotation and certificate expiry.

## Key Features
- Integration with the CSCA Management Service for certificate signing.
- Compliance with ICAO Doc 9303 standards.
- Secure key management and cryptographic operations.

## Technologies
- OpenSSL or BouncyCastle for cryptographic operations.
- TLS/HTTPS for secure communication.
- XMLDSIG/CMS for digital signatures.

## Data Flow
1. Receive DSCs from the CSCA Management Service.
2. Sign SOD files for the Passport Personalization Engine.
3. Publish signed SOD files for ePassport issuance.

## Deployment
- Use HSMs for key storage.
- Deploy on secure, redundant infrastructure.
- Regularly update DSCs and manage key rotation.