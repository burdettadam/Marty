# Document Signer Service

## Overview

The Document Signer Service is responsible for maintaining Document Signer Certificates (DSCs) signed by the CSCA. It signs Document Security Object (SOD) files containing hashes of LDS data groups and handles key rotation and certificate expiry.

## Features

- Management of Document Signer Certificates (DSCs).
- Signing of Document Security Object (SOD) files.
- Key rotation and certificate expiry handling.
- Integration with CSCA Management for certificate signing.

## Directory Structure

- `config/`: Configuration files for the service.
- `src/`: Source code for the service.
- `tests/`: Unit and integration tests for the service.
