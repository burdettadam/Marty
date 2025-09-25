# Protocols Document

This document tracks the protocols used in the interoperable passport issuance and verification system.

## Protocols

### 1. ICAO Doc 9303 – Machine Readable Travel Documents
- **Purpose:** Defines the logical and physical structure of passports (MRTDs).
- **Key Features:**
  - MRZ (Machine Readable Zone)
  - LDS (Logical Data Structure on the chip)
  - SOD (Signed Object Document)
- **Protocols/Specs:**
  - BAC (Basic Access Control)
  - PACE (Password Authenticated Connection Establishment)
  - EAC (Extended Access Control)
  - Active Authentication

### 2. ISO/IEC 18013-5 – Mobile Driving License (mDL) and Mobile Documents (mDoc)
- **Purpose:** Defines the framework for mobile driving licenses and general-purpose mobile documents and their verification.
- **Key Features:**
  - Device retrieval (mobile credential data from a device to a reader)
  - Data structure for license and document attributes
  - Security mechanisms (data authentication, integrity, and confidentiality)
  - Reader authentication
- **Protocols/Specs:**
  - Online vs. offline verification
  - Device engagement (QR code, NFC, BLE)
  - Transfer protocols for data retrieval
  - Signed data elements and authentication mechanisms
  - Reader authentication and authorization (selective disclosure)
  - Proximity verification and anti-cloning
  - mDoc namespaces and document types
  - Issuer-specific data elements

### 3. ICAO Digital Travel Credential (DTC) 
- **Purpose:** Defines the framework for digital travel credentials derived from ePassports.
- **Key Features:**
  - Three types of DTCs (virtual, physical, and combined)
  - DTC token structure and data elements
  - Trust framework and authentication mechanisms
  - Travel credential verification
- **Protocols/Specs:**
  - Token generation and sharing
  - Document binding and validation
  - DTC verification for online and offline scenarios
  - Border control system integration
  - Privacy-enhancing technologies
  - Biometric verification and liveness detection

## Digital Travel Credentials (DTC) Protocol

### Overview
Digital Travel Credentials (DTCs) are standardized by ICAO as a digital representation of physical passports. DTCs enable travelers to securely share their identity information with border authorities and other relevant parties while maintaining control over their data.

### DTC Types
According to ICAO specifications, DTCs can be issued in three types:
1. **Virtual DTC (vDTC)**: A standalone digital credential that can be used without the physical passport.
2. **Physical DTC (pDTC)**: Used alongside the physical passport, enhancing the security and convenience of travel.
3. **Temporary DTC (tDTC)**: Limited validity credential issued for specific purposes or durations.

### Technical Specifications
- **Token Format**: Based on ICAO Document 9303 Part 12 and 13
- **Data Elements**: Includes minimum mandatory data elements from physical passport:
  - Facial image
  - Name (primary and secondary identifiers)
  - Date of birth
  - Nationality
  - Document number
  - Document expiry date
  - Document type
- **Encoding**: JSON-based structure with CBOR encoding for efficiency
- **Security Mechanisms**: 
  - Digital signatures using ECDSA with P-256 curve
  - Document authentication using PKI infrastructure
  - Optional biometric binding and verification
  - Chip authentication for pDTC
  
### Implementation
The DTC Engine service implements:
- Creation of DTCs from existing passport data
- Secure storage and access control for DTCs
- QR code generation for offline verification
- Device transfer protocols for mobile use
- Linkage mechanisms to physical passports
- Verification protocols consistent with ICAO standards
- Interface for border control systems integration
- Selective disclosure capabilities
- Revocation mechanisms for compromised credentials

### Protocol Flow
1. **Creation**: 
   - DTC created from passport data (MRZ, personal details, biometrics)
   - Data is structured according to ICAO specifications
   - Digital signature calculated and applied
2. **Signing**: 
   - DTC signed using the Document Signer service
   - Trust chain established to CSCA
3. **Storage**: 
   - DTC stored securely with appropriate access controls
   - Access control policy determined by DTC type
4. **Usage**: 
   - DTC can be transferred to mobile devices
   - Can be displayed as QR codes for offline verification
   - Proximity verification using NFC/BLE when available
   - Linked to physical passport for pDTC type
5. **Verification**: 
   - Border control systems verify the DTC token
   - Trust chain verification to validate authenticity
   - Biometric verification when required
   - Cross-verification with physical passport (for pDTC)

### Security Features
- Access control mechanisms (password, biometric, certificate)
- Digital signatures using Document Signer certificates
- Selective disclosure of attributes
- Tamper-evident data structures
- Document binding to prevent unauthorized use
- Secure channel establishment for data transfer
- Anti-cloning mechanisms
- Liveness detection for biometric verification

### Integration Points
- **Document Signer Service**: For signing DTCs
- **Passport Engine**: For accessing passport data during DTC creation
- **Inspection System**: For verification of DTCs
- **Trust Anchor Management**: For certificate validation

### Standards Compliance
- ICAO Digital Travel Credential Technical Report
- ICAO Doc 9303 Parts 12 and 13 for DTC specifications
- ISO/IEC 18013-5 (shared components with mDL/mDoc)
- ICAO Doc 9303 for data structures and cryptographic protocols
- FIDO protocols for secure authentication (optional integration)

### 4. X.509 (ITU-T) / RFC 5280 – Public Key Infrastructure
- **Purpose:** Used for CSCA and DSC certificates.
- **Key Features:**
  - Certificate chains
  - Signature verification
  - CRL (Certificate Revocation List) handling

### 5. ICAO PKD (Public Key Directory) Protocols
- **Purpose:** Synchronization and distribution of trust lists.
- **Key Features:**
  - CSCA Master List Format
  - DSC List Files
  - CRL Files
  - Synchronization Protocols (FTP/HTTPS)

### 6. BSI TR-03110 – Technical Guidelines for Inspection Systems
- **Purpose:** Reference implementation guidelines for inspection systems.
- **Key Features:**
  - Terminal authentication
  - Passive/active authentication
  - Chip access protocols
  - CRL/OCSP use

### 7. ASN.1 – Abstract Syntax Notation One
- **Purpose:** Binary encoding of certificate structures, SOD, etc.
- **Key Features:**
  - SOD signature blocks
  - LDS hashes

### 8. ISO/IEC 14443 – Proximity Card Protocol
- **Purpose:** Defines RFID interface used to communicate with ePassport chips.
- **Key Features:**
  - Communication protocols for proximity cards

### 9. Bluetooth Low Energy (BLE)
- **Purpose:** Used for device-to-device communication in mDL verification.
- **Key Features:**
  - Proximity establishment
  - Secure channel establishment
  - mDL data exchange

### 10. TLS / HTTPS
- **Purpose:** Secure the exchange of credentials, CRLs, and certificate lists.
- **Key Features:**
  - Encryption of data in transit

### 11. XMLDSIG (XML Digital Signature) / CMS (Cryptographic Message Syntax)
- **Purpose:** Used in SOD signature structure and PKD update files.
- **Key Features:**
  - Digital signature verification

### 12. CBOR and CBOR Object Signing and Encryption (COSE)
- **Purpose:** Used in mDL data encoding and signing.
- **Key Features:**
  - Compact binary data format
  - Standardized object signing format
  - Efficient data transfer for mobile applications

## Notes
- This document will be updated as new protocols are adopted or existing ones are modified.