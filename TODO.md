# Marty Project TODO Board

*Last Updated: May 12, 2025*

This document tracks the progress and status of the Marty gRPC Service project, organized in a Jira-style board with checkboxes for tracking task completion. Since we're following Test-Driven Development (TDD), tasks are prioritized based on test status and coverage.

## 📋 Project Overview Status

- [x] Project structure setup
- [x] Base architecture defined
- [x] Proto definitions created
- [x] Docker integration established
- [x] CI/CD workflow implemented
- [ ] Security audit complete
- [ ] Performance testing complete
- [ ] Production deployment ready

## 🔍 Test Coverage Status

### Unit Tests
- [x] Basic infrastructure tests (ElementaryFile, DataGroup functionality)
- [x] MRZ and DG1 tests
- [x] Security tests (SOD, DG14, DG15)
- [x] ISO 9796-2 signature scheme tests
- [x] Certificate validation tests
- [x] Key management tests
- [ ] Complete test coverage for all services (>90% coverage)

### Integration Tests
- [x] Service-specific integration tests setup
- [x] CSCA Service integration tests
- [x] Document Signer integration tests
- [x] Passport Engine integration tests
- [x] Inspection System integration tests
- [x] Trust Anchor integration tests
- [x] MDL Engine integration tests
- [🚧] mDoc Engine integration tests
- [x] Setup combined MDL and mDoc integration tests (mdl_mdoc_integration_tests)
- [ ] DTC Engine integration tests

### End-to-End Tests
- [x] Basic passport flow E2E tests
- [x] Multiple passport processing tests
- [ ] Error handling and recovery E2E tests
- [ ] Performance under load E2E tests
- [ ] Security E2E tests
- [ ] Edge-case handling E2E tests

### Third-Party Integration Tests
- [x] ZeroPass/pymrtd integrated tests
- [x] PassportEye integrated tests
- [x] Certificate validator integrated tests
- [ ] OpenXPKI integration tests expanded

## 🚀 Service Implementation Status

### CSCA Management Service
- [x] Base service implementation
- [x] Certificate generation
- [x] Certificate storage
- [x] Certificate signing
- [x] Complete certificate lifecycle management
- [ ] Key rotation implementation
- [ ] Security hardening
- [ ] Metrics and monitoring

### Document Signer (DS) Service
- [x] Base service implementation
- [x] Document signing functionality
- [ ] Extended signing algorithms
- [ ] DSC management features
- [ ] Key rotation automation
- [ ] Expiry management
- [ ] Metrics and monitoring

### Passport Personalization Engine
- [x] Base service implementation
- [x] LDS generation
- [x] Required Data Groups creation
- [ ] Extended biometrics support
- [ ] Batch processing optimization
- [ ] Advanced personalization features
- [ ] Performance tuning
- [ ] Metrics and monitoring

### MDL Engine
- [x] Base service implementation
- [ ] ISO/IEC 18013-5 compliance
- [ ] Mobile credential generation
- [ ] Signing integration
- [ ] Verification features
- [ ] Metrics and monitoring

### mDoc Engine
- [x] Base service implementation
- [🚧] Mobile document generation
- [ ] Document signing
- [ ] Document verification
- [ ] Standards compliance
- [ ] Metrics and monitoring

### DTC Engine
- [x] Base service implementation
- [ ] Digital Travel Credential generation
- [ ] ICAO DTC specifications compliance
- [ ] Integration with passport engine
- [ ] Advanced features
- [ ] Metrics and monitoring

### Inspection System
- [x] Base service implementation
- [x] MRZ parsing
- [x] Document verification
- [ ] Advanced inspection features
- [ ] Biometric verification
- [ ] Active authentication implementation
- [ ] Extended Access Control (EAC)
- [ ] Metrics and monitoring

### Trust Anchor Management
- [x] Base service implementation
- [x] Certificate management
- [x] Certificate revocation checking
- [ ] ICAO PKD synchronization
- [ ] Complete CRL management
- [ ] Trust store optimization
- [ ] Metrics and monitoring

### PKD & Master List Management Service
- [x] Base service implementation
- [x] Master list processing
- [x] Certificate distribution
- [ ] Complete offline verification
- [x] PKD mirror implementation
- [ ] Trust hierarchy management
- [ ] Metrics and monitoring

## 🔄 OpenXPKI Integration Status

- [x] Basic OpenXPKI integration structure
- [x] Certificate management integration
- [ ] Master List operations fully implemented
- [ ] Verification services expanded
- [ ] Monitoring and notification system
- [ ] Complete lifecycle management
- [ ] High availability configuration

## 🧪 Specific Feature Tasks

### Cross-Service Features
- [ ] Implement service health monitoring
- [ ] Set up centralized logging
- [ ] Add distributed tracing
- [ ] Implement rate limiting
- [ ] Add request/response validation middleware
- [ ] Implement circuit breakers
- [ ] Add caching layer for frequently accessed data

### Security Features
- [x] Basic key management
- [ ] HSM integration
- [ ] Key rotation automation
- [ ] Access controls and auditing
- [ ] Security incident monitoring
- [ ] Certificate expiry notifications
- [ ] Key usage anomaly detection

### Documentation and Standards
- [x] Basic architecture documentation
- [x] Protocol definitions
- [ ] Complete API documentation
- [ ] Deployment guides
- [ ] Security documentation
- [ ] Monitoring documentation
- [ ] Disaster recovery procedures

## 🚧 Pending Technical Debt

- [x] Refactor certificate validation logic for better reuse
- [ ] Improve error handling across services
- [ ] Optimize Docker container sizes
- [ ] Improve test performance
- [ ] Address code duplication in proto handling
- [ ] Standardize configuration handling
- [ ] Improve development environment setup
- [ ] `compile_protos.py`: Consider halting or providing a more granular error report in `compile_all_protos` if a proto file fails to compile.
- [ ] `compile_protos.py`: Streamline `__init__.py` creation in `ensure_proto_directory_exists` and `update_proto_init` to avoid overwriting.
- [ ] `compile_protos.py`: Make error handling for missing `_grpc.py` files more explicit if necessary.
- [ ] `compile_protos.py`: Evaluate if the regex in `patch_generated_file_imports` can be simplified or made more robust for maintainability.
- [ ] `compile_protos.py`: Use `sys.executable` instead of hardcoded `"python"` for `grpc_tools.protoc` for better interpreter compatibility.
- [ ] `compile_protos.py`: Consider making `PROTO_DIR` and `OUTPUT_DIR` configurable for better flexibility.

## 📈 Performance Optimization Tasks

- [ ] Optimize cryptographic operations
- [ ] Implement caching for certificate validation
- [ ] Add load balancing for high-traffic services
- [ ] Reduce memory usage in passport processing
- [ ] Optimize database queries
- [ ] Implement connection pooling
- [ ] Profile and fix CPU/memory hotspots

## 🔄 Passport Verification Implementation Phases

Based on the comprehensive analysis of missing functionality, passport verification will be implemented in phases:

### Phase 1: Core Cryptographic Verification ⚡ **(IN PROGRESS)**
- [ ] **SOD ASN.1 Structure Parsing** - Parse Security Object of Document to extract hash values
- [ ] **Data Group Hash Computation** - Compute SHA-1/SHA-256/SHA-512 hashes of data groups
- [ ] **Hash Comparison Logic** - Compare computed vs SOD-stored hash values
- [ ] **Certificate Chain Validation** - Validate SOD signature against Document Signer certificates
- [ ] **CSCA Trust Anchor Integration** - Connect to trusted CSCA root certificates

### Phase 2: RFID Communication & Chip Access 📡 **(COMPLETED)**
- [x] **Basic Access Control (BAC) Implementation** - MRZ-derived key authentication
- [x] **APDU Command Sequences** - File selection and data group reading commands
- [x] **Secure Messaging Layer** - Encrypted communication after BAC authentication
- [x] **Data Group Reading** - Read DG1-DG16 from passport chips via RFID
- [x] **Error Handling & Recovery** - Communication timeouts and authentication failures
- [x] **NFC Mobile Integration** - Android HCE and iOS Core NFC support
- [x] **Biometric Template Processing** - ISO/IEC 19794 template parsing and validation
- [x] **Hardware Abstraction Layer** - PC/SC readers with mock testing support

### Phase 3: Advanced Security Features 🔐 **(IN PROGRESS)**
- [x] **Active Authentication Protocol** - Challenge-response anti-cloning verification
- [x] **DG15 Public Key Extraction** - Parse chip authentication public keys
- [x] **ISO 9796-2 Signature Verification** - Verify active authentication responses
- [ ] **Extended Access Control (EAC)** - Terminal and Chip Authentication protocols
- [ ] **Enhanced Biometric Processing** - Advanced facial recognition and matching algorithms

### Phase 4: Production Integration 🚀
- [ ] **Hardware RFID Reader Support** - ACR122U, HID Omnikey, etc.
- [ ] **PKD Integration** - Public Key Directory for certificate updates
- [ ] **CRL/OCSP Validation** - Real-time certificate revocation checking
- [ ] **Performance Optimization** - Chip reading timeouts and retry logic
- [ ] **Comprehensive Error Recovery** - Failed communication and authentication scenarios

## 🌐 Future Improvements

- [ ] Integration with global ICAO PKD
- [ ] Machine learning for anomaly detection
- [ ] Mobile-friendly verification tools
- [ ] Support for additional eMRTD standards
- [ ] Advanced biometric verification
- [ ] Cloud-native deployment options
- [ ] Automated scaling based on load
- [ ] VICAL (Verified Issuer Certificate Authority List): Research definition, role in ICAO/MDL/mDoc, and implement as a feature if beneficial.

# How to Contribute to Marty

We welcome contributions to the Marty project! To ensure code quality and maintainability, please follow these guidelines:

*   **Code Quality:** We use Ruff for code quality checks, including complexity. Ensure your code passes these checks before submitting.
*   **Development Process:**
    1.  **API Design:** Structure your APIs thoughtfully.
    2.  **Limited Responsibility Models:** Design models with clear and limited responsibilities.
    3.  **Test-Driven Development (TDD):** Write tests first.
    4.  **Passing Tests:** Implement code to make tests pass by following defined algorithms. Do not hardcode return types merely to satisfy tests.
*   **Debugging and Refactoring:**
    *   When a test fails, first try to reduce the complexity of the failing code.
    *   Create new tests for any refactored code.
    *   Add logging to understand errors before changing the code's algorithm.
*   **Pythonic Solutions:** We favor idiomatic Python solutions.