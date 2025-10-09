# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-03

### Added

- **Semver'd Protobuf Namespaces**: Migrated all protobuf packages to versioned namespaces following `marty.<service>.v1` convention
- **Breaking Change Detection**: Added Buf-based CI workflow for automated breaking change detection in protobuf APIs
- **Versioning Policy**: Established formal protobuf versioning and breaking change policy in architecture documentation
- **Architecture Documentation**: Created comprehensive architecture.md with protobuf versioning guidelines

### Changed

- **BREAKING**: All protobuf packages renamed from simple names to versioned namespaces:
  - `passport` → `marty.passport.v1`
  - `mdoc` → `marty.mdoc.v1`  
  - `trust` → `marty.trust.v1`
  - `common_services` → `marty.common.v1`
  - `biometric_service` → `marty.biometric.v1`
  - `cmc_engine` → `marty.cmc.v1`
  - `csca_service` → `marty.csca.v1`
  - `data_lifecycle` → `marty.lifecycle.v1`
  - `document_signer` → `marty.signer.v1`
  - `dtc_engine` → `marty.dtc.v1`
  - `inspection_system` → `marty.inspection.v1`
  - `mdl_engine` → `marty.mdl.v1`
  - `pkd_service` → `marty.pkd.v1`
  - `rfid_service` → `marty.rfid.v1`
  - `storage_policy` → `marty.storage.v1`
  - `td2_service` → `marty.td2.v1`
  - `visa_service` → `marty.visa.v1`
- **Version Bump**: Project version increased from 0.1.0 to 1.0.0 to reflect breaking protobuf changes
- **GitHub Actions**: Enhanced proto-validation.yml workflow with Buf breaking change detection

### Infrastructure

- **Buf Configuration**: Added buf.yaml for protobuf linting and breaking change detection
- **Protobuf Compilation**: Regenerated all Python stubs with new package structure
- **CI/CD**: Updated GitHub Actions workflows to include breaking change validation

### Migration Guide

This is a breaking change that requires updating any external clients consuming the gRPC APIs:

1. **Update Protobuf Imports**: Change any direct .proto imports to use new package names
2. **Regenerate Client Stubs**: Regenerate client code from updated .proto files
3. **Update Service References**: Update any hardcoded service or message type references
4. **Test Integration**: Thoroughly test all integrations after migration

### Technical Details

- All protobuf type references now use fully qualified names (e.g., `marty.common.v1.ApiError`)
- Python import statements remain unchanged (still use `src.proto.service_pb2`)
- Cross-service type references updated to use new qualified names
- Buf breaking change detection configured for future API evolution

## [0.1.0] - 2025-09-XX

### Added

- Initial release with basic microservices architecture
- Core protobuf definitions for passport, mDoc, trust anchor, and other services
- gRPC service implementations
- Basic CI/CD pipelines

### Features

- Electronic passport processing
- Mobile driving license support
- Digital travel credential handling
- Trust anchor and PKI management
- Document signing services
- Biometric data processing
- RFID operations
- Data lifecycle management

---

**Note**: This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format. For detailed technical information about the protobuf versioning policy and migration procedures, see [docs/architecture.md](docs/architecture.md).
