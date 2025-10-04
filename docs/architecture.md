# Architecture Documentation

## Overview

Marty is an enterprise-grade microservices platform for secure digital identity document management, designed for ICAO PKI compliance and supporting eMRTD, mDL, and DTC standards.

## Protobuf Versioning Policy

### Package Naming Convention

As of version 1.0.0, Marty follows semantic versioning for all protobuf definitions. All protobuf packages use the following naming convention:

```
marty.<service>.<version>
```

Where:
- `marty` is the top-level namespace
- `<service>` is the service domain (e.g., `passport`, `mdoc`, `trust`, `common`)
- `<version>` follows semantic versioning (e.g., `v1`, `v2`)

### Current v1 Package Structure

| Service Domain | Package Name | Description |
|---|---|---|
| Common Services | `marty.common.v1` | Shared error handling, logging, and common types |
| Passport Engine | `marty.passport.v1` | Electronic passport processing |
| Mobile Document | `marty.mdoc.v1` | ISO 18013-5 mobile driving license support |
| Mobile Driving License | `marty.mdl.v1` | MDL-specific processing |
| Trust Anchor | `marty.trust.v1` | PKI trust management and certificate validation |
| Digital Travel Credential | `marty.dtc.v1` | DTC processing engine |
| Document Signer | `marty.signer.v1` | Digital signature services |
| CSCA Service | `marty.csca.v1` | Country Signing Certificate Authority |
| PKD Service | `marty.pkd.v1` | Public Key Directory |
| Biometric Service | `marty.biometric.v1` | Biometric data processing |
| RFID Service | `marty.rfid.v1` | RFID reader operations |
| CMC Engine | `marty.cmc.v1` | Crew Member Certificate |
| Inspection System | `marty.inspection.v1` | Document inspection workflows |
| Storage Policy | `marty.storage.v1` | Annex 9 compliant data retention |
| Data Lifecycle | `marty.lifecycle.v1` | Data lifecycle management |
| TD2 Service | `marty.td2.v1` | TD-2 document processing |
| Visa Service | `marty.visa.v1` | Electronic visa processing |

### Breaking Change Policy

1. **Major Version Changes**: Any breaking change to a protobuf API requires a new major version (e.g., `v1` → `v2`)

2. **Breaking Changes Include**:
   - Removing fields, messages, or services
   - Changing field types
   - Changing field numbers
   - Renaming fields, messages, or services
   - Changing the semantics of existing fields

3. **Non-Breaking Changes**:
   - Adding new fields (with appropriate defaults)
   - Adding new messages
   - Adding new services or RPC methods
   - Adding new enum values
   - Deprecating (but not removing) existing elements

### Version Migration Strategy

1. **Parallel Versions**: Multiple versions can coexist during migration periods
2. **Deprecation Notice**: Old versions are marked deprecated 6 months before removal
3. **Client Migration**: Clients must migrate to new versions within the deprecation period
4. **Backward Compatibility**: Services maintain compatibility with one previous major version

### Breaking Change Detection

The project uses [Buf](https://buf.build) for automated breaking change detection:

- **Continuous Integration**: All pull requests are checked for breaking changes
- **Automated Enforcement**: CI fails if breaking changes are detected without version bumps
- **Local Development**: Developers can run `buf breaking` locally before pushing

### Implementation Details

- **Code Generation**: Python stubs are automatically generated from protobuf definitions
- **Import Strategy**: Python services import from `src.proto.<service>_pb2` modules
- **Compilation**: Use `make compile-protos` to regenerate Python stubs
- **Validation**: Use `buf lint` and `buf breaking` for validation

## Service Architecture

Each service is designed as an independent microservice with:

- **gRPC API**: Defined by protobuf specifications
- **Health Checks**: Standard gRPC health checking
- **Metrics**: Prometheus-compatible metrics
- **Logging**: Structured logging with correlation IDs
- **Security**: mTLS and certificate-based authentication

## Migration Notes

### v0.1.0 → v1.0.0 Migration

This release represents a major architectural shift to semver'd protobuf namespaces:

1. **Package Renaming**: All packages moved from simple names (e.g., `passport`) to versioned namespaces (e.g., `marty.passport.v1`)
2. **Code Generation**: All Python stubs regenerated with new package structure
3. **Breaking Change CI**: Added automated breaking change detection
4. **Version Policy**: Established formal versioning policy for future changes

### Future Considerations

- **Service Mesh**: Consider implementing with Istio or Linkerd
- **API Gateway**: Add centralized API gateway for external clients
- **Schema Registry**: Consider schema registry for enterprise deployments
- **Multi-tenancy**: Design for multi-tenant scenarios in future versions

## References

- [ICAO PKI Standards](https://www.icao.int/Security/FAL/PKI/Pages/default.aspx)
- [ISO 18013-5 Mobile Driving License](https://www.iso.org/standard/69084.html)
- [Protocol Buffers Language Guide](https://developers.google.com/protocol-buffers/docs/proto3)
- [Buf Documentation](https://docs.buf.build/)